"""One typed future-tag facet on the ORIGINAL hosted-dispatch owner.

Prepare/Dispatch use the same saved-config loan, selected Connection, finite
HTTP custodian and immutable local journal as Play cleanup. This module cannot
create a tag: it can dispatch only the fixed protected bind-version-tag job.
An empty 204 or later GET is never a tag-creation/native-finality receipt.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import github_play_cleanup as p
from . import version_future_tag as tag
from . import version_hosted_tag as hosted_tag

PROTOCOL = "mrk-github-version-tag/1"
PLATFORMS = {"android": ("android",), "ios": ("ios",), "both": ("android", "ios")}


@dataclass(frozen=True, slots=True)
class Selection:
    candidate_id: str
    row_sha256: str
    final_commit: str

    @classmethod
    def parse(cls, value):
        row = p.obj(value, {"candidateId", "rowSha256", "finalCommit"})
        p.allocation._uuid(row["candidateId"])
        p.hex_text(row["rowSha256"], 64); p.hex_text(row["finalCommit"], 40)
        return cls(row["candidateId"], row["rowSha256"], row["finalCommit"])

    def value(self):
        return {"candidateId": self.candidate_id, "rowSha256": self.row_sha256, "finalCommit": self.final_commit}


def saved_source(raw):
    p.need(type(raw) is bytes and 0 < len(raw) <= p.LOCAL_CONFIG_LIMIT, "configuration-invalid")
    p.version_text.public_version_selection(raw.decode("utf-8"))
    config = p.parse_config_text(raw.decode("utf-8"))
    enabled = tuple(k for k in ("android", "ios") if config[k].get("enabled") is True)
    p.need(enabled in PLATFORMS.values(), "configuration-invalid")
    platform = next(k for k, v in PLATFORMS.items() if v == enabled)
    digest = hashlib.sha256(raw).hexdigest()
    return p.Source(p.branch(config["source"]["candidateBranch"]), digest, platform, digest)


def candidate_data(value):
    row = p.obj(value, {"candidateId", "rowSha256", "platform", "source", "identityRevision", "baseVersion", "version", "futureTag"})
    p.allocation._uuid(row["candidateId"])
    p.hex_text(row["rowSha256"], 64); p.hex_text(row["identityRevision"], 64)
    p.require(row["platform"] in PLATFORMS)
    source = p.policy.SourceBinding.parse(row["source"])
    p.require(source.ref.startswith("refs/heads/") and source.configuration_sha256 == row["identityRevision"])
    p.policy.parse_version(row["baseVersion"], PLATFORMS[row["platform"]], automatic=True)
    p.policy.parse_version(row["version"], PLATFORMS[row["platform"]], automatic=True)
    tag.reference(row["futureTag"])
    return dict(row)


def confirmation(prepared):
    c = prepared.candidate
    return ("Dispatch a future-tag binding for " + c["futureTag"] + " to " + prepared.source_sha
        + " in " + prepared.target.repository + "? Reserved version " + c["version"]["name"]
        + " (build " + str(c["version"]["build"]) + ") came from branch source " + c["source"]["commit"]
        + ". The tag name does not determine that number. The protected workflow must prove the exact version-only commit and claim this candidate once. "
        "It creates only an absent lightweight tag; it never moves an existing tag. Creating it may trigger your other automation. "
        "This job does not build, sign, access Stores or upload. Candidate builds remain branch-triggered. "
        "The configured branch " + prepared.branch + " is mutable; a changed dispatch head must refuse. "
        "An acknowledgement is not a tag receipt or a run ID. Stopping cannot undo a sent request.")


def parse_prepared(row):
    p.obj(row, {"target", "accountLogin", "branch", "sourceSha", "sourceTree", "savedConfigSha256", "workflowId",
        "callerSha256", "authority", "checkpoint", "ledgerBlob", "candidate", "confirmation"})
    target = p.Target.parse(row["target"])
    p.require(target.version_tag is not None and target.pending_purpose is None)
    authority = p.allocation.AuthorityRegistration.parse(row["authority"])
    checkpoint = p.allocation.Checkpoint.parse(row["checkpoint"])
    c = candidate_data(row["candidate"])
    selected = target.version_tag
    p.require(c["candidateId"] == selected.candidate_id and c["rowSha256"] == selected.row_sha256
        and row["sourceSha"] == selected.final_commit and c["source"]["commit"] != row["sourceSha"]
        and c["source"]["ref"] == "refs/heads/" + p.branch(row["branch"])
        and row["savedConfigSha256"] == c["identityRevision"]
        and authority.protected_branch and authority.repository_id == target.scope.repository_id
        and authority.repository.lower() == target.repository.lower())
    for key in ("sourceSha", "sourceTree", "ledgerBlob"): p.hex_text(row[key], 40)
    for key in ("savedConfigSha256", "callerSha256"): p.hex_text(row[key], 64)
    value = p.Prepared(target, p.login(row["accountLogin"]), row["branch"], row["sourceSha"], row["sourceTree"],
        row["savedConfigSha256"], p._id(row["workflowId"]), row["callerSha256"], authority, checkpoint,
        row["ledgerBlob"], None, None, None, c)
    p.require(value.value() == row and len(p.canonical(row)) <= p.MAX_PREPARED_BYTES
        and hashlib.sha256(p.canonical_caller(target)).hexdigest() == value.caller_sha256)
    return value


def dispatch_body(prepared):
    c = prepared.candidate
    intent = hosted_tag.Intent(c["platform"], c["candidateId"], c["rowSha256"], prepared.source_sha)
    return p.canonical({"ref": prepared.branch, "inputs": {"operation": "bind-version-tag", "platform": c["platform"],
        "confirmation": intent.confirmation()}})


class Operation(p.Operation):
    def selected(self, snapshot, *, prepared=None):
        selected = self.target.version_tag
        p.need(selected is not None, "invalid-input")
        ledger = snapshot.ledger
        rows = [r for r in ledger.reservations if r.request.candidate_id == selected.candidate_id]
        p.need(len(rows) == 1 and rows[0].sha256 == selected.row_sha256, "review-changed")
        row = rows[0]
        p.need(row.request.future_tag is not None, "review-changed")
        g = ledger.genesis
        authority = p.allocation.AuthorityRegistration(g.project_id, self.target.repository, g.repository_id, g.ledger_id, g.sha256, True)
        ledger.admit(authority, snapshot.checkpoint if prepared is None else prepared.checkpoint)
        c = candidate_data({"candidateId": row.request.candidate_id, "rowSha256": row.sha256,
            "platform": next(k for k, v in PLATFORMS.items() if v == row.request.enabled_platforms),
            "source": row.request.source.value(), "identityRevision": row.request.identity_revision,
            "baseVersion": p.policy.version_value(row.request.base_version), "version": p.policy.version_value(row.version),
            "futureTag": row.request.future_tag})
        if prepared is not None:
            p.need(authority == prepared.authority and c == prepared.candidate, "review-changed")
        return authority, row, c

    def tag(self, candidate):
        return self.take("tag", "git/ref/" + candidate["futureTag"].removeprefix("refs/"), missing=True)

    def prepare(self):
        source = self.source
        p.need(source is not None, "configuration-invalid")
        name = self.identity()  # 1–2
        head, tree = self.branch("branch-before", source.branch)  # 3
        p.need(head == self.target.version_tag.final_commit, "source-changed")
        workflow = self.workflow()  # 4
        caller = p.release._contents(self.take("caller", "contents/" + p.WORKFLOW_PATH + "?ref=" + head),
                                    p.WORKFLOW_PATH, p.MAX_CALLER_BYTES, "caller-mismatch")  # 5
        p.need(caller == p.canonical_caller(self.target), "caller-mismatch")
        entries = p.release._source_tree(self.take("current-tree", "git/trees/" + tree + "?recursive=1"),
            self.target, tree, (p.WORKFLOW_PATH, p.version_text.CONFIG_PATH))  # 6
        p.release._match_blob(entries[p.WORKFLOW_PATH], caller)
        self.protection("protection-before")  # 7
        current = self.ref("ref-before")  # 8
        snapshot = self.snapshot(current)  # 9
        authority, row, candidate = self.selected(snapshot)
        p.need(not any(b.candidate_id == row.request.candidate_id for b in snapshot.ledger.tag_bindings), "previous-attempt")
        p.need(row.request.source.ref == "refs/heads/" + source.branch and candidate["platform"] == source.platform
            and row.request.identity_revision == source.saved_sha256, "source-changed")
        # Existing complete original B config/version/tree proof; no simulated
        # native source and no hosted localProjectId/enrollment requirement.
        before = self.take("original-commit", "git/commits/" + row.request.source.commit)  # 10
        p.need(type(before) is dict and before.get("sha") == row.request.source.commit
            and type(before.get("tree")) is dict and before["tree"].get("sha") == row.request.source.tree, "source-changed")
        final = self.take("final-commit", "git/commits/" + head)  # 11
        p.need(type(final) is dict and final.get("sha") == head
            and type(final.get("tree")) is dict and final["tree"].get("sha") == tree
            and type(final.get("parents")) is list and len(final["parents"]) == 1
            and type(final["parents"][0]) is dict
            and final["parents"][0].get("sha") == row.request.source.commit, "source-changed")
        raw = p.release._contents(self.take("original-config", "contents/" + p.version_text.CONFIG_PATH
            + "?ref=" + row.request.source.commit, config=True), p.version_text.CONFIG_PATH, p.MAX_CONFIG_BYTES, "config-invalid")  # 12
        self.guard_document(raw)
        p.need(hashlib.sha256(raw).hexdigest() == source.saved_sha256, "source-changed")
        p.release._match_blob(entries[p.version_text.CONFIG_PATH], raw)
        selection = p.version_text.public_version_selection(raw.decode("utf-8"))
        entries = p.release._source_tree(self.take("original-tree", "git/trees/" + row.request.source.tree + "?recursive=1"),
            self.target, row.request.source.tree, (p.version_text.CONFIG_PATH, selection.source))  # 13
        version = p.release._contents(self.take("original-version", "contents/" + p.release._quote_path(selection.source)
            + "?ref=" + row.request.source.commit), selection.source, p.MAX_VERSION_BYTES, "version-invalid")  # 14
        p.release._match_blob(entries[p.version_text.CONFIG_PATH], raw); p.release._match_blob(entries[selection.source], version)
        p.need(hashlib.sha256(version).hexdigest() == row.request.source.version_sha256, "source-changed")
        parsed = p.version_text.original_text(selection, version)
        p.need(p.ReleaseVersion(parsed.values[0], int(parsed.values[1])) == row.request.base_version, "source-changed")
        p.need(self.tag(candidate) is None, "tag-exists")  # 15
        p.need(self.branch("branch-after", source.branch) == (head, tree), "source-changed")  # 16
        p.need(self.ref("ref-after") == current, "authority-changed")  # 17
        self.protection("protection-after"); self.repository("repository-after")  # 18–19
        p.need(len(self.steps) == p.MAX_REQUESTS)
        return p.Prepared.parse(p.Prepared(self.target, name, source.branch, head, tree, source.saved_sha256, workflow,
            hashlib.sha256(caller).hexdigest(), authority, snapshot.checkpoint, snapshot.blob, None, None, None, candidate).value())

    def current_for_dispatch(self, prepared):
        source = self.source
        p.need(source is not None and source.saved_sha256 == prepared.saved_config_sha256
            and source.branch == prepared.branch and source.platform == prepared.candidate["platform"], "review-changed")
        p.need(self.identity() == prepared.account_login, "target-changed")  # 1–2
        p.need(self.branch("branch-before", source.branch) == (prepared.source_sha, prepared.source_tree), "source-changed")  # 3
        p.need(self.workflow() == prepared.workflow_id, "workflow-unavailable")  # 4
        self.protection("protection-before")  # 5
        current = self.ref("ref-before")  # 6
        p.need(current == prepared.checkpoint.commit, "review-changed")
        snapshot = self.snapshot(current)  # 7
        self.selected(snapshot, prepared=prepared)
        p.need(snapshot.blob == prepared.ledger_blob and not any(b.candidate_id == prepared.candidate["candidateId"]
            for b in snapshot.ledger.tag_bindings), "previous-attempt")
        p.need(self.tag(prepared.candidate) is None, "tag-exists")  # 8
        p.need(self.ref("ref-after") == current, "authority-changed")  # 9
        p.need(self.branch("branch-after", source.branch) == (prepared.source_sha, prepared.source_tree), "source-changed")  # 10
        self.protection("protection-after"); self.repository("repository-after")  # 11–12; sole POST13 by original dispatch.


def observation(value):
    row = p.obj(value, {"counterCommit", "ledgerSha256", "binding", "assurance"})
    p.hex_text(row["counterCommit"], 40); p.hex_text(row["ledgerSha256"], 64)
    p.require(row["binding"] in ("unclaimed", "claimed-tag-absent", "claimed-tag-matches", "mismatch")
        and row["assurance"] == "later-binding-read-not-creation-proof")
    return dict(row)


def observe(record, exchange):
    original = p.pending_record(record); prepared = p.Prepared.parse(original["prepared"])
    op = Operation(prepared.target, None, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": original["claimed"],
        "acknowledged": original["acknowledged"], "observed": None, "control": p._control()}
    try:
        op.identity(); op.protection("protection-before")
        current = op.ref("ref-before"); snapshot = op.snapshot(current)
        _, row, c = op.selected(snapshot, prepared=prepared)
        if current != prepared.checkpoint.commit:
            p.allocation._ancestry(op.take("counter-ancestry", "compare/" + prepared.checkpoint.commit + "..." + current
                + "?per_page=1&page=1"), prepared.checkpoint.commit, current)
        matches = [b for b in snapshot.ledger.tag_bindings if b.candidate_id == c["candidateId"]]
        present = op.tag(c)
        state = "unclaimed" if not matches and present is None else "mismatch"
        if matches and matches[0].reservation_sha256 == row.sha256 and matches[0].final_commit == prepared.source_sha and matches[0].final_tree == prepared.source_tree:
            state = "claimed-tag-absent" if present is None else "mismatch"
            if type(present) is dict and present.get("ref") == c["futureTag"] and present.get("object") == {"type": "commit", "sha": prepared.source_sha}:
                state = "claimed-tag-matches"
            elif present is not None:
                try: tag.check_ref(present, c["futureTag"], prepared.source_sha); state = "claimed-tag-matches"
                except ValueError: pass
        p.need(op.ref("ref-after") == current, "authority-changed")
        op.protection("protection-after"); op.repository("repository-after")
        result.update(effect="observed-unconfirmed", reason="none", observed=observation({"counterCommit": current,
            "ledgerSha256": hashlib.sha256(snapshot.ledger.to_bytes()).hexdigest(), "binding": state,
            "assurance": "later-binding-read-not-creation-proof"}))
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError, p.ReadFailure) as error:
        result["reason"] = p.reason(error)
    result["control"] = dict(op.control)
    return result
