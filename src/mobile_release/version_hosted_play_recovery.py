"""Optional, one-claim cleanup of a *known, joined* hosted Play edit.

Only the existing Ruby owner handles plaintext IDs/AEAD/provider IO. The same
Git journal holds ciphertext; it is neither an allocation nor a cleanup receipt.
Unknown insert responses/children and legacy fences cannot become recoverable.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import hashlib
import math
import os
from pathlib import Path
import re
import sys
from uuid import uuid4

from . import android_store_versions as android
from . import version_allocation as allocation
from . import version_policy as p
from ._desktop_github_engine import _decode_json
from .build_inputs import finite_scratch
from .owned_process import run_owned

KEY = "MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_BASE64"
VERSION = "MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_VERSION"
AAD = "MOBILE_RELEASE_PLAY_EDIT_RECOVERY_AAD"
CAPSULE = "MOBILE_RELEASE_PLAY_EDIT_RECOVERY_CAPSULE"
PURPOSE = "hosted-play-edit-recovery/1"
CAPSULE_LIMIT = 4096
PLAIN_LIMIT = 2048
VERIFY_SECONDS = 5
MAX_REQUESTS = 24
MAX_WRITES = 2
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)


def need(value):
    from .version_hosted import need as require
    require(value, "play-recovery")


def _base64(value, maximum, exact=None):
    need(type(value) is str and value.isascii() and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        need(False)
    need(0 < len(raw) <= maximum and (exact is None or len(raw) == exact)
         and base64.b64encode(raw).decode("ascii") == value)
    return raw


@dataclass(frozen=True, slots=True)
class Capsule:
    key_version: str
    nonce: str
    ciphertext: str
    tag: str
    aad_sha256: str

    def __post_init__(self):
        need(type(self.key_version) is str and _VERSION.fullmatch(self.key_version) is not None)
        _base64(self.nonce, 12, 12)
        _base64(self.ciphertext, PLAIN_LIMIT)
        _base64(self.tag, 16, 16)
        p._match(self.aad_sha256, p._DIGEST)
        need(len(p.canonical(self.value())) <= CAPSULE_LIMIT)

    def value(self):
        return {"schemaVersion": 1, "algorithm": "AES-256-GCM", "keyVersion": self.key_version,
            "nonce": self.nonce, "ciphertext": self.ciphertext, "tag": self.tag, "aadSha256": self.aad_sha256}

    @classmethod
    def parse(cls, value):
        row = p._object(value, {"schemaVersion", "algorithm", "keyVersion", "nonce", "ciphertext", "tag", "aadSha256"})
        need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["algorithm"] == "AES-256-GCM")
        return cls(*(row[key] for key in ("keyVersion", "nonce", "ciphertext", "tag", "aadSha256")))


@dataclass(frozen=True, slots=True)
class Claim:
    cleanup_attempt_id: str
    run_id: str
    attempt: int

    def __post_init__(self):
        allocation._uuid(self.cleanup_attempt_id)
        need(type(self.run_id) is str and _NUMBER.fullmatch(self.run_id) is not None
             and int(self.run_id) <= (1 << 64) - 1)
        p._integer(self.attempt, 999, 1)

    def value(self):
        return {"cleanupAttemptId": self.cleanup_attempt_id, "runId": self.run_id, "attempt": self.attempt}

    @classmethod
    def parse(cls, value):
        row = p._object(value, {"cleanupAttemptId", "runId", "attempt"})
        return cls(row["cleanupAttemptId"], row["runId"], row["attempt"])


@dataclass(frozen=True, slots=True)
class Record:
    capsule: Capsule
    claim: Claim | None = None

    def __post_init__(self):
        need(type(self.capsule) is Capsule and (self.claim is None or type(self.claim) is Claim))

    def value(self):
        return {"capsule": self.capsule.value(), "claim": None if self.claim is None else self.claim.value()}

    @classmethod
    def parse(cls, value):
        row = p._object(value, {"capsule", "claim"})
        return cls(Capsule.parse(row["capsule"]), None if row["claim"] is None else Claim.parse(row["claim"]))


def _selected(journal, original):
    from .version_hosted import _Journal, PlayQuery
    need(type(journal) is _Journal and type(original) is PlayQuery and journal._loaded
         and journal.play_query == original)
    journal._usable()
    original.require_state(journal._state)
    rows = [row for row in journal._state.candidates if row.request.candidate_id == original.candidate_id]
    need(len(rows) == 1)
    row = rows[0]
    need(row.request.project_id == journal.settings.authority.project_id
         and row.request.sha256 == original.request_sha256
         and any(item.local_project_id == row.local_project_id
                 and item.authority_project_id == row.request.project_id for item in journal._state.enrollments))
    return row


def _aad(journal, row, original, version):
    # Canonical bytes are used directly by OpenSSL; all request/source fields
    # come from the exact selected original, never from cleanup CLI arguments.
    return p.canonical({"schemaVersion": 1, "purpose": PURPOSE, "keyVersion": version,
        "authority": journal.settings.authority.value(), "localProjectId": row.local_project_id,
        "candidateId": original.candidate_id, "requestSha256": original.request_sha256,
        "attemptId": original.attempt_id, "source": row.request.source.value(),
        "contextSha256": row.request.store_context_revision, "identityRevision": row.request.identity_revision})


def _known_insert(frame, package, context):
    """Strict original private frame, not Material's best-effort ID extraction.

    Complete INSERT is required. Subsequent bounded provider failures can be
    retained, but malformed frame/ordering/paths/cleanup claims cannot.
    """
    row = p._object(frame, {"schemaVersion", "scope", "contextSha256", "packageName", "pages", "queryFinished", "temporaryEdit"})
    need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["scope"] == android.SCOPE
         and row["contextSha256"] == context and row["packageName"] == package and row["queryFinished"] is False)
    effect = p._object(row["temporaryEdit"], {"insertAttempted", "editId", "deleteAttempted", "deleteConfirmed"})
    need(effect["insertAttempted"] is True and type(effect["deleteAttempted"]) is bool
         and effect["deleteConfirmed"] is False and type(effect["editId"]) is str
         and android._EDIT.fullmatch(effect["editId"]) is not None)
    pages = row["pages"]
    need(type(pages) is list and 1 <= len(pages) <= 5)
    steps = [page.get("step") if type(page) is dict else None for page in pages]
    has_delete = steps[-1] == "delete"
    following = steps[1:-1] if has_delete else steps[1:]
    need(steps[0] == "insert" and following == list(android.COLLECTIONS[:len(following)])
         and len(following) <= 3 and effect["deleteAttempted"] == has_delete)
    total = 0
    for index, page in enumerate(pages):
        page = p._object(page, {"step", "request", "response"})
        step = page["step"]
        need(page["request"] == android.request(step, package, None if index == 0 else effect["editId"]))
        response = p._object(page["response"], {"status", "failure", "bodyBase64"})
        status, failure, encoded = (response[key] for key in ("status", "failure", "bodyBase64"))
        need(status is None or type(status) is int and 100 <= status <= 599)
        need(failure in (None, "provider_request_unconfirmed", "inventory_limit"))
        raw = None
        if encoded is not None:
            limit = android.EDIT_RAW_LIMIT if step in {"insert", "delete"} else android.RAW_LIMIT
            need(type(encoded) is str and encoded.isascii() and len(encoded) <= 4 * ((limit + 2) // 3))
            raw = base64.b64decode(encoded, validate=True)
            need(len(raw) <= limit and base64.b64encode(raw).decode("ascii") == encoded
                 and status is not None and failure is None)
            total += len(raw)
            need(total <= android.RAW_TOTAL_LIMIT)
        else:
            need(failure is not None)
        if index == 0:
            need(status == 200 and failure is None and raw is not None)
            created = p._object(android._json(raw), {"id", "expiryTimeSeconds"})
            need(created["id"] == effect["editId"] and type(created["expiryTimeSeconds"]) is str
                 and re.fullmatch(r"[1-9][0-9]{0,18}", created["expiryTimeSeconds"], re.ASCII) is not None)
        elif step == "delete":
            need(not (status == 204 and failure is None and raw == b""))


class Capture:
    """One optional selected key + SAME Material's private returned capsule."""
    def __init__(self, *, enabled):
        self.selected = {name: os.environ.get(name, "") for name in (KEY, VERSION)}
        self.enabled = any(self.selected.values())
        need(not self.enabled or enabled)
        if self.enabled:
            _base64(self.selected[KEY], 32, 32)
            need(_VERSION.fullmatch(self.selected[VERSION]) is not None)
        self.original = self.journal = self.row = self.aad = self.capsule = self.returned = None
        self.consumed = False

    def __repr__(self):
        return "<HostedPlayRecoveryCapture private>"

    def check(self):
        need(all(os.environ.get(name, "") == value for name, value in self.selected.items()))

    def bind(self, journal, request, source, original):
        if not self.enabled:
            return
        self.check()
        need(self.original is None and original is journal._play_original
             and source is journal.remote.source and source.material.recovery is self
             and source.material._source is source)
        row = _selected(journal, original)
        need(row.request == request and request.source == source.binding)
        self.journal, self.row, self.original = journal, row, original
        self.aad = _aad(journal, row, original, self.selected[VERSION])

    def environment(self):
        if not self.enabled:
            return {}
        self.check()
        need(self.original is not None and self.aad is not None)
        return {**self.selected, AAD: self.aad.decode("ascii")}

    def frame(self, completed, package, context):
        if not self.enabled:
            return completed.stdout
        need(self.returned is None and self.original is not None)
        self.returned = completed  # Retained before parsing; never replaced.
        frame = android._json(completed.stdout, frame=True)
        need("hostedRecovery" in frame)
        value = frame.pop("hostedRecovery")
        if value is not None:
            _known_insert(frame, package, context)
            capsule = Capsule.parse(value)
            need(capsule.key_version == self.selected[VERSION]
                 and capsule.aad_sha256 == hashlib.sha256(self.aad).hexdigest())
            self.capsule = capsule
        return p.canonical(frame) + b"\n"


def retain_play_recovery(journal, request, source, original):
    from .version_hosted_store import Material
    need(type(source.material) is Material)
    material, capture = source.material, source.material.recovery
    need(type(capture) is Capture and capture.enabled and not capture.consumed
         and capture.journal is journal and capture.original is original is journal._play_original
         and material._play_original is original and material._source is source
         and material._play_used and material._play_closed and not material._play_consumed
         and material._play_cleanup == "unconfirmed" and capture.capsule is not None
         and capture.returned is material._play_return and original.recovery is None)
    source.remaining()
    need(material.context(source) == request.store_context_revision
         and _selected(journal, original) == capture.row and capture.row.request == request)
    capture.check()
    capture.consumed = material._play_consumed = True  # Before sole original CAS.
    journal._commit_play_recovery(original, replace(original, recovery=Record(capture.capsule)), capture.row)


def _original_source(source, row):
    """Re-read immutable original blobs; never reset HEAD or invent a Git read."""
    from . import version_hosted as h
    from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseVersion, parse_config_text
    request = row.request
    source.head(source.context.authority["headSha"])
    tree, _, _ = source.commit(request.source.commit)
    raw = source.entry(request.source.commit, h.version_text.CONFIG_PATH, MAX_CONFIG_BYTES)
    config = parse_config_text(raw.decode("utf-8"))
    enabled = tuple(key for key in ("android", "ios") if config[key].get("enabled") is True)
    need(enabled == request.enabled_platforms == h._PLATFORMS[source.context.platform] and "android" in enabled)
    package = config["android"].get("applicationId")
    android.package_identity(package)
    selection = h.version_text.public_version_selection(raw.decode("utf-8"))
    version_raw = source.entry(request.source.commit, selection.source, MAX_VERSION_BYTES)
    parsed = h.version_text.original_text(selection, version_raw)
    binding = p.SourceBinding(request.source.commit, tree, request.source.ref,
        hashlib.sha256(raw).hexdigest(), hashlib.sha256(version_raw).hexdigest())
    identity = {"platform": source.context.platform, "packageName": package}
    if "ios" in enabled:
        app, bundle = config["ios"].get("appStoreAppId"), config["ios"].get("bundleId")
        h.ios.app_identity(app, bundle)
        identity.update(appId=app, bundleId=bundle)
    need(binding == request.source and p.digest(identity) == request.identity_revision
         and ReleaseVersion(parsed.values[0], int(parsed.values[1])) == request.base_version)
    source.binding, source.enabled, source.package = binding, enabled, package
    source.remaining()


class Cleanup:
    """Same action endpoint/material; two joined children, one durable claim.

    No wire/JSON result can construct this holder's returned/closed provenance.
    The verifier has no SDK or network; DELETE is unavailable before claim ACK.
    """
    def __init__(self, journal, material, original):
        from .version_hosted_store import Material
        need(type(material) is Material and material.platform == "android"
             and material.recovery.enabled and not material.used)
        self.journal, self.material, self.original = journal, material, original
        self.source = journal.remote.source
        need(self.source.material is material and journal._play_original is None)
        self.row = _selected(journal, original)
        record = original.recovery
        need(type(record) is Record and record.claim is None and journal._schema_version == 3)
        self.capsule = record.capsule
        need(self.capsule.key_version == material.recovery.selected[VERSION])
        self.aad = _aad(journal, self.row, original, self.capsule.key_version)
        need(hashlib.sha256(self.aad).hexdigest() == self.capsule.aad_sha256)
        self.verified = self.deleted = self.claim = None
        self.verify_entered = self.delete_entered = self.claim_entered = self.clear_entered = False
        self.private_returns = []
        self.scratch = []

    def __repr__(self):
        return "<HostedPlayCleanup private>"

    def current(self):
        self.source.remaining()
        self.material.check()
        need(self.source.material is self.material and self.journal.remote.source is self.source
             and self.material.recovery.selected[VERSION] == self.capsule.key_version)

    def _child(self, mode):
        from .version_hosted_store import _GAC
        self.current()
        # ALL work/child cleanup stays within the one action's original end.
        # DELETE also leaves 8s (including the owned child's 3s tail) for CAS.
        hard_end = min(self.source.end - 8, self.source.last + VERIFY_SECONDS) if mode == "verify" else self.source.end - 8
        need(hard_end - self.source.last >= 1)
        with finite_scratch(layout="store-selection", cancellation=self.source.guard) as selected:
            self.scratch.append(selected)
            snapshot = selected.put("google-adc", self.material.google)
            path = selected.require(snapshot)
            with finite_scratch(layout="online-runner", cancellation=self.source.guard) as runner:
                self.scratch.append(runner)
                self.current()
                selected.require(snapshot)
                # verify reuses Input's bounded SA *read*, but loads no SDK and
                # cannot authenticate. No token/P8/GitHub credential in this env.
                env = {**self.material._environment(), **self.material.recovery.selected,
                    AAD: self.aad.decode("ascii"), CAPSULE: p.canonical(self.capsule.value()).decode("ascii"),
                    _GAC: str(path), "MOBILE_RELEASE_PLAY_PACKAGE": self.source.package,
                    "MOBILE_RELEASE_PLAY_CONTEXT": self.row.request.store_context_revision,
                    "MOBILE_RELEASE_PLAY_READ_END_NS": str(math.floor(hard_end * 10**9)),
                    "MOBILE_RELEASE_PLAY_HARD_END_NS": str(math.floor(hard_end * 10**9))}
                timeout = math.floor(hard_end - self.source.last)
                need(timeout >= 1)
                result = run_owned(("bundle", "exec", "ruby", str(self.material.tooling / "fastlane/play_edit_recovery.rb"), mode),
                    cwd=runner._path, environ=env, capture=True, text=False, output_limit=1024,
                    timeout=timeout, cancellation=self.source.guard)
                self.private_returns.append(result)  # Even a late failure stays retained.
                self.current()
                need(type(result.returncode) is int and result.returncode == 0 and result.stderr == b""
                     and type(result.stdout) is bytes and 0 < len(result.stdout) <= 1024)
                body = _decode_json(result.stdout, limit=1024, nodes=24, depth=2)
                need(type(body) is dict and type(body.get("schemaVersion")) is int)
                expected = {"schemaVersion": 1, "scope": PURPOSE, "mode": mode,
                    "capsuleSha256": p.digest(self.capsule.value()), "aadSha256": self.capsule.aad_sha256}
                if mode == "verify":
                    expected["verified"] = True
                    need(body.get("verified") is True)
                else:
                    expected.update(deleteAttempted=True, deleteConfirmed=True)
                    need(body.get("deleteAttempted") is True and body.get("deleteConfirmed") is True)
                need(body == expected)
                selected.require(snapshot)
            selected.require(snapshot)
        self.current()  # Both actual scratch closures, not merely output DATA.
        return result

    def verify(self):
        need(not self.verify_entered and self.claim is None and not self.delete_entered)
        self.verify_entered = True
        self.material.used = True
        self.verified = self._child("verify")

    def claim_once(self):
        need(self.verified is not None and not self.claim_entered and self.claim is None
             and self.journal._cleanup_original is None)
        self.current()
        need(_selected(self.journal, self.original) == self.row)
        self.claim_entered = True
        actual = self.source.context.authority
        claim = Claim(str(uuid4()), actual["runId"], actual["attempt"])
        selected = replace(self.original, recovery=Record(self.capsule, claim))
        self.journal._cleanup_original = self  # Retain BEFORE possible lost ACK.
        self.journal._commit_play_recovery(self.original, selected, self.row)
        self.current()
        self.claim = selected  # Only after actual CAS AND full readback.

    def delete(self):
        need(self.claim is not None and not self.delete_entered and self.journal._cleanup_original is self
             and _selected(self.journal, self.claim) == self.row)
        self.current()
        self.delete_entered = True
        self.deleted = self._child("delete")

    def clear(self):
        need(self.deleted is not None and not self.clear_entered and self.claim is not None
             and self.journal._cleanup_original is self and _selected(self.journal, self.claim) == self.row)
        self.current()
        self.clear_entered = True
        self.journal._commit_play_recovery(self.claim, None, self.row)
        self.current()


def _admit(context):
    from . import version_hosted as h
    need(context.stage == "candidate" and context.current_job == "version_reserve"
         and context.platform in {"android", "both"} and context.selected_platform == context.platform
         and os.environ.get("MOBILE_RELEASE_OPERATION") == "recover-play-edit")
    parts = context.confirmation.split(":")
    need(len(parts) == 3 and parts[0] == "recover-play-edit")
    allocation._uuid(parts[1]); allocation._uuid(parts[2])
    need(all(not os.environ.get(key, "") for key in (h.POLICY_ENV, "MOBILE_RELEASE_RECOVERY_RUN_ID",
        "MOBILE_RELEASE_RECOVERY_CONFIRMATION", "MOBILE_RELEASE_DESKTOP_REQUEST", "MOBILE_RELEASE_DESKTOP_SOURCE_SHA",
        "MOBILE_RELEASE_DESKTOP_EXPECTED_REF")))
    token = os.environ.get(h.TOKEN_ENV, "")
    need(1 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token))
    settings = h.ci.Settings.parse(os.environ.get(h.ci.AUTHORITY_ENV, ""))
    need(settings.authority.repository == context.repository["fullName"]
         and settings.authority.repository_id == context.repository["id"])
    return settings, parts[1], parts[2]


def _recover(source, settings, remote, material, candidate, attempt):
    from . import version_hosted as h
    h._attempt(remote, source.context)
    journal = h._Journal(remote, settings)
    journal.load()
    original = journal.play_query
    need(original is not None and (original.candidate_id, original.attempt_id) == (candidate, attempt))
    row = _selected(journal, original)
    _original_source(source, row)
    commit = remote.read("git/commits/" + row.request.source.commit)
    need(commit.get("sha") == row.request.source.commit and type(commit.get("tree")) is dict
         and commit["tree"].get("sha") == row.request.source.tree)
    held = Cleanup(journal, material, original)
    held.verify()  # Wrong secret/account/tag cannot consume a claim.
    remote.journal_current(journal.commit)
    held.claim_once()
    # One protected authority check immediately before token/DELETE, no new
    # reservation/current-source requirement for this original historical edit.
    allocation._repository_identity(remote.read(""), settings.authority)
    h.enrollment._protection(remote.read("branches/" + allocation.LEDGER_BRANCH + "/protection"))
    remote.journal_current(journal.commit)
    held.delete()
    remote.journal_current(journal.commit)
    held.clear()
    need(journal.writes == 2 and remote.calls <= MAX_REQUESTS and source.git_calls <= 12)
    return {"schemaVersion": 1, "status": "play-edit-cleanup-confirmed", "candidateId": candidate,
        "playAttemptId": attempt, "cleanupAttemptId": held.claim.recovery.claim.cleanup_attempt_id,
        "allocation": "not-performed", "inventory": "not-observed"}


def recover(app_root, tooling_root):
    from . import version_hosted as h
    from .version_hosted_store import Material
    selected = os.environ.get("MOBILE_RELEASE_SELECTED_PLATFORM", "")
    need(selected in {"android", "both"})
    context = h.workflow.Context.current("candidate", selected)
    settings, candidate, attempt = _admit(context)
    root, tooling = h.workflow._safe_path(app_root), h.workflow._safe_path(tooling_root)
    need(root.is_dir() and tooling.is_dir() and (root / ".git").is_dir() and not (root / ".git").is_symlink())
    guard, owns = h.cancellation_owner(None, h.ProcessCleanupError, "Hosted Play cleanup is unconfirmed")
    scope = h.CleanupScope(guard, lambda: None, owns_cancellation=owns, first_primary=True)
    try:
        with scope:
            if owns:
                guard.install(); guard.activate()
            source = h._Source(root, context, guard)
            material = Material(tooling, platform="android")  # Never P8, even for original paired request.
            need(material.recovery.enabled)
            source.material = material
            remote = h._Remote(settings.authority, source, h._live(source, tooling, os.environ[h.TOKEN_ENV]))
            remote.max_calls = MAX_REQUESTS
            result = _recover(source, settings, remote, material, candidate, attempt)
    finally:
        scope.__exit__(*sys.exc_info())
    guard.check()
    return result


def main(argv=None):
    from . import version_hosted as h
    try:
        need((sys.argv[1:] if argv is None else argv) == ["cleanup"])
        result = recover(Path(os.environ.get("MOBILE_RELEASE_APP_ROOT", "")),
                         Path(os.environ.get("MOBILE_RELEASE_TOOLING_ROOT", "")))
        print(p.canonical(result).decode("ascii"))
        return 0
    except (Exception, KeyboardInterrupt):
        # Never print crypto/provider/parser errors or a decrypted ID.
        print(h._DIAGNOSTICS["play-recovery"], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
