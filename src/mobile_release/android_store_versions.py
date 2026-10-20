"""Current Google Play edit inventory DATA, never a native Store receipt.

Google exposes these inventories through a temporary edit. Creating/deleting
that edit is a real external effect and may invalidate another edit for the
same application/account. All three CURRENT lists must be read and that exact
edit deleted; this is not all historical uploads or cross-uploader uniqueness.
The original StorePreflightRun and native Google material/clock/joins remain
the authority. The v1 historical and v2 iOS policies are deliberately unchanged.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from . import version_policy as policy
from ._desktop_github_engine import _decode_json

QUERY = "android-current-versions"
CONSENT = "local-android-current-versions-edit-v1"
SCOPE = "play-android-current-inventory/1"
RESULT_SCOPE = "local-android-current-version-inventory"
POLICY_SCOPE = "require-current-android-inventory"
RAW_LIMIT = 128 * 1024
EDIT_RAW_LIMIT = 16 * 1024
RAW_TOTAL_LIMIT = 1024 * 1024
FRAME_LIMIT = 2 * 1024 * 1024
MAX_ROWS = 400
MAX_RELEASES = 400
MAX_CODES = 4000
MAX_REQUESTS = 5  # insert, tracks, bundles, APKs, delete; token stays private
QUERY_SECONDS = 60
READ_SECONDS = 50  # Within the same command; remaining time is cleanup only.
COLLECTIONS = ("tracks", "bundles", "apks")
COUNTS = ("tracks", "releases", "versionCodes", "bundles", "apks")
LIMITATIONS = ["non-publishing", "no-project-commands", "no-build-or-signing", "no-release-readiness",
    "point-in-time-account-access", "saved-inputs-not-atomic", "current-visible-only",
    "not-atomic-store-snapshot", "historical-uniqueness-not-established", "external-uploaders-not-coordinated",
    "temporary-play-edit", "may-invalidate-another-play-edit"]
OBSERVATIONS = frozenset({"observed", "not-checked", "not-permitted", "inconclusive", "too-many",
                         "unsupported-format", "temporary-edit-unconfirmed"})
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z", re.ASCII)
_EDIT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z", re.ASCII)
_DECIMAL = re.compile(r"[1-9][0-9]{0,9}\Z", re.ASCII)
_KINDS = {name: "androidpublisher#" + name + "ListResponse" for name in COLLECTIONS}


class InventoryError(ValueError):
    def __init__(self, reason="inconclusive"):
        self.reason = reason if reason in OBSERVATIONS - {"observed"} else "inconclusive"
        super().__init__("Current Google Play versions could not be established")


def _need(value, reason="inconclusive"):
    if not value:
        raise InventoryError(reason)


def package_identity(value):
    _need(type(value) is str and len(value) <= 255 and _PACKAGE.fullmatch(value) is not None)


def selected_query(context: dict) -> bool:
    return context.get("query") == QUERY and context.get("platform") == "android"


def query_prerequisites(config) -> bool:
    try:
        if not config.platform_enabled("android") or config.section("android").get("identityStatus") == "blocked":
            return False
        package_identity(config.section("android").get("applicationId"))
        return True
    except InventoryError:
        return False


def fixed_argv(tooling_root) -> tuple[str, ...]:
    return ("bundle", "exec", "ruby", str(tooling_root / "fastlane/android_store_versions.rb"))


def read_saved_versions(operation, config, material):
    """The same StorePreflightRun's sixth command and original Google loan.

    This query has explicit temporary-edit consent. It must not be dispatched
    through an ordinary online-access bool or treated as a side-effect-free GET.
    Command/process/material/input cleanup remains on the original owners.
    """
    import math
    import time
    from ._store_runtime import StoreRuntimeContext
    from .build_inputs import finite_scratch
    from .credentials import SelectedStoreMaterial
    from .desktop_store_preflight import StorePreflightRun
    from .errors import StoreOperationError
    from .owned_process import ProcessError, run_owned
    from .reporting import Finding, Status
    from .stores import _require_fastlane_bundle, _runtime_environment
    from .tooling import _complete_tooling_root
    from . import paired_store_versions as paired

    _need(type(operation) is StorePreflightRun and (selected_query(operation.request.context)
          or paired.selected_query(operation.request.context))
          and operation.source.require_operation() is operation and type(material) is SelectedStoreMaterial)
    operation.checkpoint()
    runtime, invocation = operation.runtime, operation.invocation
    _need(type(runtime) is StoreRuntimeContext and query_prerequisites(config))
    platforms = paired.PLATFORMS if paired.selected_query(operation.request.context) else ("android",)
    material.require(config=config, platforms=platforms, invocation=invocation)
    runtime.require(root=config.root, invocation=invocation)
    package = config.section("android")["applicationId"]
    context = policy.digest(operation.request.context)
    tooling = runtime.tooling_root
    reader = tooling / "fastlane/android_store_versions.rb"
    if not _complete_tooling_root(tooling) or reader.is_symlink() or not reader.is_file():
        return [Finding("store.online.fastfile", Status.FAIL, "Bundled Play inventory reader is unavailable.",
                        category="store-access")], unavailable("not-checked")
    try:
        _require_fastlane_bundle(tooling, cancellation=operation.guard, runtime_context=runtime)
    except ProcessError:
        raise
    except StoreOperationError:
        return [Finding("store.online.bundle", Status.FAIL, "Pinned Store dependencies are unavailable.",
                        category="store-access")], unavailable("not-checked")

    def current():
        operation._source_post()
        operation._received_post()
        material.require(config=config, platforms=platforms, invocation=invocation)
        runtime.require(root=config.root, invocation=invocation)
        _need(config.section("android")["applicationId"] == package and policy.digest(operation.request.context) == context)

    with finite_scratch(layout="online-runner", cancellation=operation.guard,
                        parent=runtime.private_directory) as runner:
        current()
        selected = material.lane_environment(platform="android")
        _need(set(selected) == {"GOOGLE_APPLICATION_CREDENTIALS"})
        environment = _runtime_environment(runtime.environment())
        environment.update(selected)
        now = time.monotonic()
        hard_end = min(operation.source.work_end, now + QUERY_SECONDS)
        read_end = min(now + READ_SECONDS, hard_end - 10)
        _need(now < read_end)
        environment.update({"BUNDLE_GEMFILE": str(tooling / "Gemfile"), "FASTLANE_HIDE_CHANGELOG": "true",
            "FASTLANE_OPT_OUT_USAGE": "true", "FASTLANE_SKIP_DOCS": "true", "FASTLANE_SKIP_UPDATE_CHECK": "true",
            "MOBILE_RELEASE_PLAY_PACKAGE": package, "MOBILE_RELEASE_PLAY_CONTEXT": context,
            "MOBILE_RELEASE_PLAY_READ_END_NS": str(math.floor(read_end * 1_000_000_000)),
            "MOBILE_RELEASE_PLAY_HARD_END_NS": str(math.floor(hard_end * 1_000_000_000))})
        argv = fixed_argv(tooling)
        with runtime.command(argv, capture=True):
            completed = run_owned(argv, cwd=runner._path, environ=environment, capture=True, text=False,
                timeout=QUERY_SECONDS, output_limit=FRAME_LIMIT, cancellation=operation.guard)
        current()
        raw = (completed.stdout if type(completed.returncode) is int and completed.returncode == 0
               and type(completed.stdout) is bytes and completed.stderr == b"" else None)
    current()
    # A missing/failed worker response cannot establish that its POST never ran.
    return [], (unavailable("temporary-edit-unconfirmed", temporary_edit="unconfirmed") if raw is None else
                summary_from_frame(raw, context_sha256=context, package_name=package))


def request(step: str, package: str, edit_id: str | None = None) -> dict:
    package_identity(package)
    _need(step in ("insert", *COLLECTIONS, "delete"))
    path = f"/androidpublisher/v3/applications/{package}/edits"
    if step != "insert":
        _need(type(edit_id) is str and _EDIT.fullmatch(edit_id) is not None)
        path += "/" + edit_id
        if step != "delete":
            path += "/" + step
    else:
        _need(edit_id is None)
    return {"kind": "current_" + step, "method": "POST" if step == "insert" else "DELETE" if step == "delete" else "GET",
            "path": path, "query": {}, "body": {} if step == "insert" else None}


def _json(raw: bytes, *, frame=False) -> dict:
    limit = FRAME_LIMIT if frame else RAW_LIMIT
    _need(type(raw) is bytes and 0 < len(raw) <= limit)
    value = _decode_json(raw, limit=limit, nodes=1024 if frame else 20_000, depth=16, exact=True)
    _need(type(value) is dict)
    return value


def unavailable(reason: str, *, temporary_edit="not-started") -> dict:
    _need(reason in OBSERVATIONS - {"observed"} and temporary_edit in {"not-started", "deleted", "unconfirmed"})
    _need((reason == "temporary-edit-unconfirmed") == (temporary_edit == "unconfirmed"))
    return {"observation": reason, "coverage": SCOPE, "revision": None, "counts": None,
            "maxBuild": None, "marketingVersion": None, "temporaryEdit": temporary_edit,
            "historicalUniqueness": "not-established"}


def valid_summary(value: object) -> bool:
    if not (type(value) is dict and set(value) == {"observation", "coverage", "revision", "counts", "maxBuild",
            "marketingVersion", "temporaryEdit", "historicalUniqueness"}
            and type(value["observation"]) is str and value["observation"] in OBSERVATIONS
            and value["coverage"] == SCOPE and value["historicalUniqueness"] == "not-established"
            and value["marketingVersion"] is None):
        return False
    if value["observation"] != "observed":
        return (all(value[k] is None for k in ("revision", "counts", "maxBuild"))
            and value["temporaryEdit"] in {"not-started", "deleted", "unconfirmed"}
            and (value["observation"] == "temporary-edit-unconfirmed") == (value["temporaryEdit"] == "unconfirmed"))
    counts = value["counts"]
    return (value["temporaryEdit"] == "deleted" and type(counts) is dict and set(counts) == set(COUNTS)
        and all(type(counts[k]) is int and 0 <= counts[k] <= (MAX_CODES if k == "versionCodes" else MAX_ROWS) for k in COUNTS)
        and type(value["revision"]) is str and policy._DIGEST.fullmatch(value["revision"]) is not None
        and type(value["maxBuild"]) is int and 0 <= value["maxBuild"] <= policy.MAX_BUILD
        and ((counts["versionCodes"] + counts["bundles"] + counts["apks"] == 0) == (value["maxBuild"] == 0)))


def valid_result(value: object) -> bool:
    from ._desktop_store_preflight_protocol import validate_result
    from .reporting import FAILING_STATUSES
    if not (type(value) is dict and set(value) == {"schemaVersion", "scope", "findings", "limitations", "currentVersions"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == RESULT_SCOPE and value["limitations"] == LIMITATIONS
            and valid_summary(value["currentVersions"])):
        return False
    from ._desktop_store_preflight_protocol import SCOPE as ACCESS_SCOPE, LIMITATIONS as ACCESS_LIMITATIONS
    basic = {k: v for k, v in value.items() if k != "currentVersions"}
    basic.update(scope=ACCESS_SCOPE, limitations=list(ACCESS_LIMITATIONS))
    try:
        validate_result(basic, platform="android")
        return (value["currentVersions"]["observation"] != "observed"
                or all(row["status"] not in FAILING_STATUSES and row["check"] != "store-access" for row in value["findings"]))
    except (ValueError, TypeError, KeyError):
        return False


def project_result(findings, summary: dict) -> dict:
    from ._desktop_store_preflight_protocol import project_result as access_result
    result = access_result(findings, platform="android")
    result.update(scope=RESULT_SCOPE, limitations=list(LIMITATIONS), currentVersions=summary)
    _need(valid_result(result))
    return result


def summary_from_frame(raw: bytes, *, context_sha256: str, package_name: str) -> dict:
    """Require original raw lists AND a positive exact-owned edit deletion.

    Partial frames may explain remote cleanup uncertainty but can never mint a
    floor. No SDK-normalized model or boolean 'buildUnused' is accepted here.
    """
    package_identity(package_name)
    policy._match(context_sha256, policy._DIGEST)
    cleanup = "unconfirmed"  # Malformed/lost producer data cannot prove no edit.
    try:
        frame = _json(raw, frame=True)
        _need(set(frame) == {"schemaVersion", "scope", "contextSha256", "packageName", "pages", "queryFinished", "temporaryEdit"}
            and type(frame["schemaVersion"]) is int and frame["schemaVersion"] == 1 and frame["scope"] == SCOPE
            and frame["contextSha256"] == context_sha256 and frame["packageName"] == package_name
            and type(frame["pages"]) is list and len(frame["pages"]) <= MAX_REQUESTS
            and type(frame["queryFinished"]) is bool)
        effect = policy._object(frame["temporaryEdit"], {"insertAttempted", "editId", "deleteAttempted", "deleteConfirmed"})
        _need(all(type(effect[k]) is bool for k in ("insertAttempted", "deleteAttempted", "deleteConfirmed"))
            and (effect["editId"] is None or type(effect["editId"]) is str and _EDIT.fullmatch(effect["editId"]) is not None))
        pages = frame["pages"]
        if not effect["insertAttempted"]:
            _need(not pages and effect["editId"] is None and not effect["deleteAttempted"]
                  and not effect["deleteConfirmed"] and not frame["queryFinished"])
            return unavailable("not-checked")
        _need(bool(pages))
        total_bytes, digests, responses = 0, [], []
        edit_id = None

        def response(page, step, *, delete=False):
            nonlocal total_bytes
            _need(type(page) is dict and set(page) == {"step", "request", "response"}
                  and page["step"] == step and page["request"] == request(step, package_name, edit_id))
            value = policy._object(page["response"], {"status", "bodyBase64", "failure"})
            status, encoded, failure = (value[k] for k in ("status", "bodyBase64", "failure"))
            _need(status is None or type(status) is int and 100 <= status <= 599)
            _need(failure in (None, "provider_request_unconfirmed", "inventory_limit"))
            body = None
            if encoded is not None:
                limit = EDIT_RAW_LIMIT if step in {"insert", "delete"} else RAW_LIMIT
                _need(type(encoded) is str and encoded.isascii() and len(encoded) <= 4 * ((limit + 2) // 3))
                body = base64.b64decode(encoded, validate=True)
                _need(len(body) <= limit and base64.b64encode(body).decode("ascii") == encoded)
                total_bytes += len(body)
                _need(total_bytes <= RAW_TOTAL_LIMIT, "too-many")
            expected = status == (204 if delete else 200)
            if not expected or failure is not None or body is None or (not delete and not body):
                return None, "not-permitted" if status in (401, 403) else "too-many" if failure == "inventory_limit" else "inconclusive"
            if delete:
                _need(body == b"")
            digests.append({"step": step, "request": page["request"], "sha256": hashlib.sha256(body).hexdigest()})
            return body, None

        inserted, failure = response(pages[0], "insert")
        if inserted is None:
            _need(len(pages) == 1 and effect["editId"] is None and not effect["deleteAttempted"]
                  and not effect["deleteConfirmed"] and not frame["queryFinished"])
            return unavailable("temporary-edit-unconfirmed", temporary_edit="unconfirmed")
        created = _json(inserted)
        _need(set(created) == {"id", "expiryTimeSeconds"} and type(created["id"]) is str
              and _EDIT.fullmatch(created["id"]) is not None and type(created["expiryTimeSeconds"]) is str
              and re.fullmatch(r"[1-9][0-9]{0,18}", created["expiryTimeSeconds"], re.ASCII) is not None)
        edit_id = created["id"]
        _need(effect["editId"] == edit_id)
        following = pages[1:]
        has_delete = bool(following) and following[-1].get("step") == "delete"
        _need(effect["deleteAttempted"] == has_delete)
        if has_delete:
            deleted, delete_failure = response(following[-1], "delete", delete=True)
            _need(effect["deleteConfirmed"] == (deleted is not None))
            cleanup = "deleted" if deleted is not None else "unconfirmed"
            following = following[:-1]
        else:
            _need(not effect["deleteConfirmed"])
        _need(len(following) <= len(COLLECTIONS))
        for step, page in zip(COLLECTIONS, following):
            body, error = response(page, step)
            if error is not None:
                failure = failure or error
            responses.append(body)
        if cleanup != "deleted":
            return unavailable("temporary-edit-unconfirmed", temporary_edit="unconfirmed")
        _need(frame["queryFinished"] and len(following) == len(COLLECTIONS), failure or "inconclusive")
        _need(failure is None, failure or "inconclusive")
        counts = dict.fromkeys(COUNTS, 0)
        maximum = 0

        def code(value, *, text=False):
            nonlocal maximum
            _need((type(value) is str and _DECIMAL.fullmatch(value) is not None) if text else type(value) is int,
                  "unsupported-format")
            number = int(value)
            _need(1 <= number <= policy.MAX_BUILD, "unsupported-format")
            maximum = max(maximum, number)
            return number

        for name, body in zip(COLLECTIONS, responses):
            result = _json(body)
            _need(set(result) <= {"kind", name} and ("kind" not in result or result["kind"] == _KINDS[name]))
            # Google JSON omits an empty repeated field. This is accepted only
            # inside the complete 200 response of the fixed, unfiltered list;
            # unknown pagination/fields, failed or missing responses still refuse.
            rows = result.get(name, [])
            _need(type(rows) is list)
            _need(len(rows) <= MAX_ROWS, "too-many")
            counts[name] = len(rows)
            seen = set()
            for row in rows:
                _need(type(row) is dict)
                if name == "tracks":
                    _need(set(row) <= {"track", "releases"} and type(row.get("track")) is str
                          and 0 < len(row["track"]) <= 255 and row["track"] not in seen)
                    seen.add(row["track"])
                    releases = row.get("releases", [])
                    _need(type(releases) is list)
                    counts["releases"] += len(releases)
                    _need(counts["releases"] <= MAX_RELEASES, "too-many")
                    for release in releases:
                        _need(type(release) is dict and set(release) <= {"name", "versionCodes", "releaseNotes", "status",
                            "userFraction", "countryTargeting", "inAppUpdatePriority"}
                            and release.get("status") in {"draft", "inProgress", "halted", "completed"})
                        values = release.get("versionCodes", [])
                        _need(type(values) is list)
                        counts["versionCodes"] += len(values)
                        _need(counts["versionCodes"] <= MAX_CODES, "too-many")
                        for value in values:
                            code(value, text=True)  # Duplicates across tracks are legitimate.
                else:
                    _need(set(row) <= ({"versionCode", "sha1", "sha256"} if name == "bundles" else {"versionCode", "binary"}))
                    value = code(row.get("versionCode"))
                    _need(value not in seen)
                    seen.add(value)
        summary = {"observation": "observed", "coverage": SCOPE,
            "revision": policy.digest({"scope": SCOPE, "contextSha256": context_sha256, "packageName": package_name,
                                        "responses": digests}),
            "counts": counts, "maxBuild": maximum, "marketingVersion": None, "temporaryEdit": "deleted",
            "historicalUniqueness": "not-established"}
        _need(valid_summary(summary))
        return summary
    except (InventoryError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, binascii.Error) as error:
        if cleanup == "unconfirmed":
            return unavailable("temporary-edit-unconfirmed", temporary_edit="unconfirmed")
        return unavailable(error.reason if isinstance(error, InventoryError) else "inconclusive", temporary_edit=cleanup)


@dataclass(frozen=True, slots=True)
class CurrentInventory:
    identity_revision: str
    context_revision: str
    revision: str
    observed_at: int
    max_build: int
    counts: tuple[int, int, int, int, int]

    def __post_init__(self):
        for value in (self.identity_revision, self.context_revision, self.revision):
            policy._match(value, policy._DIGEST)
        policy._integer(self.observed_at, (1 << 63) - 1)
        policy._need(type(self.counts) is tuple and len(self.counts) == len(COUNTS))
        policy._need(valid_summary({"observation": "observed", "coverage": SCOPE, "revision": self.revision,
            "counts": dict(zip(COUNTS, self.counts)), "maxBuild": self.max_build, "marketingVersion": None,
            "temporaryEdit": "deleted", "historicalUniqueness": "not-established"}))

    def value(self):
        return {"platform": "android", "scope": SCOPE, "identityRevision": self.identity_revision,
            "contextRevision": self.context_revision, "revision": self.revision, "observedAt": self.observed_at,
            "maxBuild": self.max_build, "marketingVersion": None, "counts": dict(zip(COUNTS, self.counts)),
            "complete": True, "formatSupported": True, "temporaryEdit": "deleted", "historicalUniqueness": "not-established"}

    @classmethod
    def parse(cls, value):
        row = policy._object(value, {"platform", "scope", "identityRevision", "contextRevision", "revision", "observedAt",
            "maxBuild", "marketingVersion", "counts", "complete", "formatSupported", "temporaryEdit", "historicalUniqueness"})
        policy._need(row["platform"] == "android" and row["scope"] == SCOPE and row["complete"] is True
            and row["formatSupported"] is True and row["marketingVersion"] is None and row["temporaryEdit"] == "deleted"
            and row["historicalUniqueness"] == "not-established")
        counts = policy._object(row["counts"], set(COUNTS))
        return cls(row["identityRevision"], row["contextRevision"], row["revision"], row["observedAt"], row["maxBuild"],
                   tuple(counts[k] for k in COUNTS))


def constraints(observations, enabled, identity_revision, context_revision, selected, *, now):
    policy._need(type(selected) is policy.VersionPolicy and selected.store_scope == POLICY_SCOPE, "invalid-policy")
    policy._need(enabled == ("android",) and type(observations) is tuple and len(observations) == 1
                 and type(observations[0]) is CurrentInventory, "store-platform-mismatch")
    policy._match(identity_revision, policy._DIGEST)
    policy._match(context_revision, policy._DIGEST)
    policy._integer(now, (1 << 63) - 1)
    original = observations[0]
    policy._need(original.identity_revision == identity_revision and original.context_revision == context_revision,
                 "store-identity-changed")
    policy._need(0 <= now - original.observed_at <= selected.store_max_age_seconds, "store-observation-stale")
    return original.max_build


def propose(selected, *, source, base, allocated, enabled, identity_revision, context_revision, observations, now):
    increment = selected.increment_for(source)
    base = policy.version(base, enabled, automatic=True)
    allocated = policy.version(allocated, enabled, automatic=True)
    floor = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    build = max(base.build, allocated.build, floor) + 1
    policy._need(build <= min(selected.build_ceiling, policy.MAX_BUILD), "build-exhausted")
    name = max((base.name, allocated.name), key=policy.numeric_version)
    major, minor, patch = policy.numeric_version(name)
    if increment != "build":
        name = ".".join(map(str, {"patch": (major, minor, patch + 1), "minor": (major, minor + 1, 0),
                                 "major": (major + 1, 0, 0)}[increment]))
    return policy.version(policy.ReleaseVersion(name, build), enabled, automatic=True)


def check_reserved(reserved, selected, *, enabled, identity_revision, context_revision, observations, now):
    policy.version(reserved, enabled, automatic=True)
    floor = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    policy._need(reserved.build > floor, "reservation-consumed")
