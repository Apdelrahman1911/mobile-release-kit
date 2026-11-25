"""Bounded *currently visible* App Store version inventory DATA.

The original StorePreflightRun, selected P8, HTTP reader and native joins own
the observation. This parser cannot mint their receipt. Complete means that
three finite current collection traversals completed, NOT an atomic snapshot,
all historical uploads, or permission to reuse a number Apple no longer lists.
The v1 application-all-builds policy deliberately does not accept this scope.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from . import version_policy as policy
from ._desktop_github_engine import _decode_json

QUERY = "ios-current-versions"
CONSENT = "local-ios-current-versions-read-v1"
SCOPE = "asc-ios-current-inventory/1"
RESULT_SCOPE = "local-ios-current-version-inventory"
POLICY_SCOPE = "require-current-ios-inventory"
RAW_LIMIT = 128 * 1024
RAW_TOTAL_LIMIT = 1024 * 1024
FRAME_LIMIT = 2 * 1024 * 1024
PAGE_LIMIT = 200
MAX_PAGES = 2
MAX_ROWS = PAGE_LIMIT * MAX_PAGES
MAX_REQUESTS = 8  # app before + 2 pages for each of 3 lists + app after
QUERY_SECONDS = 60
ORIGIN = "https://api.appstoreconnect.apple.com"
COLLECTIONS = ("builds", "buildUploads", "appStoreVersions")
LIMITATIONS = ["non-publishing", "no-project-commands", "no-build-or-signing", "no-release-readiness",
              "point-in-time-account-access", "saved-inputs-not-atomic", "current-visible-only",
              "not-atomic-store-snapshot", "historical-uniqueness-not-established", "external-uploaders-not-coordinated"]
OBSERVATIONS = frozenset({"observed", "not-checked", "not-permitted", "inconclusive", "too-many", "unsupported-format"})
_APP = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z", re.ASCII)
_BUNDLE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z", re.ASCII)
_PLATFORMS = frozenset({"IOS", "MAC_OS", "TV_OS", "VISION_OS"})


class InventoryError(ValueError):
    def __init__(self, reason: str = "inconclusive") -> None:
        self.reason = reason if reason in OBSERVATIONS - {"observed", "not-checked"} else "inconclusive"
        super().__init__("Current App Store versions could not be established")


def _need(value: bool, reason: str = "inconclusive") -> None:
    if not value:
        raise InventoryError(reason)


def app_identity(app_id: object, bundle_id: object) -> None:
    _need(type(app_id) is str and _APP.fullmatch(app_id) is not None)
    _need(type(bundle_id) is str and len(bundle_id) <= 255 and _BUNDLE.fullmatch(bundle_id) is not None)


def selected_query(context: dict) -> bool:
    return context.get("query") == QUERY and context.get("platform") == "ios"


def query_prerequisites(config) -> bool:
    try:
        if not config.platform_enabled("ios") or config.section("ios").get("identityStatus") == "blocked":
            return False
        app_identity(config.section("ios").get("appStoreAppId"), config.section("ios").get("bundleId"))
        return True
    except InventoryError:
        return False


def fixed_argv(tooling_root) -> tuple[str, ...]:
    return ("bundle", "exec", "ruby", str(tooling_root / "fastlane/apple_store_versions.rb"))


def request(kind: str, app_id: str, *, cursor: str | None = None) -> dict:
    """Exact read schedule vocabulary; no caller URL, token or write method."""
    _need(type(app_id) is str and _APP.fullmatch(app_id) is not None)
    if kind in {"app-before", "app-after"}:
        path, query = f"/v1/apps/{app_id}", {"fields[apps]": "bundleId"}
    elif kind == "builds":
        path, query = "/v1/builds", {"filter[app]": app_id, "include": "app,preReleaseVersion",
            "fields[builds]": "version,app,preReleaseVersion", "fields[apps]": "bundleId",
            "fields[preReleaseVersions]": "version,platform,app", "limit": "200"}
    elif kind == "buildUploads":
        path, query = f"/v1/apps/{app_id}/buildUploads", {
            "fields[buildUploads]": "cfBundleVersion,cfBundleShortVersionString,platform,build", "limit": "200"}
    elif kind == "appStoreVersions":
        path, query = f"/v1/apps/{app_id}/appStoreVersions", {
            "fields[appStoreVersions]": "versionString,platform", "limit": "200"}
    else:
        raise InventoryError()
    if cursor is not None:
        _need(kind in COLLECTIONS and type(cursor) is str and 0 < len(cursor) <= 1024
              and cursor.isascii() and all(33 <= ord(c) <= 126 for c in cursor))
        query = {**query, "cursor": cursor}
    return {"kind": "current_" + kind.replace("-", "_"), "method": "GET", "path": path, "query": query, "body": None}


def _next(link: object, kind: str, app_id: str) -> dict | None:
    if link is None:
        return None
    _need(type(link) is str and link.isascii() and 0 < len(link) <= 4096)
    parsed = urlsplit(link)
    _need(parsed.scheme == "https" and parsed.netloc == "api.appstoreconnect.apple.com"
          and not parsed.fragment and not parsed.username and not parsed.password)
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
    _need(len(pairs) == len(dict(pairs)) and "cursor" in dict(pairs))
    expected = request(kind, app_id, cursor=dict(pairs)["cursor"])
    _need(parsed.path == expected["path"] and dict(pairs) == expected["query"])
    return expected


def _resource(value: object, kind: str, fields: set[str]) -> dict:
    _need(type(value) is dict and {"type", "id", "attributes"} <= set(value)
          <= {"type", "id", "attributes", "relationships", "links"} and value["type"] == kind
          and type(value["id"]) is str and _ID.fullmatch(value["id"]) is not None)
    attrs = value["attributes"]
    _need(type(attrs) is dict and set(attrs) == fields)
    return attrs


def _one_relation(value: dict, field: str, kind: str, *, nullable: bool = False) -> str | None:
    relations = value.get("relationships", {})
    _need(type(relations) is dict)
    relation = relations.get(field)
    _need(type(relation) is dict and {"data"} <= set(relation) <= {"data", "links", "meta"})
    data = relation["data"]
    if data is None and nullable:
        return None
    _need(type(data) is dict and set(data) == {"type", "id"} and data["type"] == kind
          and type(data["id"]) is str and _ID.fullmatch(data["id"]) is not None)
    return data["id"]


def _app(value: object, app_id: str, bundle_id: str) -> None:
    attrs = _resource(value, "apps", {"bundleId"})
    _need(value["id"] == app_id and attrs["bundleId"] == bundle_id and not value.get("relationships"))


def _json(raw: bytes, *, frame: bool = False) -> dict:
    _need(type(raw) is bytes and 0 < len(raw) <= (FRAME_LIMIT if frame else RAW_LIMIT))
    # The fixed Ruby reader writes JSON plus one LF. Charge that LF above;
    # do not strip arbitrary whitespace or change raw provider-page parsing.
    if frame and raw.endswith(b"\n"):
        raw = raw[:-1]
    value = _decode_json(raw, limit=FRAME_LIMIT if frame else RAW_LIMIT,
                         nodes=1024 if frame else 20_000, depth=16, exact=True)
    _need(type(value) is dict)
    return value


def unavailable(reason: str) -> dict:
    _need(reason in OBSERVATIONS - {"observed"})
    return {"observation": reason, "coverage": SCOPE, "revision": None, "counts": None,
            "maxBuild": None, "marketingVersion": None, "historicalUniqueness": "not-established"}


def valid_summary(value: object) -> bool:
    if not (type(value) is dict and set(value) == {"observation", "coverage", "revision", "counts",
            "maxBuild", "marketingVersion", "historicalUniqueness"}
            and type(value["observation"]) is str and value["observation"] in OBSERVATIONS
            and value["coverage"] == SCOPE and value["historicalUniqueness"] == "not-established"):
        return False
    if value["observation"] != "observed":
        return all(value[k] is None for k in ("revision", "counts", "maxBuild", "marketingVersion"))
    counts = value["counts"]
    if not (type(counts) is dict and set(counts) == set(COLLECTIONS)
            and all(type(n) is int and 0 <= n <= MAX_ROWS for n in counts.values())
            and type(value["revision"]) is str and policy._DIGEST.fullmatch(value["revision"])
            and type(value["maxBuild"]) is int and 0 <= value["maxBuild"] <= policy.MAX_BUILD):
        return False
    name = value["marketingVersion"]
    try:
        if name is not None:
            policy.numeric_version(name)
        # Marketing-only App Store records are real even with zero builds.
        return ((counts["builds"] + counts["buildUploads"] == 0) == (value["maxBuild"] == 0)
                and (sum(counts.values()) == 0) == (name is None))
    except policy.VersionPolicyError:
        return False


def valid_result(value: object) -> bool:
    from . import apple_provisioning_bundle_read as bundle
    from .reporting import FAILING_STATUSES
    if not (type(value) is dict and set(value) == {"schemaVersion", "scope", "findings", "limitations", "currentVersions"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == RESULT_SCOPE and value["limitations"] == LIMITATIONS
            and valid_summary(value["currentVersions"])):
        return False
    comparable = {**value, "scope": bundle.SCOPE, "limitations": list(bundle.LIMITATIONS), "observation": "not-checked"}
    del comparable["currentVersions"]
    return (bundle.valid_result(comparable)
            and (value["currentVersions"]["observation"] != "observed"
                 or all(item["status"] not in FAILING_STATUSES for item in value["findings"])))


def project_result(findings, summary: dict) -> dict:
    from ._desktop_store_preflight_protocol import project_result as access_result
    result = access_result(findings, platform="ios")
    result.update(scope=RESULT_SCOPE, limitations=list(LIMITATIONS), currentVersions=summary)
    _need(valid_result(result))
    return result


def read_saved_versions(operation, config, material):
    """The original Store run's seventh command, not a second process owner."""
    from . import apple_provisioning_bundle_read as bundle
    findings, raw = bundle._read_raw_frame(operation, config, material, expected_query=QUERY)
    if findings or raw is None:
        return findings, unavailable("not-checked" if findings else "inconclusive")
    return findings, summary_from_frame(raw, context_sha256=policy.digest(operation.request.context),
        app_id=config.section("ios")["appStoreAppId"], bundle_id=config.section("ios")["bundleId"])


def summary_from_frame(raw: bytes, *, context_sha256: str, app_id: str, bundle_id: str) -> dict:
    """Parse original raw pages, not SDK-normalized models or success receipts."""
    app_identity(app_id, bundle_id)
    policy._match(context_sha256, policy._DIGEST)
    try:
        frame = _json(raw, frame=True)
        _need(set(frame) == {"schemaVersion", "scope", "contextSha256", "appStoreAppId", "bundleId", "pages", "queryFinished"}
              and type(frame["schemaVersion"]) is int and frame["schemaVersion"] == 1 and frame["scope"] == SCOPE
              and frame["contextSha256"] == context_sha256 and frame["appStoreAppId"] == app_id
              and frame["bundleId"] == bundle_id and type(frame["pages"]) is list
              and type(frame["queryFinished"]) is bool and 1 <= len(frame["pages"]) <= MAX_REQUESTS)
        position = total_bytes = 0
        counts = dict.fromkeys(COLLECTIONS, 0)
        build_floor, marketing = 0, None
        digests: list[dict] = []
        included_seen: dict[tuple[str, str], bytes] = {}

        def take(kind: str, expected: dict) -> dict:
            nonlocal position, total_bytes
            _need(position < len(frame["pages"]))
            page = frame["pages"][position]; position += 1
            _need(type(page) is dict and set(page) == {"step", "request", "response"}
                  and page["step"] == kind and page["request"] == expected)
            response = page["response"]
            _need(type(response) is dict and set(response) == {"status", "bodyBase64", "failure"})
            status, encoded, failure = (response[k] for k in ("status", "bodyBase64", "failure"))
            _need(status is None or type(status) is int and 100 <= status <= 599)
            _need(failure in (None, "provider_request_unconfirmed", "inventory_limit"))
            if failure is not None:
                _need(encoded is None)
                raise InventoryError("not-permitted" if status in (401, 403) else "too-many" if failure == "inventory_limit" else "inconclusive")
            _need(type(encoded) is str and encoded.isascii() and 0 < len(encoded) <= 4 * ((RAW_LIMIT + 2) // 3))
            original = base64.b64decode(encoded, validate=True)
            _need(0 < len(original) <= RAW_LIMIT and base64.b64encode(original).decode("ascii") == encoded)
            total_bytes += len(original)
            _need(total_bytes <= RAW_TOTAL_LIMIT, "too-many")
            _need(status == 200, "not-permitted" if status in (401, 403) else "inconclusive")
            digests.append({"step": kind, "request": expected, "sha256": hashlib.sha256(original).hexdigest()})
            result = _json(original)
            _need("error" not in result and "errors" not in result
                  and set(result) <= {"data", "links", "meta", "included"})
            return result

        def version_row(build: object, name: object) -> None:
            nonlocal build_floor, marketing
            # No dotted/suffixed/leading-zero build coercion. Manual values and
            # Apple's broader build formats remain outside this shared integer policy.
            _need(type(build) is str and re.fullmatch(r"[1-9][0-9]{0,9}", build, re.ASCII) is not None,
                  "unsupported-format")
            number = int(build)
            _need(number <= policy.MAX_BUILD, "unsupported-format")
            build_floor = max(build_floor, number)
            name_row(name)

        def name_row(name: object) -> None:
            nonlocal marketing
            try:
                numeric = policy.numeric_version(name)
            except policy.VersionPolicyError:
                raise InventoryError("unsupported-format") from None
            if marketing is None or numeric > policy.numeric_version(marketing):
                marketing = name

        before = take("app-before", request("app-before", app_id))
        _need(not before.get("included"))
        _app(before.get("data"), app_id, bundle_id)
        for kind in COLLECTIONS:
            expected, seen_ids, seen_requests, expected_total = request(kind, app_id), set(), set(), None
            for page_number in range(MAX_PAGES):
                fingerprint = policy.digest(expected)
                _need(fingerprint not in seen_requests)
                seen_requests.add(fingerprint)
                document = take(kind, expected)
                rows, links, meta = (document.get(k) for k in ("data", "links", "meta"))
                _need(type(rows) is list and len(rows) <= PAGE_LIMIT and type(links) is dict and type(meta) is dict)
                paging = meta.get("paging")
                _need(type(paging) is dict and type(paging.get("total")) is int and paging["total"] >= 0)
                _need(paging["total"] <= MAX_ROWS, "too-many")
                _need(expected_total is None or expected_total == paging["total"])
                expected_total = paging["total"]
                included = document.get("included", [])
                _need(type(included) is list and len(included) <= PAGE_LIMIT + 1)
                joined: dict[tuple[str, str], dict] = {}
                for item in included:
                    _need(kind == "builds" and type(item) is dict and item.get("type") in {"apps", "preReleaseVersions"})
                    if item["type"] == "apps":
                        _app(item, app_id, bundle_id)
                    else:
                        attrs = _resource(item, "preReleaseVersions", {"version", "platform"})
                        _need(type(attrs["platform"]) is str and attrs["platform"] in _PLATFORMS
                              and type(item.get("relationships")) is dict and set(item["relationships"]) == {"app"}
                              and _one_relation(item, "app", "apps") == app_id)
                    key = (item["type"], item["id"])
                    encoded = policy.canonical(item)
                    _need(key not in joined and (key not in included_seen or included_seen[key] == encoded))
                    included_seen[key] = encoded
                    joined[key] = item
                needed: set[tuple[str, str]] = set()
                for row in rows:
                    if kind == "builds":
                        attrs = _resource(row, "builds", {"version"})
                        _need(type(row.get("relationships")) is dict and set(row["relationships"]) == {"app", "preReleaseVersion"})
                        selected_app = _one_relation(row, "app", "apps")
                        train = _one_relation(row, "preReleaseVersion", "preReleaseVersions")
                        _need(selected_app == app_id and ("apps", selected_app) in joined
                              and ("preReleaseVersions", train) in joined)
                        needed.update({("apps", selected_app), ("preReleaseVersions", train)})
                        train_attrs = joined[("preReleaseVersions", train)]["attributes"]
                        if train_attrs["platform"] == "IOS":
                            version_row(attrs["version"], train_attrs["version"])
                            counts[kind] += 1
                    elif kind == "buildUploads":
                        attrs = _resource(row, kind, {"cfBundleVersion", "cfBundleShortVersionString", "platform"})
                        _need(type(attrs["platform"]) is str and attrs["platform"] in _PLATFORMS)
                        relations = row.get("relationships", {})
                        _need(type(relations) is dict and set(relations) <= {"build"})
                        if "build" in relations:
                            _one_relation(row, "build", "builds", nullable=True)
                        if attrs["platform"] == "IOS":
                            # A not-yet-created Build relationship does NOT make
                            # an upload's requested number available for reuse.
                            version_row(attrs["cfBundleVersion"], attrs["cfBundleShortVersionString"])
                            counts[kind] += 1
                    else:
                        attrs = _resource(row, kind, {"versionString", "platform"})
                        _need(type(attrs["platform"]) is str and attrs["platform"] in _PLATFORMS and not row.get("relationships"))
                        if attrs["platform"] == "IOS":
                            name_row(attrs["versionString"])
                            counts[kind] += 1
                    _need(row["id"] not in seen_ids)
                    seen_ids.add(row["id"])
                _need(set(joined) == needed and len(seen_ids) <= expected_total)
                following = _next(links.get("next"), kind, app_id)
                if following is None:
                    _need(len(seen_ids) == expected_total)
                    break
                _need(bool(rows) and len(seen_ids) < expected_total)
                _need(page_number + 1 < MAX_PAGES, "too-many")
                expected = following
            else:
                raise InventoryError("too-many")
        after = take("app-after", request("app-after", app_id))
        _need(not after.get("included"))
        _app(after.get("data"), app_id, bundle_id)
        # A final token/clock check may fail after the last raw page. Neither
        # those complete-looking pages nor the outer process's exit clears it.
        _need(position == len(frame["pages"]) and frame["queryFinished"])
        result = {"observation": "observed", "coverage": SCOPE,
            "revision": policy.digest({"scope": SCOPE, "contextSha256": context_sha256,
                "appStoreAppId": app_id, "bundleId": bundle_id, "pages": digests}),
            "counts": counts, "maxBuild": build_floor, "marketingVersion": marketing,
            "historicalUniqueness": "not-established"}
        _need(valid_summary(result))
        return result
    except InventoryError as error:
        return unavailable(error.reason)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, binascii.Error):
        return unavailable("inconclusive")


@dataclass(frozen=True, slots=True)
class CurrentInventory:
    """Sanitized durable policy input, NOT a mintable native receipt.

    observed_at must come from the original native operation's EARLIEST clock,
    not result arrival or a newly constructed receipt. Native current P8/source
    and genuine original joins are checked separately before this DATA is used.
    """
    identity_revision: str
    context_revision: str
    revision: str
    observed_at: int
    max_build: int
    marketing_version: str | None
    counts: tuple[int, int, int]

    def __post_init__(self) -> None:
        for value in (self.identity_revision, self.context_revision, self.revision):
            policy._match(value, policy._DIGEST)
        policy._integer(self.observed_at, (1 << 63) - 1)
        policy._integer(self.max_build, policy.MAX_BUILD)
        policy._need(type(self.counts) is tuple and len(self.counts) == 3
                     and all(type(n) is int and 0 <= n <= MAX_ROWS for n in self.counts))
        policy._need(valid_summary({"observation": "observed", "coverage": SCOPE, "revision": self.revision,
            "counts": dict(zip(COLLECTIONS, self.counts)), "maxBuild": self.max_build,
            "marketingVersion": self.marketing_version, "historicalUniqueness": "not-established"}))

    def value(self) -> dict:
        return {"platform": "ios", "scope": SCOPE, "identityRevision": self.identity_revision,
            "contextRevision": self.context_revision, "revision": self.revision, "observedAt": self.observed_at,
            "maxBuild": self.max_build, "marketingVersion": self.marketing_version,
            "counts": dict(zip(COLLECTIONS, self.counts)), "complete": True, "formatSupported": True,
            "historicalUniqueness": "not-established"}

    @classmethod
    def parse(cls, value: object) -> CurrentInventory:
        row = policy._object(value, {"platform", "scope", "identityRevision", "contextRevision", "revision",
            "observedAt", "maxBuild", "marketingVersion", "counts", "complete", "formatSupported", "historicalUniqueness"})
        policy._need(row["platform"] == "ios" and row["scope"] == SCOPE and row["complete"] is True
                     and row["formatSupported"] is True and row["historicalUniqueness"] == "not-established")
        counts = policy._object(row["counts"], set(COLLECTIONS))
        return cls(row["identityRevision"], row["contextRevision"], row["revision"], row["observedAt"],
                   row["maxBuild"], row["marketingVersion"], tuple(counts[k] for k in COLLECTIONS))


def constraints(observations: tuple[CurrentInventory, ...], enabled: tuple[str, ...],
                identity_revision: str, context_revision: str, selected: policy.VersionPolicy,
                *, now: int) -> tuple[int, tuple[str, ...]]:
    policy._need(type(selected) is policy.VersionPolicy and selected.store_scope == POLICY_SCOPE, "invalid-policy")
    policy._need(enabled == ("ios",) and type(observations) is tuple and len(observations) == 1
                 and type(observations[0]) is CurrentInventory, "store-platform-mismatch")
    policy._match(identity_revision, policy._DIGEST)
    policy._match(context_revision, policy._DIGEST)
    policy._integer(now, (1 << 63) - 1)
    original = observations[0]
    policy._need(original.identity_revision == identity_revision and original.context_revision == context_revision,
                 "store-identity-changed")
    policy._need(0 <= now - original.observed_at <= selected.store_max_age_seconds, "store-observation-stale")
    return original.max_build, (() if original.marketing_version is None else (original.marketing_version,))


def propose(selected: policy.VersionPolicy, *, source: str, base, allocated, enabled: tuple[str, ...],
            identity_revision: str, context_revision: str, observations: tuple[CurrentInventory, ...], now: int):
    """Explicit v2 proposer; the historical v1 proposer is unchanged."""
    increment = selected.increment_for(source)
    base = policy.version(base, enabled, automatic=True)
    allocated = policy.version(allocated, enabled, automatic=True)
    floor, marketing = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    build = max(base.build, allocated.build, floor) + 1
    policy._need(build <= policy.IOS_INTEGER_MAX_BUILD, "ios-integer-build-exhausted")
    policy._need(build <= selected.build_ceiling, "build-exhausted")
    name = max((base.name, allocated.name, *marketing), key=policy.numeric_version)
    major, minor, patch = policy.numeric_version(name)
    if increment != "build":
        parts = {"patch": (major, minor, patch + 1), "minor": (major, minor + 1, 0), "major": (major + 1, 0, 0)}[increment]
        name = ".".join(map(str, parts))
    return policy.version(policy.ReleaseVersion(name, build), enabled, automatic=True)


def check_reserved(reserved, selected: policy.VersionPolicy, *, enabled: tuple[str, ...],
                   identity_revision: str, context_revision: str, observations: tuple[CurrentInventory, ...], now: int) -> None:
    policy.version(reserved, enabled, automatic=True)
    floor, names = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    policy._need(reserved.build > floor and all(policy.numeric_version(reserved.name) >= policy.numeric_version(n)
                                              for n in names), "reservation-consumed")
