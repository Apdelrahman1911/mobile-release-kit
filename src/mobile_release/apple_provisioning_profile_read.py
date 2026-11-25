"""One selected-key App Store profile/reference METADATA read.

The existing StorePreflightRun owns the P8, process, original source checks and
all finality. No downloaded profile/certificate bytes, key binding, assignment
or provider mutation is accepted or produced here. A metadata candidate is only
a reason to inspect existing resources before considering creation elsewhere.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from . import apple_provisioning_api as api
from . import apple_provisioning_bundle_read as bundle

QUERY = "app-store-profile-reuse"
CONSENT = "local-ios-profile-reuse-read-v1"
SCOPE = "local-ios-profile-reuse-metadata-read"
MAX_PROFILES = 200
MAX_CERTIFICATE_REFERENCES = 400
MAX_INCLUDED = MAX_PROFILES + MAX_CERTIFICATE_REFERENCES
LIMITATIONS = [*bundle.LIMITATIONS, "metadata-only", "no-private-key-match",
              "no-profile-authentication", "no-account-certificate-inventory"]
_PROFILE_ATTRIBUTES = frozenset({"name", "platform", "profileType", "profileState", "uuid",
                                 "createdDate", "expirationDate"})
_BUNDLE_ATTRIBUTES = frozenset({"identifier", "platform", "seedId"})
_CERTIFICATE_ATTRIBUTES = frozenset({"certificateType", "platform", "expirationDate"})
_COUNTS = frozenset({"matchingProfiles", "activeProfiles", "currentMetadataCandidates", "relatedCertificates"})
_CHECKED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")


def selected_query(context: dict) -> bool:
    return context.get("query") == QUERY and context.get("platform") == "ios"


def fixed_argv(tooling_root: Path) -> tuple[str, ...]:
    return ("bundle", "exec", "ruby", str(tooling_root / "fastlane/apple_provisioning_profile_read.rb"))


def _checked_at(now: datetime) -> str:
    now = api.utc(now)
    api.require(now.year >= 1970, "invalid_time")
    return now.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _valid_checked_at(value: object) -> bool:
    if type(value) is not str or _CHECKED_AT.fullmatch(value) is None:
        return False
    try:
        return _checked_at(api.timestamp(value)) == value
    except api.ProvisioningError:
        return False


def unavailable(observation: str) -> dict:
    api.require(observation in {"not-permitted", "inconclusive", "not-checked"})
    return {"observation": observation, "counts": None, "checkedAt": None}


def valid_summary(value: object) -> bool:
    if not (type(value) is dict and set(value) == {"observation", "counts", "checkedAt"}
            and type(value["observation"]) is str and value["observation"] in bundle.OBSERVATIONS):
        return False
    if value["observation"] not in {"found", "not-returned"}:
        return value["counts"] is None and value["checkedAt"] is None
    counts = value["counts"]
    if not (type(counts) is dict and set(counts) == _COUNTS
            and all(type(counts[key]) is int and counts[key] >= 0 for key in _COUNTS)
            and counts["currentMetadataCandidates"] <= counts["activeProfiles"] <= counts["matchingProfiles"] <= MAX_PROFILES
            and counts["relatedCertificates"] <= MAX_CERTIFICATE_REFERENCES and _valid_checked_at(value["checkedAt"])):
        return False
    if value["observation"] == "not-returned":
        return all(number == 0 for number in counts.values())
    return counts["matchingProfiles"] > 0 and counts["relatedCertificates"] > 0


def _attributes(resource: object, expected_type: str, fields: frozenset[str]) -> dict:
    # BEFORE Profile.parse: its normal download-capable parser intentionally
    # decodes profileContent when present, even with require_content=False.
    api.require(type(resource) is dict and resource.get("type") == expected_type
                and set(resource) <= {"type", "id", "attributes", "relationships", "links"})
    api.identifier(resource.get("id"))
    attributes = resource.get("attributes")
    api.require(type(attributes) is dict and set(attributes) == fields)
    return attributes


def _references(row: dict) -> tuple[str, tuple[str, ...]]:
    relations = row.get("relationships")
    api.require(type(relations) is dict and set(relations) == {"bundleId", "certificates"})
    result = []
    for name, resource_type in (("bundleId", "bundleIds"), ("certificates", "certificates")):
        relation = relations[name]
        api.require(type(relation) is dict and {"data"} <= set(relation) <= {"data", "links", "meta"})
        links = relation.get("links", {})
        api.require(type(links) is dict and links.get("next") is None)
        items = relation["data"] if name == "certificates" else [relation["data"]]
        # Reuse the existing Profile relationship bound rather than broaden it.
        api.require(type(items) is list and 0 < len(items) <= 50)
        identifiers = []
        for item in items:
            api.require(type(item) is dict and set(item) == {"type", "id"} and item["type"] == resource_type)
            identifiers.append(api.identifier(item["id"]))
        api.require(len(set(identifiers)) == len(identifiers))
        meta = relation.get("meta", {})
        api.require(type(meta) is dict)
        # A returned array alone is not proof that a to-many relationship is
        # exhaustive. Missing total is inconclusive, not implicit completeness.
        if name == "certificates" or "paging" in meta:
            paging = meta.get("paging")
            api.require(type(paging) is dict and type(paging.get("total")) is int
                        and paging["total"] == len(identifiers))
        result.append(tuple(identifiers))
    return result[0][0], result[1]


def _metadata_summary(payload: dict, *, bundle_id: str, now: datetime) -> dict:
    api.require("errors" not in payload and "error" not in payload
                and set(payload) <= {"data", "included", "links", "meta"})
    rows, links, meta = (payload.get(key) for key in ("data", "links", "meta"))
    api.require(type(rows) is list and len(rows) <= MAX_PROFILES and type(links) is dict
                and links.get("next") is None and type(meta) is dict)
    paging = meta.get("paging")
    api.require(type(paging) is dict and type(paging.get("total")) is int and paging["total"] == len(rows))
    included = payload.get("included", [])
    api.require(type(included) is list and len(included) <= MAX_INCLUDED)

    # Preflight EVERY sparse resource before any download-capable parser. No
    # certificate/profile content is decoded, including for unrelated apps.
    for row in rows:
        _attributes(row, "profiles", _PROFILE_ATTRIBUTES)
    for item in included:
        api.require(type(item) is dict and item.get("type") in {"bundleIds", "certificates"}
                    and "relationships" not in item)
        _attributes(item, item["type"], _BUNDLE_ATTRIBUTES if item["type"] == "bundleIds" else _CERTIFICATE_ATTRIBUTES)

    profiles, needed_bundles, needed_certificates, profile_ids, profile_uuids = [], set(), set(), set(), set()
    certificate_references = 0
    for row in rows:
        bundle_resource, certificate_resources = _references(row)
        certificate_references += len(certificate_resources)
        api.require(certificate_references <= MAX_CERTIFICATE_REFERENCES)
        profile = api.Profile.parse(row)
        api.require(profile.resource_id not in profile_ids and profile.uuid not in profile_uuids and profile.content is None)
        profile_ids.add(profile.resource_id)
        profile_uuids.add(profile.uuid)
        profiles.append(profile)
        needed_bundles.add(bundle_resource)
        needed_certificates.update(certificate_resources)

    bundles, certificates, seen, by_identifier = {}, {}, set(), {}
    for item in included:
        identity = (item["type"], item["id"])
        api.require(identity not in seen)
        seen.add(identity)
        if item["type"] == "bundleIds":
            value = api.BundleId.parse(item)
            api.require(value.platform in {"IOS", "UNIVERSAL"} and value.identifier not in by_identifier)
            by_identifier[value.identifier] = value.resource_id
            bundles[value.resource_id] = value
        else:
            attributes = item["attributes"]
            api.require(attributes["certificateType"] in api.CERTIFICATE_TYPES
                        and attributes["platform"] in {None, "IOS", "UNIVERSAL"})
            certificates[item["id"]] = api.timestamp(attributes["expirationDate"])
    # Exact referent union: no hidden missing/extra/contradictory resources.
    api.require(set(bundles) == needed_bundles and set(certificates) == needed_certificates)
    matching = [profile for profile in profiles if bundles[profile.bundle_id_resource].identifier == bundle_id]
    active = [profile for profile in matching if profile.state == "ACTIVE"]
    candidates = [profile for profile in active if profile.created_at <= now < profile.expires_at
                  and all(now < certificates[reference] for reference in profile.certificate_resources)]
    related = {reference for profile in matching for reference in profile.certificate_resources}
    return {"observation": "found" if matching else "not-returned", "checkedAt": _checked_at(now),
            "counts": {"matchingProfiles": len(matching), "activeProfiles": len(active),
                       "currentMetadataCandidates": len(candidates), "relatedCertificates": len(related)}}


def summary_from_frame(raw: bytes, *, context_sha256: str, bundle_id: str, now: datetime) -> dict:
    """Comparison DATA from one original raw response, never native finality."""
    now = api.utc(now)
    _checked_at(now)
    reason, original = bundle._response_from_frame(raw, context_sha256=context_sha256, bundle_id=bundle_id)
    if reason is not None:
        return unavailable(reason)
    try:
        result = _metadata_summary(api.document(original), bundle_id=bundle_id, now=now)
        api.require(valid_summary(result))
        return result
    except (api.ProvisioningError, ValueError, TypeError, KeyError, UnicodeError):
        return unavailable("inconclusive")


def valid_result(value: object) -> bool:
    if not (type(value) is dict and set(value) == {"schemaVersion", "scope", "findings", "limitations", "profileReuse"}
            and value.get("scope") == SCOPE and value.get("limitations") == LIMITATIONS
            and valid_summary(value.get("profileReuse"))):
        return False
    ordinary = {**value, "scope": bundle.SCOPE, "limitations": list(bundle.LIMITATIONS), "observation": "not-checked"}
    del ordinary["profileReuse"]
    return bundle.valid_result(ordinary)


def project_result(findings: list, summary: dict) -> dict:
    value = bundle.project_result(findings, "not-checked")
    del value["observation"]
    value.update(scope=SCOPE, limitations=list(LIMITATIONS), profileReuse=summary)
    api.require(valid_result(value), "invalid_profile_read_result")
    return value


def read_saved_profiles(operation, config, material) -> tuple[list, dict]:
    findings, raw = bundle._read_raw_frame(operation, config, material, expected_query=QUERY)
    if findings or raw is None:
        return findings, unavailable("not-checked" if findings else "inconclusive")
    # This worker clock is comparison DATA only. Native publication still owes
    # its original selected-context/key/source checks and all original joins.
    summary = summary_from_frame(raw, context_sha256=api.digest(api.canonical(operation.request.context)),
                                 bundle_id=config.section("ios")["bundleId"], now=datetime.now(timezone.utc))
    return findings, summary
