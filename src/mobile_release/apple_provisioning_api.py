"""Closed, credential-free App Store Connect provisioning wire contract.

The caller is the *original*, selected-account provisioning owner. This module
does not authenticate, acquire an account, retry a request, follow arbitrary
URLs, or turn a release-operation consent into provisioning permission. Response
bodies and resources are private working data, not log/renderer DTOs.

Public API shapes checked against Apple's documentation on 2026-10-19:
``post-v1-bundleids``, ``post-v1-certificates``, ``post-v1-profiles`` and their
GET/schema pages at developer.apple.com/documentation/appstoreconnectapi.
Only iOS App Store profiles and distribution certificates are supported here.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from .errors import ValidationError

API_ORIGIN = "https://api.appstoreconnect.apple.com"
MAX_RESPONSE_BYTES = 6 * 1024 * 1024
MAX_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 4 * 1024 * 1024
MAX_RESOURCES = 2000
MAX_PAGES = 25
CERTIFICATE_TYPES = frozenset({"DISTRIBUTION", "IOS_DISTRIBUTION"})
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
TEAM_RE = re.compile(r"[A-Z0-9]{10}\Z")
BUNDLE_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")
UUID_RE = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z")


class ProvisioningError(ValidationError):
    """A fixed, safely reportable diagnostic; never a provider/native message."""

    def __init__(self, code: str) -> None:
        # Codes are internal literals; do not pass Apple error detail here.
        self.code = code
        super().__init__("Apple provisioning: " + code.replace("_", " ") + ".")


def require(condition: bool, code: str = "invalid_provider_response") -> None:
    if not condition:
        raise ProvisioningError(code)


def identifier(value: object) -> str:
    require(type(value) is str and ID_RE.fullmatch(value) is not None)
    return value


def timestamp(value: object) -> datetime:
    require(type(value) is str and len(value) <= 40)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ProvisioningError("invalid_provider_response") from None


def utc(value: datetime) -> datetime:
    require(type(value) is datetime and value.tzinfo is not None, "invalid_time")
    return value.astimezone(timezone.utc)


def canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise ProvisioningError("invalid_input") from None


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ProvisioningError("invalid_provider_response")


def document(content: bytes) -> dict:
    require(type(content) is bytes and 0 < len(content) <= MAX_RESPONSE_BYTES)
    try:
        result = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ProvisioningError("invalid_provider_response") from None
    require(type(result) is dict)
    # JSON's byte bound alone does not bound a deeply nested hostile document.
    remaining, stack = 100_000, [(result, 0)]
    while stack:
        node, depth = stack.pop()
        remaining -= 1
        require(remaining >= 0 and depth <= 32)
        if type(node) is dict:
            require(len(node) + len(stack) <= remaining)
            stack.extend((value, depth + 1) for value in node.values())
        elif type(node) is list:
            require(len(node) + len(stack) <= remaining)
            stack.extend((value, depth + 1) for value in node)
    return result


def _content(value: object, maximum: int) -> bytes:
    require(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ProvisioningError("invalid_provider_response") from None
    require(0 < len(result) <= maximum and base64.b64encode(result).decode("ascii") == value)
    return result


@dataclass(frozen=True, repr=False)
class AppleRequest:
    """Internal wire request, not a generic caller-selected HTTP endpoint."""

    kind: str
    method: str
    path: str
    resource_type: str
    query: tuple[tuple[str, str], ...] = ()
    body: bytes | None = field(default=None, repr=False)

    @property
    def url(self) -> str:
        return API_ORIGIN + self.path + ("?" + urlencode(self.query) if self.query else "")

    def summary(self) -> dict:
        return {"kind": self.kind, "method": self.method}


@dataclass(frozen=True, repr=False)
class AppleResponse:
    status: int
    body: bytes = field(repr=False)
    # This is supplied by the actual transport owner, NOT parsed from Apple JSON.
    settled: bool = False


def request_wire(request: AppleRequest) -> dict:
    """Private owner-to-adapter frame; never a renderer preview/log record."""
    validate_request(request)
    return {"kind": request.kind, "method": request.method, "path": request.path,
            "query": dict(request.query), "body": None if request.body is None else document(request.body)}


def request_sha256(request: AppleRequest) -> str:
    return digest(canonical(request_wire(request)))


def response_from_adapter(frame: bytes, *, settled: bool) -> AppleResponse:
    """Private Ruby adapter result + ORIGINAL native-owner finality.

    The Ruby worker deliberately supplies no finality field. A renderer result,
    frame EOF or a newly acquired process observer cannot supply ``settled``.
    """
    value = document(frame)
    require(set(value) == {"status", "body", "failure"} and type(settled) is bool,
            "invalid_adapter_result")
    status, body, failure = value["status"], value["body"], value["failure"]
    require(status is None or type(status) is int and 100 <= status <= 599, "invalid_adapter_result")
    require(failure is None or type(failure) is str and failure == "provider_request_unconfirmed", "invalid_adapter_result")
    if failure is not None:
        require(body is None, "invalid_adapter_result")
        if status in {400, 401, 403, 404, 405, 409, 422}:
            return AppleResponse(status, b"{}", settled)
        raise ProvisioningError("provider_outcome_unknown")
    require(status is not None and type(body) is str and body.isascii() and 0 < len(body) <= MAX_RESPONSE_BYTES,
            "invalid_adapter_result")
    return AppleResponse(status, body.encode("ascii"), settled)


def list_bundle_ids(bundle_id: str) -> AppleRequest:
    require(type(bundle_id) is str and len(bundle_id) <= 255 and BUNDLE_RE.fullmatch(bundle_id) is not None,
            "invalid_bundle_id")
    return AppleRequest("list_bundle_ids", "GET", "/v1/bundleIds", "bundleIds", (
        ("filter[identifier]", bundle_id), ("fields[bundleIds]", "identifier,platform,seedId"), ("limit", "200"),
    ))


def list_certificates() -> AppleRequest:
    return AppleRequest("list_certificates", "GET", "/v1/certificates", "certificates", (
        ("filter[certificateType]", "DISTRIBUTION,IOS_DISTRIBUTION"),
        ("fields[certificates]", "certificateType,platform,expirationDate,certificateContent"), ("limit", "200"),
    ))


PROFILE_FIELDS = "name,platform,profileType,profileState,uuid,createdDate,expirationDate,bundleId,certificates"
PROFILE_RELATIONS = (("include", "bundleId,certificates"),
                     ("fields[bundleIds]", "identifier,platform,seedId"),
                     ("fields[certificates]", "certificateType,platform,expirationDate"))


def list_profiles() -> AppleRequest:
    # This endpoint has no filter[bundleId]. Do not invent one and mistake an
    # ignored/unsupported filter for an exhaustive target-specific inventory.
    return AppleRequest("list_profiles", "GET", "/v1/profiles", "profiles", (
        ("filter[profileType]", "IOS_APP_STORE"), ("fields[profiles]", PROFILE_FIELDS),
        *PROFILE_RELATIONS, ("limit", "200"),
    ))


def download_profile(resource_id: str) -> AppleRequest:
    return AppleRequest("download_profile", "GET", "/v1/profiles/" + identifier(resource_id), "profiles", (
        ("fields[profiles]", PROFILE_FIELDS + ",profileContent"), *PROFILE_RELATIONS,
    ))


def register_bundle_id(bundle_id: str, name: str) -> AppleRequest:
    list_bundle_ids(bundle_id)  # Exact shared identity policy.
    _name(name)
    return AppleRequest("register_bundle_id", "POST", "/v1/bundleIds", "bundleIds", body=canonical({
        "data": {"type": "bundleIds", "attributes": {"identifier": bundle_id, "name": name, "platform": "IOS"}},
    }))


def create_certificate(csr_pem: bytes) -> AppleRequest:
    # Native owner verifies the PKCS#10 signature and key association. This is
    # only a bounded public-CSR envelope check, never a private-key parser.
    require(type(csr_pem) is bytes and 0 < len(csr_pem) <= 32 * 1024, "invalid_public_csr")
    try:
        text = csr_pem.decode("ascii")
    except UnicodeError:
        raise ProvisioningError("invalid_public_csr") from None
    require(re.fullmatch(r"-----BEGIN CERTIFICATE REQUEST-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+"
                         r"-----END CERTIFICATE REQUEST-----\n?", text) is not None, "invalid_public_csr")
    return AppleRequest("create_certificate", "POST", "/v1/certificates", "certificates", body=canonical({
        "data": {"type": "certificates", "attributes": {"certificateType": "DISTRIBUTION", "csrContent": text}},
    }))


def _name(value: str) -> None:
    require(type(value) is str and 0 < len(value) <= 128 and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            "invalid_name")


def create_profile(name: str, bundle_id_resource: str, certificate_resource: str) -> AppleRequest:
    _name(name)
    return AppleRequest("create_profile", "POST", "/v1/profiles", "profiles", body=canonical({
        "data": {"type": "profiles", "attributes": {"name": name, "profileType": "IOS_APP_STORE"},
                 "relationships": {
                     "bundleId": {"data": {"type": "bundleIds", "id": identifier(bundle_id_resource)}},
                     "certificates": {"data": [{"type": "certificates", "id": identifier(certificate_resource)}]},
                 }},
    }))


def validate_request(request: AppleRequest) -> None:
    """Rebuild the one allowed shape; no direct dataclass construction bypass."""
    require(type(request) is AppleRequest and type(request.query) is tuple, "invalid_request")
    try:
        query = dict(request.query)
        require(len(query) == len(request.query), "invalid_request")
        if request.kind == "list_bundle_ids":
            expected = list_bundle_ids(query.get("filter[identifier]"))
        elif request.kind == "list_certificates":
            expected = list_certificates()
        elif request.kind == "list_profiles":
            expected = list_profiles()
        elif request.kind == "download_profile":
            require(type(request.path) is str and request.path.startswith("/v1/profiles/"), "invalid_request")
            expected = download_profile(request.path.removeprefix("/v1/profiles/"))
        else:
            payload = document(request.body)
            attributes = payload["data"]["attributes"]
            if request.kind == "register_bundle_id":
                expected = register_bundle_id(attributes["identifier"], attributes["name"])
            elif request.kind == "create_certificate":
                expected = create_certificate(attributes["csrContent"].encode("ascii"))
            elif request.kind == "create_profile":
                relationships = payload["data"]["relationships"]
                expected = create_profile(attributes["name"], relationships["bundleId"]["data"]["id"],
                                          relationships["certificates"]["data"][0]["id"])
            else:
                raise ProvisioningError("invalid_request")
        expected_query = dict(expected.query)
        if "cursor" in query:
            cursor = query["cursor"]
            require(request.kind.startswith("list_") and type(cursor) is str and 0 < len(cursor) <= 1024
                    and all(32 < ord(c) < 127 for c in cursor), "invalid_request")
            expected_query["cursor"] = cursor
        require(request.method == expected.method and request.path == expected.path
                and request.resource_type == expected.resource_type and request.body == expected.body
                and query == expected_query, "invalid_request")
    except (KeyError, IndexError, TypeError, AttributeError, ValueError, UnicodeError):
        raise ProvisioningError("invalid_request") from None


def _checked_response(response: AppleResponse) -> dict:
    require(type(response) is AppleResponse and type(response.settled) is bool and response.settled,
            "transport_unsettled")
    require(type(response.status) is int, "invalid_provider_response")
    if response.status in (401, 403):
        raise ProvisioningError("account_access_denied")
    # Even 404 on a list/read is NOT proof of an absent signing resource.
    require(200 <= response.status < 300, "provider_read_unavailable")
    payload = document(response.body)
    require("errors" not in payload and "data" in payload)
    return payload


def _next_request(original: AppleRequest, url: object) -> AppleRequest:
    require(type(url) is str and len(url) <= 4096, "unsafe_pagination")
    try:
        parsed = urlsplit(url)
        require(parsed.scheme == "https" and parsed.netloc == "api.appstoreconnect.apple.com"
                and parsed.path == original.path and not parsed.fragment and not parsed.username
                and not parsed.password, "unsafe_pagination")
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
    except (ValueError, UnicodeError):
        raise ProvisioningError("unsafe_pagination") from None
    query = dict(pairs)
    require(len(pairs) == len(query) and set(query) == set(dict(original.query)) | {"cursor"}
            and all(query.get(key) == value for key, value in original.query)
            and 0 < len(query["cursor"]) <= 1024 and all(32 < ord(c) < 127 for c in query["cursor"]),
            "unsafe_pagination")
    return replace(original, query=tuple(pairs))


def _resource(value: object, expected_type: str) -> dict:
    require(type(value) is dict and value.get("type") == expected_type)
    identifier(value.get("id"))
    require(type(value.get("attributes")) is dict)
    return value


def collect(request: AppleRequest, send: Callable[[AppleRequest], AppleResponse], *,
            inspect_page: Callable[[dict], None] | None = None) -> tuple[dict, ...]:
    """Complete bounded inventory, or an error; never a partial success list.

    Stable page totals and unique IDs detect common drift but are not an atomic
    account snapshot. The operation owner must reobserve under its account lease
    immediately before a mutation and compare the reviewed observation.
    """
    require(request.kind in {"list_bundle_ids", "list_certificates", "list_profiles"}
            and request.method == "GET" and request.body is None, "invalid_query")
    validate_request(request)
    result, seen, current, total, byte_count = [], set(), request, None, 0
    for _ in range(MAX_PAGES):
        response = send(current)
        payload = _checked_response(response)
        if inspect_page is not None:
            inspect_page(payload)
        byte_count += len(response.body)
        require(byte_count <= MAX_INVENTORY_BYTES, "inventory_limit")
        data, links = payload.get("data"), payload.get("links")
        paging = payload.get("meta", {}).get("paging") if type(payload.get("meta")) is dict else None
        require(type(data) is list and len(data) <= 200 and type(links) is dict
                and type(paging) is dict and type(paging.get("total")) is int
                and 0 <= paging["total"] <= MAX_RESOURCES, "incomplete_inventory")
        require(total is None or total == paging["total"], "inventory_changed")
        total = paging["total"]
        for item in data:
            result.append(_resource(item, request.resource_type))
        require(len(result) <= total and len(result) <= MAX_RESOURCES, "incomplete_inventory")
        next_url = links.get("next")
        if next_url is None:
            require(len(result) == total, "incomplete_inventory")
            require(len({item["id"] for item in result}) == len(result), "duplicate_resource")
            return tuple(result)
        require(type(next_url) is str and bool(data) and next_url not in seen, "unsafe_pagination")
        seen.add(next_url)
        current = _next_request(request, next_url)
    raise ProvisioningError("inventory_limit")


def single(response: AppleResponse, resource_type: str, *, inspect_page: Callable[[dict], None] | None = None) -> dict:
    payload = _checked_response(response)
    if inspect_page is not None:
        inspect_page(payload)
    return _resource(payload.get("data"), resource_type)


@dataclass(frozen=True, repr=False)
class BundleId:
    resource_id: str
    identifier: str
    platform: str
    seed_id: str

    @classmethod
    def parse(cls, value: dict) -> BundleId:
        data = _resource(value, "bundleIds")
        attributes = data["attributes"]
        bundle = attributes.get("identifier")
        require(type(bundle) is str and len(bundle) <= 255 and BUNDLE_RE.fullmatch(bundle) is not None)
        require(attributes.get("platform") in {"IOS", "UNIVERSAL", "MAC_OS"})
        seed = attributes.get("seedId")
        require(type(seed) is str and TEAM_RE.fullmatch(seed) is not None)
        return cls(data["id"], bundle, attributes["platform"], seed)


@dataclass(frozen=True, repr=False)
class Certificate:
    resource_id: str
    certificate_type: str
    expires_at: datetime
    content: bytes = field(repr=False)

    @classmethod
    def parse(cls, value: dict) -> Certificate:
        data = _resource(value, "certificates")
        attributes = data["attributes"]
        require(attributes.get("certificateType") in CERTIFICATE_TYPES)
        require(attributes.get("platform") in {None, "IOS", "UNIVERSAL"})
        return cls(data["id"], attributes["certificateType"], timestamp(attributes.get("expirationDate")),
                   _content(attributes.get("certificateContent"), MAX_CERTIFICATE_BYTES))


def _relationship(value: dict, name: str, expected_type: str, many: bool) -> tuple[str, ...]:
    relations = value.get("relationships")
    require(type(relations) is dict)
    relation = relations.get(name)
    require(type(relation) is dict and "data" in relation)
    links = relation.get("links", {})
    require(type(links) is dict and links.get("next") is None, "incomplete_relationship")
    data = relation["data"]
    items = data if many else [data]
    require(type(items) is list and 0 < len(items) <= 50, "incomplete_relationship")
    identifiers = []
    for item in items:
        require(type(item) is dict and item.get("type") == expected_type)
        identifiers.append(identifier(item.get("id")))
    require(len(set(identifiers)) == len(identifiers), "incomplete_relationship")
    meta = relation.get("meta", {})
    require(type(meta) is dict)
    if "paging" in meta:
        paging = meta["paging"]
        require(type(paging) is dict and type(paging.get("total")) is int
                and paging["total"] == len(identifiers), "incomplete_relationship")
    return tuple(sorted(identifiers))


@dataclass(frozen=True, repr=False)
class Profile:
    resource_id: str
    name: str
    uuid: str
    state: str
    created_at: datetime
    expires_at: datetime
    bundle_id_resource: str
    certificate_resources: tuple[str, ...]
    content: bytes | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, value: dict, *, require_content: bool = False) -> Profile:
        data = _resource(value, "profiles")
        attributes = data["attributes"]
        require(attributes.get("profileType") == "IOS_APP_STORE"
                and attributes.get("platform") in {"IOS", "UNIVERSAL"})
        require(attributes.get("profileState") in {"ACTIVE", "INVALID"})
        uuid = attributes.get("uuid")
        require(type(uuid) is str and UUID_RE.fullmatch(uuid) is not None)
        _name(attributes.get("name"))
        created, expires = timestamp(attributes.get("createdDate")), timestamp(attributes.get("expirationDate"))
        require(created < expires)
        content = None
        if require_content or "profileContent" in attributes:
            content = _content(attributes.get("profileContent"), MAX_PROFILE_BYTES)
        return cls(data["id"], attributes["name"], uuid.upper(), attributes["profileState"], created, expires,
                   _relationship(data, "bundleId", "bundleIds", False)[0],
                   _relationship(data, "certificates", "certificates", True), content)


def resource_sha256(value: BundleId | Certificate | Profile) -> str:
    """Bind readback/approval to validated identity, not only a returned ID.

    Profile bytes are authenticated separately after a current download. They
    are deliberately absent from list/create comparison; certificate DER is not.
    """
    if type(value) is BundleId:
        fields = ("bundleIds", value.resource_id, value.identifier, value.platform, value.seed_id)
    elif type(value) is Certificate:
        fields = ("certificates", value.resource_id, value.certificate_type,
                  utc(value.expires_at).isoformat(), digest(value.content))
    else:
        require(type(value) is Profile)
        fields = ("profiles", value.resource_id, value.name, value.uuid, value.state,
                  utc(value.created_at).isoformat(), utc(value.expires_at).isoformat(),
                  value.bundle_id_resource, value.certificate_resources)
    return digest(canonical(fields))


def validate_profile_included(payload: dict, bundles: tuple[BundleId, ...], certificates: tuple[Certificate, ...],
                              *, bundle_id: str) -> None:
    """Do not discard contradictory related identity/team evidence.

    Sparse included certificate metadata is not native key proof. Missing
    included resources do not imply absence (invalid profiles may refer to
    removed assets); explicit conflicting metadata for known assets refuses.
    """
    included = payload.get("included", [])
    require(type(included) is list and len(included) <= 4000)
    known_bundles = {value.resource_id: value for value in bundles}
    known_certificates = {value.resource_id: value for value in certificates}
    seen = set()
    for value in included:
        require(type(value) is dict and value.get("type") in {"bundleIds", "certificates"})
        identity = (value["type"], identifier(value.get("id")))
        require(identity not in seen, "duplicate_resource")
        seen.add(identity)
        if value["type"] == "bundleIds":
            related = BundleId.parse(value)
            known = known_bundles.get(related.resource_id)
            if known is not None or related.identifier == bundle_id:
                require(related == known, "contradictory_related_identity")
        else:
            data = _resource(value, "certificates")
            attributes = data["attributes"]
            known = known_certificates.get(data["id"])
            # Other/removed certificate types on invalid profiles are not
            # usable here, but cannot expand the distribution inventory.
            if known is not None:
                require(attributes.get("certificateType") == known.certificate_type
                        and attributes.get("platform") in {None, "IOS", "UNIVERSAL"}
                        and timestamp(attributes.get("expirationDate")) == known.expires_at,
                        "contradictory_related_identity")
                if "certificateContent" in attributes:
                    require(_content(attributes["certificateContent"], MAX_CERTIFICATE_BYTES) == known.content,
                            "contradictory_related_identity")
