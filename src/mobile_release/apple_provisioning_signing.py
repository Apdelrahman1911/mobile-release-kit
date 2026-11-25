"""Existing-key App Store profile preparation on the original Apple owner.

This leaf performs no credential lookup, private-key extraction, HTTP, vault
write, assignment or native admission. The SAME SavedCommand Apple operation
provides the current P8/P12 loans, fixed Ruby calls, durable account inventory
and original joins. A ``CertificateBinding`` must come from its actual current
P12/SPKI, pinned-chain and selected-ASC comparison, never from this parser.

Only reuse/download or one explicitly approved profile creation is supported.
Bundle registration, certificate issuance, CSR generation, capabilities,
devices, revocation and automatic retries remain outside this mode.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field, replace
from datetime import datetime

from . import apple_provisioning_api as api
from .apple_provisioning import (
    SIGNING_SCOPE, CertificateBinding, NativeKeyRef, Observation, PendingMutation,
    ProvisioningContext, ProvisioningPlan, ProvisioningProvider, ProvisioningTarget,
    prepare, validate_download,
)
from .apple_provisioning_recovery import ProvisioningAttempt

SCOPE = "existing-p12-app-store-profile"
MODES = frozenset({"profile-review", "profile-reuse", "profile-create", "profile-reconcile"})
PAGE_LIMIT = 128 * 1024
PAGES = 2
INVENTORY_LIMIT = 1024 * 1024
PROFILE_LIMIT = 1024 * 1024
DOWNLOAD_LIMIT = 1536 * 1024
FRAME_LIMIT = 2 * 1024 * 1024
MAX_ROWS = 400
MAX_CERTIFICATE_REFERENCES = 800
_PROFILE_ATTRIBUTES = frozenset({"name", "platform", "profileType", "profileState", "uuid", "createdDate", "expirationDate"})
_BUNDLE_ATTRIBUTES = frozenset({"identifier", "platform", "seedId"})
_CERTIFICATE_ATTRIBUTES = frozenset({"certificateType", "platform", "expirationDate"})
_READS = frozenset({"list_bundle_ids", "list_certificates", "list_profiles", "download_profile"})


def profile_name(operation_id: str) -> str:
    api.identifier(operation_id)
    return "MRK-" + api.digest(operation_id.encode("utf-8"))[:24]


def validate_request(request: api.AppleRequest, target: ProvisioningTarget, operation_id: str) -> None:
    """Closed subset of the existing provisioning wire, never a generic URL."""
    api.validate_request(request)
    api.identifier(operation_id)
    api.require(request.kind in _READS | {"create_profile"}, "unsupported_profile_operation")
    if request.kind == "list_bundle_ids":
        api.require(dict(request.query)["filter[identifier]"] == target.bundle_id, "bundle_identity_conflict")
    if request.kind == "create_profile":
        body = api.document(request.body)["data"]
        api.require(body["attributes"]["name"] == profile_name(operation_id), "invalid_profile_plan")


def response_from_frame(raw: bytes, *, context_sha256: str, operation_id: str,
                        target: ProvisioningTarget, request: api.AppleRequest,
                        ack_sha256: str | None, settled: bool) -> api.AppleResponse:
    """Exact raw capture plus ORIGINAL command finality, not a JSON receipt.

    The cap is on the private handoff after the SDK has buffered the response;
    it is not a socket/RSS bound. Only the actual retained C/A/W owner may supply
    ``settled``. Raw duplicate members are still present for ``api.document``.
    """
    validate_request(request, target, operation_id)
    api.require(type(context_sha256) is str and api.HEX_RE.fullmatch(context_sha256) is not None
                and type(settled) is bool and (ack_sha256 is None if request.method == "GET" else
                type(ack_sha256) is str and api.HEX_RE.fullmatch(ack_sha256) is not None), "invalid_adapter_result")
    api.require(type(raw) is bytes and 0 < len(raw) <= FRAME_LIMIT, "invalid_adapter_result")
    value = api.document(raw)
    api.require(set(value) == {"schemaVersion", "scope", "contextSha256", "bundleId", "operationId",
                              "requestSha256", "ackSha256", "response"}
                and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
                and value["contextSha256"] == context_sha256 and value["bundleId"] == target.bundle_id
                and value["operationId"] == operation_id and value["requestSha256"] == api.request_sha256(request)
                and value["ackSha256"] == ack_sha256, "invalid_adapter_result")
    result = value["response"]
    api.require(type(result) is dict and set(result) == {"status", "bodyBase64", "failure"}, "invalid_adapter_result")
    status, encoded, failure = (result[name] for name in ("status", "bodyBase64", "failure"))
    api.require(status is None or type(status) is int and 100 <= status <= 599, "invalid_adapter_result")
    api.require(failure is None or type(failure) is str and failure == "provider_request_unconfirmed", "invalid_adapter_result")
    if failure is not None:
        api.require(encoded is None, "invalid_adapter_result")
        if status in {400, 401, 403, 404, 405, 409, 422}:
            return api.AppleResponse(status, b"{}", settled)
        raise api.ProvisioningError("provider_outcome_unknown")
    limit = PAGE_LIMIT if request.kind.startswith("list_") else DOWNLOAD_LIMIT
    api.require(type(status) is int and type(encoded) is str and encoded.isascii()
                and 0 < len(encoded) <= 4 * ((limit + 2) // 3), "invalid_adapter_result")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise api.ProvisioningError("invalid_adapter_result") from None
    api.require(0 < len(body) <= limit and base64.b64encode(body).decode("ascii") == encoded, "invalid_adapter_result")
    return api.AppleResponse(status, body, settled)


def _attributes(value: object, resource_type: str, fields: frozenset[str], *, optional=frozenset()) -> dict:
    # Reject unexpected content BEFORE invoking the download-capable parsers.
    api.require(type(value) is dict and value.get("type") == resource_type
                and set(value) <= {"type", "id", "attributes", "relationships", "links"})
    api.identifier(value.get("id"))
    attributes = value.get("attributes")
    api.require(type(attributes) is dict and fields <= set(attributes) <= fields | optional)
    return attributes


def _profile_references(value: dict) -> tuple[str, tuple[str, ...], bool]:
    relationships = value.get("relationships")
    api.require(type(relationships) is dict and set(relationships) == {"bundleId", "certificates"}, "incomplete_relationship")
    complete, references = True, []
    for name, kind in (("bundleId", "bundleIds"), ("certificates", "certificates")):
        relation = relationships[name]
        api.require(type(relation) is dict and {"data"} <= set(relation) <= {"data", "meta", "links"}, "incomplete_relationship")
        links, meta = relation.get("links", {}), relation.get("meta", {})
        api.require(type(links) is dict and links.get("next") is None and type(meta) is dict, "incomplete_relationship")
        items = relation["data"] if name == "certificates" else [relation["data"]]
        api.require(type(items) is list and 0 < len(items) <= 50, "incomplete_relationship")
        ids = []
        for item in items:
            api.require(type(item) is dict and set(item) == {"type", "id"} and item["type"] == kind, "incomplete_relationship")
            ids.append(api.identifier(item["id"]))
        api.require(len(set(ids)) == len(ids), "incomplete_relationship")
        if "paging" in meta:
            paging = meta["paging"]
            api.require(type(paging) is dict and type(paging.get("total")) is int and paging["total"] == len(ids), "incomplete_relationship")
        elif name == "certificates":
            # Typical sparse responses need not state relationship completeness.
            # They can nominate an exact existing profile for CMS inspection, but
            # cannot prove there is NO reusable profile and justify a new POST.
            complete = False
        references.append(tuple(sorted(ids)))
    return references[0][0], references[1], complete


@dataclass(frozen=True, repr=False)
class SigningInventory:
    observation: Observation
    profile_relationships_complete: bool

    def __post_init__(self):
        api.require(type(self.observation) is Observation and self.observation.scope == SIGNING_SCOPE
                    and type(self.profile_relationships_complete) is bool, "invalid_signing_inventory")
        if self.observation.available:
            api.require(self.observation.reason == ("observed" if self.profile_relationships_complete else
                "profile_relationship_evidence_incomplete"), "invalid_signing_inventory")
        else:
            api.require(not self.profile_relationships_complete and not self.observation.bundles
                        and not self.observation.certificates and not self.observation.profiles, "invalid_signing_inventory")


def observe_signing(context: ProvisioningContext, target: ProvisioningTarget,
                    provider: ProvisioningProvider, *, now: datetime) -> SigningInventory:
    """Three finite inventories or an unavailable result; no truncated absence.

    ``now`` is captured BEFORE the first provider call. Stable totals/unique IDs
    are drift checks, not an atomic Apple snapshot. The parent reobserves before
    creation under its SAME account lease and repeats original loan checks.
    """
    now = api.utc(now)
    byte_count, complete, certificate_references = 0, True, 0
    bundles, certificates = (), ()
    related_seen, profile_uuids = {}, set()

    def collect(request):
        pages = 0

        def send(selected):
            nonlocal pages, byte_count
            api.require(pages < PAGES, "inventory_limit")
            validate_request(selected, target, context.operation_id)
            api.require(selected.kind == request.kind, "unexpected_provider_query")
            pages += 1  # Before any owner callback or provider call.
            provider.check(context)
            response = provider.send(selected)
            provider.check(context)
            api.require(type(response) is api.AppleResponse and type(response.body) is bytes
                        and 0 < len(response.body) <= PAGE_LIMIT, "inventory_limit")
            byte_count += len(response.body)
            api.require(byte_count <= INVENTORY_LIMIT, "inventory_limit")
            api.require(type(response.status) is int and (response.status == 200 or not 200 <= response.status < 300),
                        "unexpected_provider_status")
            return response

        def page(payload):
            nonlocal complete, certificate_references
            api.require(set(payload) <= {"data", "links", "meta", "included"} and "errors" not in payload)
            rows, links, meta = payload.get("data"), payload.get("links"), payload.get("meta")
            paging = meta.get("paging") if type(meta) is dict else None
            api.require(type(rows) is list and len(rows) <= 200 and type(links) is dict and type(paging) is dict
                        and type(paging.get("total")) is int and 0 <= paging["total"] <= MAX_ROWS, "incomplete_inventory")
            api.require(pages < PAGES or links.get("next") is None, "inventory_limit")
            if request.kind != "list_profiles":
                api.require("included" not in payload, "unexpected_related_resource")
                fields = _BUNDLE_ATTRIBUTES if request.kind == "list_bundle_ids" else _CERTIFICATE_ATTRIBUTES | {"certificateContent"}
                for row in rows:
                    _attributes(row, request.resource_type, fields)
                    api.require("relationships" not in row)
                return
            included = payload.get("included", [])
            api.require(type(included) is list and len(included) <= 600, "inventory_limit")
            # Complete preflight across ALL rows precedes any content decoder.
            for row in rows:
                _attributes(row, "profiles", _PROFILE_ATTRIBUTES)
            for row in included:
                api.require(type(row) is dict and row.get("type") in {"bundleIds", "certificates"} and "relationships" not in row)
                _attributes(row, row["type"], _BUNDLE_ATTRIBUTES if row["type"] == "bundleIds" else _CERTIFICATE_ATTRIBUTES)
            needed, seen = set(), set()
            for row in rows:
                bundle_id, cert_ids, relationship_complete = _profile_references(row)
                complete = complete and relationship_complete
                certificate_references += len(cert_ids)
                api.require(certificate_references <= MAX_CERTIFICATE_REFERENCES, "inventory_limit")
                needed.add(("bundleIds", bundle_id))
                needed.update(("certificates", identity) for identity in cert_ids)
            for row in included:
                identity = (row["type"], row["id"])
                api.require(identity in needed and identity not in seen, "unexpected_related_resource")
                seen.add(identity)
                fingerprint = api.digest(api.canonical(row["attributes"]))
                api.require(identity not in related_seen or related_seen[identity] == fingerprint, "inventory_changed")
                related_seen[identity] = fingerprint
                if row["type"] == "bundleIds":
                    value = api.BundleId.parse(row)
                    api.require(value.platform in {"IOS", "UNIVERSAL"}, "contradictory_related_identity")
                else:
                    attributes = row["attributes"]
                    api.require(attributes["certificateType"] in api.CERTIFICATE_TYPES
                                and attributes["platform"] in {None, "IOS", "UNIVERSAL"}, "contradictory_related_identity")
                    api.timestamp(attributes["expirationDate"])
            # Missing included metadata is NOT permission to create. It remains
            # comparison-only even when the requested linkage array was present.
            complete = complete and seen == needed
            api.validate_profile_included(payload, bundles, certificates, bundle_id=target.bundle_id)

        return api.collect(request, send, inspect_page=page)

    try:
        bundles = tuple(api.BundleId.parse(row) for row in collect(api.list_bundle_ids(target.bundle_id)))
        api.require(len(bundles) <= 1 and all(row.identifier == target.bundle_id and row.platform in {"IOS", "UNIVERSAL"}
                                            for row in bundles), "wrong_bundle_inventory")
        certificates = tuple(api.Certificate.parse(row) for row in collect(api.list_certificates()))
        profiles = tuple(api.Profile.parse(row) for row in collect(api.list_profiles()))
        for profile in profiles:
            api.require(profile.uuid not in profile_uuids and profile.content is None, "duplicate_resource")
            profile_uuids.add(profile.uuid)
        provider.check(context)
        reason = "observed" if complete else "profile_relationship_evidence_incomplete"
        return SigningInventory(Observation(context, target.bundle_id, now, True, reason, bundles, certificates, profiles), complete)
    except api.ProvisioningError as error:
        reason = error.code
    except Exception:
        reason = "provider_read_unavailable"  # Never provider/private error text.
    # BaseException interruptions propagate to the original cancellation owner.
    return SigningInventory(Observation(context, target.bundle_id, now, False, reason), False)


def prepare_existing_profile(context: ProvisioningContext, target: ProvisioningTarget, inventory: SigningInventory, *,
                             bindings: tuple[CertificateBinding, ...], selected_key: NativeKeyRef,
                             pending: tuple[PendingMutation, ...], now: datetime,
                             selected_profile: str | None = None) -> ProvisioningPlan:
    api.require(type(inventory) is SigningInventory and type(selected_key) is NativeKeyRef, "invalid_signing_inventory")
    api.require(type(pending) is tuple and len(pending) <= 32 and all(type(row) is PendingMutation for row in pending),
                "invalid_pending_inventory")
    plan = prepare(context, target, inventory.observation, bindings=bindings, csr=None, pending=pending,
                   now=now, selected_key=selected_key, selected_profile=selected_profile)
    if plan.action in {"register_bundle_id", "prepare_csr", "create_certificate"}:
        return replace(plan, action="manual", reason="bundle_registration_required" if plan.action == "register_bundle_id" else
                       "existing_distribution_identity_required", request=None, csr=None)
    if plan.action == "create_profile" and not inventory.profile_relationships_complete:
        return replace(plan, action="blocked", reason="profile_relationship_evidence_incomplete", request=None)
    return plan


@dataclass(frozen=True, repr=False)
class ProfileCreationReceipt:
    """Sparse 201 DATA retained by the live original attempt, not a profile.

    An exact ID permits only an exact GET. Supplied fields must agree; missing
    fields are NOT synthesized from a request and do not authenticate content.
    The digest differs deliberately from the full GET resource digest.
    """
    resource_id: str
    attributes_json: bytes = field(repr=False)
    bundle_resource: str | None
    certificate_resources: tuple[str, ...] | None
    content_sha256: str | None

    @property
    def sha256(self):
        return api.digest(api.canonical({"type": "profiles", "id": self.resource_id,
            "attributes": api.document(self.attributes_json), "bundleId": self.bundle_resource,
            "certificates": self.certificate_resources, "profileSha256": self.content_sha256}))

    @classmethod
    def parse(cls, response: api.AppleResponse, plan: ProvisioningPlan, before: Observation):
        api.require(response.status == 201 and type(response.body) is bytes and len(response.body) <= DOWNLOAD_LIMIT,
                    "unexpected_provider_status")
        payload = api._checked_response(response)
        api.require(set(payload) <= {"data", "links", "meta", "included"}, "invalid_provider_response")
        data = payload.get("data")
        api.require(type(data) is dict and data.get("type") == "profiles"
                    and set(data) <= {"type", "id", "attributes", "relationships", "links"}, "invalid_provider_response")
        resource_id = api.identifier(data.get("id"))
        api.require(resource_id not in {row.resource_id for row in before.profiles}, "creation_returned_existing_resource")
        attributes = data.get("attributes", {})
        api.require(type(attributes) is dict and set(attributes) <= _PROFILE_ATTRIBUTES | {"profileContent"})
        expected = {"name": profile_name(plan.context.operation_id), "profileType": "IOS_APP_STORE", "profileState": "ACTIVE"}
        for name, value in expected.items():
            api.require(name not in attributes or attributes[name] == value, "profile_identity_mismatch")
        api.require("platform" not in attributes or attributes["platform"] in {"IOS", "UNIVERSAL"}, "profile_identity_mismatch")
        normalized = {key: value for key, value in attributes.items() if key != "profileContent"}
        if "uuid" in attributes:
            api.require(type(attributes["uuid"]) is str and api.UUID_RE.fullmatch(attributes["uuid"]) is not None)
            normalized["uuid"] = attributes["uuid"].upper()
        for name in ("createdDate", "expirationDate"):
            if name in attributes:
                normalized[name] = api.timestamp(attributes[name]).isoformat()
        if {"createdDate", "expirationDate"} <= normalized.keys():
            api.require(api.timestamp(normalized["createdDate"]) < api.timestamp(normalized["expirationDate"]), "profile_identity_mismatch")
        relations = data.get("relationships", {})
        api.require(type(relations) is dict and set(relations) <= {"bundleId", "certificates"})
        bundle_resource, certificate_resources = None, None
        if "bundleId" in relations:
            bundle_resource = api._relationship(data, "bundleId", "bundleIds", False)[0]
            api.require(bundle_resource == plan.bundle.resource_id, "profile_identity_mismatch")
        if "certificates" in relations:
            certificate_resources = api._relationship(data, "certificates", "certificates", True)
            api.require(certificate_resources == (plan.certificate.resource_id,), "profile_identity_mismatch")
        api.validate_profile_included(payload, before.bundles, before.certificates, bundle_id=plan.target.bundle_id)
        content_hash = api.digest(api._content(attributes["profileContent"], PROFILE_LIMIT)) if "profileContent" in attributes else None
        return cls(resource_id, api.canonical(normalized), bundle_resource, certificate_resources, content_hash)

    def matches(self, profile: api.Profile) -> bool:
        if type(profile) is not api.Profile or profile.resource_id != self.resource_id:
            return False
        actual = {"name": profile.name, "uuid": profile.uuid, "profileState": profile.state,
                  "profileType": "IOS_APP_STORE", "createdDate": profile.created_at.isoformat(),
                  "expirationDate": profile.expires_at.isoformat()}
        fields = api.document(self.attributes_json)
        # Both supported platform values denote this iOS profile scope; parsing
        # a GET still requires IOS|UNIVERSAL independently.
        return (all(name == "platform" or actual.get(name) == value for name, value in fields.items())
                and (self.bundle_resource is None or self.bundle_resource == profile.bundle_id_resource)
                and (self.certificate_resources is None or self.certificate_resources == profile.certificate_resources)
                and (self.content_sha256 is None or profile.content is not None and api.digest(profile.content) == self.content_sha256))


class ProfileCreationAttempt(ProvisioningAttempt):
    """Same one-attempt/ACK/STOP/reconciliation engine; sparse response only."""
    def __init__(self, plan: ProvisioningPlan, inventory: SigningInventory):
        api.require(type(inventory) is SigningInventory and inventory.profile_relationships_complete
                    and plan.action == "create_profile", "invalid_profile_plan")
        self.receipt = None
        super().__init__(plan, inventory.observation)

    @classmethod
    def resume(cls, *_args, **_kwargs):
        # Historical rows authorize only the separate GET-only review. Neither
        # the live sparse receipt nor its original send/save owners are restored.
        raise api.ProvisioningError("profile_creation_not_replayable")

    def _response_identity(self, response):
        receipt = ProfileCreationReceipt.parse(response, self.plan, self.before)
        self.receipt = receipt
        return receipt.resource_id, receipt.sha256

    def _response_matches(self, resource):
        # Called by the narrow shared recovery hook; default old comparison is
        # unchanged for Bundle/certificate/ordinary full-profile attempts.
        return (type(self.receipt) is ProfileCreationReceipt and self.record.response_resource_id == self.receipt.resource_id
                and self.record.response_resource_sha256 == self.receipt.sha256 and self.receipt.matches(resource))


def created_download_plan(attempt: ProfileCreationAttempt, response: api.AppleResponse, *, now: datetime) -> ProvisioningPlan:
    """Validate exact GET after retained 201 ID; CMS/save/finality still owed."""
    api.require(type(attempt) is ProfileCreationAttempt and type(attempt.receipt) is ProfileCreationReceipt
                and attempt.record.status == "recovery_required" and attempt.record.reason == "readback_required"
                and attempt.record.response_resource_id == attempt.receipt.resource_id, "profile_readback_required")
    plan = attempt.plan
    api.require(type(response) is api.AppleResponse and response.status == 200 and type(response.body) is bytes
                and 0 < len(response.body) <= DOWNLOAD_LIMIT, "invalid_provider_response")
    data = api.single(response, "profiles", inspect_page=lambda value: api.validate_profile_included(
        value, attempt.before.bundles, attempt.before.certificates, bundle_id=plan.target.bundle_id))
    attributes = _attributes(data, "profiles", _PROFILE_ATTRIBUTES | {"profileContent"})
    # Core's global profile limit is intentionally larger. Enforce this mode's
    # private receive cap BEFORE its content decoder or native trailer exists.
    api._content(attributes["profileContent"], PROFILE_LIMIT)
    profile = api.Profile.parse(data, require_content=True)
    api.require(attempt._response_matches(profile) and profile.name == profile_name(plan.context.operation_id)
                and profile.bundle_id_resource == plan.bundle.resource_id
                and profile.certificate_resources == (plan.certificate.resource_id,), "profile_readback_changed")
    download = replace(plan, action="download_profile", reason="created_profile_authentication_required",
                       request=api.download_profile(profile.resource_id), profile=profile)
    validate_download(download, response, now=now)
    return download


def validate_reused_download(plan: ProvisioningPlan, response: api.AppleResponse, *, now: datetime) -> api.Profile:
    api.require(type(response) is api.AppleResponse and response.status == 200 and type(response.body) is bytes
                and 0 < len(response.body) <= DOWNLOAD_LIMIT, "invalid_provider_response")
    data = api.single(response, "profiles")
    attributes = _attributes(data, "profiles", _PROFILE_ATTRIBUTES | {"profileContent"})
    api._content(attributes["profileContent"], PROFILE_LIMIT)
    return validate_download(plan, response, now=now)
