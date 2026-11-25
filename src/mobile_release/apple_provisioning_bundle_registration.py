"""Bundle-ID-only adaptation of the existing provisioning plan/attempt.

The native SavedCommand owner still owns selected P8 authority, complete
account-wide pending state, consent, clocks and all original joins. None of
these comparison objects is an authorization or native settlement receipt.
Only the fixed provider adapter performs GET/POST; no certificate/profile
query, content download, private signing key, capability change or release
action is reachable through this slice.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime

from . import apple_provisioning_api as api
from .apple_provisioning import (
    BUNDLE_ID_SCOPE, MAX_OBSERVATION_AGE, Observation, PendingMutation,
    ProvisioningContext, ProvisioningPlan, ProvisioningProvider, ProvisioningTarget,
)

RAW_LIMIT = 32 * 1024
FRAME_LIMIT = 64 * 1024


def response_from_frame(raw: bytes, *, context_sha256: str, operation_id: str,
                        target: ProvisioningTarget, request: api.AppleRequest,
                        ack_sha256: str | None, settled: bool) -> api.AppleResponse:
    """Original raw SDK capture plus the ORIGINAL command owner's finality.

    ``settled`` has exactly the same owner-only meaning as
    ``api.response_from_adapter``. The private Ruby frame contains no such
    field and cannot establish it, the parent joins, or account-journal state.
    This decoder is used only after the same retained run_owned C/A/W command
    returns, with original source/material POSTs still required by the caller.
    """
    api.require(type(context_sha256) is str and api.HEX_RE.fullmatch(context_sha256) is not None
                and type(settled) is bool, "invalid_adapter_result")
    api.identifier(operation_id)
    expected = (api.list_bundle_ids(target.bundle_id) if request.method == "GET" else
                api.register_bundle_id(target.bundle_id, target.display_name))
    api.require(request == expected and (ack_sha256 is None if request.method == "GET" else
                type(ack_sha256) is str and api.HEX_RE.fullmatch(ack_sha256) is not None), "invalid_adapter_result")
    api.require(type(raw) is bytes and 0 < len(raw) <= FRAME_LIMIT, "invalid_adapter_result")
    value = api.document(raw)
    api.require(set(value) == {"schemaVersion", "contextSha256", "bundleId", "operationId", "requestSha256", "ackSha256", "response"}
                and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
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
        # Preserve the existing adapter's exact known-rejection handling. 404
        # still fails every GET inventory; no failure becomes absence/retry.
        if status in {400, 401, 403, 404, 405, 409, 422}:
            return api.AppleResponse(status, b"{}", settled)
        raise api.ProvisioningError("provider_outcome_unknown")
    api.require(type(status) is int and type(encoded) is str and encoded.isascii()
                and 0 < len(encoded) <= 4 * ((RAW_LIMIT + 2) // 3), "invalid_adapter_result")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise api.ProvisioningError("invalid_adapter_result") from None
    api.require(0 < len(body) <= RAW_LIMIT and base64.b64encode(body).decode("ascii") == encoded,
                "invalid_adapter_result")
    return api.AppleResponse(status, body, settled)


def observe_bundle(context: ProvisioningContext, target: ProvisioningTarget,
                   provider: ProvisioningProvider, *, now: datetime) -> Observation:
    """One exact filtered GET, never pagination or absence on denied access.

    ``AppleResponse.settled`` must come from the actual original provider call,
    not from its JSON, child exit code or this parser. It is per-call evidence;
    the enclosing native owner still owes its complete parent settlement.
    """
    now = api.utc(now)
    request = api.list_bundle_ids(target.bundle_id)
    entered = False

    def send(selected: api.AppleRequest) -> api.AppleResponse:
        nonlocal entered
        api.require(not entered and selected == request, "unexpected_provider_query")
        entered = True
        provider.check(context)
        response = provider.send(selected)
        provider.check(context)
        api.require(type(response) is api.AppleResponse and type(response.body) is bytes
                    and 0 < len(response.body) <= RAW_LIMIT, "invalid_provider_response")
        api.require(type(response.status) is int and (response.status == 200 or not 200 <= response.status < 300),
                    "unexpected_provider_status")
        return response

    def page(value: dict) -> None:
        # Check raw sparse members BEFORE resource interpretation. No included
        # certificate/profile content is decoded or adopted by this read.
        api.require(set(value) == {"data", "links", "meta"}, "incomplete_inventory")
        rows, links, meta = value["data"], value["links"], value["meta"]
        paging = meta.get("paging") if type(meta) is dict else None
        api.require(type(rows) is list and len(rows) <= 200 and type(links) is dict
                    and links.get("next") is None and type(paging) is dict
                    and type(paging.get("total")) is int and paging["total"] == len(rows),
                    "incomplete_inventory")
        api.require(all(type(row) is dict and type(row.get("attributes")) is dict
                        and set(row["attributes"]) == {"identifier", "platform", "seedId"}
                        for row in rows), "invalid_provider_response")

    try:
        bundles = tuple(api.BundleId.parse(row) for row in api.collect(request, send, inspect_page=page))
        api.require(all(row.identifier == target.bundle_id and row.platform in {"IOS", "UNIVERSAL"}
                        for row in bundles), "wrong_bundle_inventory")
        api.require(len(bundles) <= 1, "ambiguous_bundle_id")
        return Observation(context, target.bundle_id, now, True, "observed", bundles, scope=BUNDLE_ID_SCOPE)
    except api.ProvisioningError as error:
        return Observation(context, target.bundle_id, now, False, error.code, scope=BUNDLE_ID_SCOPE)
    except Exception:
        # Native/provider error text may contain credentials or private data.
        # BaseException interruptions deliberately propagate to the original.
        return Observation(context, target.bundle_id, now, False, "provider_read_unavailable", scope=BUNDLE_ID_SCOPE)


def prepare_bundle(context: ProvisioningContext, target: ProvisioningTarget, observation: Observation, *,
                   pending: tuple[PendingMutation, ...], now: datetime) -> ProvisioningPlan:
    """A bounded next Bundle-ID action, not an Apple signing setup plan.

    The original owner supplies the full durable account roster and exact
    selected scope. New-app declaration/Existing continuity veto are repeated
    at native Prepare/Start and the actual pre-send durable ACK boundary.
    """
    now = api.utc(now)
    api.require(type(observation) is Observation and observation.scope == BUNDLE_ID_SCOPE,
                "observation_scope_changed")
    api.require(target.entitlements_json == b"{}", "bundle_scope_entitlements_unsupported")
    api.require(observation.context == context and observation.bundle_id == target.bundle_id,
                "observation_context_changed")
    api.require(observation.observed_at <= now < observation.observed_at + MAX_OBSERVATION_AGE,
                "observation_expired")
    api.require(type(pending) is tuple and len(pending) <= 32
                and all(type(row) is PendingMutation for row in pending), "invalid_pending_inventory")
    common = dict(context=context, target=target, observation_sha256=observation.sha256,
                  valid_until=observation.observed_at + MAX_OBSERVATION_AGE)

    def result(action: str, reason: str, **selected) -> ProvisioningPlan:
        return ProvisioningPlan(**common, action=action, reason=reason, **selected)

    if any(row.account_ref == context.account_ref and row.unresolved for row in pending):
        return result("reconcile", "earlier_account_operation_unresolved")
    if not observation.available:
        return result("blocked", observation.reason)
    if target.app_id_prefix != target.team_id:
        return result("manual", "legacy_app_id_prefix_unsupported")
    api.require(all(type(row) is api.BundleId and row.identifier == target.bundle_id
                    for row in observation.bundles), "wrong_bundle_inventory")
    if len(observation.bundles) > 1:
        return result("blocked", "ambiguous_bundle_id")
    if observation.bundles:
        bundle = observation.bundles[0]
        if bundle.platform not in {"IOS", "UNIVERSAL"} or bundle.seed_id != target.app_id_prefix:
            return result("blocked", "bundle_identity_conflict")
        # Prefix is only comparison DATA, not proof of the selected Apple team
        # or of usable private keys, capabilities, profiles or signing readiness.
        return result("reuse_bundle_id", "reuse_existing_bundle_id", bundle=bundle)
    if target.existing_application:
        return result("blocked", "existing_application_identity_missing")
    return result("register_bundle_id", "new_application_registration_requires_approval",
                  request=api.register_bundle_id(target.bundle_id, target.display_name))
