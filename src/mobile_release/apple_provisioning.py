"""Reuse-first Apple signing preparation, separate from Store release execution.

These are internal application-service contracts. The registered native owner
supplies account authorization, current credential loans, account-wide mutation
coordination, durable pending-operation history and actual transport finality.
None of these dataclasses is an IPC authorization token. There is deliberately
no ambient authentication, key generation, assignment, install, revocation,
release upload or automatically enabled provider route here.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from . import apple_provisioning_api as api
from .apple_provisioning_api import ProvisioningError

MAX_OBSERVATION_AGE = timedelta(minutes=5)
SIGNING_SCOPE = "signing-resources"
BUNDLE_ID_SCOPE = "bundle-identifiers"
_NATIVE_ID = re.compile(r"[0-9a-f]{32}\Z")
_BASE_ENTITLEMENTS = frozenset({"application-identifier", "com.apple.developer.team-identifier",
                              "get-task-allow", "beta-reports-active", "keychain-access-groups"})


@dataclass(frozen=True, repr=False)
class NativeKeyRef:
    """Exact existing vault identity, agreed with the credentials lane.

    Generation/revision IDs are random IDs, NOT revision counters. Full equality
    matters across restart. This reference does not dereference or grant key use.
    An ASC P8 API-key record cannot stand in for an Apple signing private key.
    """

    vault_id: str
    generation_id: str
    record_id: str
    revision_id: str
    revision_counter: int

    def __post_init__(self) -> None:
        identifiers = (self.vault_id, self.generation_id, self.record_id, self.revision_id)
        api.require(all(type(value) is str and _NATIVE_ID.fullmatch(value) is not None
                        and value != "0" * 32 for value in identifiers)
                    and len(set(identifiers)) == 4
                    and type(self.revision_counter) is int and 1 <= self.revision_counter <= 0xFFFFFFFF,
                    "invalid_native_key_reference")


@dataclass(frozen=True, repr=False)
class PublicCSR:
    key_ref: NativeKeyRef
    csr_pem: bytes = field(repr=False)
    public_key_sha256: str

    def __post_init__(self) -> None:
        api.require(type(self.key_ref) is NativeKeyRef and type(self.public_key_sha256) is str
                    and api.HEX_RE.fullmatch(self.public_key_sha256) is not None, "invalid_public_csr")
        api.create_certificate(self.csr_pem)


@dataclass(frozen=True, repr=False)
class ProvisioningContext:
    project_id: str
    client_id: str
    operation_id: str
    observation_revision: int
    account_ref: str
    credential_record_id: str
    credential_revision: int
    credential_context_revision: int

    def __post_init__(self) -> None:
        for value in (self.project_id, self.client_id, self.operation_id, self.account_ref, self.credential_record_id):
            api.identifier(value)
        api.require(all(type(value) is int and 1 <= value <= 0xFFFFFFFF for value in (
            self.observation_revision, self.credential_revision, self.credential_context_revision)), "invalid_context")


@dataclass(frozen=True, repr=False)
class ProvisioningTarget:
    bundle_id: str
    team_id: str
    app_id_prefix: str
    display_name: str
    existing_application: bool = True
    # Immutable bounded JSON rather than a mutable graph surviving approval.
    entitlements_json: bytes = field(default=b"{}", repr=False)

    def __post_init__(self) -> None:
        api.list_bundle_ids(self.bundle_id)
        api.register_bundle_id(self.bundle_id, self.display_name)
        api.require(type(self.team_id) is str and api.TEAM_RE.fullmatch(self.team_id) is not None
                    and type(self.app_id_prefix) is str and api.TEAM_RE.fullmatch(self.app_id_prefix) is not None
                    and type(self.existing_application) is bool, "invalid_target")
        api.require(type(self.entitlements_json) is bytes and 0 < len(self.entitlements_json) <= 16 * 1024,
                    "invalid_entitlements")
        claims = api.document(self.entitlements_json)
        object.__setattr__(self, "entitlements_json", api.canonical(claims))
        # Call the existing typed entitlement policy; even local draft claims
        # may not contradict the selected project/team or enable debugging.
        required = self.entitlements()
        for key, value in self.base_entitlements().items():
            if key in claims:
                api.require(type(claims[key]) is type(value) and claims[key] == value, "conflicting_entitlements")
        from .ios_entitlements import validate_profile_entitlements
        try:
            validate_profile_entitlements(required, required)
        except api.ValidationError:
            raise ProvisioningError("unsupported_entitlements") from None

    def base_entitlements(self) -> dict:
        return {"application-identifier": self.app_id_prefix + "." + self.bundle_id,
                "com.apple.developer.team-identifier": self.team_id,
                "get-task-allow": False, "beta-reports-active": True}

    def entitlements(self) -> dict:
        return {**json.loads(self.entitlements_json), **self.base_entitlements()}


class ProvisioningProvider(Protocol):
    """Original selected-account owner, not a caller-supplied endpoint/token."""

    def check(self, context: ProvisioningContext) -> None: ...
    def send(self, request: api.AppleRequest) -> api.AppleResponse: ...


@dataclass(frozen=True, repr=False)
class Observation:
    context: ProvisioningContext
    bundle_id: str
    observed_at: datetime
    available: bool
    reason: str
    bundles: tuple[api.BundleId, ...] = ()
    certificates: tuple[api.Certificate, ...] = ()
    profiles: tuple[api.Profile, ...] = ()
    scope: str = SIGNING_SCOPE

    def __post_init__(self) -> None:
        api.require(type(self.scope) is str and self.scope in {SIGNING_SCOPE, BUNDLE_ID_SCOPE},
                    "invalid_observation_scope")
        # A Bundle-ID-only read says NOTHING about certificates or profiles.
        # Empty defaults cannot be mistaken for a complete signing inventory.
        if self.scope == BUNDLE_ID_SCOPE:
            api.require(self.certificates == () and self.profiles == (), "invalid_observation_scope")

    @property
    def sha256(self) -> str:
        def when(value: datetime) -> str:
            return api.utc(value).isoformat()
        return api.digest(api.canonical({
            "context": asdict(self.context), "bundleId": self.bundle_id, "scope": self.scope,
            "available": self.available, "reason": self.reason,
            "bundles": sorted((b.resource_id, b.identifier, b.platform, b.seed_id) for b in self.bundles),
            "certificates": sorted((c.resource_id, c.certificate_type, when(c.expires_at), api.digest(c.content))
                                   for c in self.certificates),
            "profiles": sorted((p.resource_id, p.name, p.uuid, p.state, when(p.created_at), when(p.expires_at),
                                p.bundle_id_resource, p.certificate_resources) for p in self.profiles),
        }))

    def summary(self) -> dict:
        return {"scope": self.scope, "available": self.available, "reason": self.reason,
                "bundleCount": len(self.bundles), "certificateCount": len(self.certificates),
                "profileCount": len(self.profiles), "credentialReady": False}


def observe(context: ProvisioningContext, target: ProvisioningTarget, provider: ProvisioningProvider,
            *, now: datetime) -> Observation:
    """Read only; permission errors/incomplete pages cannot become absence."""
    now = api.utc(now)

    def read(request: api.AppleRequest) -> api.AppleResponse:
        provider.check(context)
        response = provider.send(request)
        provider.check(context)
        return response

    try:
        bundles = tuple(api.BundleId.parse(value) for value in api.collect(api.list_bundle_ids(target.bundle_id), read))
        api.require(all(b.identifier == target.bundle_id for b in bundles), "wrong_bundle_inventory")
        certificates = tuple(api.Certificate.parse(value) for value in api.collect(api.list_certificates(), read))
        profiles = tuple(api.Profile.parse(value) for value in api.collect(api.list_profiles(), read,
            inspect_page=lambda page: api.validate_profile_included(page, bundles, certificates, bundle_id=target.bundle_id)))
        return Observation(context, target.bundle_id, now, True, "observed", bundles, certificates, profiles)
    except ProvisioningError as error:
        return Observation(context, target.bundle_id, now, False, error.code)
    except Exception:
        # The provider exception might contain private URLs/body/account data.
        return Observation(context, target.bundle_id, now, False, "provider_read_unavailable")


@dataclass(frozen=True, repr=False)
class CertificateBinding:
    """Trusted native certificate/key inspection, never accepted from JSON.

    The native owner checks current key custody, certificate signature/purpose,
    Team ID and public-key equality. We additionally bind its result to the
    exact returned certificate bytes, selected context and current validity.
    """

    certificate_id: str
    certificate_sha256: str
    public_key_sha256: str
    key_ref: NativeKeyRef
    team_id: str
    not_before: datetime
    not_after: datetime

    def matches(self, certificate: api.Certificate, target: ProvisioningTarget, now: datetime) -> bool:
        api.require(type(self.key_ref) is NativeKeyRef and self.team_id == target.team_id
                    and self.certificate_id == certificate.resource_id
                    and self.certificate_sha256 == api.digest(certificate.content)
                    and type(self.public_key_sha256) is str and api.HEX_RE.fullmatch(self.public_key_sha256) is not None
                    and api.utc(self.not_before) < api.utc(self.not_after)
                    and api.utc(self.not_after) == certificate.expires_at, "native_certificate_mismatch")
        return api.utc(self.not_before) <= now < api.utc(self.not_after)


@dataclass(frozen=True, repr=False)
class PendingMutation:
    """Loaded by the durable owner; account-wide certificate uncertainty wins."""

    account_ref: str
    operation_id: str
    kind: str
    status: str
    # The actual durable owner supplies this separate axis after its original
    # parent joins. A helper's succeeded/failed status alone never frees an
    # account, and a restored record does not recreate those original joins.
    native_settlement: str = "unknown"

    def __post_init__(self) -> None:
        api.require(type(self.native_settlement) is str
                    and self.native_settlement in {"pending", "known", "unknown"},
                    "invalid_pending_settlement")

    @property
    def unresolved(self) -> bool:
        return self.native_settlement != "known" or self.status not in {"succeeded", "failed", "cancelled"}


@dataclass(frozen=True, repr=False)
class ProvisioningPlan:
    context: ProvisioningContext
    target: ProvisioningTarget
    observation_sha256: str
    valid_until: datetime
    action: str
    reason: str
    request: api.AppleRequest | None = field(default=None, repr=False)
    bundle: api.BundleId | None = field(default=None, repr=False)
    certificate: api.Certificate | None = field(default=None, repr=False)
    binding: CertificateBinding | None = field(default=None, repr=False)
    profile: api.Profile | None = field(default=None, repr=False)
    csr: PublicCSR | None = field(default=None, repr=False)

    @property
    def sha256(self) -> str:
        request = self.request
        binding = None if self.binding is None else {
            **asdict(self.binding), "not_before": self.binding.not_before.isoformat(),
            "not_after": self.binding.not_after.isoformat(),
        }
        return api.digest(api.canonical({
            "context": asdict(self.context),
            "target": {**asdict(self.target), "entitlements_json": api.digest(self.target.entitlements_json)},
            "observation": self.observation_sha256, "validUntil": self.valid_until.isoformat(),
            "action": self.action, "reason": self.reason,
            "request": None if request is None else {
                "kind": request.kind, "method": request.method, "path": request.path, "query": request.query,
                "bodySha256": None if request.body is None else api.digest(request.body),
            },
            "binding": binding,
            "selection": {name: None if value is None else api.resource_sha256(value) for name, value in (
                ("bundle", self.bundle), ("certificate", self.certificate), ("profile", self.profile))},
            "csr": None if self.csr is None else {"keyRef": asdict(self.csr.key_ref),
                    "publicKeySha256": self.csr.public_key_sha256, "csrSha256": api.digest(self.csr.csr_pem)},
        }))

    def summary(self) -> dict:
        return {"action": self.action, "reason": self.reason,
                "approvalRequired": self.request is not None and self.request.method == "POST",
                "credentialReady": False}


def prepare(context: ProvisioningContext, target: ProvisioningTarget, observation: Observation, *,
            bindings: tuple[CertificateBinding, ...], csr: PublicCSR | None,
            pending: tuple[PendingMutation, ...], now: datetime,
            selected_key: NativeKeyRef | None = None, selected_profile: str | None = None) -> ProvisioningPlan:
    """Prepare one next action, not blanket consent for a chain of creations.

    ``pending`` must be the owner's complete account-wide durable inventory.
    An empty tuple supplied by an untrusted caller is not authorization. The
    account lease/owner remains responsible for cross-client admission.
    """
    now = api.utc(now)
    api.require(type(observation) is Observation and observation.scope == SIGNING_SCOPE,
                "observation_scope_changed")
    api.require(observation.context == context and observation.bundle_id == target.bundle_id,
                "observation_context_changed")
    api.require(observation.observed_at <= now < observation.observed_at + MAX_OBSERVATION_AGE,
                "observation_expired")
    common = dict(context=context, target=target, observation_sha256=observation.sha256,
                  valid_until=observation.observed_at + MAX_OBSERVATION_AGE)

    def result(action: str, reason: str, **kwargs) -> ProvisioningPlan:
        return ProvisioningPlan(**common, action=action, reason=reason, **kwargs)

    if any(p.account_ref == context.account_ref and p.unresolved for p in pending):
        return result("reconcile", "earlier_account_operation_unresolved")
    if not observation.available:
        return result("blocked", observation.reason)
    if target.app_id_prefix != target.team_id:
        # Keep the two observations separate. Current ios._ipa_profile_policy
        # intentionally does not support legacy prefixes; do not claim support
        # here that the actual signing owner would later reject.
        return result("manual", "legacy_app_id_prefix_unsupported")
    bundles = [b for b in observation.bundles if b.identifier == target.bundle_id]
    if len(bundles) > 1:
        return result("blocked", "ambiguous_bundle_id")
    bundle = bundles[0] if bundles else None
    if bundle is not None and (bundle.platform not in {"IOS", "UNIVERSAL"} or bundle.seed_id != target.app_id_prefix):
        return result("blocked", "bundle_identity_conflict")
    if bundle is None and target.existing_application:
        return result("blocked", "existing_application_identity_missing")

    certificates = {c.resource_id: c for c in observation.certificates}
    api.require(len({b.certificate_id for b in bindings}) == len(bindings), "ambiguous_native_binding")
    available = []
    for binding in bindings:
        api.require(binding.certificate_id in certificates, "native_certificate_not_observed")
        certificate = certificates[binding.certificate_id]
        if binding.matches(certificate, target, now) and (selected_key is None or binding.key_ref == selected_key):
            available.append((certificate, binding))
    if len(available) > 1:
        return result("select_existing_certificate", "multiple_owned_certificates")
    certificate, binding = available[0] if available else (None, None)
    if certificate is None and any(c.expires_at > now for c in observation.certificates):
        # We cannot know quota from a local count; existing identities with an
        # unknown/lost key require recovery/selection, never automatic issuance.
        return result("recover_existing_key", "existing_certificate_key_unavailable")

    profiles = [p for p in observation.profiles if bundle is not None and certificate is not None
                and p.bundle_id_resource == bundle.resource_id and p.certificate_resources == (certificate.resource_id,)
                and p.state == "ACTIVE" and p.created_at <= now < p.expires_at]
    if selected_profile is not None:
        profiles = [p for p in profiles if p.resource_id == selected_profile]
        if not profiles:
            return result("blocked", "selected_profile_unavailable")
    if len(profiles) > 1:
        return result("select_existing_profile", "multiple_compatible_profiles")
    if profiles:
        profile = profiles[0]
        return result("download_profile", "reuse_existing_assets", request=api.download_profile(profile.resource_id),
                      bundle=bundle, certificate=certificate, binding=binding, profile=profile)

    claims = target.entitlements()
    groups = claims.get("keychain-access-groups")
    if (set(claims) - _BASE_ENTITLEMENTS
            or groups is not None and groups != [target.app_id_prefix + "." + target.bundle_id]):
        # Enabling capabilities/device registration/agreements is intentionally
        # not in this closed provider role. Nondefault keychain groups likewise
        # need explicit capability review. Existing valid profiles can be reused.
        return result("manual", "capability_setup_required")
    if bundle is None:
        return result("register_bundle_id", "new_application_registration_requires_approval",
                      request=api.register_bundle_id(target.bundle_id, target.display_name))
    if certificate is None:
        if csr is None:
            return result("prepare_csr", "native_signing_key_and_csr_required", bundle=bundle)
        api.require(selected_key is None or csr.key_ref == selected_key, "native_key_selection_changed")
        return result("create_certificate", "certificate_issuance_requires_approval",
                      request=api.create_certificate(csr.csr_pem), bundle=bundle, csr=csr)
    # Stable name helps narrow readback but does NOT confer idempotency or sole
    # attribution. Unknown sends never become retryable merely by name absence.
    name = "MRK-" + api.digest(context.operation_id.encode("utf-8"))[:24]
    return result("create_profile", "profile_creation_requires_approval",
                  request=api.create_profile(name, bundle.resource_id, certificate.resource_id),
                  bundle=bundle, certificate=certificate, binding=binding)


def validate_download(plan: ProvisioningPlan, response: api.AppleResponse, *, now: datetime) -> api.Profile:
    """Validate resource identity/bytes only; still NOT an authenticated profile."""
    api.require(plan.action == "download_profile" and plan.profile is not None
                and plan.bundle is not None and plan.binding is not None and plan.certificate is not None,
                "invalid_profile_plan")
    profile = api.Profile.parse(api.single(response, "profiles", inspect_page=lambda page:
        api.validate_profile_included(page, (plan.bundle,), (plan.certificate,), bundle_id=plan.target.bundle_id)),
        require_content=True)
    api.require(profile.resource_id == plan.profile.resource_id and profile.uuid == plan.profile.uuid
                and profile.bundle_id_resource == plan.profile.bundle_id_resource
                and profile.certificate_resources == plan.profile.certificate_resources
                and profile.created_at == plan.profile.created_at and profile.expires_at == plan.profile.expires_at
                and profile.name == plan.profile.name and profile.state == "ACTIVE"
                and profile.created_at <= api.utc(now) < profile.expires_at, "profile_readback_changed")
    api.require(plan.binding.matches(plan.certificate, plan.target, api.utc(now)), "certificate_expired")
    return profile


def validate_profile_claims(plan: ProvisioningPlan, profile: api.Profile, payload: dict, *, now: datetime,
                            deadline=None) -> None:
    """Pure policy comparison AFTER authentication, never authentication itself.

    Public for focused synthetic tests. No result/certificate assignment token is
    issued here. Use authenticate_downloaded_profile for the actual two-CMS and
    original-producer finality path; native credentials own the eventual sink.
    """
    from .ios import _ipa_profile_policy
    from .ios_entitlements import validate_profile_entitlements
    api.require(plan.binding is not None and plan.certificate is not None and profile.content is not None,
                "profile_validation_pending")
    now = api.utc(now)
    api.require(plan.binding.matches(plan.certificate, plan.target, now), "certificate_expired")
    api.require(type(payload) is dict and payload.get("UUID") == profile.uuid
                and payload.get("ApplicationIdentifierPrefix") == [plan.target.app_id_prefix]
                and payload.get("Platform") == ["iOS"]
                and profile.created_at <= now < profile.expires_at, "profile_identity_mismatch")
    def profile_time(value: object) -> datetime:
        api.require(type(value) is datetime, "profile_identity_mismatch")
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else api.utc(value)
    api.require(profile_time(payload.get("CreationDate")) == profile.created_at
                and profile_time(payload.get("ExpirationDate")) == profile.expires_at, "profile_identity_mismatch")
    certificates = payload.get("DeveloperCertificates")
    api.require(type(certificates) is list and len(certificates) == 1 and type(certificates[0]) is bytes
                and api.digest(certificates[0]) == plan.binding.certificate_sha256, "profile_certificate_mismatch")
    try:
        _ipa_profile_policy(payload, plan.target.bundle_id, plan.target.team_id)
        validate_profile_entitlements(plan.target.entitlements(), payload.get("Entitlements", {}), deadline=deadline)
    except api.ValidationError:
        raise ProvisioningError("profile_entitlements_mismatch") from None


@dataclass(frozen=True, repr=False)
class AuthenticatedProfile:
    """Private native-sink input; not a public readiness or assignment decision."""

    profile: api.Profile
    key_ref: NativeKeyRef
    certificate_sha256: str


def authenticate_downloaded_profile(plan: ProvisioningPlan, response: api.AppleResponse, *,
                                    cancellation, now: datetime, deadline=None) -> AuthenticatedProfile:
    """Actual existing macOS CMS/finality boundary; no decode-only fallback.

    The actual credentials owner must retain the same current key loan and
    context, consume this private result, and perform its own assignment policy.
    This function does not install or write a profile and is not Linux-qualified.
    """
    from ._lifetime_evidence import ProfileCallEvidence
    from ._profile_callers import consume_profile_evidence
    from .inspection import InspectionDeadline
    from .ios_profiles import decode_authenticated_profile
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    cancellation.check()
    profile = validate_download(plan, response, now=now)
    evidence = ProfileCallEvidence(operation="decode")
    primary, payload = None, None
    try:
        payload = decode_authenticated_profile(profile.content, cancellation=cancellation,
                                               deadline=deadline, _evidence=evidence)
    except BaseException as error:
        primary = error
    consume_profile_evidence(evidence, primary=primary,
                             message="Apple provisioning profile lifetime is unconfirmed; preserve the operation")
    if primary is not None:
        raise primary
    deadline.check()
    cancellation.check()
    # Native authentication can outlive a profile/certificate's last seconds.
    # Recheck actual current time, not only the pre-call observation timestamp.
    validate_profile_claims(plan, profile, payload, now=datetime.now(timezone.utc), deadline=deadline)
    return AuthenticatedProfile(profile, plan.binding.key_ref, plan.binding.certificate_sha256)
