"""Existing P12/public-leaf + exact App Store profile comparison in a fixed child.

No P12, password or private key enters this module. The credentials owner must
derive the leaf/chain/full-SPKI from its SAME current private P12 loan. This code
does real profile authentication and fixed Security calls; only the original
dedicated CredentialInspect parent can provide containment and finality.

Generic chain/codeSigning and exact authenticated profile authorization are
separate checks. Their conjunction applies ONLY to this existing profile and
application. It cannot create a standalone CertificateBinding, authorize a new
profile/certificate, save an assignment or mark a build/Store release ready.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import apple_provisioning_api as api
from .apple_provisioning import ProvisioningTarget
from .apple_provisioning_chain import _checkpoint, _inputs, _verify_leaf_chain_in_worker
from .cancellation import DefaultCancellation
from .inspection import InspectionDeadline

MAX_PROFILE_BYTES = 4 * 1024 * 1024


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExistingProfileComparison:
    """Private immutable-input comparison DATA, deliberately not an authority.

    No key reference, assessment/ready flag, provider action or serialization
    method. Original captured public bytes remain borrowed by identity for the
    native parent's final comparison. A Python object is never a native grant.
    """

    __slots__ = ("_target", "_leaf", "_profile", "_uuid", "_created_at", "_expires_at",
                 "_chain_checked_at", "_profile_checked_at")

    def __init__(self, target: ProvisioningTarget, leaf: bytes, profile: bytes, uuid: str,
                 created_at: datetime, expires_at: datetime, chain_checked_at: datetime,
                 profile_checked_at: datetime) -> None:
        self._target, self._leaf, self._profile, self._uuid = target, leaf, profile, uuid
        self._created_at, self._expires_at = created_at, expires_at
        self._chain_checked_at, self._profile_checked_at = chain_checked_at, profile_checked_at

    def __reduce_ex__(self, protocol):
        raise TypeError("existing profile comparison is private worker data")

    @property
    def target(self) -> ProvisioningTarget:
        return self._target

    @property
    def certificate_der(self) -> bytes:
        return self._leaf

    @property
    def profile_bytes(self) -> bytes:
        return self._profile

    @property
    def certificate_sha256(self) -> str:
        return hashlib.sha256(self._leaf).hexdigest()

    @property
    def profile_sha256(self) -> str:
        return hashlib.sha256(self._profile).hexdigest()

    @property
    def profile_uuid(self) -> str:
        return self._uuid

    @property
    def profile_created_at(self) -> datetime:
        return self._created_at

    @property
    def profile_expires_at(self) -> datetime:
        return self._expires_at

    @property
    def chain_checked_at(self) -> datetime:
        return self._chain_checked_at

    @property
    def profile_checked_at(self) -> datetime:
        return self._profile_checked_at


def _profile_comparison(target: ProvisioningTarget, leaf_der: bytes, payload: dict, *,
                        now: datetime, deadline: InspectionDeadline | None = None) -> tuple[str, datetime, datetime]:
    """Pure comparison AFTER actual authentication; does not issue a result."""
    from .ios import _ipa_profile_policy
    from .ios_entitlements import validate_profile_entitlements

    api.require(type(target) is ProvisioningTarget and type(leaf_der) is bytes and type(payload) is dict,
                "invalid_existing_profile")
    api.require(target.app_id_prefix == target.team_id, "legacy_app_id_prefix_unsupported")
    now = api.utc(now)
    uuid = payload.get("UUID")
    api.require(type(uuid) is str and api.UUID_RE.fullmatch(uuid) is not None
                and payload.get("ApplicationIdentifierPrefix") == [target.app_id_prefix]
                and payload.get("Platform") == ["iOS"], "existing_profile_identity_mismatch")
    certificates = payload.get("DeveloperCertificates")
    api.require(type(certificates) is list and len(certificates) == 1 and type(certificates[0]) is bytes
                and certificates[0] == leaf_der, "existing_profile_certificate_mismatch")

    def profile_date(value):
        api.require(type(value) is datetime, "existing_profile_date_mismatch")
        # The authenticated plist/DER decoder returns naive UTC dates. Arbitrary
        # strings, numeric timestamps and caller historical dates are not used.
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else api.utc(value)

    created, expires = (profile_date(payload.get(name)) for name in ("CreationDate", "ExpirationDate"))
    api.require(created <= now < expires, "existing_profile_not_current")
    try:
        # Same strict current policy as actual IPA inspection, including the
        # modern Team-ID prefix restriction. No enterprise/ad-hoc/development
        # or legacy-purpose fallback is introduced here.
        _ipa_profile_policy(payload, target.bundle_id, target.team_id)
        validate_profile_entitlements(target.entitlements(), payload.get("Entitlements", {}), deadline=deadline)
    except api.ValidationError:
        raise api.ProvisioningError("existing_profile_entitlements_mismatch") from None
    return uuid, created, expires


def _inspect_existing_profile_in_worker(target: ProvisioningTarget, leaf_der: bytes,
                                        intermediates: tuple[bytes, ...], profile_bytes: bytes, *,
                                        cancellation: DefaultCancellation,
                                        deadline: InspectionDeadline) -> ExistingProfileComparison:
    """PRIVATE dedicated-child operation, never a Desktop/main-thread API.

    The caller must be the original CredentialInspect child, not IOSArchive or
    Store. This module does not register that role or fabricate its currentness.
    No authenticated payload, proof callback, keyref, CSR or signing key input is
    accepted. All production authentication below uses the unchanged originals.
    """
    from ._lifetime_evidence import ProfileCallEvidence
    from ._profile_callers import consume_profile_evidence
    from .ios_profiles import decode_authenticated_profile

    api.require(type(target) is ProvisioningTarget, "invalid_existing_target")
    api.require(target.app_id_prefix == target.team_id, "legacy_app_id_prefix_unsupported")
    _inputs(leaf_der, intermediates)
    api.require(type(profile_bytes) is bytes and 0 < len(profile_bytes) <= MAX_PROFILE_BYTES,
                "invalid_existing_profile")
    _checkpoint(cancellation, deadline)
    evidence = ProfileCallEvidence(operation="decode")
    primary, payload = None, None
    try:
        payload = decode_authenticated_profile(profile_bytes, deadline=deadline,
                                               cancellation=cancellation, _evidence=evidence)
    except BaseException as error:
        primary = error
    # A result-shaped profile is not useful until both original CMS producers
    # and their actual resource/cancellation owners have settled. Preserve fatal
    # and first-interruption behavior from the unchanged caller adapter.
    consume_profile_evidence(evidence, primary=primary,
                             message="Existing Apple profile lifetime is unknown; end this inspection worker")
    if primary is not None:
        raise primary
    _checkpoint(cancellation, deadline)
    started_at = _utc_now()
    _profile_comparison(target, leaf_der, payload, now=started_at, deadline=deadline)
    chain_checked_at = _verify_leaf_chain_in_worker(leaf_der, intermediates,
                                                   cancellation=cancellation, deadline=deadline)
    _checkpoint(cancellation, deadline)
    current = _utc_now()
    api.require(type(chain_checked_at) is datetime and started_at <= api.utc(chain_checked_at) <= current,
                "existing_chain_clock_changed")
    uuid, created, expires = _profile_comparison(target, leaf_der, payload, now=current, deadline=deadline)
    result = ExistingProfileComparison(target, leaf_der, profile_bytes, uuid, created, expires,
                                       chain_checked_at, current)
    _checkpoint(cancellation, deadline)
    return result
