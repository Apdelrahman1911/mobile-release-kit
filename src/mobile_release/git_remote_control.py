"""Bounded private HTTP control DATA for the same retained Git operation.

This is neither a credential clock nor permission to retire an operation. The
original native Connection applies it only after its genuine joined receipt.
The live HTTP owner still emits null expiry and refuses any expiry header.
"""
from __future__ import annotations

from ._desktop_github_engine import _check_control, REASONS
from . import _github_connection_transport as http


def empty():
    return http._control()


def checked(value):
    # Scalars only; do not retain a caller's mutable dictionary or extra keys.
    return dict(_check_control(value))


def refusal(original, reason):
    # Cleanup uncertainty is a separate absorbing outcome, not a made-up HTTP
    # control reason. Keep every known limit while that original remains held.
    if reason == "cleanup-unknown":
        return checked(original)
    if reason not in REASONS or reason == "none":
        reason = "response-invalid"
    return merge(original, http._refuse(checked(original), reason))


def merge(original, incoming):
    """Conservatively combine only the existing owner's finite grammar.

    Malformed new DATA cannot erase an already known not-before or expiry.
    A cooldown combined with another refusal uses the original response-invalid
    retirement path, never an invalid unauthorized+delay combination.
    """
    old = checked(original)
    try:
        new = checked(incoming)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        result = http._refuse(old, "response-invalid")
        result["credentialExpiresAt"] = old["credentialExpiresAt"]
        return checked(result)
    expiries = [v for v in (old["credentialExpiresAt"], new["credentialExpiresAt"]) if v is not None]
    blocked = old["cooldownBlocked"] or new["cooldownBlocked"]
    delays = [v for v in (old["cooldownSeconds"], new["cooldownSeconds"]) if v is not None]
    delay = None if blocked or not delays else max(delays)
    reasons = (old["reason"], new["reason"])
    if "response-invalid" in reasons:
        reason = "response-invalid"
    elif old["reason"] in http._FATAL or new["reason"] == "none":
        reason = old["reason"]
    elif old["reason"] == "none" or new["reason"] in http._FATAL:
        reason = new["reason"]
    else:
        reason = old["reason"]
    if (delay is not None or blocked) and any(v not in ("none", "rate-limited") for v in reasons):
        reason = "response-invalid"
    elif delay is not None or blocked:
        reason = "rate-limited"
    return checked({"reason": reason, "credentialExpiresAt": min(expiries) if expiries else None,
                    "cooldownSeconds": delay, "cooldownBlocked": blocked})
