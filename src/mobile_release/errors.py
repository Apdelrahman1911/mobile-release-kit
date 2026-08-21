from __future__ import annotations


class MobileReleaseError(Exception):
    """Base class for expected, safely reportable failures."""


class ConfigurationError(MobileReleaseError):
    """The project configuration is missing, malformed, or contradictory."""


class ValidationError(MobileReleaseError):
    """A release input or artifact did not satisfy a fail-closed invariant."""


class CredentialError(MobileReleaseError):
    """A credential declaration or private credential file is unsafe."""


class MutationGuardError(MobileReleaseError):
    """A Store mutation was requested outside an approved CI context."""


class StoreOperationError(MobileReleaseError):
    """A Store operation failed or did not produce verifiable readback."""
