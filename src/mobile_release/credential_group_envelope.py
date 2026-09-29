"""Complete, versioned GitHub input groups; no file, tool or service access.

Decoded values stay private to the existing credential consumers. This module
only selects groups from the core requirements and validates supplied strings;
it never grants Store/build authority or validates native signing material.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Iterable, Mapping

from .credential_policy import credential_format_error, material_size_limit
from .credential_requirements import Requirement
from .errors import CredentialError

INPUT_GROUP_PROTOCOL = "mrk-github-input-group/1"
INPUT_GROUP_MAX_BYTES = 48_000


@dataclass(frozen=True)
class InputField:
    id: str
    name: str
    input: str

    @property
    def names(self) -> tuple[str, ...]:
        return (self.name, self.name.removesuffix("_BASE64") + "_PATH") if self.input == "file" else (self.name,)


@dataclass(frozen=True)
class InputGroup:
    kind: str
    secret_name: str
    fields: tuple[InputField, ...]

    @property
    def names(self) -> frozenset[str]:
        return frozenset(name for field in self.fields for name in field.names)


# These are explicit core associations, not renderer-provided secret names.
INPUT_GROUPS = (
    InputGroup("android-keystore", "MOBILE_RELEASE_INPUT_ANDROID_KEYSTORE_V1", (
        InputField("file", "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64", "file"),
        InputField("storePassword", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "secret"),
        InputField("keyAlias", "MOBILE_RELEASE_ANDROID_KEY_ALIAS", "text"),
        InputField("keyPassword", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD", "secret"),
    )),
    InputGroup("android-firebase", "MOBILE_RELEASE_INPUT_ANDROID_FIREBASE_V1", (
        InputField("file", "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64", "file"),
    )),
    InputGroup("apple-p12", "MOBILE_RELEASE_INPUT_APPLE_P12_V1", (
        InputField("file", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", "file"),
        InputField("password", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD", "secret"),
    )),
    InputGroup("apple-profile", "MOBILE_RELEASE_INPUT_APPLE_PROFILE_V1", (
        InputField("file", "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64", "file"),
    )),
    InputGroup("asc-p8", "MOBILE_RELEASE_INPUT_ASC_P8_V1", (
        InputField("file", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", "file"),
        InputField("keyId", "MOBILE_RELEASE_ASC_KEY_ID", "text"),
        InputField("issuerId", "MOBILE_RELEASE_ASC_ISSUER_ID", "text"),
    )),
    InputGroup("ios-firebase", "MOBILE_RELEASE_INPUT_IOS_FIREBASE_V1", (
        InputField("file", "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64", "file"),
    )),
    InputGroup("google-wif", "MOBILE_RELEASE_INPUT_GOOGLE_WIF_V1", (
        InputField("provider", "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", "text"),
        InputField("serviceAccount", "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT", "text"),
    )),
    InputGroup("project-read-token", "MOBILE_RELEASE_INPUT_PROJECT_READ_TOKEN_V1", (
        InputField("token", "MOBILE_RELEASE_PROJECT_READ_TOKEN", "secret"),
    )),
    InputGroup("apple-review-contact", "MOBILE_RELEASE_INPUT_APPLE_REVIEW_CONTACT_V1", (
        InputField("firstName", "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME", "secret"),
        InputField("lastName", "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME", "secret"),
        InputField("email", "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL", "secret"),
        InputField("phone", "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE", "secret"),
    )),
    InputGroup("apple-review-demo-account", "MOBILE_RELEASE_INPUT_APPLE_REVIEW_DEMO_ACCOUNT_V1", (
        InputField("username", "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME", "secret"),
        InputField("password", "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD", "secret"),
    )),
    InputGroup("apple-operation-commitment", "MOBILE_RELEASE_INPUT_APPLE_OPERATION_COMMITMENT_V1", (
        InputField("keyBase64", "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64", "secret"),
        InputField("keyVersion", "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION", "text"),
    )),
)
INPUT_GROUP_ENVIRONMENT_NAMES = frozenset(group.secret_name for group in INPUT_GROUPS)


def input_group(kind: str) -> InputGroup:
    for group in INPUT_GROUPS:
        if group.kind == kind:
            return group
    raise CredentialError("Unknown GitHub input group")


def groups_for_requirements(required: Iterable[Requirement]) -> tuple[InputGroup, ...]:
    names = {item.name for item in required}
    selected = []
    for group in INPUT_GROUPS:
        fields = {field.name for field in group.fields}
        if fields & names:
            if not fields <= names:
                raise CredentialError("Core requirements selected an incomplete GitHub input group")
            selected.append(group)
    return tuple(selected)


def _observe_input_environment(environ: Mapping[str, str], names: Iterable[str]) -> dict[str, str]:
    """Observe each fixed selected key once; never enumerate ambient values."""
    observed = {}
    for name in sorted(set(names)):
        try:
            observed[name] = environ[name]
        except KeyError:
            pass
    return observed


def envelope_present(environ: Mapping[str, str], group: InputGroup) -> bool:
    # GitHub expands an absent secret to ""; it is the only empty fallback.
    try:
        return environ[group.secret_name] != ""
    except KeyError:
        return False

def _invalid(group: InputGroup, detail: str) -> CredentialError:
    # Only fixed core names and fixed explanations, never submitted values.
    return CredentialError(f"GitHub input group {group.kind}: {detail}")


def validate_input_field(group: InputGroup, field: InputField, value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _invalid(group, f"{field.id} must be nonempty text without NUL")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise _invalid(group, f"{field.id} must be valid UTF-8") from None
    if field.name.endswith("_BASE64"):
        if len(value) > ((material_size_limit(field.name) + 2) // 3) * 4:
            raise _invalid(group, f"{field.id} exceeds the material size limit")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise _invalid(group, f"{field.id} must be canonical Base64") from None
        if not decoded or len(decoded) > material_size_limit(field.name) or base64.b64encode(decoded).decode("ascii") != value:
            raise _invalid(group, f"{field.id} must be bounded, nonempty canonical Base64")
    if credential_format_error(field.name, value):
        raise _invalid(group, f"{field.id} has an invalid format")
    return value


def _validated_values(group: InputGroup, values: object) -> dict[str, str]:
    if type(values) is not dict or set(values) != {field.id for field in group.fields}:
        raise _invalid(group, "values must contain exactly every field in this group")
    return {field.name: validate_input_field(group, field, values[field.id]) for field in group.fields}


def _envelope_bytes(group: InputGroup, value: object) -> bytes:
    if type(value) is not str:
        raise _invalid(group, "the envelope must be UTF-8 JSON text")
    if len(value) > INPUT_GROUP_MAX_BYTES:
        raise _invalid(group, "the encoded envelope must be at most 48000 bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise _invalid(group, "the envelope must be valid UTF-8") from None
    if not encoded or len(encoded) > INPUT_GROUP_MAX_BYTES:
        raise _invalid(group, "the encoded envelope must be at most 48000 bytes")
    return encoded


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate input-group field")
        result[name] = value
    return result


def _no_constant(_value):
    raise ValueError("non-JSON input-group constant")


def decode_group_envelope(kind: str, value: str) -> dict[str, str]:
    group = input_group(kind)
    encoded = _envelope_bytes(group, value)
    try:
        envelope = json.loads(encoded, object_pairs_hook=_unique_object, parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _invalid(group, "malformed or duplicate JSON fields") from None
    if (type(envelope) is not dict or set(envelope) != {"protocol", "kind", "values"}
            or envelope["protocol"] != INPUT_GROUP_PROTOCOL or envelope["kind"] != group.kind):
        raise _invalid(group, "expected the exact protocol, kind and values envelope")
    return _validated_values(group, envelope["values"])


def encode_group_envelope(kind: str, values: Mapping[str, str]) -> bytes:
    """Encode complete guide field IDs for a private, bounded encryption loan.

    This is not a CLI/output operation. The native owner still has to qualify
    the exact toolkit/caller, selection and original private record before use.
    """
    group = input_group(kind)
    supplied = dict(values)
    if sum(len(value) for value in supplied.values() if type(value) is str) > INPUT_GROUP_MAX_BYTES:
        raise _invalid(group, "the encoded envelope must be at most 48000 bytes")
    canonical = _validated_values(group, supplied)
    envelope = {"protocol": INPUT_GROUP_PROTOCOL, "kind": kind,
                "values": {field.id: canonical[field.name] for field in group.fields}}
    return _envelope_bytes(group, json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))


def group_mask_commands(group: InputGroup, values: Mapping[str, str]) -> tuple[str, ...]:
    """Return GitHub's single-line commands for private scalar/Base64 values.

    Public WIF identifiers must remain usable as action outputs. This does not
    persist values or claim to wipe Python's immutable string allocations.
    """
    commands = []
    for field in group.fields:
        if field.input == "text":
            continue
        for name in field.names:
            value = values.get(name)
            if value:
                escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                commands.append("::add-mask::" + escaped)
    return tuple(commands)


def google_wif_inputs(environ: Mapping[str, str]) -> dict[str, str]:
    """The fixed pre-auth consumer: exactly one validated public pair."""
    group = input_group("google-wif")
    observed = _observe_input_environment(environ, (group.secret_name, *(field.name for field in group.fields)))
    if envelope_present(observed, group):
        values = decode_group_envelope(group.kind, observed[group.secret_name])
    else:
        values = _validated_values(group, {field.id: observed.get(field.name, "") for field in group.fields})
    return {"provider": values["MOBILE_RELEASE_GOOGLE_WIF_PROVIDER"],
            "service_account": values["MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT"]}
