from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from sys import exc_info
from typing import Any, Iterable, Mapping

from .cancellation import CleanupScope as _ProfileCleanup, DefaultCancellation as _ProfileCancellation
from .config import ConfigurationError, ReleaseConfig
from .errors import CredentialError, ValidationError
from .reporting import Finding, Status
from .tooling import canonical_external_path

STAGES = ("candidate", "external-testing", "production")
ENVIRONMENT_NAMES = {
    "candidate": "mobile-candidate",
    "external-testing": "mobile-external-testing",
    "production": "mobile-production",
}
MAX_PRIVATE_MATERIAL_SIZE = 32 * 1024 * 1024
SMALL_PRIVATE_MATERIAL_SIZE = 4 * 1024 * 1024
PROFILE_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
ALLOWED_CREDENTIAL_NAMES = {
    "GOOGLE_APPLICATION_CREDENTIALS",
    "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
    "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
    "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
    "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
    "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE",
    "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
    "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION",
    "MOBILE_RELEASE_ASC_ISSUER_ID",
    "MOBILE_RELEASE_ASC_KEY_ID",
    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
    "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT",
    "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER",
    "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
    "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",
    "MOBILE_RELEASE_PROJECT_READ_TOKEN",
}
CREDENTIAL_ENVIRONMENT_NAMES = ALLOWED_CREDENTIAL_NAMES | {
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "GH_TOKEN",
    "GOOGLE_GHA_CREDS_PATH",
    "GITHUB_TOKEN",
}
_CREDENTIAL_CAPABILITY_PREFIXES = (
    "ACTIONS_ID_TOKEN_",
    "APP_STORE_",
    "ARM_",
    "ASC_",
    "AWS_",
    "AZURE_",
    "CLOUDSDK_",
    "FASTLANE_",
    "GCLOUD_",
    "GH_",
    "GOOGLE_",
    "MATCH_",
    "OIDC_",
    "PLAY_",
    "SUPPLY_",
)
_CREDENTIAL_CAPABILITY_COMPONENT_RE = re.compile(
    r"(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH_SOCK|CREDENTIALS?|PASSWORD|PASSPHRASE|"
    r"PRIVATE_KEY|SECRET|SESSION_TOKEN|TOKEN)(?:_|$)"
)
ARTIFACT_VALIDATION_ENVIRONMENT_NAMES = frozenset(
    {
        "CI",
        "DEVELOPER_DIR",
        "HOME",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "RUNNER_TEMP",
        "SDKROOT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
    }
)
PRIVATE_CREDENTIAL_PATH_NAMES = {
    name for name in ALLOWED_CREDENTIAL_NAMES if name.endswith("_PATH")
}
CREDENTIAL_MATERIAL_GROUPS = (
    frozenset(
        {
            "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
        }
    ),
    frozenset(
        {
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
        }
    ),
    frozenset(
        {
            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
        }
    ),
    frozenset(
        {
            "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
            "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
        }
    ),
    frozenset(
        {
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
        }
    ),
    frozenset(
        {
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",
        }
    ),
)


def is_credential_capability_name(name: str) -> bool:
    """Return whether an environment name can grant external account authority.

    The explicit release contract is supplemented with common CI/OIDC/cloud
    families so application-owned checks and local artifact tools cannot inherit
    an unrelated ambient credential under a name the shared tool does not use.
    """

    return (
        name in CREDENTIAL_ENVIRONMENT_NAMES
        or name.startswith(_CREDENTIAL_CAPABILITY_PREFIXES)
        or _CREDENTIAL_CAPABILITY_COMPONENT_RE.search(name) is not None
    )


def scrub_credential_capabilities(environ: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment without Store, cloud, OIDC, or secret capabilities."""

    return {
        name: value
        for name, value in environ.items()
        if not is_credential_capability_name(name)
    }


def artifact_validation_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """Return a minimal non-authoritative environment for binary inspection tools."""

    scrubbed = scrub_credential_capabilities(environ)
    result = {
        name: scrubbed[name]
        for name in ARTIFACT_VALIDATION_ENVIRONMENT_NAMES
        if scrubbed.get(name)
    }
    result.update({"LANG": "C", "LC_ALL": "C"})
    return result


@dataclass(frozen=True)
class Requirement:
    name: str
    kind: str  # secret, variable, file, or manual
    stage: str
    platform: str
    alternatives: tuple[str, ...] = ()
    reason: str = ""


def requirements(
    config: ReleaseConfig,
    stage: str = "all",
    *,
    purpose: str = "full",
    platforms: Iterable[str] | None = None,
) -> list[Requirement]:
    if stage != "all" and stage not in STAGES:
        raise CredentialError(f"unknown credential stage: {stage}")
    if purpose not in {"full", "signing", "store"}:
        raise CredentialError(f"unknown credential purpose: {purpose}")
    stages = STAGES if stage == "all" else (stage,)
    selected = set(platforms if platforms is not None else config.enabled_platforms)
    values: list[Requirement] = []
    for current in stages:
        if config.platform_enabled("android") and "android" in selected:
            if current == "candidate" and purpose in {"full", "signing"}:
                values.extend(
                    [
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
                            "secret",
                            current,
                            "android",
                            alternatives=("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",),
                            reason="Android release signing key",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                            "secret",
                            current,
                            "android",
                            reason="Android keystore password",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                            "variable",
                            current,
                            "android",
                            reason="Android private-key alias",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
                            "secret",
                            current,
                            "android",
                            reason="Android private-key password",
                        ),
                    ]
                )
                if config.section("services").get("androidFirebase") == "required":
                    values.append(
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
                            "secret",
                            current,
                            "android",
                            alternatives=("MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",),
                            reason="Android Firebase client configuration",
                        )
                    )
            if purpose in {"full", "store"}:
                values.extend(_google_requirements(current))

        if config.platform_enabled("ios") and "ios" in selected:
            if current == "candidate" and purpose in {"full", "signing"}:
                values.extend(
                    [
                        Requirement(
                            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
                            "secret",
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",),
                            reason="Apple distribution certificate and private key",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
                            "secret",
                            current,
                            "ios",
                            reason="Apple P12 password",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
                            "secret",
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",),
                            reason="App Store provisioning profile",
                        ),
                    ]
                )
                if config.section("services").get("iosFirebase") == "required":
                    values.append(
                        Requirement(
                            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
                            "secret",
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",),
                            reason="iOS Firebase client configuration",
                        )
                    )
            if purpose in {"full", "store"}:
                values.extend(_apple_api_requirements(current))
            if purpose in {"full", "store"} and current in {"external-testing", "production"}:
                values.extend(_apple_review_requirements(current, config))

        if (
            current == "candidate"
            and purpose in {"full", "signing"}
            and config.section("source").get("projectReadTokenRequired")
        ):
            values.append(
                Requirement(
                    "MOBILE_RELEASE_PROJECT_READ_TOKEN",
                    "secret",
                    current,
                    "project",
                    reason="Read-only project dependency access",
                )
            )
    return values


def _google_requirements(stage: str) -> list[Requirement]:
    return [
        Requirement(
            "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER",
            "variable",
            stage,
            "android",
            reason="Google Workload Identity provider",
        ),
        Requirement(
            "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT",
            "variable",
            stage,
            "android",
            reason="Least-privileged Google service-account email",
        ),
    ]


def _apple_api_requirements(stage: str) -> list[Requirement]:
    return [
        Requirement(
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
            "secret",
            stage,
            "ios",
            alternatives=("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",),
            reason="App Store Connect API private key",
        ),
        Requirement(
            "MOBILE_RELEASE_ASC_KEY_ID",
            "variable",
            stage,
            "ios",
            reason="App Store Connect API key ID",
        ),
        Requirement(
            "MOBILE_RELEASE_ASC_ISSUER_ID",
            "variable",
            stage,
            "ios",
            reason="App Store Connect API issuer ID",
        ),
    ]


def _apple_review_requirements(stage: str, config: ReleaseConfig) -> list[Requirement]:
    requirements = [
        Requirement(
            name,
            "secret",
            stage,
            "ios",
            reason="Private App Review contact information",
        )
        for name in (
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE",
        )
    ]
    requirements.extend(
        [
            Requirement(
                "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
                "secret",
                stage,
                "ios",
                reason="HMAC key binding private Apple review state to recoverable operations",
            ),
            Requirement(
                "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION",
                "variable",
                stage,
                "ios",
                reason="Version of the retained private-state commitment key",
            ),
        ]
    )
    if config.section("ios").get("review", {}).get("demoAccountRequired"):
        requirements.extend(
            [
                Requirement(
                    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME",
                    "secret",
                    stage,
                    "ios",
                    reason="Private App Review demo-account username",
                ),
                Requirement(
                    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
                    "secret",
                    stage,
                    "ios",
                    reason="Private App Review demo-account password",
                ),
            ]
        )
    return requirements


def load_credentials_file(path: Path, project_root: Path) -> dict[str, str]:
    path = path.expanduser()
    if not path.is_absolute():
        raise CredentialError("credentials file path must be absolute")
    try:
        resolved = canonical_external_path(path, label="credentials file")
    except (FileNotFoundError, OSError, ValidationError) as error:
        raise CredentialError("credentials file must not be a symlink") from error
    if not resolved.is_file():
        raise CredentialError("credentials file must be a regular file")
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        pass
    else:
        raise CredentialError("credentials file must live outside the project repository")
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode & 0o077:
        raise CredentialError("credentials file must not be readable or writable by group/others")
    if resolved.stat().st_size > 256 * 1024:
        raise CredentialError("credentials file is unexpectedly large")
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CredentialError("credentials file must be UTF-8") from error
    values: dict[str, str] = {}
    for number, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("export ") or "=" not in raw:
            raise CredentialError(f"invalid credentials-file syntax on line {number}")
        key, value = raw.split("=", 1)
        if key.strip() != key or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise CredentialError(f"invalid credential name on line {number}")
        if key not in ALLOWED_CREDENTIAL_NAMES:
            raise CredentialError(
                f"unsupported credential name on line {number}; "
                "arbitrary environment overrides are forbidden"
            )
        if key in values:
            raise CredentialError(f"duplicate credential name on line {number}: {key}")
        if "\x00" in value:
            raise CredentialError(f"NUL is forbidden in a credential value on line {number}: {key}")
        if not value:
            raise CredentialError(f"empty credential value on line {number}: {key}")
        values[key] = value
    return values


def credential_values_from_environment(environ: Mapping[str, str]) -> dict[str, str]:
    return {
        name: environ[name]
        for name in ALLOWED_CREDENTIAL_NAMES
        if environ.get(name)
    }


def _reject_ambiguous_material(values: Mapping[str, str], source: str) -> None:
    for alternatives in CREDENTIAL_MATERIAL_GROUPS:
        configured = sorted(name for name in alternatives if values.get(name))
        if len(configured) > 1:
            raise CredentialError(
                f"ambiguous {source} credential material; mutually exclusive alternatives: "
                + ", ".join(configured)
            )


def resolve_credential_values(
    config: ReleaseConfig,
    *,
    credentials_file: Path | None = None,
    credentials_from_env: bool = False,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Resolve only allowlisted credentials; an explicit file wins by material family."""

    resolved = (
        credential_values_from_environment(environ if environ is not None else os.environ)
        if credentials_from_env
        else {}
    )
    _reject_ambiguous_material(resolved, "explicit environment mode")
    if credentials_file is None:
        return resolved

    file_values = load_credentials_file(credentials_file, config.root)
    _reject_ambiguous_material(file_values, "credentials file")
    for alternatives in CREDENTIAL_MATERIAL_GROUPS:
        if alternatives & file_values.keys():
            for name in alternatives:
                resolved.pop(name, None)
    resolved.update(file_values)
    return resolved


def credential_values_for_purpose(
    config: ReleaseConfig,
    values: Mapping[str, str],
    *,
    stage: str,
    purpose: str,
    platforms: Iterable[str],
) -> dict[str, str]:
    """Select the minimum credential subset for one execution capability."""

    allowed: set[str] = set()
    selected = tuple(platforms)
    for item in requirements(config, stage, purpose=purpose, platforms=selected):
        allowed.add(item.name)
        allowed.update(item.alternatives)
    if purpose == "store" and "android" in selected:
        allowed.add("GOOGLE_APPLICATION_CREDENTIALS")
    return {name: values[name] for name in allowed if values.get(name)}


def _github_names(root: Path, environment: str) -> tuple[set[str], set[str], str | None]:
    def query(kind: str) -> set[str] | None:
        try:
            result = subprocess.run(
                ["gh", kind, "list", "--env", environment, "--json", "name"],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode:
            return None
        try:
            parsed = json.loads(result.stdout)
            return {item["name"] for item in parsed if isinstance(item, dict) and item.get("name")}
        except (json.JSONDecodeError, TypeError, KeyError):
            return None

    secret_names = query("secret")
    variable_names = query("variable")
    if secret_names is None or variable_names is None:
        return set(), set(), "GitHub environment names could not be queried with gh"
    return secret_names, variable_names, None


def _private_path_error(
    value: str,
    project_root: Path,
    *,
    maximum_size: int = MAX_PRIVATE_MATERIAL_SIZE,
) -> str | None:
    path = Path(value).expanduser()
    if not path.is_absolute():
        return "The declared private path must be absolute."
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            return "The declared private path must not traverse a symlink."
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return "The declared private path does not exist."
    if not resolved.is_file():
        return "The declared private path must be a regular file."
    try:
        file_stat = resolved.stat()
    except OSError:
        return "The declared private path could not be inspected."
    if file_stat.st_size < 1 or file_stat.st_size > maximum_size:
        return "The declared private file is empty or exceeds its safety size limit."
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        return "The declared private file must not be accessible by group or others."
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        return None
    return "Private credential material must live outside the project repository."


def _value_state(
    name: str, values: Mapping[str, str], project_root: Path
) -> tuple[Status, str | None]:
    value = values.get(name)
    if not value:
        return Status.MISSING, None
    if name.endswith("_PATH"):
        if error := _private_path_error(value, project_root):
            return Status.INVALID, error
    if name.endswith("_BASE64"):
        maximum_size = _material_size_limit(name)
        if len(value) > ((maximum_size + 2) // 3) * 4 + 4:
            return Status.INVALID, "The configured Base64 value exceeds its safety size limit."
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return Status.INVALID, "The configured value is not strict Base64."
        if not decoded:
            return Status.INVALID, "The configured Base64 value decodes to an empty file."
        if len(decoded) > maximum_size:
            return Status.INVALID, "The decoded private file exceeds its safety size limit."
    format_error = _credential_format_error(name, value)
    if format_error:
        return Status.INVALID, format_error
    return Status.CONFIGURED, None


def _material_size_limit(name: str) -> int:
    if any(token in name for token in ("P8", "PROFILE", "SERVICE", "SERVICES")):
        return SMALL_PRIVATE_MATERIAL_SIZE
    return MAX_PRIVATE_MATERIAL_SIZE


def _credential_format_error(name: str, value: str) -> str | None:
    if name == "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64":
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return "The commitment key must be canonical base64."
        if len(decoded) != 32:
            return "The commitment key must decode to exactly 32 bytes."
    patterns = {
        "MOBILE_RELEASE_ANDROID_KEY_ALIAS": r"[A-Za-z0-9_.-]{1,255}",
        "MOBILE_RELEASE_ASC_KEY_ID": r"[A-Z0-9]{10}",
        "MOBILE_RELEASE_ASC_ISSUER_ID": (
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        ),
        "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER": (
            r"projects/[1-9][0-9]*/locations/global/workloadIdentityPools/"
            r"[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+"
        ),
        "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT": (
            r"[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9-]+\.iam\.gserviceaccount\.com"
        ),
        "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION": r"[A-Za-z0-9_.-]{1,64}",
    }
    pattern = patterns.get(name)
    if pattern and not re.fullmatch(pattern, value):
        return "The configured value has an invalid public identifier format."
    if name == "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL" and not re.fullmatch(
        r"[^\s@]+@[^\s@]+\.[^\s@]+", value
    ):
        return "The configured review contact email has an invalid format."
    return None


def credential_findings(
    config: ReleaseConfig,
    *,
    stage: str,
    credentials_file: Path | None = None,
    credentials_from_env: bool = False,
    github: bool = False,
    purpose: str = "full",
    platforms: Iterable[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[Finding]:
    env = resolve_credential_values(
        config,
        credentials_file=credentials_file,
        credentials_from_env=credentials_from_env,
        environ=environ,
    )
    github_cache: dict[str, tuple[set[str], set[str], str | None]] = {}
    result: list[Finding] = []
    requested = requirements(config, stage, purpose=purpose, platforms=platforms)
    if not github and purpose == "store":
        google_stages = {
            item.stage
            for item in requested
            if item.platform == "android"
            and item.name
            in {"MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT"}
        }
        requested = [
            item
            for item in requested
            if not (
                item.platform == "android"
                and item.name
                in {
                    "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER",
                    "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT",
                }
            )
        ]
        requested.extend(
            Requirement(
                "GOOGLE_APPLICATION_CREDENTIALS",
                "file",
                current_stage,
                "android",
                reason="Local read-only Google Application Default Credentials file",
            )
            for current_stage in sorted(google_stages)
        )
    for item in requested:
        candidates = (
            (item.name,)
            if github
            else (item.name, *item.alternatives)
        )
        status = Status.MISSING
        configured_name: str | None = None
        remediation: str | None = None
        if github:
            environment = ENVIRONMENT_NAMES[item.stage]
            if environment not in github_cache:
                github_cache[environment] = _github_names(config.root, environment)
            secrets, variables, error = github_cache[environment]
            if error:
                status = Status.MANUAL
                remediation = error
            else:
                available = variables if item.kind == "variable" else secrets
                configured_name = next((name for name in candidates if name in available), None)
                status = Status.CONFIGURED if configured_name else Status.MISSING
        else:
            for candidate in candidates:
                if status != Status.MISSING:
                    break
                candidate_status, candidate_remediation = _value_state(candidate, env, config.root)
                if candidate_status != Status.MISSING:
                    configured_name = candidate
                    status = candidate_status
                    remediation = candidate_remediation
                    break
        if status == Status.MISSING:
            remediation = (
                f"Configure {item.name} in {ENVIRONMENT_NAMES[item.stage]}"
                if github
                else f"Provide {item.name} in an explicit credentials file or environment mode"
            )
        result.append(
            Finding(
                code=f"credential.{item.stage}.{item.platform}.{item.name.lower()}",
                status=status,
                category="credentials",
                message=(
                    f"{item.stage}/{item.platform}: {item.name} is configured"
                    if status == Status.CONFIGURED
                    else f"{item.stage}/{item.platform}: {item.name} is {status.value.lower()}"
                ),
                remediation=remediation,
                details={
                    "stage": item.stage,
                    "platform": item.platform,
                    "kind": item.kind,
                    "configuredName": configured_name,
                    "reason": item.reason,
                },
            )
        )
    return result


def _materialize(
    values: Mapping[str, str],
    base64_name: str,
    path_name: str,
    directory: Path,
    filename: str,
    *,
    project_root: Path,
) -> Path | None:
    if value := values.get(path_name):
        if error := _private_path_error(
            value, project_root, maximum_size=_material_size_limit(base64_name)
        ):
            raise CredentialError(f"{path_name} is unsafe: {error}")
        return Path(value).expanduser().resolve(strict=True)
    if value := values.get(base64_name):
        maximum_size = _material_size_limit(base64_name)
        if len(value) > ((maximum_size + 2) // 3) * 4 + 4:
            raise CredentialError(f"{base64_name} exceeds its safety size limit")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise CredentialError(f"{base64_name} is not strict Base64") from error
        if not decoded or len(decoded) > maximum_size:
            raise CredentialError(f"{base64_name} decodes to an empty or oversized file")
        path = directory / filename
        path.write_bytes(decoded)
        path.chmod(0o600)
        return path
    return None


def _run_private(
    argv: list[str], *, environ: Mapping[str, str], timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            env=dict(environ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        raise CredentialError(f"credential validation tool failed or timed out: {argv[0]}") from error


def _close_profile_descriptor(descriptor: int) -> None:
    # The caller relinquishes this number before calling: close may have taken
    # effect even when it raises. Retrying could close a reused foreign handle.
    try:
        os.close(descriptor)
    except OSError:
        raise CredentialError("local profile descriptor cleanup could not be confirmed; end this process before retrying") from None


def _open_profile_directory(home: Path) -> tuple[Path, int]:
    """Create/open the provisioning-profile directory without following child symlinks."""

    try:
        resolved_home = home.expanduser().resolve(strict=True)
    except OSError as error:
        raise CredentialError("the local home directory is unavailable") from error
    if not resolved_home.is_dir():
        raise CredentialError("the local home path is not a directory")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = child = None
    current = resolved_home
    try:
        try:
            descriptor = os.open(resolved_home, flags)
        except OSError as error:
            raise CredentialError("the local home directory could not be opened safely") from error
        for component in ("Library", "MobileDevice", "Provisioning Profiles"):
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise CredentialError(
                    "provisioning-profile directory must not traverse a symbolic link"
                ) from error
            previous = descriptor
            descriptor = child
            child = None
            _close_profile_descriptor(previous)
            current /= component
        return current, descriptor
    except BaseException:
        try:
            if child is not None:
                closing, child = child, None
                _close_profile_descriptor(closing)
        finally:
            if descriptor is not None:
                closing, descriptor = descriptor, None
                _close_profile_descriptor(closing)
        raise


def _read_regular_at(directory_descriptor: int, name: str) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_PRIVATE_MATERIAL_SIZE:
            raise CredentialError("provisioning-profile destination is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_PRIVATE_MATERIAL_SIZE + 1)
        after = os.fstat(descriptor)
        if len(content) != details.st_size or any(
            getattr(details, key) != getattr(after, key) for key in ("st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise CredentialError("provisioning-profile destination changed while being inspected")
        return content
    finally:
        if descriptor is not None:
            closing, descriptor = descriptor, None
            _close_profile_descriptor(closing)


@contextmanager
def _temporary_profile_installation(
    content: bytes, profile_uuid: str, home: Path, *, cancellation: _ProfileCancellation | None = None,
):
    """Install already-authenticated exact bytes without clobbering another file.

    Inode ownership is not a multi-context lifetime lease: local signing's shared
    keychain/profile concurrency is separately tracked as QA-003.
    """
    if (type(profile_uuid) is not str or not PROFILE_UUID_RE.fullmatch(profile_uuid)
            or type(content) is not bytes or not 0 < len(content) <= MAX_PRIVATE_MATERIAL_SIZE):
        raise CredentialError("authenticated provisioning profile identity is invalid")
    owns_cancellation = cancellation is None
    cancellation = cancellation if cancellation is not None else _ProfileCancellation(
        CredentialError, "local signing cancellation handlers could not be restored",
    )
    directory = descriptor = None
    name = f"{profile_uuid}.mobileprovision"
    stage = None
    created = False
    identity = None
    attempted = False
    linked = False
    failed_cleanup = False

    def file_identity(filename: str):
        details = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        return (details.st_dev, details.st_ino) if stat.S_ISREG(details.st_mode) else None

    def cleanup() -> None:
        nonlocal directory, failed_cleanup
        try:
            if attempted and identity is not None:
                try:
                    current_identity = file_identity(name)
                    if current_identity == identity:
                        if _read_regular_at(directory, name) == content:
                            os.unlink(name, dir_fd=directory)
                        else:
                            failed_cleanup = True
                    elif linked:
                        failed_cleanup = True  # Preserve an intervening replacement.
                except FileNotFoundError:
                    pass
                except (OSError, CredentialError):
                    failed_cleanup = True
            if stage is not None and created:
                if identity is None:
                    failed_cleanup = True  # Empty private residue, not a guessed unlink.
                else:
                    try:
                        if file_identity(stage) == identity:
                            os.unlink(stage, dir_fd=directory)
                        else:
                            failed_cleanup = True
                    except FileNotFoundError:
                        pass
                    except OSError:
                        failed_cleanup = True
        finally:
            if directory is not None:
                closing, directory = directory, None
                try:
                    _close_profile_descriptor(closing)
                except CredentialError:
                    failed_cleanup = True
        if failed_cleanup:
            raise CredentialError(
                "temporary provisioning profile changed or could not be cleaned up safely; "
                "end this process and inspect its owned private staging files before retrying"
            )

    scope = _ProfileCleanup(cancellation, cleanup, owns_cancellation=owns_cancellation)
    try:
        with scope:
            if owns_cancellation:
                cancellation.install()
                cancellation.activate()
            with cancellation.deferred():
                _, directory = _open_profile_directory(home)
                cancellation.check()
                try:
                    existing = _read_regular_at(directory, name)
                except FileNotFoundError:
                    existing = None
                cancellation.check()
                if existing is not None:
                    if existing != content:
                        raise CredentialError("a different provisioning profile is already installed with the same UUID")
                else:
                    stage = f".mobile-release-profile-{secrets.token_hex(16)}"
                    try:
                        descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                        created = True
                        details = os.fstat(descriptor)
                        identity = (details.st_dev, details.st_ino)
                        cancellation.check()
                        with os.fdopen(descriptor, "wb", closefd=False) as handle:
                            handle.write(content)
                            handle.flush()
                            os.fsync(descriptor)
                    finally:
                        if descriptor is not None:
                            # Initial fstat can fail before any bytes are written.
                            # Only this still-owned FD can recover deletion authority.
                            if identity is None:
                                try:
                                    details = os.fstat(descriptor)
                                    identity = (details.st_dev, details.st_ino)
                                except OSError:
                                    failed_cleanup = True
                            closing, descriptor = descriptor, None
                            try:
                                _close_profile_descriptor(closing)
                            except CredentialError:
                                failed_cleanup = True
                    if failed_cleanup:
                        raise CredentialError("private provisioning-profile descriptor cleanup could not be confirmed")
                    cancellation.check()
                    # Arm ownership before the syscall: interruption after a successful
                    # link must still remove our file, never a pre-existing destination.
                    attempted = True
                    try:
                        os.link(stage, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                        linked = True
                    except FileExistsError:
                        if _read_regular_at(directory, name) != content:
                            raise CredentialError("a different provisioning profile appeared during installation") from None
                        linked = file_identity(name) == identity
                    cancellation.check()
                    if file_identity(stage) != identity:
                        raise CredentialError("private provisioning-profile staging file was replaced")
                    os.unlink(stage, dir_fd=directory)
                    stage = None
                    cancellation.check()
            yield
    except OSError:
        raise CredentialError("provisioning profile could not be installed safely") from None
    finally:
        # Normal with-exit dispatch precedes __exit__'s protected frame.
        scope.__exit__(*exc_info())


def _utc_datetime(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _parse_certificate_datetime(value: str) -> datetime:
    parsed = parsedate_to_datetime(value.strip())
    if not isinstance(parsed, datetime):
        raise ValueError("certificate date is invalid")
    return _utc_datetime(parsed)


@contextmanager
def _temporary_apple_signing_environment(
    *, p12: Path, password: str, profile: Path, directory: Path, home: Path | None = None
):
    """Install validated Apple material temporarily without exposing it in output."""

    from .ios import _profile_validity
    from .ios_profiles import decode_authenticated_profile, read_profile_bytes

    # Authenticate ONE snapshot before inspecting or mutating user keychains.
    # A later replacement of the supplied path cannot change installed bytes.
    try:
        supplied = read_profile_bytes(profile)
        profile_payload = decode_authenticated_profile(supplied)
        _profile_validity(profile_payload)
    except ValidationError as error:
        raise CredentialError(str(error)) from None
    profile_uuid = profile_payload.get("UUID")
    if not isinstance(profile_uuid, str) or not PROFILE_UUID_RE.fullmatch(profile_uuid):
        raise CredentialError("provisioning profile UUID is missing or invalid")

    env = scrub_credential_capabilities(os.environ)
    env["MOBILE_RELEASE_LOCAL_P12_PASSWORD"] = password
    keychain = directory / "signing.keychain-db"
    certificate = directory / "signing-certificate.pem"
    chain_certificates = directory / "signing-chain.pem"
    private_key = directory / "signing-private-key.pem"
    keychain_password = secrets.token_hex(32)
    original_default = ""
    original_keychains: list[str] = []
    created_keychain = False
    changed_keychain_search = False
    changed_default = False
    installed_profile = ExitStack()

    def require(argv: list[str], action: str) -> subprocess.CompletedProcess[str]:
        result = _run_private(argv, environ=env)
        if result.returncode:
            raise CredentialError(f"could not {action} for local Apple signing preflight")
        return result

    def extract(arguments: list[str], action: str) -> None:
        base = [
            "openssl",
            "pkcs12",
            "-in",
            str(p12),
            *arguments,
            "-passin",
            "env:MOBILE_RELEASE_LOCAL_P12_PASSWORD",
        ]
        result = _run_private(base, environ=env)
        if result.returncode:
            result = _run_private(
                ["openssl", "pkcs12", "-legacy", *base[2:]], environ=env
            )
        if result.returncode:
            raise CredentialError(f"could not {action} for local Apple signing preflight")

    def cleanup_signing() -> None:
        cleanup_failed = False

        def cleanup(argv: list[str]) -> bool:
            try:
                return _run_private(argv, environ=env).returncode == 0
            except CredentialError:
                return False

        try:
            if changed_keychain_search:
                cleanup_failed = not cleanup(
                    ["security", "list-keychains", "-d", "user", "-s", *original_keychains]
                ) or cleanup_failed
            if changed_default and original_default:
                cleanup_failed = not cleanup(
                    ["security", "default-keychain", "-d", "user", "-s", original_default]
                ) or cleanup_failed
            if created_keychain:
                cleanup_failed = not cleanup(
                    ["security", "delete-keychain", str(keychain)]
                ) or cleanup_failed
        finally:
            try:
                installed_profile.close()
            except (CredentialError, OSError):
                cleanup_failed = True
        if cleanup_failed:
            raise CredentialError("local Apple signing material could not be completely cleaned up")

    cancellation = _ProfileCancellation(
        CredentialError, "local signing cancellation handlers could not be restored",
    )
    scope = _ProfileCleanup(cancellation, cleanup_signing, owns_cancellation=True)
    try:
        with scope:
            cancellation.install()
            cancellation.activate()
            with cancellation.deferred():
                installed_profile.enter_context(_temporary_profile_installation(
                    supplied, profile_uuid, home or Path.home(), cancellation=cancellation,
                ))
            default_result = require(
                ["security", "default-keychain", "-d", "user"],
                "inspect the default keychain",
            )
            original_default = default_result.stdout.strip().strip('"')
            if not original_default:
                raise CredentialError("the current default keychain could not be identified")
            list_result = require(
                ["security", "list-keychains", "-d", "user"],
                "inspect the keychain search list",
            )
            original_keychains = [
                quoted or bare
                for quoted, bare in re.findall(
                    r'"([^"\r\n]+)"|([^\s"]+)', list_result.stdout
                )
            ]
            with cancellation.deferred():
                require(
                    ["security", "create-keychain", "-p", keychain_password, str(keychain)],
                    "create an ephemeral keychain",
                )
                created_keychain = True
            require(
                ["security", "set-keychain-settings", "-lut", "21600", str(keychain)],
                "configure the ephemeral keychain",
            )
            require(
                ["security", "unlock-keychain", "-p", keychain_password, str(keychain)],
                "unlock the ephemeral keychain",
            )
            extract(
                ["-clcerts", "-nokeys", "-out", str(certificate)],
                "extract the Apple distribution certificate",
            )
            extract(
                ["-nocerts", "-nodes", "-out", str(private_key)],
                "extract the Apple distribution private key",
            )
            extract(
                ["-cacerts", "-nokeys", "-out", str(chain_certificates)],
                "extract the Apple distribution certificate chain",
            )
            private_key.chmod(0o600)
            require(
                [
                    "security",
                    "import",
                    str(private_key),
                    "-k",
                    str(keychain),
                    "-T",
                    "/usr/bin/codesign",
                    "-T",
                    "/usr/bin/security",
                ],
                "import the Apple distribution identity",
            )
            require(
                [
                    "security",
                    "import",
                    str(certificate),
                    "-k",
                    str(keychain),
                    "-T",
                    "/usr/bin/codesign",
                    "-T",
                    "/usr/bin/security",
                ],
                "import the Apple distribution certificate",
            )
            if (
                chain_certificates.is_file()
                and b"-----BEGIN CERTIFICATE-----" in chain_certificates.read_bytes()
            ):
                require(
                    [
                        "security",
                        "import",
                        str(chain_certificates),
                        "-k",
                        str(keychain),
                        "-T",
                        "/usr/bin/codesign",
                        "-T",
                        "/usr/bin/security",
                    ],
                    "import the Apple distribution certificate chain",
                )
            require(
                [
                    "security",
                    "set-key-partition-list",
                    "-S",
                    "apple-tool:,apple:,codesign:",
                    "-s",
                    "-k",
                    keychain_password,
                    str(keychain),
                ],
                "authorize codesign to use the ephemeral keychain",
            )
            with cancellation.deferred():
                require(
                    ["security", "list-keychains", "-d", "user", "-s", str(keychain)],
                    "activate the ephemeral keychain",
                )
                changed_keychain_search = True
            with cancellation.deferred():
                require(
                    ["security", "default-keychain", "-d", "user", "-s", str(keychain)],
                    "select the ephemeral keychain",
                )
                changed_default = True

            yield {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": profile_uuid}
    finally:
        scope.__exit__(*exc_info())


def _fingerprint_from_text(text: str) -> str | None:
    match = re.search(r"SHA(?:-)?256(?: fingerprint)?:?\s*=*\s*([0-9A-Fa-f:]{64,95})", text)
    return match.group(1).replace(":", "").lower() if match else None


def _validate_android_material(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path
) -> Finding:
    keystore = _materialize(
        values,
        "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
        directory,
        "android-keystore",
        project_root=config.root,
    )
    if keystore is None:
        return Finding(
            "credential-material.android",
            Status.MISSING,
            "Android signing keystore is missing.",
            category="credentials",
        )
    required = (
        "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
        "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
        "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
    )
    if any(not values.get(name) for name in required):
        return Finding(
            "credential-material.android",
            Status.MISSING,
            "Android signing passwords or alias are incomplete.",
            category="credentials",
        )
    env = scrub_credential_capabilities(os.environ)
    env.update(values)
    env["LC_ALL"] = "C"
    result = _run_private(
        [
            "keytool",
            "-J-Duser.timezone=UTC",
            "-list",
            "-v",
            "-keystore",
            str(keystore),
            "-alias",
            values["MOBILE_RELEASE_ANDROID_KEY_ALIAS"],
            "-storepass:env",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
            "-keypass:env",
            "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
        ],
        environ=env,
    )
    output = result.stdout + result.stderr
    if result.returncode or "PrivateKeyEntry" not in output:
        return Finding(
            "credential-material.android",
            Status.INVALID,
            "Android keystore/alias/passwords do not expose a private-key entry.",
            category="credentials",
        )
    fingerprint = _fingerprint_from_text(output)
    expected = config.section("android").get("uploadCertificateSha256", "").replace(":", "").lower()
    if not fingerprint or fingerprint != expected:
        return Finding(
            "credential-material.android",
            Status.INVALID,
            "Android signing key fingerprint does not match approved configuration.",
            category="credentials",
        )
    validity_match = re.search(
        r"Valid from:\s*(.*?)\s+until:\s*(.+)$",
        output,
        re.MULTILINE | re.IGNORECASE,
    )
    if not validity_match:
        return Finding(
            "credential-material.android",
            Status.INVALID,
            "Android certificate validity window could not be determined.",
            category="credentials",
        )
    try:
        valid_from = _parse_certificate_datetime(validity_match.group(1))
        expires = _parse_certificate_datetime(validity_match.group(2))
    except (TypeError, ValueError):
        return Finding(
            "credential-material.android",
            Status.INVALID,
            "Android certificate validity window has an unrecognized format.",
            category="credentials",
        )
    current = datetime.now(timezone.utc)
    if valid_from > current or expires <= current:
        return Finding(
            "credential-material.android",
            Status.INVALID,
            "Android upload certificate is not currently valid.",
            category="credentials",
        )
    return Finding(
        "credential-material.android",
        Status.PASS,
        "Android keystore, private-key alias, certificate expiry, and fingerprint are valid.",
        category="credentials",
    )


def _validate_p8(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path
) -> Finding:
    p8 = _materialize(
        values,
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
        directory,
        "AuthKey.p8",
        project_root=config.root,
    )
    if p8 is None:
        return Finding(
            "credential-material.apple-p8",
            Status.MISSING,
            "App Store Connect P8 private key is missing.",
            category="credentials",
        )
    result = _run_private(
        ["openssl", "pkey", "-in", str(p8), "-check", "-noout"],
        environ=scrub_credential_capabilities(os.environ),
    )
    public = _run_private(
        ["openssl", "pkey", "-in", str(p8), "-pubout", "-text_pub", "-noout"],
        environ=scrub_credential_capabilities(os.environ),
    )
    output = public.stdout + public.stderr
    if (
        result.returncode
        or public.returncode
        or not re.search(r"(?:prime256v1|P-256)", output, re.IGNORECASE)
    ):
        return Finding(
            "credential-material.apple-p8",
            Status.INVALID,
            "App Store Connect P8 is not a valid EC P-256 private key.",
            category="credentials",
        )
    return Finding(
        "credential-material.apple-p8",
        Status.PASS,
        "App Store Connect P8 is a valid EC P-256 private key.",
        category="credentials",
    )


def _validate_apple_signing_material(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path
) -> list[Finding]:
    from .ios import _profile_validity
    from .ios_profiles import load_authenticated_profile

    p12 = _materialize(
        values,
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
        directory,
        "distribution.p12",
        project_root=config.root,
    )
    profile = _materialize(
        values,
        "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
        "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
        directory,
        "profile.mobileprovision",
        project_root=config.root,
    )
    password = values.get("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD")
    findings: list[Finding] = []
    if not p12 or not profile or password is None:
        findings.append(
            Finding(
                "credential-material.apple-signing",
                Status.MISSING,
                "Apple P12/password/provisioning profile are incomplete.",
                category="credentials",
            )
        )
        return findings
    try:
        payload = load_authenticated_profile(profile)
        _profile_validity(payload)
    except ValidationError:
        return [Finding(
            "credential-material.apple-profile", Status.INVALID,
            "Apple profile issuer, modern signed content or current validity could not be verified; "
            "use an Apple-issued profile and supported macOS tooling.", category="credentials",
        )]
    env = scrub_credential_capabilities(os.environ)
    env.update(values)
    certificate = directory / "distribution-certificate.pem"
    private_key = directory / "private-key.pem"

    def extract_pkcs12(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        command = ["openssl", "pkcs12", "-in", str(p12), *arguments]
        result = _run_private(command, environ=env)
        if result.returncode:
            result = _run_private(
                ["openssl", "pkcs12", "-legacy", "-in", str(p12), *arguments],
                environ=env,
            )
        return result

    extract = extract_pkcs12(
        [
            "-clcerts",
            "-nokeys",
            "-passin",
            "env:MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "-out",
            str(certificate),
        ]
    )
    key_check = extract_pkcs12(
        [
            "-nocerts",
            "-nodes",
            "-passin",
            "env:MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "-out",
            str(private_key),
        ]
    )
    if private_key.exists():
        private_key.chmod(0o600)
    if extract.returncode or key_check.returncode or not certificate.is_file():
        findings.append(
            Finding(
                "credential-material.apple-p12",
                Status.INVALID,
                "Apple P12/password does not contain an extractable certificate and private key.",
                category="credentials",
            )
        )
        return findings
    certificate_check = _run_private(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-checkend",
            "0",
            "-fingerprint",
            "-sha256",
            "-subject",
            "-dates",
            "-ext",
            "extendedKeyUsage",
        ],
        environ=env,
    )
    fingerprint = _fingerprint_from_text(certificate_check.stdout + certificate_check.stderr)
    expected = config.section("ios").get("distributionCertificateSha256", "").replace(":", "").lower()
    certificate_output = certificate_check.stdout + certificate_check.stderr
    validity_match = re.search(
        r"(?ims)^notBefore=(.+?)$.*^notAfter=(.+?)$", certificate_output
    )
    try:
        current = datetime.now(timezone.utc)
        certificate_current = bool(validity_match) and (
            _parse_certificate_datetime(validity_match.group(1))
            <= current
            < _parse_certificate_datetime(validity_match.group(2))
        )
    except (TypeError, ValueError):
        certificate_current = False
    team_id = config.section("ios").get("teamId", "")
    distribution_purpose = bool(
        re.search(r"(?:Apple|iPhone) Distribution", certificate_output, re.IGNORECASE)
        and re.search(rf"OU\s*=\s*{re.escape(team_id)}\b", certificate_output)
        and re.search(r"Code Signing", certificate_output, re.IGNORECASE)
    )
    certificate_public = directory / "certificate-public.pem"
    key_public = directory / "key-public.pem"
    cert_public_result = _run_private(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout", "-out", str(certificate_public)],
        environ=env,
    )
    key_public_result = _run_private(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(key_public)],
        environ=env,
    )
    keys_match = (
        cert_public_result.returncode == 0
        and key_public_result.returncode == 0
        and certificate_public.read_bytes() == key_public.read_bytes()
    )
    if (
        certificate_check.returncode
        or not certificate_current
        or not fingerprint
        or fingerprint != expected
        or not distribution_purpose
        or not keys_match
    ):
        findings.append(
            Finding(
                "credential-material.apple-p12",
                Status.INVALID,
                "Apple distribution certificate is expired or its fingerprint is not approved.",
                category="credentials",
            )
        )
        return findings
    findings.append(
        Finding(
            "credential-material.apple-p12",
            Status.PASS,
            "Apple P12 contains a current private key and approved distribution certificate.",
            category="credentials",
        )
    )
    ios = config.section("ios")
    if not isinstance(payload, dict):
        valid = False
    else:
        entitlements = payload.get("Entitlements", {})
        teams = payload.get("TeamIdentifier", [])
        expiration = payload.get("ExpirationDate")
        valid = (
            isinstance(entitlements, dict)
            and entitlements.get("application-identifier") == f"{ios.get('teamId')}.{ios.get('bundleId')}"
            and type(teams) is list and teams == [ios.get("teamId")]
            and entitlements.get("get-task-allow") is False
            and entitlements.get("beta-reports-active") is True
            and not payload.get("ProvisionedDevices")
            and not payload.get("ProvisionsAllDevices")
            and isinstance(expiration, datetime)
            and _utc_datetime(expiration) > datetime.now(timezone.utc)
        )
        profile_certs = payload.get("DeveloperCertificates", [])
        try:
            pem_text = certificate.read_text(encoding="ascii")
            pem_match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                pem_text,
                re.DOTALL,
            )
            if not pem_match:
                raise ValueError("certificate PEM is absent")
            cert_der = ssl.PEM_cert_to_DER_cert(pem_match.group(0))
            certificate_digest = hashlib.sha256(cert_der).digest()
            profile_digests = {hashlib.sha256(item).digest() for item in profile_certs}
        except (UnicodeDecodeError, ValueError, TypeError):
            certificate_digest = b""
            profile_digests = set()
        valid = valid and certificate_digest in profile_digests
    findings.append(
        Finding(
            "credential-material.apple-profile",
            Status.PASS if valid else Status.INVALID,
            "Apple-issued profile matches the team, bundle, signer, distribution policy, and validity."
            if valid
            else "Apple profile does not match the approved team/bundle/signer/distribution policy.",
            category="credentials",
        )
    )
    return findings


def _validate_firebase_material(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path, platform: str
) -> Finding | None:
    policy_key = f"{platform}Firebase"
    if config.section("services").get(policy_key) != "required":
        return None
    if platform == "android":
        path = _materialize(
            values,
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
            directory,
            "google-services.json",
            project_root=config.root,
        )
        try:
            payload = json.loads(path.read_text(encoding="utf-8")) if path else None
            package_names = {
                item.get("client_info", {}).get("android_client_info", {}).get("package_name")
                for item in payload.get("client", [])
            }
            valid = config.section("android").get("applicationId") in package_names
        except (AttributeError, json.JSONDecodeError, UnicodeDecodeError):
            valid = False
    else:
        import plistlib

        path = _materialize(
            values,
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",
            directory,
            "GoogleService-Info.plist",
            project_root=config.root,
        )
        try:
            payload = plistlib.loads(path.read_bytes()) if path else None
            valid = payload.get("BUNDLE_ID") == config.section("ios").get("bundleId")
        except (AttributeError, plistlib.InvalidFileException):
            valid = False
    return Finding(
        f"credential-material.{platform}-firebase",
        Status.PASS if valid else Status.INVALID,
        f"{platform} Firebase client file matches the Store application identity."
        if valid
        else f"{platform} Firebase client file is missing, malformed, or for another application.",
        category="credentials",
    )


def validate_signing_material(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for name in PRIVATE_CREDENTIAL_PATH_NAMES & values.keys():
        if error := _private_path_error(values[name], config.root):
            return [
                Finding(
                    "credential-material.private-path",
                    Status.INVALID,
                    error,
                    category="credentials",
                )
            ]
    with tempfile.TemporaryDirectory(prefix="mobile-release-credentials-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        for platform in platforms:
            try:
                if platform == "android":
                    findings.append(_validate_android_material(config, values, directory))
                elif platform == "ios":
                    findings.extend(_validate_apple_signing_material(config, values, directory))
                firebase = _validate_firebase_material(config, values, directory, platform)
                if firebase:
                    findings.append(firebase)
            except (CredentialError, OSError) as error:
                findings.append(
                    Finding(
                        f"credential-material.{platform}",
                        Status.INVALID,
                        str(error),
                        category="credentials",
                    )
                )
    return findings


def validate_store_material(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
) -> list[Finding]:
    findings: list[Finding] = []
    selected = set(platforms)
    for name in PRIVATE_CREDENTIAL_PATH_NAMES & values.keys():
        if error := _private_path_error(values[name], config.root):
            return [
                Finding(
                    "credential-material.private-path",
                    Status.INVALID,
                    error,
                    category="credentials",
                )
            ]
    with tempfile.TemporaryDirectory(prefix="mobile-release-store-credentials-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        if "ios" in selected:
            try:
                findings.append(_validate_p8(config, values, directory))
            except (CredentialError, OSError) as error:
                findings.append(
                    Finding(
                        "credential-material.apple-p8",
                        Status.INVALID,
                        str(error),
                        category="credentials",
                    )
                )
        if "android" in selected:
            adc = values.get("GOOGLE_APPLICATION_CREDENTIALS")
            if not adc:
                findings.append(
                    Finding(
                        "credential-material.google-adc",
                        Status.MISSING,
                        "Local Google Store preflight requires explicit Application Default Credentials.",
                        category="credentials",
                    )
                )
            else:
                error = _private_path_error(adc, config.root)
                try:
                    payload = json.loads(Path(adc).read_text(encoding="utf-8")) if not error else None
                    valid = isinstance(payload, dict) and payload.get("type") in {
                        "external_account",
                        "service_account",
                        "authorized_user",
                    }
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    valid = False
                findings.append(
                    Finding(
                        "credential-material.google-adc",
                        Status.PASS if valid else Status.INVALID,
                        "Explicit Google ADC credential configuration is structurally valid."
                        if valid
                        else "Explicit Google ADC credential configuration is missing or malformed.",
                        category="credentials",
                    )
                )
    return findings


def store_lane_environment(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
) -> dict[str, str]:
    """Return only Store credentials, materializing a documented P8 path as in-memory Base64."""

    selected = tuple(platforms)
    result = credential_values_for_purpose(
        config,
        values,
        stage="candidate",
        purpose="store",
        platforms=selected,
    )
    if (
        "ios" in set(selected)
        and not result.get("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64")
        and (path_value := result.get("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH"))
    ):
        if error := _private_path_error(
            path_value,
            config.root,
            maximum_size=SMALL_PRIVATE_MATERIAL_SIZE,
        ):
            raise CredentialError(f"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH is unsafe: {error}")
        try:
            content = Path(path_value).expanduser().resolve(strict=True).read_bytes()
        except OSError as error:
            raise CredentialError("App Store Connect P8 path could not be read") from error
        result["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"] = base64.b64encode(content).decode(
            "ascii"
        )
        result.pop("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH", None)
    return result


@contextmanager
def _restore_build_targets(backups: list[tuple[Path, bytes | None, int | None]]):
    try:
        yield
    finally:
        for target, content, mode in reversed(backups):
            if content is None:
                target.unlink(missing_ok=True)
            else:
                if target.is_symlink():
                    target.unlink()
                target.write_bytes(content)
                target.chmod(mode or 0o600)


@contextmanager
def materialize_build_inputs(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
    prepare_ios_signing: bool = False,
):
    """Materialize configured client files temporarily and restore the exact prior tree."""

    selected = set(platforms)
    for name in PRIVATE_CREDENTIAL_PATH_NAMES & values.keys():
        if error := _private_path_error(values[name], config.root):
            raise CredentialError(error)
    backups: list[tuple[Path, bytes | None, int | None]] = []
    material_paths: dict[str, str] = {}
    build_environment: dict[str, str] = {}
    with (
        tempfile.TemporaryDirectory(prefix="mobile-release-build-inputs-") as temporary,
        _restore_build_targets(backups),
    ):
        directory = Path(temporary)
        directory.chmod(0o700)
        material_specs = (
            (
                "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                "android-keystore",
            ),
            (
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
                "distribution.p12",
            ),
            (
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
                "profile.mobileprovision",
            ),
            (
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
                "AuthKey.p8",
            ),
        )
        for base64_name, path_name, filename in material_specs:
            if base64_name.startswith("MOBILE_RELEASE_ANDROID") and "android" not in selected:
                continue
            if base64_name.startswith(("MOBILE_RELEASE_APPLE", "MOBILE_RELEASE_ASC")) and "ios" not in selected:
                continue
            path = _materialize(
                values,
                base64_name,
                path_name,
                directory,
                filename,
                project_root=config.root,
            )
            if path:
                material_paths[path_name] = str(path)
                if path_name == "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH":
                    build_environment[path_name] = str(path)

        if (
            "android" in selected
            and config.section("services").get("androidFirebase") == "required"
        ):
            from .discovery import discover_project, selected_android_module

            source = _materialize(
                values,
                "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
                "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
                directory,
                "google-services.json",
                project_root=config.root,
            )
            module = selected_android_module(config, discover_project(config.root))
            if not source or not module:
                raise CredentialError("Android Firebase material or application module is unavailable")
            module_relative = module.lstrip(":").replace(":", "/")
            try:
                module_dir = config.project_path(module_relative)
                target = config.project_path(
                    f"{module_relative}/google-services.json"
                    if module_relative
                    else "google-services.json"
                )
            except ConfigurationError as error:
                raise CredentialError(
                    "Android Firebase destination must not traverse a symbolic link"
                ) from error
            if not module_dir.is_dir():
                raise CredentialError("Android Firebase application module is unavailable")
            if target.is_symlink():
                raise CredentialError("Android Firebase destination must not be a symlink")
            backups.append(
                (
                    target,
                    target.read_bytes() if target.is_file() else None,
                    stat.S_IMODE(target.stat().st_mode) if target.is_file() else None,
                )
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)

        if "ios" in selected and config.section("services").get("iosFirebase") == "required":
            source = _materialize(
                values,
                "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
                "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",
                directory,
                "GoogleService-Info.plist",
                project_root=config.root,
            )
            examples = []
            for path in config.root.rglob("GoogleService-Info.plist.example"):
                if ".git" in path.parts or "build" in path.parts:
                    continue
                try:
                    examples.append(config.project_path(str(path)))
                except ConfigurationError as error:
                    raise CredentialError(
                        "iOS Firebase marker must not traverse a symbolic link"
                    ) from error
            if not source or len(examples) != 1:
                raise CredentialError(
                    "iOS Firebase requires exactly one tracked GoogleService-Info.plist.example"
                )
            target = config.project_path(str(examples[0].with_suffix("")))
            if examples[0].is_symlink() or target.is_symlink():
                raise CredentialError("iOS Firebase source marker/destination must not be a symlink")
            backups.append(
                (
                    target,
                    target.read_bytes() if target.is_file() else None,
                    stat.S_IMODE(target.stat().st_mode) if target.is_file() else None,
                )
            )
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)

        signing_context = nullcontext({})
        if (
            prepare_ios_signing
            and "ios" in selected
        ):
            p12_value = material_paths.get("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH")
            profile_value = material_paths.get(
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH"
            )
            password = values.get("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD")
            if not p12_value or not profile_value or password is None:
                raise CredentialError("Apple signing material is incomplete for a signed local build")
            signing_context = _temporary_apple_signing_environment(
                p12=Path(p12_value),
                password=password,
                profile=Path(profile_value),
                directory=directory,
            )

        with signing_context as signing_updates:
            build_environment.update(signing_updates)
            if "android" in selected:
                for name in (
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                    "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
                ):
                    if values.get(name):
                        build_environment[name] = values[name]
            if values.get("MOBILE_RELEASE_PROJECT_READ_TOKEN"):
                build_environment["MOBILE_RELEASE_PROJECT_READ_TOKEN"] = values[
                    "MOBILE_RELEASE_PROJECT_READ_TOKEN"
                ]
            yield dict(build_environment)
