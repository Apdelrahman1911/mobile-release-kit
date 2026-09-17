from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import threading
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path, PurePosixPath
from sys import exc_info
from typing import Any, Callable, Iterable, Mapping

from .cancellation import CleanupScope as _ProfileCleanup, DefaultCancellation as _ProfileCancellation, cancellation_owner
from .config import ConfigurationError, ReleaseConfig
from .errors import CredentialError, ValidationError
from .reporting import FAILING_STATUSES, Finding, Status
from .checked_files import inspect_external_path, read_external_bytes
from .build_inputs import (
    BuildInputs, FiniteScratch, InputSnapshot, InvocationCustody, TargetReplacement,
    finite_scratch, invocation_custody,
)
from .local_signing import SigningLease, _same_file_state, local_signing_lease
from .owned_process import ProcessCleanupError, ProcessError, preserve_lifetime_error, run_owned
from ._lifetime_evidence import ProfileCallEvidence
from ._profile_callers import consume_profile_evidence, fatal_cancellation_error

# Public names remain available here for existing CLI/integration callers.
from .credential_requirements import (
    ENVIRONMENT_NAMES, STAGES, Requirement, requirements,
    _apple_api_requirements, _apple_review_requirements, _google_requirements,
)
from .credential_policy import (
    MAX_PRIVATE_MATERIAL_SIZE, SMALL_PRIVATE_MATERIAL_SIZE,
    credential_format_error as _shared_credential_format_error,
    firebase_payload_matches_application as _shared_firebase_payload_matches_application,
    material_size_limit as _shared_material_size_limit,
)

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



def load_credentials_file(
    path: Path, project_root: Path, *, cancellation: _ProfileCancellation | None = None,
) -> dict[str, str]:
    try:
        content = read_external_bytes(path, kind="credentials-file", project_root=project_root,
                                      cancellation=cancellation)
    except ProcessError:
        raise
    except ValidationError as error:
        raise CredentialError(str(error)) from None
    try:
        lines = content.decode("utf-8").splitlines()
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
    cancellation: _ProfileCancellation | None = None,
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

    file_values = load_credentials_file(credentials_file, config.root, cancellation=cancellation)
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
    cancellation: _ProfileCancellation | None = None,
) -> str | None:
    # This is diagnostic only. A successful observation does not authorize a
    # subsequent reopen; each consumer selects bytes through the checked walk.
    if maximum_size not in {SMALL_PRIVATE_MATERIAL_SIZE, MAX_PRIVATE_MATERIAL_SIZE}:
        raise CredentialError("unknown private material size policy")
    try:
        inspect_external_path(
            Path(value), kind="private-small" if maximum_size == SMALL_PRIVATE_MATERIAL_SIZE else "private-general",
            project_root=project_root, cancellation=cancellation,
        )
    except ProcessError:
        raise
    except ValidationError as error:
        return str(error)
    return None


def _value_state(
    name: str, values: Mapping[str, str], project_root: Path, *,
    cancellation: _ProfileCancellation | None = None,
) -> tuple[Status, str | None]:
    value = values.get(name)
    if not value:
        return Status.MISSING, None
    if name.endswith("_PATH"):
        if error := _private_path_error(value, project_root, cancellation=cancellation):
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
    """Compatibility seam; shared pure policy preserves the existing fallback."""
    return _shared_material_size_limit(name)


def _credential_format_error(name: str, value: str) -> str | None:
    """Compatibility seam; admission remains separate from scalar-format policy."""
    return _shared_credential_format_error(name, value)


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
    cancellation: _ProfileCancellation | None = None,
) -> list[Finding]:
    env = resolve_credential_values(
        config,
        credentials_file=credentials_file,
        credentials_from_env=credentials_from_env,
        environ=environ,
        cancellation=cancellation,
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
                candidate_status, candidate_remediation = _value_state(candidate, env, config.root,
                                                                       cancellation=cancellation)
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


def _selected_material_bytes(
    values: Mapping[str, str], base64_name: str, path_name: str, *,
    project_root: Path, cancellation: _ProfileCancellation | None = None,
) -> bytes | None:
    """Select an external source once, never return its filename to consumers."""
    if values.get(base64_name) and values.get(path_name):
        raise CredentialError("private material has mutually exclusive input sources")
    maximum_size = _material_size_limit(base64_name)
    if value := values.get(path_name):
        if type(value) is not str:
            raise CredentialError("private material path must be a string")
        try:
            return read_external_bytes(
                Path(value), kind="private-small" if maximum_size == SMALL_PRIVATE_MATERIAL_SIZE else "private-general",
                project_root=project_root, cancellation=cancellation,
            )
        except ProcessError:
            raise
        except ValidationError as error:
            raise CredentialError(str(error)) from None
    if value := values.get(base64_name):
        if type(value) is not str or len(value) > ((maximum_size + 2) // 3) * 4 + 4:
            raise CredentialError(f"{base64_name} exceeds its safety size limit")
        try:
            content = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise CredentialError(f"{base64_name} is not strict Base64") from None
        if not content or len(content) > maximum_size:
            raise CredentialError(f"{base64_name} decodes to an empty or oversized file")
        return content
    return None


def _materialize(
    values: Mapping[str, str],
    base64_name: str,
    path_name: str,
    scratch: FiniteScratch,
    role: str,
    *,
    project_root: Path,
) -> InputSnapshot | None:
    """Publish one checked selection; no consumer reopens its external source."""
    content = _selected_material_bytes(values, base64_name, path_name, project_root=project_root,
                                       cancellation=scratch.cancellation)
    return None if content is None else scratch.put(role, content)


def _material_guard(scratch: FiniteScratch, cancellation: _ProfileCancellation | None) -> _ProfileCancellation:
    if type(scratch) is not FiniteScratch or cancellation is not None and cancellation is not scratch.cancellation:
        raise CredentialError("private material cancellation owner differs from its scratch")
    scratch._owner()
    return scratch.cancellation


def _run_private(
    argv: list[str], *, environ: Mapping[str, str], timeout: int = 30,
    cancellation: _ProfileCancellation | None = None, on_start: Callable[[int], None] | None = None,
    cwd: Path | None = None, capture: bool = True, cleanup: bool = False,
    execution_source=None, execution_scope=None, journal_binding=None,
) -> subprocess.CompletedProcess[str]:
    if execution_source is not None and execution_scope is not None:
        raise ProcessError("choose an account source or a selected command scope, not both")
    if journal_binding is not None and execution_scope is None:
        raise ProcessError("journalled command needs its original selected scope")
    if execution_source is not None:
        execution_scope = execution_source.new_scope()
    return run_owned(argv, environ=environ, timeout=timeout, cancellation=cancellation,
                     on_start=on_start, cwd=cwd, capture=capture, cleanup=cleanup,
                     execution_scope=execution_scope, journal_binding=journal_binding)


def _close_profile_descriptor(descriptor: int) -> None:
    # The caller relinquishes this number before calling: close may have taken
    # effect even when it raises. Retrying could close a reused foreign handle.
    try:
        os.close(descriptor)
    except OSError as error:
        raise preserve_lifetime_error(ProcessCleanupError(
            "local profile descriptor cleanup could not be confirmed; end this process before retrying",
        ), previous=error) from None


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
    creator_pid = os.getpid()
    current = resolved_home
    try:
        try:
            descriptor = os.open(resolved_home, flags)
        except OSError as error:
            raise CredentialError("the local home directory could not be opened safely") from error
        for component in ("Library", "MobileDevice", "Provisioning Profiles"):
            if creator_pid != os.getpid():
                raise CredentialError("inherited profile-directory acquisition cannot continue")
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


def _read_regular_at(directory_descriptor: int, name: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or not 0 <= details.st_size <= MAX_PRIVATE_MATERIAL_SIZE:
            raise CredentialError("provisioning-profile destination is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_PRIVATE_MATERIAL_SIZE + 1)
        after = os.fstat(descriptor)
        if (len(content) != details.st_size or not _same_file_state(details, after)
                or not _same_file_state(details, os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False))):
            raise CredentialError("provisioning-profile destination changed while being inspected")
        return content, details
    finally:
        if descriptor is not None:
            closing, descriptor = descriptor, None
            _close_profile_descriptor(closing)


@contextmanager
def _temporary_profile_installation(
    content: bytes, profile_uuid: str, home: Path, *, cancellation: _ProfileCancellation | None = None,
    observer: Callable | None = None, reserved_stage: str | None = None, retain: Callable[[], bool] | None = None,
    on_conflict: Callable[[], None] | None = None,
):
    """Install already-authenticated exact bytes without clobbering another file.

    The signing caller holds the account lease, journals write-before-use events,
    and can retain resources after genuinely ambiguous in-flight native work.
    """
    if (type(profile_uuid) is not str or not PROFILE_UUID_RE.fullmatch(profile_uuid)
            or type(content) is not bytes or not 0 < len(content) <= MAX_PRIVATE_MATERIAL_SIZE):
        raise CredentialError("authenticated provisioning profile identity is invalid")
    if reserved_stage is not None and not re.fullmatch(r"\.mobile-release-profile-[0-9a-f]{32}", reserved_stage):
        raise CredentialError("invalid reserved profile stage")
    cancellation, owns_cancellation = cancellation_owner(cancellation,
        ProcessCleanupError, "local signing cancellation handlers could not be restored",
    )
    owner_pid = os.getpid()
    directory = descriptor = None
    name = f"{profile_uuid}.mobileprovision"
    stage = None
    created = False
    identity = None
    attempted = False
    linked = False
    failed_cleanup = False
    snapshot_failed = False
    reused_identity = None
    conflicts: set[str] = set()

    def conflict(filename: str) -> None:
        nonlocal failed_cleanup
        # Preserve this observation even before ExitStack registers our owner.
        # Other original-owned names/handles remain independently cleanable.
        failed_cleanup = True
        conflicts.add(filename)
        if on_conflict is not None:
            on_conflict()

    def event(phase: str, **values) -> None:
        if owner_pid != os.getpid():
            raise CredentialError("inherited profile installer cannot mutate parent resources")
        if observer is not None:
            observer(phase, **values)

    def close_copies() -> None:
        nonlocal directory, descriptor
        try:
            if descriptor is not None:
                closing, descriptor = descriptor, None
                _close_profile_descriptor(closing)
        finally:
            if directory is not None:
                closing, directory = directory, None
                _close_profile_descriptor(closing)

    def file_state(filename: str) -> os.stat_result | None:
        if owner_pid != os.getpid():
            raise CredentialError("inherited profile installer has no file authority")
        details = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        if owner_pid != os.getpid():
            raise CredentialError("inherited profile installer has no file authority")
        return details if stat.S_ISREG(details.st_mode) else None

    def file_identity(details: os.stat_result | None) -> tuple[int, int] | None:
        return None if details is None else (details.st_dev, details.st_ino)

    def snapshot(filename: str) -> tuple[bytes, os.stat_result]:
        nonlocal snapshot_failed
        if filename in conflicts:
            raise CredentialError("provisioning-profile observation already failed; preserve it for explicit recovery")
        try:
            return _read_regular_at(directory, filename)
        except ProcessError as error:
            # This raw reader's owned close raises a direct typed error; it has
            # no handler-restoration envelope. An ordinary missing-file error
            # chained to a prior body failure is NOT a new snapshot failure.
            if error.fatal:
                # Even a first/racing read can fail before reused/owned identity
                # is set. Unwind may close raw handles, not retry or resolve it.
                snapshot_failed = True
            raise
        except FileNotFoundError:
            raise  # Initial/owned absence is not a failed resource lifetime.
        except (OSError, CredentialError):
            conflict(filename)
            raise

    def require_current(filename: str, details: os.stat_result) -> None:
        try:
            current = file_state(filename)
        except OSError:
            conflict(filename)
            raise
        if not _same_file_state(details, current):
            conflict(filename)
            raise CredentialError("provisioning profile changed after inspection; preserve it for explicit recovery")

    def cleanup() -> None:
        nonlocal directory, failed_cleanup
        if owner_pid != os.getpid():
            close_copies()
            return
        try:
            # Retention covers uncertain files, never our raw write handles or
            # failure reporting. A return here would skip the final error check.
            if not snapshot_failed and (retain is None or not retain()):
                if reused_identity is not None and name not in conflicts:
                    try:
                        before = file_state(name)
                        if file_identity(before) != reused_identity:
                            conflict(name)
                        else:
                            observed_content, observed = snapshot(name)
                            if (observed_content != content or not _same_file_state(before, observed)
                                    or not _same_file_state(observed, file_state(name))):
                                conflict(name)
                    except (OSError, CredentialError) as error:
                        if isinstance(error, ProcessError) and error.fatal:
                            raise
                        conflict(name)  # Not owned; preserve replacement/deletion.
                # EEXIST reuse has already checked the LAST borrowed observation.
                # Do not inspect it again as an unrelated owned-stage identity.
                if attempted and identity is not None and reused_identity is None and name not in conflicts:
                    try:
                        before = file_state(name)
                        if file_identity(before) == identity:
                            observed_content, observed = snapshot(name)
                            if (observed_content == content and _same_file_state(before, observed)
                                    and _same_file_state(observed, file_state(name))):
                                os.unlink(name, dir_fd=directory)
                            else:
                                conflict(name)
                        elif linked:
                            conflict(name)  # Preserve an intervening replacement.
                    except FileNotFoundError:
                        pass
                    except (OSError, CredentialError) as error:
                        if isinstance(error, ProcessError) and error.fatal:
                            raise
                        conflict(name)
                if stage is not None and created and stage not in conflicts:
                    if identity is None:
                        conflict(stage)  # Empty private residue, not a guessed unlink.
                    else:
                        try:
                            before = file_state(stage)
                            if file_identity(before) == identity and _same_file_state(before, file_state(stage)):
                                os.unlink(stage, dir_fd=directory)
                            else:
                                conflict(stage)
                        except FileNotFoundError:
                            pass
                        except OSError:
                            conflict(stage)
                if directory is not None:
                    os.fsync(directory)
                if not failed_cleanup:
                    event("resolved")
        finally:
            close_copies()
        if failed_cleanup:
            raise CredentialError(
                "temporary provisioning profile changed or could not be cleaned up safely; "
                "end this process and inspect its owned private staging files before retrying"
            )

    scope = _ProfileCleanup(cancellation, cleanup, owns_cancellation=owns_cancellation, fork_cleanup=close_copies,
                            first_primary=True)
    try:
        try:
            with scope:
                if owns_cancellation:
                    cancellation.install()
                    cancellation.activate()
                with cancellation.deferred():
                    _, directory = _open_profile_directory(home)
                    cancellation.check()
                    try:
                        existing = snapshot(name)
                    except FileNotFoundError:
                        existing = None
                    cancellation.check()
                    event("inspected")
                    if existing is not None:
                        if existing[0] != content:
                            raise CredentialError("a different provisioning profile is already installed with the same UUID")
                        require_current(name, existing[1])
                        reused_identity = file_identity(existing[1])
                        event("reused", identity=reused_identity)
                    else:
                        stage = reserved_stage or f".mobile-release-profile-{secrets.token_hex(16)}"
                        event("stage-intent")
                        try:
                            descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                            created = True
                            details = os.fstat(descriptor)
                            identity = (details.st_dev, details.st_ino)
                            event("stage-created", identity=identity)
                            cancellation.check()
                            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                                handle.write(content)
                                handle.flush()
                                os.fsync(descriptor)
                        finally:
                            if descriptor is not None:
                                # Initial fstat can fail before any bytes are written.
                                # Only this still-owned FD can recover deletion authority.
                                try:
                                    if identity is None:
                                        try:
                                            details = os.fstat(descriptor)
                                            identity = (details.st_dev, details.st_ino)
                                            event("stage-created", identity=identity)
                                        except OSError:
                                            failed_cleanup = True
                                finally:
                                    # A failed identity checkpoint is not permission
                                    # to abandon the already acquired descriptor.
                                    closing, descriptor = descriptor, None
                                    _close_profile_descriptor(closing)
                        if failed_cleanup:
                            raise CredentialError("private provisioning-profile descriptor cleanup could not be confirmed")
                        cancellation.check()
                        # Arm ownership before the syscall: interruption after a successful
                        # link must still remove our file, never a pre-existing destination.
                        attempted = True
                        event("link-intent")
                        try:
                            os.link(stage, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                            linked = True
                        except FileExistsError:
                            existing = snapshot(name)
                            if existing[0] != content:
                                raise CredentialError("a different provisioning profile appeared during installation") from None
                            require_current(name, existing[1])
                            linked = file_identity(existing[1]) == identity
                            if not linked:
                                reused_identity = file_identity(existing[1])
                        os.fsync(directory)
                        if not linked:
                            event("reused", identity=reused_identity)
                        event("linked", owned=linked)
                        cancellation.check()
                        try:
                            before = file_state(stage)
                            if file_identity(before) != identity:
                                conflict(stage)
                                raise CredentialError("private provisioning-profile staging file was replaced")
                            require_current(stage, before)
                            os.unlink(stage, dir_fd=directory)
                        except FileNotFoundError:
                            # Known owned absence still aborts admission, but is
                            # not an ambiguous stat/unlink result. An earlier
                            # require_current conflict remains latched, if any.
                            raise
                        except OSError:
                            # Entry can fail before ExitStack registers us. Keep
                            # this name conflicted even if unlink took effect;
                            # neither cleanup owner may implicitly retry it.
                            conflict(stage)
                            raise
                        stage = None
                        os.fsync(directory)
                        event("stage-removed")
                        cancellation.check()
                    # Our own stage unlink changes nlink/ctime. Obtain a FRESH
                    # bounded snapshot, but never reselect its admitted identity.
                    final_content, final_state = snapshot(name)
                    expected_identity = identity if linked else reused_identity
                    if final_content != content or file_identity(final_state) != expected_identity:
                        conflict(name)
                        raise CredentialError("provisioning profile changed before signing admission")
                    require_current(name, final_state)
                    cancellation.check()
                yield
        finally:
            # Normal with-exit dispatch precedes __exit__'s protected frame.
            scope.__exit__(*exc_info())
    except BaseException as error:
        fatal = fatal_cancellation_error(
            error, cancellation, "local profile cleanup is unconfirmed; end this process before retrying",
        )
        if fatal is not None:
            raise fatal from None
        if isinstance(error, OSError):
            raise CredentialError("provisioning profile could not be installed safely") from None
        raise


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


def _signing_profile_identity(profile_payload: dict) -> str:
    """Pure current-validity/UUID policy, after profile lifetime consumption."""
    from .ios import _profile_validity

    try:
        _profile_validity(profile_payload)
    except ProcessError:
        raise
    except ValidationError as error:
        raise CredentialError(str(error)) from None
    profile_uuid = profile_payload.get("UUID")
    if not isinstance(profile_uuid, str) or not PROFILE_UUID_RE.fullmatch(profile_uuid):
        raise CredentialError("provisioning profile UUID is missing or invalid")
    return profile_uuid


def _authenticated_signing_profile(profile: Path, *, cancellation: _ProfileCancellation) -> tuple[bytes, dict]:
    """Authenticate one original snapshot before creating account-session authority."""
    from .inspection import InspectionDeadline
    from .ios_profiles import decode_authenticated_profile, read_profile_bytes

    deadline = InspectionDeadline()
    evidence = ProfileCallEvidence(operation="load")
    primary = None
    try:
        supplied = read_profile_bytes(profile, cancellation=cancellation, deadline=deadline, _evidence=evidence)
        profile_payload = decode_authenticated_profile(supplied, cancellation=cancellation, deadline=deadline, _evidence=evidence)
    except BaseException as error:
        primary = error
    consume_profile_evidence(evidence, primary=primary,
                             message="local Apple profile lifetime is unconfirmed; end this invocation")
    if primary is not None:
        if isinstance(primary, ProcessError):
            raise primary
        if isinstance(primary, ValidationError):
            raise CredentialError(str(primary)) from None
        raise primary
    _signing_profile_identity(profile_payload)
    deadline.check()
    return supplied, profile_payload


@contextmanager
def _temporary_apple_signing_environment(
    *, p12: Path | InputSnapshot, password: str, profile: Path | InputSnapshot,
    directory: Path | FiniteScratch, home: Path | None = None, project_root: Path | None = None,
    lease: SigningLease | None = None,
    cancellation: _ProfileCancellation | None = None,
):
    """Lease all account-global resources; keep ambiguous work recoverable."""

    if type(directory) is not FiniteScratch and project_root is None:
        raise CredentialError("standalone Apple input selection requires its explicit project root")
    lease_context = local_signing_lease(home=home, cancellation=cancellation) if lease is None else nullcontext(lease)
    with lease_context as owner:
        owner._admit_execution()
        if owner.active is not None:
            raise CredentialError("this account lease already has an active signing context")
        if cancellation is not None and cancellation is not owner.cancellation:
            raise CredentialError("Apple material cancellation owner differs from its account lease")
        cancellation = owner.cancellation
        if type(directory) is not FiniteScratch:
            # Compatibility for private direct callers: they must name the
            # actual project boundary. No guessed cwd/root or external reopen.
            with finite_scratch(layout="signing-validation", cancellation=cancellation, parent=directory) as scratch:
                selected_p12 = _materialize(
                    {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH": str(p12)},
                    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
                    scratch, "distribution-p12", project_root=project_root,
                )
                selected_profile = _materialize(
                    {"MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH": str(profile)},
                    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64", "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
                    scratch, "apple-profile", project_root=project_root,
                )
                with _temporary_apple_signing_environment(
                    p12=selected_p12, password=password, profile=selected_profile,
                    directory=scratch, lease=owner, cancellation=cancellation,
                ) as updates:
                    yield updates
            return
        scratch = directory
        _material_guard(scratch, cancellation)
        # One genuine profile call finishes before any native account read.
        supplied, profile_payload = _authenticated_signing_profile(scratch.require(profile), cancellation=cancellation)
        scratch.require(profile)
        profile_uuid = profile_payload["UUID"]

        env = scrub_credential_capabilities(os.environ)
        env.update(HOME=str(owner.home), MOBILE_RELEASE_LOCAL_P12_PASSWORD=password)
        keychain_password = secrets.token_hex(32)
        installed_profile = ExitStack()
        profile_conflict = False
        session = owner.session()
        session.bind_runner(_run_private, environment=env)
        keychain = session.keychain
        creator_pid = os.getpid()

        def require(argv: list[str], action: str, kind: str) -> subprocess.CompletedProcess[str]:
            result = session.run(argv, kind=kind)
            if result.returncode:
                raise CredentialError(f"could not {action} for local Apple signing preflight")
            return result

        def extract(arguments: list[str], action: str) -> bytes:
            base = ["openssl", "pkcs12", "-in", str(scratch.require(p12)), *arguments,
                    "-passin", "env:MOBILE_RELEASE_LOCAL_P12_PASSWORD"]
            result = session.run(base, kind="extract")
            # Only a fully completed native nonzero allows the legacy-format
            # fallback. An ambiguous command is not automatically reissued.
            if result.returncode < 0:
                raise ProcessError("Apple extraction was interrupted; it cannot be retried", dispatched=True)
            if result.returncode > 0:
                scratch.require(p12)
                result = session.run(["openssl", "pkcs12", "-legacy", *base[2:]], kind="extract")
            if result.returncode < 0:
                raise ProcessError("Apple legacy extraction was interrupted; no further extraction is allowed", dispatched=True)
            if result.returncode:
                raise CredentialError(f"could not {action} for local Apple signing preflight")
            scratch.require(p12)
            return result.stdout.encode("utf-8")  # Original owned capture decoded strict UTF-8.

        def retain_profile() -> bool:
            return (session.unresolved or cancellation.lifetime_ledger.fatal
                    or (session.state is not None and session.state["inflight"] is not None))

        def preserve_profile_conflict() -> None:
            nonlocal profile_conflict
            profile_conflict = True  # No I/O; also active before installer registration.

        def cleanup_signing() -> None:
            primary = exc_info()[1]
            if creator_pid != os.getpid():
                return  # Child copies have been closed, never remove parent resources.
            # ExitStack.close() may detach a callback exception from the body.
            # Retain ALL earlier facts, even before a later failure makes them fatal.
            observed = preserve_lifetime_error(ProcessError(
                "local Apple signing resource cleanup is unconfirmed; end this process before retrying",
            ), previous=primary)
            cleanup_failed = False
            first_failure: BaseException | None = None

            def quarantine() -> None:
                if cancellation.lifetime_ledger.fatal or observed.fatal:
                    session.unresolved = True

            def failed(error: BaseException) -> None:
                nonlocal cleanup_failed, first_failure
                cleanup_failed = True
                if first_failure is None:
                    first_failure = error
                preserve_lifetime_error(observed, previous=error)
                if observed.fatal:
                    cancellation.lifetime_ledger._abort(error)
                quarantine()

            quarantine()  # Before either registered owner can inspect retention.
            session.cleaning = True
            try:
                try:
                    if session.fd is not None:
                        try:
                            if session.state is not None and session.state["inflight"] is not None:
                                if not session.journal_failed and not session.unresolved:
                                    try:
                                        session.finish_original_command_if_settled()
                                    except BaseException as error:
                                        failed(error)
                            if session.state is not None and not session.journal_failed and not retain_profile():
                                try:
                                    session.cleanup_native()
                                except BaseException as error:
                                    failed(error)
                        finally:
                            try:
                                installed_profile.close()
                            except BaseException as error:
                                failed(error)
                        # These are additional reconciliation/finalization, not
                        # the already-registered independent cleanup above.
                        if not observed.fatal and not retain_profile() and not session.journal_failed and not profile_conflict:
                            if session.intent is None or session.state is None:
                                cleanup_failed = session.cleanup_unstarted_initialization() or cleanup_failed
                            else:
                                try:
                                    session.cleanup_profile()
                                    cleanup_failed = session.finish() or cleanup_failed
                                except BaseException as error:
                                    failed(error)
                        else:
                            cleanup_failed = True
                finally:
                    try:
                        session.close()  # Only descriptors; residual authority stays private/on disk.
                    except BaseException as error:
                        failed(error)
            except BaseException as error:
                failed(error)
                if isinstance(first_failure, (KeyboardInterrupt, SystemExit)):
                    raise first_failure
                if observed.fatal:
                    raise observed from None
                raise
            if isinstance(first_failure, (KeyboardInterrupt, SystemExit)):
                raise first_failure
            if observed.fatal:
                raise observed from None
            if cleanup_failed:
                raise CredentialError("local Apple signing cleanup failed or observed a conflict; run mobile-release local-signing status before retrying")

        scope = _ProfileCleanup(cancellation, cleanup_signing, owns_cancellation=False, fork_cleanup=session.close,
                                first_primary=True)
        try:
            try:
                with scope:
                    session.open(create=True)
                    session.prepare(supplied, profile_uuid)
                    with cancellation.deferred():
                        installed_profile.enter_context(_temporary_profile_installation(
                            supplied, profile_uuid, owner.home, cancellation=cancellation,
                            observer=session.profile_event, reserved_stage=session.intent["profile"]["stage"], retain=retain_profile,
                            on_conflict=preserve_profile_conflict,
                        ))
                    require(["security", "create-keychain", "-p", keychain_password, str(keychain)],
                            "create an ephemeral keychain", "create")
                    require(["security", "set-keychain-settings", "-lut", "21600", str(keychain)],
                            "configure the ephemeral keychain", "settings")
                    require(["security", "unlock-keychain", "-p", keychain_password, str(keychain)],
                            "unlock the ephemeral keychain", "unlock")
                    certificate = scratch.put("signing-certificate", extract(
                        ["-clcerts", "-nokeys"], "extract the Apple distribution certificate"))
                    private_key = scratch.put("signing-private-key", extract(
                        ["-nocerts", "-nodes"], "extract the Apple distribution private key"))
                    chain = extract(["-cacerts", "-nokeys"], "extract the Apple distribution certificate chain")
                    imports = [(private_key, "identity"), (certificate, "certificate")]
                    if b"-----BEGIN CERTIFICATE-----" in chain:
                        imports.append((scratch.put("signing-chain", chain), "certificate chain"))
                    for snapshot, action in imports:
                        require(["security", "import", str(scratch.require(snapshot)), "-k", str(keychain), "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"],
                                f"import the Apple distribution {action}", "import")
                        scratch.require(snapshot)
                    require(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", keychain_password, str(keychain)],
                            "authorize codesign to use the ephemeral keychain", "partition")
                    session.activate()
                    cancellation.check()
                    yield {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": profile_uuid}
            finally:
                scope.__exit__(*exc_info())
        except BaseException as error:
            fatal = fatal_cancellation_error(
                error, cancellation, "local Apple signing cleanup is unconfirmed; end this process before retrying",
            )
            if fatal is not None:
                raise fatal from None
            if isinstance(error, OSError):
                raise CredentialError("local Apple signing state could not be prepared or retained safely; inspect local-signing status") from None
            raise


def _fingerprint_from_text(text: str) -> str | None:
    match = re.search(r"SHA(?:-)?256(?: fingerprint)?:?\s*=*\s*([0-9A-Fa-f:]{64,95})", text)
    return match.group(1).replace(":", "").lower() if match else None


def _validate_android_material(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path | FiniteScratch, *, execution_source=None, cancellation: _ProfileCancellation | None = None,
) -> Finding:
    if type(directory) is not FiniteScratch:
        with finite_scratch(layout="signing-validation", parent=directory, cancellation=cancellation) as scratch:
            return _validate_android_material(config, values, scratch, execution_source=execution_source,
                                              cancellation=scratch.cancellation)
    scratch = directory
    cancellation = _material_guard(scratch, cancellation)
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
            str(scratch.require(keystore)),
            "-alias",
            values["MOBILE_RELEASE_ANDROID_KEY_ALIAS"],
            "-storepass:env",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
            "-keypass:env",
            "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
        ],
        environ=env,
        execution_source=execution_source, cancellation=cancellation,
    )
    scratch.require(keystore)
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
    config: ReleaseConfig, values: Mapping[str, str], directory: Path | FiniteScratch, *, execution_source=None, cancellation: _ProfileCancellation | None = None,
) -> Finding:
    if type(directory) is not FiniteScratch:
        with finite_scratch(layout="signing-validation", parent=directory, cancellation=cancellation) as scratch:
            return _validate_p8(config, values, scratch, execution_source=execution_source,
                                cancellation=scratch.cancellation)
    scratch = directory
    cancellation = _material_guard(scratch, cancellation)
    p8 = _materialize(
        values,
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
        directory,
        "asc-p8",
        project_root=config.root,
    )
    if p8 is None:
        return Finding(
            "credential-material.apple-p8",
            Status.MISSING,
            "App Store Connect P8 private key is missing.",
            category="credentials",
        )
    return _validate_selected_p8(lambda: scratch.require(p8), execution_source=execution_source,
                                 cancellation=cancellation)


def _validate_selected_p8(
    selected_path: Callable[[], Path], *, execution_source=None,
    cancellation: _ProfileCancellation | None = None,
) -> Finding:
    """Shared native P-256 checks; the selected owner rechecks each input use."""
    result = _run_private(
        ["openssl", "pkey", "-in", str(selected_path()), "-check", "-noout"],
        environ=scrub_credential_capabilities(os.environ),
        execution_source=execution_source, cancellation=cancellation,
    )
    public = _run_private(
        ["openssl", "pkey", "-in", str(selected_path()), "-pubout", "-text_pub", "-noout"],
        environ=scrub_credential_capabilities(os.environ),
        execution_source=execution_source, cancellation=cancellation,
    )
    selected_path()
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
    config: ReleaseConfig, values: Mapping[str, str], directory: Path | FiniteScratch, *, execution_source=None, cancellation: _ProfileCancellation | None = None,
) -> list[Finding]:
    from .ios import _profile_validity
    from .ios_profiles import load_authenticated_profile

    if type(directory) is not FiniteScratch:
        with finite_scratch(layout="signing-validation", parent=directory, cancellation=cancellation) as scratch:
            return _validate_apple_signing_material(config, values, scratch, execution_source=execution_source,
                                                    cancellation=scratch.cancellation)
    scratch = directory
    cancellation = _material_guard(scratch, cancellation)
    p12 = _materialize(
        values,
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",
        directory,
        "distribution-p12",
        project_root=config.root,
    )
    profile = _materialize(
        values,
        "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
        "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",
        directory,
        "apple-profile",
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
    profile_path = scratch.require(profile)
    evidence = ProfileCallEvidence(operation="load")
    primary = None
    try:
        payload = load_authenticated_profile(profile_path, cancellation=cancellation, _evidence=evidence)
        scratch.require(profile)
    except BaseException as error:
        primary = error
    consume_profile_evidence(evidence, primary=primary,
                             message="Apple material profile lifetime is unconfirmed; end this invocation")
    try:
        if primary is not None:
            raise primary
        _profile_validity(payload)
    except ValidationError as error:
        if isinstance(error, ProcessError) and error.fatal:
            raise
        return [Finding(
            "credential-material.apple-profile", Status.INVALID,
            "Apple profile issuer, modern signed content or current validity could not be verified; "
            "use an Apple-issued profile and supported macOS tooling.", category="credentials",
        )]
    env = scrub_credential_capabilities(os.environ)
    env.update(values)

    def extract_pkcs12(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        command = ["openssl", "pkcs12", "-in", str(scratch.require(p12)), *arguments]
        result = _run_private(command, environ=env, execution_source=execution_source, cancellation=cancellation)
        if result.returncode < 0:
            raise ProcessError("Apple extraction was interrupted; it cannot be retried", dispatched=True)
        if result.returncode > 0:
            result = _run_private(
                ["openssl", "pkcs12", "-legacy", "-in", str(scratch.require(p12)), *arguments],
                environ=env,
                execution_source=execution_source, cancellation=cancellation,
            )
        if result.returncode < 0:
            raise ProcessError("Apple legacy extraction was interrupted; no further extraction is allowed", dispatched=True)
        scratch.require(p12)
        return result

    extract = extract_pkcs12(
        [
            "-clcerts",
            "-nokeys",
            "-passin",
            "env:MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
        ]
    )
    key_check = extract_pkcs12(
        [
            "-nocerts",
            "-nodes",
            "-passin",
            "env:MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
        ]
    )
    if extract.returncode or key_check.returncode or not extract.stdout or not key_check.stdout:
        findings.append(
            Finding(
                "credential-material.apple-p12",
                Status.INVALID,
                "Apple P12/password does not contain an extractable certificate and private key.",
                category="credentials",
            )
        )
        return findings
    certificate_content = extract.stdout.encode("utf-8")
    certificate = scratch.put("distribution-certificate", certificate_content)
    private_key = scratch.put("private-key", key_check.stdout.encode("utf-8"))
    certificate_check = _run_private(
        [
            "openssl",
            "x509",
            "-in",
            str(scratch.require(certificate)),
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
        execution_source=execution_source, cancellation=cancellation,
    )
    scratch.require(certificate)
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
    cert_public_result = _run_private(
        ["openssl", "x509", "-in", str(scratch.require(certificate)), "-pubkey", "-noout"],
        environ=env,
        execution_source=execution_source, cancellation=cancellation,
    )
    scratch.require(certificate)
    key_public_result = _run_private(
        ["openssl", "pkey", "-in", str(scratch.require(private_key)), "-pubout"],
        environ=env,
        execution_source=execution_source, cancellation=cancellation,
    )
    scratch.require(private_key)
    keys_match = (
        cert_public_result.returncode == 0
        and key_public_result.returncode == 0
        and bool(cert_public_result.stdout)
        and cert_public_result.stdout.encode("utf-8") == key_public_result.stdout.encode("utf-8")
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
            pem_text = certificate_content.decode("ascii")
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


def _firebase_content_matches_application(
    content: bytes | None, *, platform: str, expected_identity: str | None,
) -> bool:
    """Check selected client bytes, not a previously inspected source pathname."""
    if (type(content) is not bytes or not 0 < len(content) <= SMALL_PRIVATE_MATERIAL_SIZE
            or type(expected_identity) is not str or not expected_identity):
        return False
    if platform == "android":
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return False
        return _shared_firebase_payload_matches_application(
            payload, platform=platform, expected_identity=expected_identity,
        )
    if platform != "ios":
        return False
    import plistlib
    from xml.parsers.expat import ExpatError

    try:
        payload = plistlib.loads(content)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError, RecursionError, ExpatError):
        return False
    return _shared_firebase_payload_matches_application(
        payload, platform=platform, expected_identity=expected_identity,
    )


def _validate_firebase_material(
    config: ReleaseConfig, values: Mapping[str, str], directory: Path | FiniteScratch, platform: str,
    *, cancellation: _ProfileCancellation | None = None,
) -> Finding | None:
    policy_key = f"{platform}Firebase"
    if config.section("services").get(policy_key) != "required":
        return None
    if platform == "android":
        content = _selected_material_bytes(
            values,
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
            project_root=config.root, cancellation=cancellation,
        )
    else:
        content = _selected_material_bytes(
            values,
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",
            project_root=config.root, cancellation=cancellation,
        )
    valid = _firebase_content_matches_application(
        content, platform=platform,
        expected_identity=config.section(platform).get("applicationId" if platform == "android" else "bundleId"),
    )
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
    execution_source=None,
    cancellation: _ProfileCancellation | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    selected = tuple(platforms)
    if len(set(selected)) != len(selected) or any(platform not in {"android", "ios"} for platform in selected):
        raise CredentialError("signing material requires an exact platform selection")
    with finite_scratch(layout="signing-validation", cancellation=cancellation) as directory:
        cancellation = directory.cancellation
        values = credential_values_for_purpose(config, values, stage="candidate", purpose="signing", platforms=selected)
        for platform in selected:
            try:
                platform_findings = []
                if platform == "android":
                    platform_findings.append(_validate_android_material(config, values, directory,
                                                                        execution_source=execution_source, cancellation=cancellation))
                elif platform == "ios":
                    platform_findings.extend(_validate_apple_signing_material(config, values, directory,
                                                                             execution_source=execution_source, cancellation=cancellation))
                findings.extend(platform_findings)
                if any(item.status in FAILING_STATUSES for item in platform_findings):
                    break
                firebase = _validate_firebase_material(config, values, directory, platform, cancellation=cancellation)
                if firebase:
                    findings.append(firebase)
                    if firebase.status in FAILING_STATUSES:
                        break
            except ProcessError as error:
                if error.fatal:
                    raise
                findings.append(Finding(f"credential-material.{platform}", Status.INVALID,
                                        str(error), category="credentials"))
                break
            except (CredentialError, OSError) as error:
                findings.append(
                    Finding(
                        f"credential-material.{platform}",
                        Status.INVALID,
                        str(error),
                        category="credentials",
                    )
                )
                break
    return findings


def store_material_prerequisite_findings(
    *, values: Mapping[str, str], platforms: Iterable[str],
) -> list[Finding]:
    """Cheap absence diagnostics, with no credential read or native operation."""
    if "android" in platforms and not values.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return [Finding(
            "credential-material.google-adc", Status.MISSING,
            "Local Google Store preflight requires explicit Application Default Credentials.",
            category="credentials",
        )]
    return []


class SelectedStoreMaterial:
    """A live selection of exact Store-input bytes, not a mapping authorization.

    Files belong to the borrowed finite scratch. This object adds no account,
    project journal, command runner, or independent cleanup authority.
    """

    def __init__(self, config: ReleaseConfig, values: Mapping[str, str], platforms: tuple[str, ...],
                 scratch: FiniteScratch, invocation: InvocationCustody | None,
                 *, stage: str = "candidate") -> None:
        if (not platforms or len(set(platforms)) != len(platforms)
                or any(platform not in {"android", "ios"} for platform in platforms)):
            raise CredentialError("Store material requires an exact platform selection")
        self._config, self._root, self._config_path = config, config.root, config.path
        self._configuration = self._configuration_bytes(config)
        self._platforms, self._scratch, self._invocation = platforms, scratch, invocation
        self._pid, self._thread = os.getpid(), threading.current_thread()
        if stage not in STAGES:
            raise CredentialError("Store material stage is unsupported")
        self._stage = stage
        self._values = credential_values_for_purpose(
            config, values, stage=stage, purpose="store", platforms=platforms,
        )
        self._state = "selecting"
        self._p8: InputSnapshot | None = None
        self._adc: InputSnapshot | None = None
        self._p8_content: bytes | None = None
        self._adc_content: bytes | None = None

    @staticmethod
    def _configuration_bytes(config: ReleaseConfig) -> bytes:
        return json.dumps(config.data, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")

    def _owner(self) -> None:
        if (self._pid != os.getpid() or self._thread is not threading.current_thread()
                or self._state in {"closed", "rejected"}
                or self._config.root != self._root or self._config.path != self._config_path
                or self._configuration_bytes(self._config) != self._configuration):
            raise CredentialError("Store material selection is closed, changed, or belongs to another invocation")
        self._scratch._owner()
        if self._invocation is not None:
            if self._invocation.mode not in ("online", "store"):
                raise CredentialError("Store material selection requires its online or Store invocation")
            self._invocation.require(root=self._root, cancellation=self._scratch.cancellation)
            if self._invocation.mode == "store":
                record, binding = self._invocation.lane_evidence, self._scratch._lane_binding
                if binding is None or binding._record is not record:
                    raise CredentialError("Store material is not attached to its original composite record")
                record._origin(self._scratch.cancellation)
                record._resource(binding, self._scratch)

    def _acquire(self) -> None:
        self._owner()
        if "ios" in self._platforms:
            self._p8_content = _selected_material_bytes(
                self._values, "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",
                project_root=self._root, cancellation=self._scratch.cancellation,
            )
            if self._p8_content is not None:
                self._p8 = self._scratch.put("asc-p8", self._p8_content)
        self._state = "selected"

    def validate(self, *, execution_source=None) -> tuple[Finding, ...]:
        self._owner()
        if self._state != "selected":
            raise CredentialError("Store material validation cannot be repeated")
        self._state = "validating"
        findings: list[Finding] = []
        try:
            if "ios" in self._platforms:
                if self._p8 is None:
                    findings.append(Finding("credential-material.apple-p8", Status.MISSING,
                        "App Store Connect P8 private key is missing.", category="credentials"))
                else:
                    try:
                        findings.append(_validate_selected_p8(
                            lambda: self._scratch.require(self._p8), execution_source=execution_source,
                            cancellation=self._scratch.cancellation,
                        ))
                    except ProcessError as error:
                        if error.fatal:
                            raise
                        findings.append(Finding("credential-material.apple-p8", Status.INVALID,
                                                str(error), category="credentials"))
                if any(item.status in FAILING_STATUSES for item in findings):
                    self._state = "rejected"
                    return tuple(findings)
            if "android" in self._platforms:
                # Do not read a later platform's private input after an earlier
                # validation failure. No lane can use this selection until the
                # complete validation returns; its snapshot is then reused.
                self._owner()
                if adc := self._values.get("GOOGLE_APPLICATION_CREDENTIALS"):
                    try:
                        self._adc_content = read_external_bytes(Path(adc), kind="private-general",
                            project_root=self._root, cancellation=self._scratch.cancellation)
                    except ProcessError:
                        raise
                    except ValidationError as error:
                        raise CredentialError(str(error)) from None
                    self._adc = self._scratch.put("google-adc", self._adc_content)
                valid = False
                if self._adc is not None:
                    self._scratch.require(self._adc)
                    try:
                        payload = json.loads(self._adc_content)
                        valid = isinstance(payload, dict) and payload.get("type") in {
                            "external_account", "service_account", "authorized_user",
                        }
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass
                findings.append(Finding("credential-material.google-adc", Status.PASS if valid else Status.INVALID,
                    "Explicit Google ADC credential configuration is structurally valid." if valid
                    else "Explicit Google ADC credential configuration is missing or malformed.", category="credentials"))
            self._owner()
            self._state = "validated" if not any(item.status in FAILING_STATUSES for item in findings) else "rejected"
            return tuple(findings)
        except BaseException:
            self._state = "rejected"
            raise

    def require(self, *, config: ReleaseConfig, platforms: tuple[str, ...], invocation: InvocationCustody) -> None:
        self._owner()
        if (self._state != "validated" or type(invocation) is not InvocationCustody
                or self._invocation is not invocation or config is not self._config
                or tuple(platforms) != self._platforms):
            raise CredentialError("Store execution requires its original validated material selection")

    def require_store(self, *, config: ReleaseConfig, platform: str,
                      invocation: InvocationCustody, lane_evidence) -> None:
        self.require(config=config, platforms=(platform,), invocation=invocation)
        if invocation.mode != "store" or invocation.lane_evidence is not lane_evidence:
            raise CredentialError("Store lane requires its original Store material invocation")
        lane_evidence._origin(self._scratch.cancellation)
        binding = self._scratch._lane_binding
        if binding is None or binding._record is not lane_evidence:
            raise CredentialError("Store material composite binding differs")
        lane_evidence._resource(binding, self._scratch)

    def lane_environment(self, *, platform: str | None = None) -> dict[str, str]:
        self._owner()
        if self._state != "validated" or self._invocation is None:
            raise CredentialError("standalone or unvalidated material grants no Store execution environment")
        if platform is not None and platform not in self._platforms:
            raise CredentialError("Store material was not selected for this platform")
        selected = self._platforms if platform is None else (platform,)
        result = credential_values_for_purpose(
            self._config, self._values, stage=self._stage, purpose="store", platforms=selected,
        )
        if "ios" in selected:
            if self._p8 is None or self._p8_content is None:
                raise CredentialError("selected P8 material is unavailable")
            self._scratch.require(self._p8)
            result.pop("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH", None)
            result["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"] = base64.b64encode(self._p8_content).decode("ascii")
        if "android" in selected:
            if self._adc is None:
                raise CredentialError("selected ADC material is unavailable")
            result["GOOGLE_APPLICATION_CREDENTIALS"] = str(self._scratch.require(self._adc))
        return result

    def _close(self) -> None:
        self._state = "closed"
        self._values = {}
        self._p8_content = self._adc_content = None


@contextmanager
def _selected_store_material(
    config: ReleaseConfig, *, values: Mapping[str, str], platforms: Iterable[str],
    invocation: InvocationCustody | None = None, cancellation: _ProfileCancellation | None = None,
    stage: str = "candidate", lane_evidence=None,
):
    if invocation is not None:
        if type(invocation) is not InvocationCustody:
            raise CredentialError("Store selection requires its actual invocation owner")
        if cancellation is not None and cancellation is not invocation.cancellation:
            raise CredentialError("Store selection cancellation differs from its invocation")
        cancellation = invocation.cancellation
        if lane_evidence is not invocation.lane_evidence:
            raise CredentialError("Store selection composite differs from its original invocation")
    elif lane_evidence is not None:
        raise CredentialError("Composite Store selection requires its original invocation")
    with finite_scratch(layout="store-selection", cancellation=cancellation,
                        lane_evidence=lane_evidence) as scratch:
        selected = SelectedStoreMaterial(config, values, tuple(platforms), scratch, invocation, stage=stage)
        try:
            selected._acquire()
            yield selected
        finally:
            selected._close()


def validate_store_material(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
    execution_source=None,
    cancellation: _ProfileCancellation | None = None,
) -> list[Finding]:
    selected = tuple(platforms)
    findings = store_material_prerequisite_findings(values=values, platforms=selected)
    if findings:
        return findings
    try:
        with _selected_store_material(config, values=values, platforms=selected,
                                      cancellation=cancellation) as material:
            return list(material.validate(execution_source=execution_source))
    except ProcessError:
        raise
    except (CredentialError, OSError) as error:
        return [Finding("credential-material.private-path", Status.INVALID,
                        str(error), category="credentials")]


def store_lane_environment(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
    cancellation: _ProfileCancellation | None = None,
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
        try:
            content = read_external_bytes(Path(path_value), kind="private-small",
                                          project_root=config.root, cancellation=cancellation)
        except ProcessError:
            raise
        except ValidationError as error:
            raise CredentialError(str(error)) from None
        result["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"] = base64.b64encode(content).decode(
            "ascii"
        )
        result.pop("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH", None)
    return result


_GENERATED_PROFILE_SPECIFIER = "MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"


class _MaterializedBuildEnvironment(dict[str, str]):
    """Compatible mapping; generated iOS data borrows only its live child."""

    def __init__(self, values: Mapping[str, str], inputs: BuildInputs, profile_specifier: str | None) -> None:
        super().__init__(values)
        self._inputs, self._invocation = inputs, inputs.invocation
        self._cancellation = inputs.cancellation
        self._lease = inputs.invocation.signing_lease
        self._specifier, self._live = profile_specifier, True


def materialized_profile_specifier(values: Mapping[str, str], *, invocation: InvocationCustody) -> str | None:
    """Generated profile data is not a generic credential/environment capability."""
    if _GENERATED_PROFILE_SPECIFIER not in values:
        return None
    if (type(values) is not _MaterializedBuildEnvironment or not values._live
            or type(invocation) is not InvocationCustody or values._invocation is not invocation
            or values._inputs.invocation is not invocation or invocation.child is not values._inputs
            or values._inputs.claimed or not values._inputs.prepared
            or values._cancellation is not invocation.cancellation or values._lease is not invocation.signing_lease
            or invocation.mode != "build" or values._lease is None
            or type(values._specifier) is not str or not PROFILE_UUID_RE.fullmatch(values._specifier)
            or values[_GENERATED_PROFILE_SPECIFIER] != values._specifier):
        raise CredentialError("generated profile selection requires its unchanged live iOS materialization")
    invocation.require(root=invocation.root, cancellation=values._cancellation, signing_lease=values._lease)
    return values._specifier


@contextmanager
def materialize_build_inputs(
    config: ReleaseConfig,
    *,
    values: Mapping[str, str],
    platforms: Iterable[str],
    prepare_ios_signing: bool = False,
    signing_lease: SigningLease | None = None,
    cancellation: _ProfileCancellation | None = None,
    build_inputs: BuildInputs | None = None,
):
    """Borrow one complete build-input lifetime, or acquire its outers once."""
    if signing_lease is not None:
        if cancellation is not None and cancellation is not signing_lease.cancellation:
            raise CredentialError("build material cancellation owner differs from its account lease")
        # A quarantined borrowed owner must refuse before even evaluating the
        # caller's platform iterable, let alone reserving environment/project
        # state or selecting private input bytes.
        signing_lease._admit_execution()
        cancellation = signing_lease.cancellation
    selected = tuple(platforms)
    if (not selected or len(set(selected)) != len(selected)
            or any(platform not in {"android", "ios"} for platform in selected)):
        raise CredentialError("build material requires an exact platform selection")
    if (prepare_ios_signing and "ios" in selected and signing_lease is not None
            and signing_lease.active is not None):
        raise CredentialError("this account lease already has an active signing context")
    if build_inputs is None:
        # Standalone order: guard/environment -> account -> project -> one
        # child. A supplied lease is borrowed, never acquired/released here.
        with invocation_custody(config.root, mode="build", cancellation=cancellation) as invocation:
            lease_context = (local_signing_lease(cancellation=invocation.cancellation)
                if prepare_ios_signing and "ios" in selected and signing_lease is None else nullcontext(signing_lease))
            with lease_context as owner:
                with invocation.project(signing_lease=owner), invocation.materialization(signing_lease=owner) as child:
                    with materialize_build_inputs(config, values=values, platforms=selected,
                        prepare_ios_signing=prepare_ios_signing, signing_lease=owner,
                        cancellation=invocation.cancellation, build_inputs=child) as materialized:
                        yield materialized
        return
    if type(build_inputs) is not BuildInputs or type(build_inputs.invocation) is not InvocationCustody:
        raise CredentialError("build material requires its original materialization owner")
    invocation = build_inputs.invocation
    if (cancellation is not None and cancellation is not invocation.cancellation
            or signing_lease is not invocation.signing_lease
            or invocation.child is not build_inputs or build_inputs.claimed or build_inputs.prepared
            or build_inputs.cancellation is not invocation.cancellation):
        raise CredentialError("build material invocation, child or cancellation binding differs")
    cancellation = invocation.cancellation
    invocation.require(root=config.root, cancellation=cancellation, signing_lease=signing_lease)
    if prepare_ios_signing and "ios" in selected:
        if signing_lease is None or signing_lease.active is not None:
            raise CredentialError("signed iOS material requires its unused original account lease")
    scratch = build_inputs.scratch
    _material_guard(scratch, cancellation)
    values = dict(values)  # After environment/account/project admission, not before.
    material: dict[str, InputSnapshot] = {}
    for platform, base64_name, path_name, role in (
        ("android", "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64", "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH", "android-keystore"),
        ("ios", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH", "distribution-p12"),
        ("ios", "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64", "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH", "apple-profile"),
    ):
        if platform in selected:
            snapshot = _materialize(values, base64_name, path_name, scratch, role, project_root=config.root)
            if snapshot is not None:
                material[role] = snapshot

    replacements: list[TargetReplacement] = []
    if "android" in selected and config.section("services").get("androidFirebase") == "required":
        from .discovery import discover_project, selected_android_module

        content = _selected_material_bytes(values, "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH", project_root=config.root, cancellation=cancellation)
        if not _firebase_content_matches_application(
            content, platform="android", expected_identity=config.section("android").get("applicationId"),
        ):
            raise CredentialError("Android Firebase client file is missing, malformed, or for another application")
        module = selected_android_module(config, discover_project(config.root, include_git=False, cancellation=cancellation,
            execution_source=None if signing_lease is None else signing_lease.execution_source()))
        if not module:
            raise CredentialError("Android Firebase material or application module is unavailable")
        module_relative = module.lstrip(":").replace(":", "/")
        try:
            module_dir = config.project_path(module_relative)
            target = config.project_path((module_relative + "/" if module_relative else "") + "google-services.json")
        except ConfigurationError as error:
            raise CredentialError("Android Firebase destination must not traverse a symbolic link") from error
        if not module_dir.is_dir():
            raise CredentialError("Android Firebase application module is unavailable")
        replacements.append(TargetReplacement("android-services", PurePosixPath(target.relative_to(config.root)), content))

    if "ios" in selected and config.section("services").get("iosFirebase") == "required":
        content = _selected_material_bytes(values, "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH", project_root=config.root, cancellation=cancellation)
        if not _firebase_content_matches_application(
            content, platform="ios", expected_identity=config.section("ios").get("bundleId"),
        ):
            raise CredentialError("iOS Firebase client file is missing, malformed, or for another application")
        examples = []
        for path in config.root.rglob("GoogleService-Info.plist.example"):
            cancellation.check()
            if ".git" in path.parts or "build" in path.parts or ".mobile-release" in path.parts:
                continue
            try:
                examples.append(config.project_path(str(path)))
            except ConfigurationError as error:
                raise CredentialError("iOS Firebase marker must not traverse a symbolic link") from error
            if len(examples) > 1:
                break
        if len(examples) != 1:
            raise CredentialError("iOS Firebase requires exactly one tracked GoogleService-Info.plist.example")
        try:
            target = config.project_path(str(examples[0].with_suffix("")))
        except ConfigurationError as error:
            raise CredentialError("iOS Firebase destination must not traverse a symbolic link") from error
        replacements.append(TargetReplacement("ios-services", PurePosixPath(target.relative_to(config.root)), content))

    # All selected bytes and destinations precede the one fully staged batch.
    # The existing owner checks every parent/original and rolls back safely.
    build_inputs.replace_all(tuple(replacements))
    build_environment: dict[str, str] = {}
    if "android-keystore" in material:
        build_environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"] = str(scratch.require(material["android-keystore"]))
    signing_context = nullcontext({})
    if prepare_ios_signing and "ios" in selected:
        p12, profile = material.get("distribution-p12"), material.get("apple-profile")
        password = values.get("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD")
        if p12 is None or profile is None or password is None:
            raise CredentialError("Apple signing material is incomplete for a signed local build")
        signing_context = _temporary_apple_signing_environment(p12=p12, password=password, profile=profile,
            directory=scratch, lease=signing_lease, cancellation=cancellation)
    with signing_context as signing_updates:
        profile_specifier = signing_updates.get(_GENERATED_PROFILE_SPECIFIER)
        if profile_specifier is not None:
            if type(profile_specifier) is not str or not PROFILE_UUID_RE.fullmatch(profile_specifier):
                raise CredentialError("local signing did not return a valid generated profile selection")
            build_environment[_GENERATED_PROFILE_SPECIFIER] = profile_specifier
        if "android" in selected:
            for name in ("MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                         "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"):
                if values.get(name):
                    build_environment[name] = values[name]
        if values.get("MOBILE_RELEASE_PROJECT_READ_TOKEN"):
            build_environment["MOBILE_RELEASE_PROJECT_READ_TOKEN"] = values["MOBILE_RELEASE_PROJECT_READ_TOKEN"]
        environment = _MaterializedBuildEnvironment(build_environment, build_inputs, profile_specifier)
        try:
            invocation.require(root=config.root, cancellation=cancellation, signing_lease=signing_lease)
            yield environment
        finally:
            environment._live = False
