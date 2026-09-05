from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .config import ReleaseConfig, ReleaseVersion
from .credentials import artifact_validation_environment
from .discovery import discover_project, selected_ios_container, selected_ios_scheme
from .errors import ValidationError
from .inspection import InspectionDeadline
from .reporting import FAILING_STATUSES, Finding, Status
from .tooling import recreate_private_build_directory

MAX_ENTRY_SIZE = 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
ALLOWED_ARTIFACT_NAMES = {"ios-ipa", "ios-archive", "ios-dsyms"}
NESTED_CODE_SUFFIXES = {
    ".appex",
    ".app",
    ".dylib",
    ".framework",
    ".xpc",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
MAX_NESTED_CODE_ITEMS = 512
PROFILE_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
MAX_GENERATED_FILES = 100_000
MAX_GENERATED_BYTES = 8 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class SigningValidityInterval:
    """Private result of current signing validation, never independent authority.

    This is the intersection of the actual leaf certificates and embedded
    provisioning profiles that were checked. It permits a cheap recheck after
    the last Store read, not choosing an old date for a new upload.
    """

    lower_bound: datetime
    upper_bound: datetime

    def __post_init__(self) -> None:
        for value in (self.lower_bound, self.upper_bound):
            if not isinstance(value, datetime) or value.tzinfo != timezone.utc:
                raise ValidationError("signing validity bounds must be UTC datetimes")
        if self.lower_bound >= self.upper_bound:
            raise ValidationError("signing validity interval is empty or reversed")

    def require_current(self) -> None:
        if not self.lower_bound <= _utc_now() < self.upper_bound:
            raise ValidationError(
                "IPA signing certificate or provisioning profile is not currently valid; "
                "do not re-sign or rebuild this candidate to retry its original intent"
            )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _profile_validity(profile: dict[str, Any]) -> SigningValidityInterval:
    creation = profile.get("CreationDate")
    expiration = profile.get("ExpirationDate")
    if not isinstance(creation, datetime) or not isinstance(expiration, datetime):
        raise ValidationError("profile lacks valid CreationDate/ExpirationDate bounds")
    interval = SigningValidityInterval(_utc_datetime(creation), _utc_datetime(expiration))
    interval.require_current()
    return interval


def validate_preparation_signing_time(
    interval: SigningValidityInterval, server_observed_at: str
) -> None:
    """Bind freshly validated dates to the preparer's real ASC observation.

    The original attested preparer authenticates this observation. This helper
    does not turn an HTTP Date header or an arbitrary old time into permission
    to upload and is never a historical codesign verifier.
    """

    if not isinstance(server_observed_at, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", server_observed_at
    ):
        raise ValidationError("preparation observation must be second-precision UTC RFC3339")
    try:
        observed = datetime.fromisoformat(server_observed_at.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValidationError("preparation observation must be a real UTC timestamp") from error
    if not interval.lower_bound <= observed < interval.upper_bound:
        raise ValidationError("preparation observation is outside the validated signing interval")


def _validation_environment() -> dict[str, str]:
    return artifact_validation_environment(os.environ)


def _run_native(argv: list[str], *, deadline: InspectionDeadline | None = None, **kwargs: Any) -> subprocess.CompletedProcess:
    # Never start another child after the shared inspection budget expires.
    # Already-running tools keep their explicit subprocess timeout, not a new
    # inspection clock. This is cooperative bounding, not syscall preemption.
    if deadline is not None:
        deadline.check()
    result = subprocess.run(argv, **kwargs)
    if deadline is not None:
        deadline.check()
    return result


def _validated_ipa_entries(path: Path, *, deadline: InspectionDeadline | None = None) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    if deadline is not None:
        deadline.check()
    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"IPA must be a regular non-symlink file: {path}")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise ValidationError("IPA is not a valid ZIP archive") from error
    entries = archive.infolist()
    if len(entries) > 100_000:
        archive.close()
        raise ValidationError("IPA contains an unreasonable number of ZIP entries")
    seen: set[str] = set()
    portable_seen: set[str] = set()
    total = 0
    for entry in entries:
        if deadline is not None:
            try:
                deadline.check()
            except ValidationError:
                archive.close()
                raise
        raw_name = entry.filename
        portable_name = unicodedata.normalize("NFC", raw_name).casefold().rstrip("/")
        pure = PurePosixPath(raw_name)
        parts = raw_name.split("/")
        path_parts = parts[:-1] if raw_name.endswith("/") else parts
        mode = (entry.external_attr >> 16) & 0o170000
        if (
            not raw_name
            or raw_name.startswith("/")
            or "\\" in raw_name
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in path_parts)
            or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
            or entry.flag_bits & 0x1
            or any(ord(character) < 32 or ord(character) == 127 for character in raw_name)
        ):
            archive.close()
            raise ValidationError(f"unsafe IPA entry path: {entry.filename}")
        if entry.filename in seen:
            archive.close()
            raise ValidationError(f"duplicate IPA entry: {entry.filename}")
        seen.add(entry.filename)
        if portable_name in portable_seen:
            archive.close()
            raise ValidationError(
                f"IPA has a case/Unicode-normalizing path collision: {entry.filename}"
            )
        portable_seen.add(portable_name)
        if entry.file_size > MAX_ENTRY_SIZE:
            archive.close()
            raise ValidationError(f"oversized IPA entry: {entry.filename}")
        total += entry.file_size
        if total > MAX_TOTAL_SIZE:
            archive.close()
            raise ValidationError("IPA uncompressed content exceeds safety limit")
    try:
        if archive.testzip() is not None:
            raise ValidationError("IPA contains a corrupt entry")
        if deadline is not None:
            deadline.check()
    except BaseException:
        archive.close()
        raise
    return archive, entries


def _profile_details(path: Path, *, deadline: InspectionDeadline | None = None) -> dict[str, Any] | None:
    if sys.platform != "darwin":
        return None
    from .ios_profiles import load_authenticated_profile

    return load_authenticated_profile(path, deadline=deadline)


def _code_executable(code_path: Path, *, deadline: InspectionDeadline) -> Path | None:
    """Identify an exact bundle executable, never borrow a neighboring profile."""
    from .ios_entitlements import MAX_PLIST_BYTES, load_plist_dictionary

    deadline.check()
    if code_path.is_symlink():
        raise ValidationError("signed code must not be a symbolic link")
    if code_path.is_file():
        return code_path
    if not code_path.is_dir():
        raise ValidationError("signed code object is missing or is not a regular file/bundle")
    info_path = code_path / "Info.plist"
    executable_required = code_path.suffix.lower() in {".app", ".appex", ".framework", ".xpc"}
    if not info_path.exists() and not info_path.is_symlink() and not executable_required:
        return None  # Non-executable signed resources still get empty-claim checks.
    if info_path.is_symlink() or not info_path.is_file() or info_path.stat().st_size > MAX_PLIST_BYTES:
        raise ValidationError("signed bundle Info.plist must be a bounded regular file")
    info = load_plist_dictionary(info_path.read_bytes(), deadline=deadline)
    executable = info.get("CFBundleExecutable")
    if executable is None and not executable_required:
        return None
    if (type(executable) is not str or not executable or executable in {".", ".."}
            or any(char in executable for char in "/\\:")
            or any(ord(char) < 32 or ord(char) == 127 for char in executable)):
        raise ValidationError("signed bundle executable must be a safe local basename")
    path = code_path / executable
    if path.is_symlink() or not path.is_file():
        raise ValidationError("signed bundle's declared executable is missing or unsafe")
    return path


def _code_architectures(code_path: Path, *, deadline: InspectionDeadline) -> tuple[str | None, ...]:
    from .macho import inspect_macho

    executable = _code_executable(code_path, deadline=deadline)
    if executable is None:
        return (None,)
    return tuple(f"{item.cpu},{item.subtype}" for item in inspect_macho(executable, deadline=deadline))


def _architecture_options(architecture: str | None) -> list[str]:
    return ["--architecture", architecture] if architecture is not None else []


def _codesign_fingerprint(
    app_path: Path,
    temporary: Path,
    *,
    _validity_intervals: list[SigningValidityInterval] | None = None,
    deadline: InspectionDeadline | None = None,
) -> str | None:
    if sys.platform != "darwin" or not shutil.which("codesign") or not shutil.which("openssl"):
        return None
    verify = _run_native(
        ["codesign", "--verify", "--all-architectures", "--deep", "--strict", "--verbose=2", str(app_path)],
        deadline=deadline,
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if verify.returncode:
        raise ValidationError("codesign rejected the exported application or nested code")
    return _codesign_leaf_fingerprint(
        app_path, temporary / "signer", _validity_intervals=_validity_intervals, deadline=deadline,
    )


def _openssl_certificate_date(value: str) -> datetime:
    # OpenSSL's default certificate-date format is English/GMT. Do not let
    # locale, offset guessing, omitted zones, or permissive date parsers choose
    # a different interpretation of a certificate's actual validity bounds.
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    match = re.fullmatch(
        r"([A-Za-z]{3}) {1,2}([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4}) GMT",
        value,
    )
    if match is None or match.group(1) not in months:
        raise ValidationError("signing certificate date is not an unambiguous GMT datetime")
    month, day, hour, minute, second, year = match.groups()
    try:
        return datetime(
            int(year), months.index(month) + 1, int(day), int(hour), int(minute), int(second),
            tzinfo=timezone.utc,
        )
    except ValueError as error:
        raise ValidationError("signing certificate date is not a real UTC datetime") from error


def _codesign_leaf_fingerprint(
    code_path: Path,
    prefix: Path,
    *,
    _validity_intervals: list[SigningValidityInterval] | None = None,
    deadline: InspectionDeadline | None = None,
) -> str:
    deadline = deadline if deadline is not None else InspectionDeadline()
    fingerprints = []
    # Fresh private names for every object AND slice: successful extraction
    # without a leaf cannot reuse a stale certificate from another invocation.
    with tempfile.TemporaryDirectory(prefix="mobile-release-leaf-", dir=prefix.parent) as directory:
        for index, architecture in enumerate(_code_architectures(code_path, deadline=deadline)):
            fingerprints.append(_codesign_slice_fingerprint(
                code_path, Path(directory) / f"slice-{index}-", architecture=architecture,
                _validity_intervals=_validity_intervals, deadline=deadline,
            ))
    if len(set(fingerprints)) != 1:
        raise ValidationError("signed code architectures do not share the same leaf signer")
    return fingerprints[0]


def _codesign_slice_fingerprint(
    code_path: Path, prefix: Path, *, architecture: str | None,
    _validity_intervals: list[SigningValidityInterval] | None,
    deadline: InspectionDeadline,
) -> str:
    extract = _run_native(
        ["codesign", "-d", *_architecture_options(architecture), "--extract-certificates", str(prefix), str(code_path)],
        deadline=deadline,
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    certificate = prefix.parent / f"{prefix.name}0"
    if (extract.returncode or certificate.is_symlink() or not certificate.is_file()
            or not 0 < certificate.stat().st_size <= 1024 * 1024):
        raise ValidationError("codesign could not extract the leaf signing certificate")
    fingerprint = _run_native(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-in",
            str(certificate),
            "-noout",
            "-fingerprint",
            "-sha256",
            "-dates",
        ],
        deadline=deadline,
        env=_validation_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if fingerprint.returncode:
        raise ValidationError("openssl could not inspect the leaf signing certificate")
    fingerprints = re.findall(
        r"(?m)^(?:sha256|SHA256) Fingerprint=((?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{64})$",
        fingerprint.stdout,
    )
    if len(fingerprints) != 1:
        raise ValidationError("signing certificate output lacks a SHA-256 fingerprint")
    before = re.findall(r"(?m)^notBefore=(.*)$", fingerprint.stdout)
    after = re.findall(r"(?m)^notAfter=(.*)$", fingerprint.stdout)
    if len(before) != 1 or len(after) != 1:
        raise ValidationError("signing certificate output lacks unique validity bounds")
    interval = SigningValidityInterval(
        _openssl_certificate_date(before[0]), _openssl_certificate_date(after[0])
    )
    # Default codesign verification can accept expired/postdated certificates.
    # Native signature verification remains mandatory, but it is not this date
    # check. Derive dates from the exact leaf extracted from the signed code.
    interval.require_current()
    if _validity_intervals is not None:
        _validity_intervals.append(interval)
    return fingerprints[0].replace(":", "").lower()


def _nested_codesign_identities(
    app_path: Path,
    temporary: Path,
    *,
    _validity_intervals: list[SigningValidityInterval] | None = None,
    deadline: InspectionDeadline | None = None,
) -> list[tuple[Path, str, str]] | None:
    if sys.platform != "darwin" or not shutil.which("codesign") or not shutil.which("openssl"):
        return None
    deadline = deadline if deadline is not None else InspectionDeadline()
    def is_macho(path: Path) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        try:
            with path.open("rb") as handle:
                return handle.read(4) in MACHO_MAGICS
        except OSError as error:
            raise ValidationError(
                f"nested code could not be inspected safely: {path.name}"
            ) from error

    nested_candidates: set[Path] = set()
    for path in app_path.rglob("*"):
        if deadline is not None:
            deadline.check()
        if path.is_symlink():
            raise ValidationError(f"nested code must not be a symbolic link: {path.name}")
        if path.suffix.lower() in NESTED_CODE_SUFFIXES and (
            path.is_dir() or path.is_file()
        ):
            nested_candidates.add(path)
        if is_macho(path):
            nested_candidates.add(path)
        if path.name == "CodeResources" and path.parent.name == "_CodeSignature":
            signed_container = path.parent.parent
            if signed_container != app_path:
                nested_candidates.add(signed_container)
    nested = sorted(nested_candidates, key=lambda item: item.as_posix())
    if len(nested) > MAX_NESTED_CODE_ITEMS:
        raise ValidationError("IPA contains too many nested signed-code components")
    profiled_bundles = [app_path] + [path for path in nested if path.is_dir() and path.suffix.lower() in {".app", ".appex"}]
    profiled_executables = {_code_executable(path, deadline=deadline) for path in profiled_bundles}
    result: list[tuple[Path, str, str]] = []
    for index, code_path in enumerate(nested):
        requirement = _run_native(
            [
                "codesign",
                "--verify",
                "--all-architectures",
                "--strict",
                "--verbose=2",
                "--test-requirement",
                "=designated",
                str(code_path),
            ],
            deadline=deadline,
            env=_validation_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if requirement.returncode:
            raise ValidationError(
                f"nested code does not satisfy its designated requirement: {code_path.name}"
            )
        teams = []
        for architecture in _code_architectures(code_path, deadline=deadline):
            details = _run_native(
                ["codesign", "-d", *_architecture_options(architecture), "--verbose=4", str(code_path)],
                deadline=deadline, env=_validation_environment(), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
            )
            if details.returncode:
                raise ValidationError("codesign could not inspect a nested code architecture")
            matches = re.findall(r"(?m)^TeamIdentifier=(.*)$", details.stderr + details.stdout)
            if len(matches) != 1 or not re.fullmatch(r"[A-Z0-9]{10}", matches[0]):
                raise ValidationError("nested code architecture lacks a unique valid TeamIdentifier")
            teams.append(matches[0])
        if len(set(teams)) != 1:
            raise ValidationError("nested code architectures do not share one TeamIdentifier")
        team = teams[0]
        fingerprint = _codesign_leaf_fingerprint(
            code_path, temporary / f"nested-signer-{index}-",
            _validity_intervals=_validity_intervals, deadline=deadline,
        )
        if code_path.is_dir() and code_path.suffix.lower() in {".app", ".appex"}:
            entitlements = _codesign_entitlements(code_path, deadline=deadline)
            if entitlements is None:
                raise ValidationError(
                    f"nested application entitlements could not be inspected: {code_path.name}"
                )
            _validate_nested_bundle_security(
                code_path,
                entitlements=entitlements,
                team_id=team,
                signer_fingerprint=fingerprint,
                _validity_intervals=_validity_intervals,
                deadline=deadline,
            )
        elif code_path not in profiled_executables:
            entitlements = _codesign_entitlements(code_path, deadline=deadline)
            if entitlements is None or entitlements:
                raise ValidationError(
                    "profileless nested code has signed entitlement claims; frameworks, libraries, "
                    "helpers and unsupported executable bundles cannot borrow an app's profile"
                )
        result.append((code_path, team, fingerprint))
    return result


def _codesign_entitlements(app_path: Path, *, deadline: InspectionDeadline | None = None) -> dict[str, Any] | None:
    if sys.platform != "darwin" or not shutil.which("codesign"):
        return None
    from .ios_der import decode_der_dictionary
    from .ios_entitlements import load_plist_dictionary, typed_value

    deadline = deadline if deadline is not None else InspectionDeadline()
    payload = None
    for architecture in _code_architectures(app_path, deadline=deadline):
        representations = []
        for encoding, decode in (("--der", decode_der_dictionary), ("--xml", load_plist_dictionary)):
            result = _run_native(
                ["codesign", "-d", *_architecture_options(architecture), "--entitlements", "-", encoding, str(app_path)],
                deadline=deadline, env=_validation_environment(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False,
            )
            if result.returncode:
                raise ValidationError("codesign could not inspect a signed entitlement architecture")
            representations.append(decode(result.stdout, deadline=deadline) if result.stdout else {})
        # --xml can render DER rather than the legacy XML signature slot. This
        # compares native decoder views; it is not independent legacy-slot proof.
        if typed_value(representations[0], deadline=deadline) != typed_value(representations[1], deadline=deadline):
            raise ValidationError("signed entitlement DER/XML views disagree or modern DER is missing")
        if payload is not None and typed_value(payload, deadline=deadline) != typed_value(representations[0], deadline=deadline):
            raise ValidationError("signed entitlements differ between code architectures")
        payload = representations[0]
    return payload


def _profile_certificate_fingerprints(profile: dict[str, Any]) -> set[str]:
    certificates = profile.get("DeveloperCertificates")
    if not isinstance(certificates, list) or not certificates or any(
        not isinstance(certificate, bytes) or not certificate for certificate in certificates
    ):
        raise ValidationError("provisioning profile lacks valid developer certificates")
    return {hashlib.sha256(certificate).hexdigest() for certificate in certificates}


def _utc_datetime(value: datetime) -> datetime:
    # plistlib uses naive datetimes for UTC by default. Explicit offset-aware
    # values are normalized, never interpreted in the runner's local timezone.
    try:
        if value.tzinfo is not None and value.utcoffset() is None:
            raise ValueError("timezone has no defined offset")
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )
    except (ValueError, OverflowError, TypeError) as error:
        raise ValidationError("profile date must represent a real UTC datetime") from error


def _validate_nested_bundle_security(
    code_path: Path,
    *,
    entitlements: dict[str, Any],
    team_id: str,
    signer_fingerprint: str,
    _validity_intervals: list[SigningValidityInterval] | None = None,
    deadline: InspectionDeadline | None = None,
) -> None:
    """Bind a nested app/extension to its signer, profile, team, and release entitlements."""

    from .ios_entitlements import load_plist_dictionary, validate_profile_entitlements

    info_path = code_path / "Info.plist"
    try:
        if (
            info_path.is_symlink()
            or not info_path.is_file()
            or info_path.stat().st_size > 2 * 1024 * 1024
        ):
            raise OSError("unsafe nested Info.plist")
        info = load_plist_dictionary(info_path.read_bytes(), deadline=deadline)
    except OSError as error:
        raise ValidationError(
            f"nested application Info.plist is missing or invalid: {code_path.name}"
        ) from error
    bundle_id = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
    application_identifier = entitlements.get("application-identifier")
    if (
        not isinstance(bundle_id, str)
        or not bundle_id
        or not isinstance(application_identifier, str)
        or application_identifier != f"{team_id}.{bundle_id}"
        or entitlements.get("com.apple.developer.team-identifier") != team_id
        or ("get-task-allow" in entitlements and entitlements["get-task-allow"] is not False)
    ):
        raise ValidationError(
            f"nested application entitlements do not match its signing team: {code_path.name}"
        )
    profile_path = code_path / "embedded.mobileprovision"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise ValidationError(
            f"nested application lacks a safe embedded provisioning profile: {code_path.name}"
        )
    profile = _profile_details(profile_path, deadline=deadline)
    if profile is None:
        raise ValidationError(
            f"nested provisioning profile could not be inspected: {code_path.name}"
        )
    profile_entitlements = profile.get("Entitlements")
    teams = profile.get("TeamIdentifier")
    interval = _profile_validity(profile)
    if (
        not isinstance(profile_entitlements, dict)
        or profile_entitlements.get("application-identifier") != application_identifier
        or profile_entitlements.get("get-task-allow") is not False
        or profile_entitlements.get("beta-reports-active") is not True
        or not isinstance(teams, list)
        or team_id not in teams
        or profile.get("ProvisionedDevices")
        or profile.get("ProvisionsAllDevices")
        or signer_fingerprint not in _profile_certificate_fingerprints(profile)
    ):
        raise ValidationError(
            f"nested provisioning profile does not authorize the final signer: {code_path.name}"
        )
    validate_profile_entitlements(entitlements, profile_entitlements, deadline=deadline)
    if _validity_intervals is not None:
        _validity_intervals.append(interval)


def _validate_generated_tree(
    root: Path,
    *,
    label: str,
    maximum_files: int = MAX_GENERATED_FILES,
    maximum_bytes: int = MAX_GENERATED_BYTES,
) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValidationError(f"{label} must be a real directory")
    count = 0
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *files):
            item = current_path / name
            if item.is_symlink():
                raise ValidationError(f"{label} must not contain symbolic links")
            count += 1
            if count > maximum_files:
                raise ValidationError(f"{label} contains too many generated entries")
            if item.is_file():
                total += item.stat().st_size
                if total > maximum_bytes:
                    raise ValidationError(f"{label} exceeds its generated-size safety bound")


def _validate_ipa(
    path: Path,
    *,
    expected_bundle_id: str,
    expected_team_id: str,
    expected_fingerprint: str | None,
    release: ReleaseVersion,
    require_tools: bool = False,
    _validity_intervals: list[SigningValidityInterval] | None = None,
    deadline: InspectionDeadline | None = None,
) -> list[Finding]:
    from .ios_entitlements import MAX_PLIST_BYTES, load_plist_dictionary, validate_profile_entitlements

    findings: list[Finding] = []
    deadline = deadline if deadline is not None else InspectionDeadline()
    try:
        archive, entries = _validated_ipa_entries(path, deadline=deadline)
    except ValidationError as error:
        return [Finding("ios.ipa.structure", Status.FAIL, str(error), category="ios-artifact")]
    try:
        plist_entries = [
            entry
            for entry in entries
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", entry.filename)
        ]
        if len(plist_entries) != 1:
            raise ValidationError(f"IPA must contain exactly one application; found {len(plist_entries)}")
        app_prefix = plist_entries[0].filename.removesuffix("Info.plist")
        if plist_entries[0].file_size > MAX_PLIST_BYTES:
            raise ValidationError("IPA Info.plist exceeds its bound")
        info = load_plist_dictionary(archive.read(plist_entries[0]), deadline=deadline)
        expectations = {
            "CFBundleIdentifier": expected_bundle_id,
            "CFBundleShortVersionString": release.name,
            "CFBundleVersion": str(release.build),
        }
        for key, expected in expectations.items():
            if str(info.get(key)) != expected:
                raise ValidationError(f"IPA {key} does not match the configured release value")
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable:
            raise ValidationError("IPA Info.plist lacks CFBundleExecutable")
        executable_entry = next(
            (entry for entry in entries if entry.filename == f"{app_prefix}{executable}"), None
        )
        if executable_entry is None or executable_entry.file_size == 0:
            raise ValidationError("IPA application executable is missing or empty")
        if not any(entry.filename == f"{app_prefix}_CodeSignature/CodeResources" for entry in entries):
            raise ValidationError("IPA application signature resources are missing")
        profile_entry = next(
            (entry for entry in entries if entry.filename == f"{app_prefix}embedded.mobileprovision"),
            None,
        )
        if profile_entry is None:
            raise ValidationError("IPA embedded provisioning profile is missing")
        findings.append(
            Finding(
                "ios.ipa.structure",
                Status.PASS,
                "IPA identity, version, executable, signature resources, and profile are present.",
                category="ios-artifact",
            )
        )

        with tempfile.TemporaryDirectory(prefix="mobile-release-ipa-") as temporary_string:
            temporary = Path(temporary_string)
            archive.extractall(temporary)
            deadline.check()
            app_path = temporary / app_prefix.rstrip("/")
            profile_path = app_path / "embedded.mobileprovision"
            profile = _profile_details(profile_path, deadline=deadline)
            profile_fingerprints: set[str] | None = None
            if profile is None:
                findings.append(
                    Finding(
                        "ios.ipa.profile",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Provisioning-profile inspection requires macOS security tooling.",
                        category="ios-artifact",
                    )
                )
            else:
                entitlements = profile.get("Entitlements", {})
                if not isinstance(entitlements, dict):
                    raise ValidationError("profile entitlements have an invalid structure")
                app_identifier = entitlements.get("application-identifier")
                teams = profile.get("TeamIdentifier", [])
                if app_identifier != f"{expected_team_id}.{expected_bundle_id}":
                    raise ValidationError("profile application-identifier does not match team and bundle")
                if type(teams) is not list or teams != [expected_team_id]:
                    raise ValidationError("profile TeamIdentifier does not match configuration")
                if entitlements.get("get-task-allow") is not False:
                    raise ValidationError("profile permits debugger attachment")
                if entitlements.get("beta-reports-active") is not True:
                    raise ValidationError("profile is not enabled for App Store/TestFlight distribution")
                if profile.get("ProvisionedDevices") or profile.get("ProvisionsAllDevices"):
                    raise ValidationError("profile is not an App Store distribution profile")
                interval = _profile_validity(profile)
                if _validity_intervals is not None:
                    _validity_intervals.append(interval)
                profile_fingerprints = _profile_certificate_fingerprints(profile)
                findings.append(
                    Finding(
                        "ios.ipa.profile",
                        Status.PASS,
                        "Embedded App Store profile matches the approved app and team.",
                        category="ios-artifact",
                    )
                )

            entitlements = _codesign_entitlements(app_path, deadline=deadline)
            if entitlements is None:
                findings.append(
                    Finding(
                        "ios.ipa.entitlements",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Signed-entitlement inspection requires macOS codesign.",
                        category="ios-artifact",
                    )
                )
            elif (
                entitlements.get("application-identifier")
                != f"{expected_team_id}.{expected_bundle_id}"
                or entitlements.get("com.apple.developer.team-identifier") != expected_team_id
                or ("get-task-allow" in entitlements and entitlements["get-task-allow"] is not False)
            ):
                raise ValidationError(
                    "application signed entitlements do not match the approved team/bundle release policy"
                )
            else:
                if profile is not None:
                    validate_profile_entitlements(
                        entitlements, profile.get("Entitlements", {}), deadline=deadline,
                    )
                findings.append(
                    Finding(
                        "ios.ipa.entitlements",
                        Status.PASS if profile is not None else (Status.FAIL if require_tools else Status.SKIP),
                        "All signed application entitlements fit the authoritative profile-content allowlist."
                        if profile is not None else "Complete entitlement comparison requires the embedded profile.",
                        category="ios-artifact",
                    )
                )

            fingerprint = _codesign_fingerprint(
                app_path, temporary, _validity_intervals=_validity_intervals, deadline=deadline,
            )
            if fingerprint is None:
                findings.append(
                    Finding(
                        "ios.ipa.signer",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Deep code-signing inspection requires macOS codesign and openssl.",
                        category="ios-artifact",
                    )
                )
            elif expected_fingerprint and fingerprint != expected_fingerprint.replace(":", "").lower():
                raise ValidationError("IPA signer does not match the approved distribution certificate")
            elif profile_fingerprints is not None and fingerprint not in profile_fingerprints:
                raise ValidationError(
                    "IPA signer certificate is not authorized by the embedded provisioning profile"
                )
            else:
                nested_identities = _nested_codesign_identities(
                    app_path, temporary, _validity_intervals=_validity_intervals, deadline=deadline,
                )
                if nested_identities is None:
                    raise ValidationError(
                        "nested code identity inspection requires macOS codesign and openssl"
                    )
                for nested_path, team_id, nested_fingerprint in nested_identities:
                    if team_id != expected_team_id or nested_fingerprint != fingerprint:
                        raise ValidationError(
                            "nested code signer/team does not match the approved application: "
                            f"{nested_path.name}"
                        )
                findings.append(
                    Finding(
                        "ios.ipa.signer",
                        Status.PASS,
                        "IPA and every bounded nested-code identity match the approved signer/team.",
                        category="ios-artifact",
                    )
                )
        deadline.check()
    except ValidationError as error:
        findings.append(Finding("ios.ipa.validation", Status.FAIL, str(error), category="ios-artifact"))
    finally:
        archive.close()
    return findings


def validate_ipa(
    path: Path,
    *,
    expected_bundle_id: str,
    expected_team_id: str,
    expected_fingerprint: str | None,
    release: ReleaseVersion,
    require_tools: bool = False,
    deadline: InspectionDeadline | None = None,
) -> list[Finding]:
    """Validate the final IPA against current-time signing/profile policy."""

    return _validate_ipa(
        path,
        expected_bundle_id=expected_bundle_id,
        expected_team_id=expected_team_id,
        expected_fingerprint=expected_fingerprint,
        release=release,
        require_tools=require_tools,
        deadline=deadline,
    )


def validate_ipa_current_signing(
    path: Path,
    *,
    expected_bundle_id: str,
    expected_team_id: str,
    expected_fingerprint: str | None,
    release: ReleaseVersion,
    require_tools: bool = True,
    deadline: InspectionDeadline | None = None,
) -> tuple[list[Finding], SigningValidityInterval | None]:
    """Perform every IPA check and retain the intersection of validated dates.

    No caller-selected validation time is accepted. Historical recovery instead
    authenticates the original validation proof and exact immutable bytes.
    """

    intervals: list[SigningValidityInterval] = []
    findings = _validate_ipa(
        path,
        expected_bundle_id=expected_bundle_id,
        expected_team_id=expected_team_id,
        expected_fingerprint=expected_fingerprint,
        release=release,
        require_tools=require_tools,
        _validity_intervals=intervals,
        deadline=deadline,
    )
    if any(item.status in FAILING_STATUSES or item.status == Status.SKIP for item in findings):
        return findings, None
    try:
        if len(intervals) < 2:
            raise ValidationError("IPA lacks complete current profile/certificate validity evidence")
        interval = SigningValidityInterval(
            max(item.lower_bound for item in intervals), min(item.upper_bound for item in intervals)
        )
        interval.require_current()
    except ValidationError as error:
        findings.append(Finding("ios.ipa.validity", Status.FAIL, str(error), category="ios-artifact"))
        return findings, None
    return findings, interval


def ipa_signing_evidence(path: Path, *, deadline: InspectionDeadline | None = None) -> dict[str, str]:
    """Extract public signing/profile identity from a previously validated IPA."""

    deadline = deadline if deadline is not None else InspectionDeadline()
    archive, entries = _validated_ipa_entries(path, deadline=deadline)
    try:
        profile_entries = [
            item
            for item in entries
            if re.fullmatch(r"Payload/[^/]+\.app/embedded\.mobileprovision", item.filename)
        ]
        if len(profile_entries) != 1:
            raise ValidationError("IPA must contain exactly one embedded provisioning profile")
        plist_entries = [
            item
            for item in entries
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", item.filename)
        ]
        if len(plist_entries) != 1:
            raise ValidationError("IPA must contain exactly one application")
        app_prefix = plist_entries[0].filename.removesuffix("Info.plist")
        with tempfile.TemporaryDirectory(prefix="mobile-release-profile-") as temporary_string:
            temporary = Path(temporary_string)
            archive.extractall(temporary)
            deadline.check()
            app_path = temporary / app_prefix.rstrip("/")
            profile_path = app_path / "embedded.mobileprovision"
            profile_path.write_bytes(archive.read(profile_entries[0]))
            profile = _profile_details(profile_path, deadline=deadline)
            signer_fingerprint = _codesign_fingerprint(app_path, temporary, deadline=deadline)
        if profile is None:
            raise ValidationError("iOS signing evidence extraction requires macOS security tooling")
        if signer_fingerprint is None:
            raise ValidationError("iOS signing evidence extraction requires codesign and openssl")
        profile_fingerprints = _profile_certificate_fingerprints(profile)
        interval = _profile_validity(profile)
        if signer_fingerprint not in profile_fingerprints:
            raise ValidationError(
                "IPA signer certificate is not authorized by the embedded provisioning profile"
            )
        teams = profile.get("TeamIdentifier", [])
        uuid = profile.get("UUID")
        entitlements = profile.get("Entitlements", {})
        if (
            len(teams) != 1
            or not isinstance(uuid, str)
            or not PROFILE_UUID_RE.fullmatch(uuid)
            or not isinstance(entitlements, dict)
            or entitlements.get("get-task-allow") is not False
            or entitlements.get("beta-reports-active") is not True
            or profile.get("ProvisionedDevices")
            or profile.get("ProvisionsAllDevices")
        ):
            raise ValidationError("provisioning profile lacks stable public identity fields")
        deadline.check()
        return {
            "platform": "ios",
            "kind": "apple-distribution",
            "certificateSha256": signer_fingerprint,
            "teamId": teams[0],
            "profileUuid": uuid,
            "profileExpiresAt": interval.upper_bound
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
    finally:
        archive.close()


def validate_xcarchive(
    archive: Path,
    *,
    expected_bundle_id: str,
    release: ReleaseVersion,
    symbols_policy: str,
    require_tools: bool = False,
) -> list[Finding]:
    """Validate a private archive snapshot; a signed candidate also needs pairing.

    UUID parsing is now bounded, structural and independent of dwarfdump output.
    ``require_tools`` remains compatible with archive-only preflight callers;
    signature authenticity is checked on the final IPA, not inferred here.
    """
    from .ios_artifacts import inspect_archive_symbols, snapshot_ios_artifacts

    try:
        with snapshot_ios_artifacts({"ios-archive": archive}) as snapshot:
            symbols = inspect_archive_symbols(
                snapshot.unpack("ios-archive"), expected_bundle_id=expected_bundle_id,
                release=release, require_main=symbols_policy in {"retain", "required"},
                deadline=snapshot.deadline,
            )
            snapshot.assert_unchanged()
    except (ValidationError, OSError) as error:
        message = str(error) if isinstance(error, ValidationError) else "Archive required layout is missing or unreadable."
        return [Finding("ios.archive.structure", Status.FAIL, message, category="ios-artifact")]
    return [
        Finding("ios.archive.identity", Status.PASS,
                "Archived application identity and committed version match; IPA correspondence is a separate paired check.",
                category="ios-artifact"),
        Finding("ios.archive.dsym", Status.PASS if symbols else Status.NOT_APPLICABLE,
                "Every present retained dSYM slice matches an archived native identity; this is not complete nested symbol coverage."
                if symbols else "No dSYMs retained under disabled symbol policy.", category="ios-artifact"),
    ]


def _run_checked(
    argv: list[str],
    root: Path,
    timeout: int,
    *,
    environment_overrides: dict[str, str] | None = None,
) -> None:
    environment = os.environ.copy()
    environment.update(environment_overrides or {})
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        raise ValidationError(f"command failed or timed out: {argv[0]}") from error
    if result.returncode:
        raise ValidationError(f"command failed with exit {result.returncode}: {argv[0]}")


def run_ios_build(config: ReleaseConfig, *, signed: bool) -> dict[str, Path]:
    if sys.platform != "darwin":
        raise ValidationError("iOS archive/export requires a macOS host")
    discovered = discover_project(config.root)
    container = selected_ios_container(config, discovered)
    scheme = selected_ios_scheme(config, discovered)
    if not container:
        raise ValidationError("Xcode project/workspace is ambiguous; configure ios.project or ios.workspace")
    if not scheme:
        raise ValidationError("shared Xcode scheme is ambiguous; configure ios.scheme")
    ios = config.section("ios")
    release = config.release_version()
    if prepare := ios.get("prepareCommand"):
        _run_checked(list(prepare), config.root, 10 * 60)
        discovered = discover_project(config.root)
        container = selected_ios_container(config, discovered)
        if not container:
            raise ValidationError("iOS preparation command did not produce the configured Xcode container")
    container_path = config.project_path(container[1])
    if not container_path.is_dir() or container_path.is_symlink():
        raise ValidationError("Configured Xcode project/workspace is missing or unsafe after preparation")

    build_root = recreate_private_build_directory(config, "ios")
    archive = build_root / "archive.xcarchive"
    container_flag = "-workspace" if container[0] == "workspace" else "-project"
    command = [
        "xcodebuild",
        container_flag,
        str(container_path),
        "-scheme",
        scheme,
        "-configuration",
        ios.get("archiveConfiguration", "Release"),
        "-destination",
        "generic/platform=iOS",
        "-archivePath",
        str(archive),
        "archive",
        f"MARKETING_VERSION={release.name}",
        f"CURRENT_PROJECT_VERSION={release.build}",
    ]
    if signed:
        profile = os.environ.get("MOBILE_RELEASE_IOS_PROFILE_SPECIFIER")
        if not profile:
            raise ValidationError("MOBILE_RELEASE_IOS_PROFILE_SPECIFIER is required for signed export")
        command.extend(
            [
                "MOBILE_RELEASE_IOS_CODE_SIGN_STYLE=Manual",
                f"MOBILE_RELEASE_IOS_DEVELOPMENT_TEAM={ios.get('teamId', '')}",
                f"MOBILE_RELEASE_IOS_PROVISIONING_PROFILE_SPECIFIER={profile}",
                "MOBILE_RELEASE_IOS_CODE_SIGN_IDENTITY=Apple Distribution",
            ]
        )
    else:
        command.extend(["CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO"])
    build_environment = {
        "MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS": "1",
        "MOBILE_RELEASE_VERSION_NAME": release.name,
        "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
    }
    _run_checked(
        command,
        config.root,
        60 * 60,
        environment_overrides=build_environment,
    )
    archive = config.project_path(str(archive))
    _validate_generated_tree(archive, label="generated xcarchive")
    result_paths: dict[str, Path] = {"ios-archive": archive}
    dsym_source = archive / "dSYMs"
    dsym_destination = build_root / "dsyms"
    if dsym_source.is_dir():
        dsym_source = config.project_path(str(dsym_source))
        _validate_generated_tree(
            dsym_source,
            label="generated dSYMs",
            maximum_files=20_000,
            maximum_bytes=4 * 1024 * 1024 * 1024,
        )
        shutil.copytree(dsym_source, dsym_destination)
        result_paths["ios-dsyms"] = dsym_destination
    if not signed:
        return result_paths

    import plistlib

    export_options = {
        "method": "app-store-connect",
        "destination": "export",
        "signingStyle": "manual",
        "teamID": ios.get("teamId"),
        "signingCertificate": "Apple Distribution",
        "provisioningProfiles": {ios.get("bundleId"): os.environ["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"]},
        "stripSwiftSymbols": False,
        "thinning": "<none>",
        "uploadSymbols": False,
    }
    export_plist = build_root / "ExportOptions.plist"
    with export_plist.open("wb") as handle:
        plistlib.dump(export_options, handle, sort_keys=True)
    export_dir = build_root / "export"
    _run_checked(
        [
            "xcodebuild",
            "-exportArchive",
            "-archivePath",
            str(archive),
            "-exportPath",
            str(export_dir),
            "-exportOptionsPlist",
            str(export_plist),
        ],
        config.root,
        30 * 60,
        environment_overrides=build_environment,
    )
    export_dir = config.project_path(str(export_dir))
    _validate_generated_tree(export_dir, label="iOS export directory")
    ipas = list(export_dir.glob("*.ipa"))
    if len(ipas) != 1:
        raise ValidationError(f"expected one exported IPA, found {len(ipas)}")
    ipa_source = config.project_path(str(ipas[0]))
    if ipa_source.is_symlink() or not ipa_source.is_file():
        raise ValidationError("exported IPA must be a regular non-symlink file")
    ipa = build_root / "app.ipa"
    if ipa.is_symlink():
        raise ValidationError("normalized IPA destination must not be a symlink")
    shutil.copy2(ipa_source, ipa)
    result_paths["ios-ipa"] = ipa
    return result_paths
