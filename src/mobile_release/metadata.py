from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import zipfile
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .config import ReleaseConfig
from .errors import ConfigurationError, ValidationError
from .reporting import Finding, Status

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_ARCHIVE_SIZE = 250 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".md", ".json", ".png", ".jpg", ".jpeg"}
TEXT_LIMITS = {
    "title.txt": 30,
    "name.txt": 30,
    "short_description.txt": 80,
    "subtitle.txt": 30,
    "promotional_text.txt": 170,
    "keywords.txt": 100,
    "description.txt": 4000,
    "full_description.txt": 4000,
    "whats_new.txt": 4000,
    "release_notes.txt": 4000,
    "what-to-test.txt": 4000,
}
REQUIRED_LOCALE_TEXT = {
    "android": ("title.txt", "short_description.txt", "full_description.txt"),
    "ios": (
        "description.txt",
        "keywords.txt",
        "privacy_url.txt",
        "support_url.txt",
        "release_notes.txt",
    ),
}
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:\bTODO\b|\bTBD\b|\bCHANGEME\b|example\.(?:com|org)|<[^>]+>|\{\{[^}]+\}\})"
)
SECRET_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|"
    r"[\"'](?:client_secret|private_key|private_key_id)[\"']\s*:\s*[\"'][^\"']{8,}|"
    r"(?:password|api[_ -]?key|secret)\s*[:=]\s*[^\s]{8,})"
)
LOCALE_RE = re.compile(r"^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?$")
MAX_FILE_COUNT = 10_000
MAX_STORE_URL_LENGTH = 2048
PLATFORM_METADATA_ROOTS = {
    "android": ("android",),
    "ios": ("ios", "review", "testflight"),
}
ANDROID_NOTE_LIMIT = 500
ANDROID_NOTE_MAX_BYTES = 4 * ANDROID_NOTE_LIMIT
# Validation only: upload the original text, never this case-mapped view. Explicit
# ASCII boundaries conservatively recognize placeholders next to Unicode text.
ANDROID_NOTE_CASE_MAP = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ\u0130\u0131\u017f\u212a",
    "abcdefghijklmnopqrstuvwxyziisk",
)
ANDROID_NOTE_PLACEHOLDER_RE = re.compile(
    r"(?<![a-z0-9_])(?:todo|tbd|changeme)(?![a-z0-9_])|"
    r"example\.(?:com|org)|<[^>]+>|\{\{[^}]+\}\}"
)
ANDROID_NOTE_SECRET_RE = re.compile(
    r"-----begin [a-z0-9 ]*private key-----|akia[0-9a-z]{16}|"
    r"[\"'](?:client_secret|private_key|private_key_id)[\"']\s*:\s*[\"'][^\"']{8,}|"
    r"(?:password|api[_ -]?key|secret)\s*[:=]\s*[^\s]{8,}"
)


def validate_android_release_note(text: object) -> str:
    """Validate public Play copy without trimming or normalizing uploaded bytes."""
    if not isinstance(text, str):
        raise ValidationError("Android release notes must be UTF-8 text")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError("Android release notes must be UTF-8 text") from error
    if not text.strip() or "\x00" in text:
        raise ValidationError("Android release notes must contain non-whitespace text without NUL")
    if len(text) > ANDROID_NOTE_LIMIT:
        raise ValidationError(
            f"Android release notes exceed the {ANDROID_NOTE_LIMIT}-character limit (including whitespace)"
        )
    validation_view = text.translate(ANDROID_NOTE_CASE_MAP)
    if ANDROID_NOTE_PLACEHOLDER_RE.search(validation_view):
        raise ValidationError("Android release notes contain an unresolved placeholder")
    if ANDROID_NOTE_SECRET_RE.search(validation_view):
        raise ValidationError("Android release notes contain possible secret material")
    return text


def _read_android_release_note(config: ReleaseConfig, path: Path) -> str:
    path = config.project_path(str(path))  # Reject every in-repository symlink component.
    relative = path.relative_to(config.root)
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        with os.fdopen(os.open(path, flags), "rb") as handle:
            attributes = os.fstat(handle.fileno())
            if not stat.S_ISREG(attributes.st_mode) or attributes.st_size > ANDROID_NOTE_MAX_BYTES:
                raise ValidationError(f"Android release notes must be a bounded regular file: {relative}")
            raw = handle.read(ANDROID_NOTE_MAX_BYTES + 1)
        if len(raw) > ANDROID_NOTE_MAX_BYTES:
            raise ValidationError(f"Android release notes exceed the bounded UTF-8 file size: {relative}")
        # read_text() would translate CRLF, changing both the length and intent.
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValidationError(
            f"Required Android release notes must be a readable regular UTF-8 file: {relative}"
        ) from error
    try:
        return validate_android_release_note(text)
    except ValidationError as error:
        raise ValidationError(f"{relative}: {error}") from error


def android_release_note(config: ReleaseConfig, locale: str, build: int) -> str:
    if not isinstance(locale, str) or not LOCALE_RE.fullmatch(locale):
        raise ValidationError("Android release note locale is invalid")
    if type(build) is not int or not 1 <= build <= 2_100_000_000:
        raise ValidationError("Android release notes require the authoritative positive build number")
    directory = config.project_path(
        f"{config.section('metadata')['root']}/android/{locale}/changelogs"
    )
    exact = directory / f"{build}.txt"
    try:
        exact.lstat()
    except FileNotFoundError:
        selected = directory / "default.txt"
    except OSError as error:
        raise ValidationError(f"Android release notes cannot be inspected safely: android/{locale}") from error
    else:
        # Presence, not validity, determines precedence. Never hide a broken,
        # nonregular or malicious exact-version path behind a valid fallback.
        selected = exact
    return _read_android_release_note(config, selected)


def android_release_notes(config: ReleaseConfig) -> list[dict[str, str]]:
    locales = config.section("metadata").get("androidLocales")
    if (
        not isinstance(locales, list)
        or not 1 <= len(locales) <= 250
        or any(not isinstance(locale, str) or not LOCALE_RE.fullmatch(locale) for locale in locales)
        or len(set(locales)) != len(locales)
    ):
        raise ValidationError("Android release notes require a unique nonempty configured locale set")
    build = config.release_version().build
    return [
        {"language": locale, "text": android_release_note(config, locale, build)}
        for locale in sorted(locales)
    ]


def _is_android_changelog(relative: Path) -> bool:
    return (
        len(relative.parts) == 4
        and relative.parts[0] == "android"
        and relative.parts[2] == "changelogs"
        and re.fullmatch(r"(?:default|[1-9][0-9]{0,9})\.txt", relative.name) is not None
    )


def _safe_files(root: Path) -> Iterable[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValidationError("metadata root must be a regular directory, not a symlink")
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValidationError(f"metadata must not contain symlinks: {path.relative_to(root)}")
        if path.is_file():
            count += 1
            if count > MAX_FILE_COUNT:
                raise ValidationError("metadata tree contains too many files")
            relative = path.relative_to(root)
            if path.name == ".gitkeep":
                continue
            if any(part.startswith(".") for part in relative.parts):
                raise ValidationError(f"hidden metadata file is forbidden: {relative}")
            if path.suffix.lower() not in ALLOWED_SUFFIXES:
                raise ValidationError(
                    f"unsupported metadata file type {path.suffix or '<none>'}: {relative}"
                )
            if any(part in {".", "..", ""} for part in relative.parts):
                raise ValidationError(f"unsafe metadata path: {relative}")
            if any(ord(character) < 32 for character in relative.as_posix()):
                raise ValidationError(f"metadata path contains control characters: {relative}")
            size = path.stat().st_size
            if size > MAX_FILE_SIZE:
                raise ValidationError(f"metadata file exceeds {MAX_FILE_SIZE} bytes: {relative}")
            yield path


def _safe_platform_files(root: Path, platforms: Iterable[str]) -> list[Path]:
    selected = tuple(dict.fromkeys(platforms))
    unknown = sorted(set(selected) - set(PLATFORM_METADATA_ROOTS))
    if unknown:
        raise ValidationError(f"unsupported metadata platform(s): {', '.join(unknown)}")
    files: list[Path] = []
    for relative in dict.fromkeys(
        item for platform in selected for item in PLATFORM_METADATA_ROOTS[platform]
    ):
        subtree = root / relative
        if subtree.is_symlink():
            raise ValidationError(f"metadata must not contain symlinks: {relative}")
        if not subtree.exists():
            continue
        files.extend(_safe_files(subtree))
        if len(files) > MAX_FILE_COUNT:
            raise ValidationError("metadata tree contains too many files")
    return sorted(files)


def _image_dimensions(path: Path) -> tuple[int, int] | None:
    with path.open("rb") as handle:
        header = handle.read(32)
        if header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) >= 24:
            return struct.unpack(">II", header[16:24])
        if header.startswith(b"\xff\xd8"):
            handle.seek(2)
            while True:
                marker_start = handle.read(1)
                if not marker_start:
                    return None
                if marker_start != b"\xff":
                    continue
                marker = handle.read(1)
                while marker == b"\xff":
                    marker = handle.read(1)
                if not marker:
                    return None
                if marker in {b"\xd8", b"\xd9", b"\x01"} or 0xD0 <= marker[0] <= 0xD7:
                    continue
                raw_length = handle.read(2)
                if len(raw_length) != 2:
                    return None
                length = struct.unpack(">H", raw_length)[0]
                if length < 2:
                    return None
                if marker[0] in {
                    0xC0,
                    0xC1,
                    0xC2,
                    0xC3,
                    0xC5,
                    0xC6,
                    0xC7,
                    0xC9,
                    0xCA,
                    0xCB,
                    0xCD,
                    0xCE,
                    0xCF,
                }:
                    payload = handle.read(length - 2)
                    if len(payload) < 5:
                        return None
                    return struct.unpack(">HH", payload[1:5])[::-1]
                handle.seek(length - 2, os.SEEK_CUR)
    return None


def metadata_findings(
    config: ReleaseConfig,
    *,
    check_urls: bool = False,
    platforms: Iterable[str] | None = None,
) -> list[Finding]:
    del check_urls  # Network URL validation belongs to the explicit online Store preflight.
    metadata = config.section("metadata")
    relative_root = metadata.get("root", "release/store")
    findings: list[Finding] = []
    try:
        root = config.project_path(relative_root)
    except ConfigurationError as error:
        return [Finding("metadata.paths", Status.INVALID, str(error), category="metadata")]
    if not root.is_dir():
        return [
            Finding(
                code="metadata.root",
                status=Status.MISSING,
                category="metadata",
                message=f"Store metadata directory is missing: {relative_root}",
                remediation="Create the configured metadata tree and add the required locales/assets.",
            )
        ]

    selected = set(platforms if platforms is not None else config.enabled_platforms)
    android_build = None
    if "android" in selected and config.platform_enabled("android"):
        try:
            android_build = config.release_version().build
        except (ConfigurationError, OSError):
            findings.append(Finding(
                "metadata.android.release-notes.version", Status.INVALID,
                "Android release notes require a valid committed version/build source.",
                category="metadata", remediation="Fix the configured version source before selecting changelogs.",
            ))
    for platform, key in (("android", "androidLocales"), ("ios", "iosLocales")):
        if platform not in selected:
            continue
        if not config.platform_enabled(platform):
            continue
        locales = metadata.get(key, [])
        if not locales:
            findings.append(
                Finding(
                    code=f"metadata.{platform}.locales",
                    status=Status.MISSING,
                    category="metadata",
                    message=f"No required {platform} metadata locales are declared.",
                    remediation=f"Declare metadata.{key} and add matching locale directories.",
                )
            )
            continue
        for locale in locales:
            if not LOCALE_RE.fullmatch(locale):
                findings.append(
                    Finding(
                        code=f"metadata.{platform}.locale-format",
                        status=Status.INVALID,
                        category="metadata",
                        message=f"Invalid locale identifier: {locale}",
                    )
                )
                continue
            locale_root = root / platform / locale
            if not locale_root.is_dir() or locale_root.is_symlink():
                findings.append(
                    Finding(
                        code=f"metadata.{platform}.{locale}",
                        status=Status.MISSING,
                        category="metadata",
                        message=f"No metadata directory exists for {platform}/{locale}.",
                    )
                )
            else:
                public_files = [
                    path
                    for path in locale_root.rglob("*")
                    if path.is_file() and not path.is_symlink() and path.name != ".gitkeep"
                ]
                if not public_files:
                    findings.append(
                        Finding(
                            code=f"metadata.{platform}.{locale}.empty",
                            status=Status.MISSING,
                            category="metadata",
                            message=f"Metadata locale {platform}/{locale} contains no release content.",
                        )
                    )
                missing_text = [
                    name
                    for name in REQUIRED_LOCALE_TEXT[platform]
                    if (locale_root / name).is_symlink()
                    or not (locale_root / name).is_file()
                ]
                if missing_text:
                    findings.append(
                        Finding(
                            code=f"metadata.{platform}.{locale}.required-text",
                            status=Status.MISSING,
                            category="metadata",
                            message=(
                                f"Metadata locale {platform}/{locale} lacks required Store text: "
                                f"{', '.join(missing_text)}."
                            ),
                            remediation="Add reviewed public Store copy for every configured locale.",
                        )
                    )

            if platform == "android" and android_build is not None:
                try:
                    android_release_note(config, locale, android_build)
                except (ConfigurationError, ValidationError) as error:
                    findings.append(Finding(
                        f"metadata.android.{locale}.release-notes", Status.INVALID,
                        str(error), category="metadata",
                        remediation=(
                            f"Add reviewed changelogs/{android_build}.txt or changelogs/default.txt "
                            "for this locale; fill or remove unused empty stubs."
                        ),
                    ))

    if "ios" in selected and config.platform_enabled("ios"):
        for relative in (
            "review/ios-beta-notes.txt",
            "review/ios-notes.txt",
            "testflight/what-to-test.txt",
        ):
            path = root / relative
            if path.is_symlink() or not path.is_file():
                findings.append(
                    Finding(
                        "metadata.ios.review-notes",
                        Status.MISSING,
                        f"Required reviewed iOS notes are missing: {relative}",
                        category="metadata",
                    )
                )

    try:
        files = _safe_platform_files(root, selected)
    except ValidationError as error:
        findings.append(
            Finding("metadata.paths", Status.INVALID, str(error), category="metadata")
        )
        return findings
    if not files:
        findings.append(
            Finding("metadata.files", Status.MISSING, "Store metadata tree is empty.", category="metadata")
        )
        return findings

    for path in files:
        relative = path.relative_to(root)
        if _is_android_changelog(relative):
            try:
                _read_android_release_note(config, path)
            except (ConfigurationError, ValidationError) as error:
                findings.append(Finding(
                    "metadata.android.release-notes", Status.INVALID,
                    str(error), category="metadata",
                ))
            continue
        suffix = path.suffix.lower()
        if suffix in {".txt", ".md", ".json"}:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                findings.append(
                    Finding(
                        "metadata.utf8",
                        Status.INVALID,
                        f"Metadata file is not UTF-8: {relative}",
                        category="metadata",
                    )
                )
                continue
            if not text.strip():
                findings.append(
                    Finding(
                        "metadata.empty-text",
                        Status.INVALID,
                        f"Metadata text file is empty: {relative}",
                        category="metadata",
                    )
                )
            if "\x00" in text:
                findings.append(
                    Finding(
                        "metadata.nul",
                        Status.INVALID,
                        f"Metadata file contains NUL bytes: {relative}",
                        category="metadata",
                    )
                )
            if PLACEHOLDER_RE.search(text):
                findings.append(
                    Finding(
                        "metadata.placeholder",
                        Status.FAIL,
                        f"Unresolved placeholder in {relative}",
                        category="metadata",
                    )
                )
            if SECRET_RE.search(text):
                findings.append(
                    Finding(
                        "metadata.secret-pattern",
                        Status.FAIL,
                        f"Possible secret material in {relative}",
                        category="metadata",
                        remediation="Remove private credentials and rotate them if they were committed.",
                    )
                )
            if suffix == ".json":
                try:
                    json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
                except (json.JSONDecodeError, ValidationError) as error:
                    findings.append(
                        Finding(
                            "metadata.json",
                            Status.INVALID,
                            f"Invalid JSON metadata in {relative}: {error}",
                            category="metadata",
                        )
                    )
            if path.name.endswith("_url.txt"):
                candidate = text.rstrip("\n")
                try:
                    parsed = urlsplit(candidate)
                    _ = parsed.port
                except ValueError:
                    parsed = None
                valid_url = bool(
                    parsed
                    and candidate == candidate.strip()
                    and len(candidate) <= MAX_STORE_URL_LENGTH
                    and not any(ord(character) < 32 for character in candidate)
                    and parsed.scheme == "https"
                    and parsed.hostname
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.query
                    and not parsed.fragment
                )
                if not valid_url:
                    findings.append(
                        Finding(
                            "metadata.url",
                            Status.INVALID,
                            f"Store URL must be an absolute credential-free HTTPS URL: {relative}",
                            category="metadata",
                        )
                    )
            limit = TEXT_LIMITS.get(path.name)
            if limit is not None and len(text.rstrip("\n")) > limit:
                findings.append(
                    Finding(
                        "metadata.length",
                        Status.FAIL,
                        f"{relative} exceeds its {limit}-character Store limit.",
                        category="metadata",
                    )
                )
        elif suffix in {".png", ".jpg", ".jpeg"}:
            dimensions = _image_dimensions(path)
            if not dimensions or dimensions[0] < 1 or dimensions[1] < 1:
                findings.append(
                    Finding(
                        "metadata.image",
                        Status.INVALID,
                        f"Image header or dimensions are invalid: {relative}",
                        category="metadata",
                    )
                )
    if not any(item.status in {Status.FAIL, Status.INVALID, Status.MISSING} for item in findings):
        findings.append(
            Finding(
                "metadata.valid",
                Status.PASS,
                f"Validated {len(files)} metadata files.",
                category="metadata",
            )
        )
    return findings


def build_metadata_archive(
    root: Path, output: Path, *, platform: str | None = None
) -> str:
    if not root.is_dir():
        raise ValidationError(f"metadata directory not found: {root}")
    files = _safe_platform_files(
        root, (platform,) if platform is not None else ("android", "ios")
    )
    total = sum(path.stat().st_size for path in files)
    if total > MAX_ARCHIVE_SIZE:
        raise ValidationError("metadata archive exceeds the uncompressed size limit")
    if output.is_symlink():
        raise ValidationError("metadata archive destination must not be a symlink")
    output = output.resolve()
    try:
        output.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ValidationError("metadata archive destination must be outside the metadata tree")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in files:
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return digest


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value
