"""Closed public-image import DATA policy, not native filesystem authority.

The original rooted edit lease alone binds these selections to targets. Native
picker batches, original observations and typed journal custody live elsewhere.
No image bytes or original source paths are part of a renderer projection.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .config import MAX_CONFIG_BYTES
from .errors import ValidationError
from .init_transaction import MAX_IMAGE_FILE_BYTES, MAX_TOTAL_BYTES, validate_paths
from .metadata_image_header import inspect_header
from .metadata_text import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_COMPONENTS,
                            MAX_RELATIVE_BYTES, MetadataTextInputError,
                            public_text_selection)

POLICY = "metadata-images-v1"
MAX_IMAGES = 10
MAX_IMAGE_BYTES = MAX_IMAGE_FILE_BYTES
MAX_BATCH_BYTES = 24 * 1024 * 1024
MAX_REQUEST_BYTES = 33 * 1024 * 1024
MAX_RESULT_BYTES = 512 * 1024
MAX_PREPARED_BYTES = 384 * 1024
MAX_CATALOG_BYTES = 128 * 1024
MAX_SIBLINGS = 256
MAX_NAME_BYTES = 255
MAX_DIMENSION = 16_384
MAX_PIXELS = 64 * 1024 * 1024
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,250}\.(?:png|jpg|jpeg)\Z", re.IGNORECASE)
_DOS = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(10)),
        *("lpt" + str(i) for i in range(10))}
_ANDROID_SINGLE = ("featureGraphic", "icon", "tvBanner")
_ANDROID_SEQUENCE = ("phoneScreenshots", "sevenInchScreenshots", "tenInchScreenshots",
                     "tvScreenshots", "wearScreenshots")
_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

ISSUES = {
    "image.empty": "The selected image is empty.",
    "image.limit": "The selected image exceeds the 10 MiB file limit.",
    "image.format": "Select a PNG or JPEG image; this file's contents have another format.",
    "image.header": "The image's dimension-bearing header is incomplete or invalid.",
    "image.extension": "The filename extension does not match the PNG or JPEG contents.",
    "image.dimensions": "The image dimensions exceed the bounded local inspection limits.",
    "image.device": "These dimensions do not match the selected Apple display type in the pinned Store tool.",
    "image.singleton": "Another format already occupies this single-image slot; choose the existing image format.",
    "image.portable-collision": "Two image names would collide on a supported filesystem; no file was changed.",
    "image.duplicate": "The resulting image set contains duplicate image contents.",
    "image.count": "The resulting image set exceeds the selected type's supported count.",
    "image.sibling": "An existing image in this selected set is unsupported or invalid; preserve it and review the conflict.",
    "image.total": "The selected and existing image data exceed this transaction's bounded size; use a smaller set.",
    "image.source-target": "This destination is one of your selected original files. Keep that original unchanged or select another source file.",
}


class MetadataImagesInputError(ValueError):
    """A fixed reason only, never a path/body/native exception echo."""

    def __init__(self, reason: str = "invalid_params"):
        super().__init__("Public image input was refused")
        self.reason = reason


def _require(condition: bool, reason: str = "invalid_params") -> None:
    if not condition:
        raise MetadataImagesInputError(reason)


def content_digest(raw: bytes) -> dict[str, Any]:
    return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def issue(code: str) -> dict[str, str]:
    return {"code": code, "severity": "error", "message": ISSUES[code]}


@dataclass(frozen=True)
class ImageType:
    platform: str
    identity: str
    label: str
    singleton: bool
    max_count: int
    dimensions: tuple[tuple[int, int], ...]


@lru_cache(maxsize=1)
def _types() -> tuple[ImageType, ...]:
    """Trusted packaged DATA only, never a file from the selected project."""
    try:
        with (Path(__file__).parent / "api" / "data" / "metadata-images-v1.json").open("rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
        _require(len(raw) <= MAX_CATALOG_BYTES, "catalog_unavailable")
        value = json.loads(raw)
        _require(type(value) is dict and value["schemaVersion"] == 1
                 and type(value["schemaVersion"]) is int and value["policy"] == POLICY,
                 "catalog_unavailable")
        rows = value["types"]
        _require(type(rows) is list and 8 <= len(rows) <= 64, "catalog_unavailable")
        result = []
        for row in rows:
            _require(type(row) is dict and set(row) == {
                "platform", "id", "label", "singleton", "maxCount", "dimensions"
            }, "catalog_unavailable")
            platform, identity = row["platform"], row["id"]
            _require(type(platform) is str and platform in {"android", "ios"}
                     and type(identity) is str and len(identity) <= 64
                     and type(row["label"]) is str and 1 <= len(row["label"]) <= 120
                     and type(row["singleton"]) is bool
                     and type(row["maxCount"]) is int and 1 <= row["maxCount"] <= MAX_IMAGES
                     and type(row["dimensions"]) is list and len(row["dimensions"]) <= 32,
                     "catalog_unavailable")
            if platform == "android":
                _require(identity in (*_ANDROID_SINGLE, *_ANDROID_SEQUENCE)
                         and row["singleton"] == (identity in _ANDROID_SINGLE)
                         and (not row["singleton"] or row["maxCount"] == 1)
                         and (row["singleton"] or row["maxCount"] == 8)
                         and not row["dimensions"], "catalog_unavailable")
            else:
                _require(re.fullmatch(r"APP_(?:IPHONE|IPAD|WATCH)_[A-Z0-9_]+", identity) is not None
                         and not row["singleton"] and row["maxCount"] == 10
                         and bool(row["dimensions"]), "catalog_unavailable")
            dimensions = []
            for pair in row["dimensions"]:
                _require(type(pair) is list and len(pair) == 2
                         and all(type(n) is int and 1 <= n <= MAX_DIMENSION for n in pair)
                         and pair[0] * pair[1] <= MAX_PIXELS, "catalog_unavailable")
                dimensions.append(tuple(pair))
            _require(len(set(dimensions)) == len(dimensions), "catalog_unavailable")
            result.append(ImageType(platform, identity, row["label"], row["singleton"],
                                    row["maxCount"], tuple(dimensions)))
        keys = [(row.platform, row.identity) for row in result]
        _require(len(set(keys)) == len(keys)
                 and {identity for platform, identity in keys if platform == "android"}
                 == {*_ANDROID_SINGLE, *_ANDROID_SEQUENCE}, "catalog_unavailable")
        return tuple(result)
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise MetadataImagesInputError("catalog_unavailable") from None


def image_type(platform: object, identity: object) -> ImageType:
    _require(type(platform) is str and platform in {"android", "ios"}
             and type(identity) is str and 1 <= len(identity) <= 64)
    for row in _types():
        if (row.platform, row.identity) == (platform, identity):
            return row
    raise MetadataImagesInputError("unsupported_type")


def catalog() -> dict[str, Any]:
    """Static guidance, never a runtime qualification or image inspection."""
    types = _types()
    try:
        with (Path(__file__).parent / "api" / "data" / "metadata-image-help-v1.json").open("rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
        _require(len(raw) <= MAX_CATALOG_BYTES, "catalog_unavailable")
        parsed = json.loads(raw)
        _require(type(parsed) is dict and set(parsed) == {"schemaVersion", "fields"}
                 and type(parsed["schemaVersion"]) is int and parsed["schemaVersion"] == 1
                 and type(parsed["fields"]) is list and len(parsed["fields"]) == 7,
                 "catalog_unavailable")
        fields = parsed["fields"]
        _require([row.get("id") for row in fields if type(row) is dict] == [
            "platform", "locale", "assetType", "files", "replaceExisting",
            "copyConfirmation", "recoveryConfirmation"], "catalog_unavailable")
        for row in fields:
            _require(set(row) == {"id", "label", "requiredness", "requiredWhen", "what", "why", "where", "format", "failure"}
                     and all(type(value) is str and 0 < len(value) <= 1024
                             and not any(ord(c) < 32 or ord(c) == 127 for c in value) for value in row.values())
                     and row["requiredness"] in {"required", "optional"}, "catalog_unavailable")
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise MetadataImagesInputError("catalog_unavailable") from None
    return {"schemaVersion": 1, "policy": POLICY,
            "platforms": [{"id": "android", "label": "Android / Google Play"},
                          {"id": "ios", "label": "iOS / App Store"}],
            "types": [{"platform": row.platform, "id": row.identity, "label": row.label,
                       "singleton": row.singleton, "maxCount": row.max_count,
                       "dimensions": [list(pair) for pair in row.dimensions]} for row in types],
            "limits": {"maxFiles": MAX_IMAGES, "maxFileBytes": MAX_IMAGE_BYTES,
                       "maxBatchBytes": MAX_BATCH_BYTES, "maxTransactionBytes": MAX_TOTAL_BYTES,
                       "maxDimension": MAX_DIMENSION, "maxPixels": MAX_PIXELS,
                       "formats": ["png", "jpeg"]}, "help": fields}


@dataclass(frozen=True)
class PublicImageSelection:
    """A detached closed context, not a path-write capability."""

    platform: str
    locale: str
    metadata_root: str
    asset_type: ImageType
    folder: str

    def relative_path(self, name: str) -> str:
        _require(safe_name(name), "unsafe")
        path = self.folder + "/" + name
        _require(len(path.encode("utf-8")) <= MAX_RELATIVE_BYTES
                 and len(path.split("/")) <= MAX_COMPONENTS, "unsafe")
        try:
            validate_paths([*DEPENDENCY_PATHS, path])
        except (ValueError, UnicodeError, ValidationError):
            raise MetadataImagesInputError("unsafe") from None
        return path


def public_image_selection(config_text: str, platform: object, locale: object,
                           asset_type: object) -> PublicImageSelection:
    try:
        public = public_text_selection(config_text, platform, locale)
    except MetadataTextInputError as error:
        raise MetadataImagesInputError(error.reason) from None
    kind = image_type(public.platform, asset_type)
    if public.platform == "android":
        folder = f"{public.metadata_root}/android/{public.locale}/images"
        if not kind.singleton:
            folder += "/" + kind.identity
    else:
        folder = f"{public.metadata_root}/ios/screenshots/{public.locale}/{kind.identity}"
    selection = PublicImageSelection(public.platform, public.locale, public.metadata_root, kind, folder)
    selection.relative_path("image.png")  # Closed path/depth validation, no filesystem access.
    return selection


def safe_name(name: object) -> bool:
    return (type(name) is str and _NAME.fullmatch(name) is not None
            and name.split(".", 1)[0].casefold() not in _DOS
            and not name.endswith((" ", ".")) and ".." not in name
            and len(name.encode("utf-8")) <= MAX_NAME_BYTES)


def name_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def filename_format(name: str) -> str | None:
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return "png" if suffix == "png" else "jpeg" if suffix in {"jpg", "jpeg"} else None


def image_summary(raw: bytes, name: str, kind: ImageType | None = None
                  ) -> tuple[dict[str, Any], tuple[str, ...]]:
    _require(type(raw) is bytes and type(name) is str)
    problems = []
    header = None
    if not raw:
        problems.append("image.empty")
    elif len(raw) > MAX_IMAGE_BYTES:
        problems.append("image.limit")
    elif not raw.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8")):
        problems.append("image.format")
    else:
        header = inspect_header(raw)
        if header is None:
            problems.append("image.header")
    if header is not None:
        if filename_format(name) != header.format:
            problems.append("image.extension")
        if (max(header.width, header.height) > MAX_DIMENSION
                or header.width * header.height > MAX_PIXELS):
            problems.append("image.dimensions")
        if kind is not None and kind.dimensions and (header.width, header.height) not in kind.dimensions:
            problems.append("image.device")
    return ({**content_digest(raw), "format": header.format if header else None,
             "width": header.width if header else None, "height": header.height if header else None,
             "headerChecked": header is not None and not problems}, tuple(problems))


@dataclass(frozen=True)
class SelectedImage:
    """Private core request data. Never serialize this dataclass to the UI."""

    item_id: str
    display_name: str
    data: bytes = field(repr=False)


def admit_selected_images(value: object) -> tuple[SelectedImage, ...]:
    _require(type(value) is tuple and 1 <= len(value) <= MAX_IMAGES)
    total, identifiers = 0, set()
    for item in value:
        _require(type(item) is SelectedImage and type(item.item_id) is str
                 and _TOKEN.fullmatch(item.item_id) is not None and item.item_id not in identifiers
                 and type(item.data) is bytes and 1 <= len(item.data) <= MAX_IMAGE_BYTES)
        _native_name(item.display_name)
        total += len(item.data)
        _require(total <= MAX_BATCH_BYTES, "limit")
        identifiers.add(item.item_id)
    return value  # type: ignore[return-value]


def protected_project_sources(value: object) -> tuple[str, ...]:
    """A restriction from the native batch, never destination authority.

    A selected original may already be inside the project. No non-no-op
    destination effect can target its original project-relative name. Paths
    outside the project stay native-private and do not enter this comparison.
    """
    _require(type(value) is list and len(value) <= MAX_IMAGES)
    result = []
    for path in value:
        _require(type(path) is str and 0 < len(path) <= 4096)
        try:
            _require(len(path.encode("utf-8")) <= 4096 and not path.startswith("/")
                     and all(part not in {"", ".", ".."} for part in path.split("/"))
                     and "\\" not in path and not any(ord(c) < 32 or ord(c) == 127 for c in path))
        except UnicodeError:
            raise MetadataImagesInputError() from None
        result.append(path)
    _require(len({name_key(path) for path in result}) == len(result))
    return tuple(result)



ImageObjectKey = tuple[str, int, int | bytes]


def _image_u64(value: object) -> int:
    _require(type(value) is str and 1 <= len(value) <= 20
             and value.isascii() and value.isdecimal()
             and (value == "0" or not value.startswith("0")))
    number = int(value)
    _require(number < 2**64)
    return number


def _image_object(value: object, family: str) -> ImageObjectKey:
    _require(type(family) is str and family in {"posix", "windows"} and type(value) is dict)
    if family == "posix":
        _require(set(value) == {"device", "inode"})
        return ("posix", _image_u64(value["device"]), _image_u64(value["inode"]))
    _require(set(value) == {"volumeSerial", "fileId"})
    serial = _image_u64(value["volumeSerial"])
    file_id = value["fileId"]
    _require(type(file_id) is str and re.fullmatch(r"[0-9a-f]{32}", file_id) is not None)
    # Native FILE_ID_128 bytes, in array order; never an integer/endian conversion.
    return ("windows", serial, bytes.fromhex(file_id))


@dataclass(frozen=True, slots=True)
class ImageRootIdentity:
    """Image-only immutable comparison DATA, never a root-open capability."""

    family: str
    object_key: ImageObjectKey
    directory_facts: tuple[int, int, int, int, int] | None

    def posix_values(self) -> dict[str, int]:
        _require(self.family == "posix" and self.directory_facts is not None)
        return dict(zip(("device", "inode", "mode", "uid", "gid"), self.directory_facts))


def image_registered_identity(value: object) -> ImageRootIdentity:
    _require(type(value) is dict)
    if set(value) == {"volumeSerial", "fileId"}:
        return ImageRootIdentity("windows", _image_object(value, "windows"), None)
    _require(set(value) == {"device", "inode", "mode", "uid", "gid"})
    device, inode = _image_u64(value["device"]), _image_u64(value["inode"])
    _require(inode != 0)
    for name in ("mode", "uid", "gid"):
        _require(type(value[name]) is int and 0 <= value[name] < 2**32)
    _require(value["mode"] & 0o170000 == 0o040000)
    return ImageRootIdentity("posix", ("posix", device, inode),
                             (device, inode, value["mode"], value["uid"], value["gid"]))


_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _windows_image_component(value: str) -> bool:
    # Same refusal predicate as the original native decode::component, not
    # accepted-path normalization (in particular, not Unicode case folding).
    if (not value or value in {".", ".."} or len(value.encode("utf-8")) > 255
            or len(value.encode("utf-16-le")) // 2 > 255 or value.endswith((".", " "))
            or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"/\\|?*' for c in value)):
        return False
    stem = value.split(".", 1)[0].rstrip(" ").translate(_ASCII_UPPER)
    if stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}:
        return False
    return not any(stem.startswith(prefix)
                   and stem[len(prefix):] in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"}
                   for prefix in ("COM", "LPT"))


def admit_image_root(value: object, identity: ImageRootIdentity) -> str:
    _require(type(identity) is ImageRootIdentity and type(value) is str and bool(value))
    try:
        _require(len(value.encode("utf-8")) <= 4096
                 and not any(ord(c) < 32 or ord(c) == 127 for c in value))
        if identity.family == "posix":
            # Preserve the existing wire rule. Original backend root admission
            # performs its stricter no-normalization checks before Path/IO.
            _require(value.startswith("/"))
        else:
            _require(identity.family == "windows")
            ordinary = value[4:] if value.startswith("\\\\?\\") else value
            _require(len(ordinary) > 3 and ordinary[0].isascii()
                     and ordinary[0].isalpha() and ordinary[1:3] == ":\\")
            parts = ordinary[3:].split("\\")
            _require(1 <= len(parts) <= 44 and all(_windows_image_component(part) for part in parts))
    except UnicodeError:
        raise MetadataImagesInputError() from None
    return value


def protected_source_objects(value: object, count: int, *, family: str) -> tuple[ImageObjectKey, ...]:
    """Private original restrictions, never target/recovery or recapture authority."""
    _require(type(count) is int and 1 <= count <= MAX_IMAGES
             and type(value) is list and len(value) == count)
    result = tuple(_image_object(row, family) for row in value)
    _require(len(set(result)) == count)
    return result


def admit_image_object_keys(value: object, count: int, *, family: str) -> tuple[ImageObjectKey, ...]:
    """Recheck native-only immutable keys at the original image lease boundary."""
    _require(type(family) is str and family in {"posix", "windows"}
             and type(count) is int and 1 <= count <= MAX_IMAGES
             and type(value) is tuple and len(value) == count)
    for key in value:
        _require(type(key) is tuple and len(key) == 3 and type(key[0]) is str and key[0] == family
                 and type(key[1]) is int and 0 <= key[1] < 2**64)
        if family == "posix":
            _require(type(key[2]) is int and 0 <= key[2] < 2**64)
        else:
            _require(type(key[2]) is bytes and len(key[2]) == 16)
    _require(len(set(value)) == count)
    return value


def image_observation_key(before: object, *, family: str) -> ImageObjectKey:
    """Project an actual existing backend observation; missing is never unprotected.

    Trusted absence is handled by the original ImageTargets caller, not here.
    No Windows writer exists; its full128 source DATA cannot impersonate stat.
    """
    _require(type(family) is str and family in {"posix", "windows"})
    if family == "windows":
        raise MetadataImagesInputError("unsupported_platform")
    _require(type(before) is dict and {"device", "inode"} <= set(before))
    device, inode = before["device"], before["inode"]
    _require(type(device) is int and 0 <= device < 2**64
             and type(inode) is int and 0 <= inode < 2**64)
    return ("posix", device, inode)


def _native_name(name: object) -> str:
    _require(type(name) is str and 1 <= len(name) <= MAX_NAME_BYTES)
    try:
        _require(len(name.encode("utf-8")) <= MAX_NAME_BYTES
                 and "/" not in name and "\\" not in name
                 and not any(ord(c) < 32 or ord(c) == 127 for c in name))
    except UnicodeError:
        raise MetadataImagesInputError() from None
    return name  # type: ignore[return-value]


def decode_native_images(value: object) -> tuple[SelectedImage, ...]:
    """A finite private wire decoder; it grants no original picker authority.

    Check count, stated decoded length, exact encoded expansion and the batch
    bound BEFORE base64 allocation. Native root/document capability checks are
    separate. Base64 is never included in a public result or exception.
    """
    _require(type(value) is list and 1 <= len(value) <= MAX_IMAGES)
    admitted = []
    total, encoded_total = 0, 0
    identifiers = set()
    for row in value:
        _require(type(row) is dict and set(row) == {"itemId", "displayName", "byteLength", "sha256", "base64"})
        identity, size, digest, encoded = row["itemId"], row["byteLength"], row["sha256"], row["base64"]
        _require(type(identity) is str and _TOKEN.fullmatch(identity) is not None and identity not in identifiers
                 and type(size) is int and 1 <= size <= MAX_IMAGE_BYTES
                 and type(digest) is str and _DIGEST.fullmatch(digest) is not None
                 and type(encoded) is str and len(encoded) == 4 * ((size + 2) // 3)
                 and encoded.isascii())
        name = _native_name(row["displayName"])
        total += size
        encoded_total += len(encoded)
        # Each independently encoded file can need its own padding quantum.
        _require(total <= MAX_BATCH_BYTES
                 and encoded_total <= 4 * ((MAX_BATCH_BYTES + 2) // 3 + MAX_IMAGES - 1), "limit")
        identifiers.add(identity)
        admitted.append((identity, name, size, digest, encoded))
    result = []
    for identity, name, size, digest, encoded in admitted:
        # Canonical padding bits matter: comparison DATA cannot alias a second
        # encoding. Avoid allocating another whole encoded copy to check them.
        padding = (3 - size % 3) % 3
        _require((not padding and not encoded.endswith("="))
                 or padding and encoded.endswith("=" * padding)
                 and not encoded.endswith("=" * (padding + 1)))
        if padding:
            tail = encoded[-padding - 1]
            _require(tail in _BASE64_ALPHABET
                     and _BASE64_ALPHABET.index(tail) & (15 if padding == 2 else 3) == 0)
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise MetadataImagesInputError() from None
        _require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
        result.append(SelectedImage(identity, name, raw))
    return tuple(result)


def target_names(selection: PublicImageSelection, images: tuple[SelectedImage, ...],
                 existing_names: tuple[str, ...]) -> tuple[str, ...]:
    """Derive before capture/review; never choose a path during Apply."""
    _require(type(selection) is PublicImageSelection and type(images) is tuple
             and 1 <= len(images) <= MAX_IMAGES and all(type(item) is SelectedImage for item in images)
             and type(existing_names) is tuple and len(existing_names) <= MAX_SIBLINGS
             and all(type(name) is str for name in existing_names))
    _require(len(set(name_key(name) for name in existing_names)) == len(existing_names), "portable_collision")
    kind = selection.asset_type
    names = []
    for index, item in enumerate(images, 1):
        suffix = item.display_name.rsplit(".", 1)[-1].lower() if filename_format(item.display_name) else "png"
        name = item.display_name if safe_name(item.display_name) else f"image-{index:02}-{hashlib.sha256(item.data).hexdigest()[:12]}.{suffix}"
        if kind.singleton:
            _require(len(images) == 1, "set_conflict")
            variants = tuple(existing for existing in existing_names
                             if existing.rsplit(".", 1)[0].casefold() == kind.identity.casefold())
            _require(len(variants) <= 1, "set_conflict")
            name = f"{kind.identity}.{suffix}"
            if variants:
                _require(filename_format(variants[0]) == filename_format(name), "singleton_format")
                name = variants[0]  # Same actual filename; JPG and JPEG are the same format.
        selection.relative_path(name)
        _require(not any(name_key(existing) == name_key(name) and existing != name for existing in existing_names),
                 "portable_collision")
        names.append(name)
    _require(len({name_key(name) for name in names}) == len(names), "portable_collision")
    return tuple(names)


def replacement_choices(value: object, images: tuple[SelectedImage, ...]) -> tuple[bool, ...]:
    _require(type(value) is list and len(value) == len(images))
    result = []
    for image, row in zip(images, value):
        _require(type(row) is dict and set(row) == {"itemId", "replaceExisting"}
                 and type(row["itemId"]) is str and row["itemId"] == image.item_id
                 and type(row["replaceExisting"]) is bool)
        result.append(row["replaceExisting"])
    return tuple(result)


def baseline(config: bytes, ignore: bytes, selection: PublicImageSelection,
             names: tuple[str, ...], observed: tuple[tuple[str, bytes], ...],
             images: tuple[SelectedImage, ...]) -> dict[str, Any]:
    inventory = {"platform": selection.platform, "locale": selection.locale,
                 "assetType": selection.asset_type.identity, "folder": selection.folder,
                 "targets": list(names), "existing": [{"name": name, **content_digest(raw)} for name, raw in observed],
                 "selected": [{"itemId": item.item_id, **content_digest(item.data)} for item in images]}
    raw = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return {"config": content_digest(config), "ignore": content_digest(ignore),
            "inventorySha256": hashlib.sha256(raw).hexdigest()}


def admit_baseline(value: object) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"config", "ignore", "inventorySha256"}
             and type(value["inventorySha256"]) is str and _DIGEST.fullmatch(value["inventorySha256"]) is not None)
    result = {"inventorySha256": value["inventorySha256"]}
    for key, maximum in (("config", MAX_CONFIG_BYTES), ("ignore", DEPENDENCY_LIMITS[1])):
        row = value[key]
        _require(type(row) is dict and set(row) == {"byteLength", "sha256"}
                 and type(row["byteLength"]) is int and 0 <= row["byteLength"] <= maximum
                 and type(row["sha256"]) is str and _DIGEST.fullmatch(row["sha256"]) is not None)
        result[key] = {"byteLength": row["byteLength"], "sha256": row["sha256"]}
    return result


def import_view(selection: PublicImageSelection, images: tuple[SelectedImage, ...],
                names: tuple[str, ...], observed: tuple[tuple[str, bytes], ...],
                replacements: tuple[bool, ...], *, dependency_bytes: int,
                protected_sources: tuple[str, ...] = ()
                ) -> tuple[dict[str, Any], tuple[bytes | None, ...]]:
    """Pure comparison/preview only. All observations must remain native-bound."""
    _require(type(selection) is PublicImageSelection
             and type(images) is tuple and type(names) is tuple and type(observed) is tuple
             and type(replacements) is tuple and 1 <= len(images) <= MAX_IMAGES
             and len(images) == len(names) == len(replacements)
             and len(observed) <= MAX_SIBLINGS and all(type(item) is SelectedImage for item in images)
             and type(dependency_bytes) is int and 0 <= dependency_bytes <= sum(DEPENDENCY_LIMITS)
             and all(type(choice) is bool for choice in replacements)
             and all(type(row) is tuple and len(row) == 2 and safe_name(row[0])
                     and type(row[1]) is bytes and len(row[1]) <= MAX_IMAGE_BYTES for row in observed)
             and all(safe_name(name) for name in names)
             and len({name_key(name) for name in names}) == len(names)
             and type(protected_sources) is tuple)
    admit_selected_images(images)
    protected = {name_key(path) for path in protected_project_sources(list(protected_sources))}
    before = dict(observed)
    _require(len(before) == len(observed) and len({name_key(name) for name in before}) == len(before), "portable_collision")
    remaining = dict(before)
    files, payloads, problems = [], [], []
    for item, name, replace in zip(images, names, replacements):
        old = before.get(name)
        _require(not replace or old is not None)
        candidate, candidate_issues = image_summary(item.data, item.display_name, selection.asset_type)
        original, _ = image_summary(old, name, selection.asset_type) if old is not None else (None, ())
        preserve = old is not None and (not replace or old == item.data)
        action = "preserve" if preserve else "create" if old is None else "replace"
        after = original if preserve else candidate
        source_target = name_key(selection.relative_path(name)) in protected
        problems.extend(candidate_issues)
        if not preserve:
            remaining[name] = item.data
            if source_target:
                problems.append("image.source-target")
        files.append({"itemId": item.item_id, "displayName": item.display_name,
                      "path": selection.relative_path(name), "action": action,
                      "before": original, "selected": candidate, "after": after,
                      "canReplace": old is not None and old != item.data and not source_target,
                      "issues": [issue(code) for code in candidate_issues]})
        payloads.append(None if preserve else item.data)
    current = []
    for name, raw in observed:
        summary, _ = image_summary(raw, name, selection.asset_type)
        current.append({"path": selection.relative_path(name), "summary": summary})
    digests = set()
    for name, raw in sorted(remaining.items()):
        summary, found = image_summary(raw, name, selection.asset_type)
        if found:
            problems.append("image.sibling")
        if summary["sha256"] in digests:
            problems.append("image.duplicate")
        digests.add(summary["sha256"])
    if len(remaining) > selection.asset_type.max_count:
        problems.append("image.count")
    if dependency_bytes + sum(len(raw) for _, raw in observed) + sum(len(raw) for raw in payloads if raw is not None) > MAX_TOTAL_BYTES:
        problems.append("image.total")
    unique = tuple(dict.fromkeys(problems))
    view = {"kind": "import", "policy": POLICY, "platform": selection.platform, "locale": selection.locale,
            "assetType": selection.asset_type.identity, "metadataRoot": selection.metadata_root, "folder": selection.folder,
            "files": files, "existing": current,
            "finalOrder": [selection.relative_path(name) for name in sorted(remaining)],
            "valid": not unique, "issues": [issue(code) for code in unique],
            "assurance": {"localCopyOnly": True, "sourceFilesUnchanged": True, "storeContacted": False,
                          "fullDecode": False, "contentApproved": False, "storeAccepted": False}}
    _require(len(json.dumps(view, ensure_ascii=True, separators=(",", ":")).encode("ascii")) <= MAX_PREPARED_BYTES,
             "limit")
    return view, tuple(payloads)
