"""Bounded private input for the original signed Android operation.

Only selected, immutable session bytes cross this channel. These objects are not
renderer DTOs, external filenames, environment values or signing authority. The
existing credential validators/materializer remain responsible for policy.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
import select
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .android_build_operation import AndroidBuildOperation

PREFIX = b"MRK-ANDROID-MATERIAL/1\n"
SUFFIX = b"\nMRK-ANDROID-MATERIAL-END\n"
HEADER_LIMIT = 1024
LIMITS = {"android-keystore": 32 * 1024**2, "store-password": 8192,
          "key-alias": 8192, "key-password": 8192, "android-firebase": 4 * 1024**2}
MATERIAL_LIMIT = sum(LIMITS.values())
FILES = {"android-keystore": "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
         "android-firebase": "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64"}
SCALARS = {"store-password": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
           "key-alias": "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
           "key-password": "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"}


def _require(condition: bool) -> None:
    from ._desktop_android_build_protocol import require
    require(condition)


def roles_for(context: dict) -> tuple[str, ...]:
    signing = context.get("signing")
    _require(type(signing) is dict)
    kinds = tuple(row["kind"] for row in signing["assignments"])
    _require(kinds in (("android-keystore",), ("android-keystore", "android-firebase")))
    return ("android-keystore", "store-password", "key-alias", "key-password", *kinds[1:])


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        _require(name not in result)
        result[name] = value
    return result


def parse_header(raw: bytes, roles: tuple[str, ...]) -> tuple[int, ...]:
    _require(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n"))
    try:
        header = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        _require(False)
    _require(type(header) is dict and set(header) == {"schemaVersion", "files"}
             and type(header["schemaVersion"]) is int and header["schemaVersion"] == 1
             and type(header["files"]) is list and len(header["files"]) == len(roles))
    lengths = []
    for role, row in zip(roles, header["files"]):
        _require(type(row) is dict and set(row) == {"role", "bytes"}
                 and row["role"] == role and role in LIMITS
                 and type(row["bytes"]) is int and 0 < row["bytes"] <= LIMITS[role])
        lengths.append(row["bytes"])
    _require(sum(lengths) <= MATERIAL_LIMIT)
    return tuple(lengths)


class PrivateAndroidMaterial:
    """One bounded received body; no repr/readback or pathname conversion."""

    def __init__(self, source, context: dict, contents: tuple[bytes, ...]) -> None:
        from ._desktop_android_build_control import AndroidBuildInput
        _require(type(source) is AndroidBuildInput and source.signed and source.material_pending)
        roles = roles_for(context)
        _require(len(contents) == len(roles) and all(type(value) is bytes
                 and 0 < len(value) <= LIMITS[role] for role, value in zip(roles, contents)))
        # Canonical immutable DATA, not an alias to the mutable decoded request.
        from ._desktop_android_build_protocol import context as checked_context, _encode
        self._source, self._context = source, _encode(checked_context(context))
        self._files: dict[str, bytes] = {}
        self._scalars: dict[str, str] = {}
        self._operation = None
        self._retired = False
        for role, value in zip(roles, contents):
            if role in FILES:
                self._files[FILES[role]] = value
            else:
                try:
                    text = value.decode("utf-8")
                except UnicodeError:
                    _require(False)
                # Existing session scalar policy treats empty as missing and
                # NUL as invalid, not whitespace/newlines as invalid passwords.
                _require(bool(text) and "\0" not in text and (role != "key-alias" or not text.startswith("-")))
                self._scalars[SCALARS[role]] = text

    def bind(self, operation: AndroidBuildOperation) -> CapturedAndroidBuildValues:
        from .android_build_operation import AndroidBuildOperation
        from ._desktop_android_build_protocol import context as checked_context, _encode
        _require(type(operation) is AndroidBuildOperation and self._operation is None
                 and not self._retired and operation.source is self._source
                 and _encode(checked_context(operation.request.context)) == self._context
                 and operation.source.operation is operation
                 and operation.source.material is self)
        self._operation = operation
        return CapturedAndroidBuildValues(self, frozenset((*self._files, *self._scalars)))

    def check(self) -> None:
        from ._desktop_android_build_protocol import context as checked_context, _encode
        operation = self._operation
        _require(operation is not None and not self._retired
                 and operation.source is self._source and self._source.material is self
                 and _encode(checked_context(operation.request.context)) == self._context)
        operation.checkpoint()

    def retire(self) -> None:
        self._source._owner()
        if self._retired:
            return
        operation = self._operation
        _require(self._source.closed and (operation is None or operation.commands_settled()
                 and operation.closed()))
        self._retired = True
        self._files.clear()
        self._scalars.clear()  # Releasing memory is not a secure-erasure claim.


class CapturedAndroidBuildValues(Mapping[str, str]):
    """Compatibility mapping of scalars, with separately bound original files.

    Iteration deliberately exposes no file bytes/base64/path to an environment
    update. Existing material selection obtains files only through material().
    """

    def __init__(self, original: PrivateAndroidMaterial, selected: frozenset[str]) -> None:
        _require(type(original) is PrivateAndroidMaterial and type(selected) is frozenset
                 and selected <= set(original._files) | set(original._scalars))
        self._original, self._selected = original, selected

    def __getitem__(self, name: str) -> str:
        self._original.check()
        if name not in self._selected or name not in self._original._scalars:
            raise KeyError(name)
        return self._original._scalars[name]

    def __iter__(self) -> Iterator[str]:
        self._original.check()
        return iter(tuple(name for name in self._original._scalars if name in self._selected))

    def __len__(self) -> int:
        self._original.check()
        return sum(name in self._selected for name in self._original._scalars)

    def select(self, allowed: set[str]) -> CapturedAndroidBuildValues:
        self._original.check()
        return CapturedAndroidBuildValues(self._original, self._selected & allowed)

    def material(self, name: str, *, root, cancellation) -> bytes | None:
        self._original.check()
        operation = self._original._operation
        _require(operation.root == root and operation.guard is cancellation)
        return self._original._files.get(name) if name in self._selected else None

    def for_invocation(self, invocation) -> CapturedAndroidBuildValues:
        self._original.check()
        operation = self._original._operation
        _require(operation.invocation is invocation and invocation.signing_lease is None
                 and operation.signing is not None and invocation.child is operation.signing.materialization
                 and invocation.child is not None and not invocation.child.claimed
                 and invocation.child.cancellation is operation.guard)
        return self


def read_material(source, request) -> PrivateAndroidMaterial:
    """Consume one exact private frame using the original nonblocking stdin.

    The public request buffer remains capped at its existing 32 KiB. Bodies
    drain incrementally; only one current immutable conversion can coexist with
    its bytearray (bounded by the largest role,32MiB). EOF/STOP is never a body.
    """
    source._owner()
    _require(source.guard is not None and source.active and source.request_returned
             and source.material_pending and source.material_receiving and source.material is None)

    def wait() -> None:
        source.guard.check()
        _require(source.fd is not None)
        if not source.buffer:
            try:
                select.select([source.fd], [], [], 0.05)
            except (OSError, ValueError) as error:
                source.stop()
                source.guard._abort(error)
                raise

    def take(length: int) -> bytes:
        value = bytearray()
        while len(value) < length:
            wait()
            count = min(length - len(value), len(source.buffer))
            value.extend(source.buffer[:count])
            del source.buffer[:count]
        return bytes(value)

    _require(take(len(PREFIX)) == PREFIX)
    header = bytearray()
    while not header.endswith(b"\n"):
        _require(len(header) < HEADER_LIMIT)
        header.extend(take(1))
    roles = roles_for(request.context)
    lengths = parse_header(bytes(header), roles)
    contents = tuple(take(length) for length in lengths)
    _require(take(len(SUFFIX)) == SUFFIX)
    original = PrivateAndroidMaterial(source, request.context, contents)
    source.material = original  # Root original private input before another poll.
    return original
