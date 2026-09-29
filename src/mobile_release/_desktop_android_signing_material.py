"""Private selected Android inputs for one original saved build.

These are not renderer values, private filenames or independent capabilities.
Shared credentials policy consumes them only through their original operation.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
import select

from ._desktop_android_build_protocol import context as checked_context, _encode, require

PREFIX = b"MRK-ANDROID-MATERIAL/1\n"
SUFFIX = b"\nMRK-ANDROID-MATERIAL-END\n"
HEADER_LIMIT = 1024
LIMITS = {"android-keystore": 32 * 1024**2, "store-password": 4096,
          "key-alias": 4096, "key-password": 4096, "android-firebase": 4 * 1024**2,
          "project-read-token": 4096}
MATERIAL_LIMIT = sum(LIMITS.values())
FILES = {"android-keystore": "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
         "android-firebase": "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64"}
SCALARS = {"store-password": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
           "key-alias": "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
           "key-password": "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
           "project-read-token": "MOBILE_RELEASE_PROJECT_READ_TOKEN"}


def roles_for(context: dict) -> tuple[str, ...]:
    selected = checked_context(context)["signing"]
    require(selected is not None)
    kinds = tuple(row["kind"] for row in selected["assignments"])
    return ("android-keystore", "store-password", "key-alias", "key-password", *kinds[1:])


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        require(name not in result)
        result[name] = value
    return result


def parse_header(raw: bytes, roles: tuple[str, ...]) -> tuple[int, ...]:
    require(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n")
            and raw.count(b"\n") == 1)
    try:
        header = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        require(False)
    require(type(header) is dict and set(header) == {"schemaVersion", "files"}
            and type(header["schemaVersion"]) is int and header["schemaVersion"] == 1
            and type(header["files"]) is list and len(header["files"]) == len(roles))
    lengths = []
    for role, row in zip(roles, header["files"]):
        require(type(row) is dict and set(row) == {"role", "bytes"} and row["role"] == role
                and role in LIMITS and type(row["bytes"]) is int and 0 < row["bytes"] <= LIMITS[role])
        lengths.append(row["bytes"])
    require(sum(lengths) <= MATERIAL_LIMIT)
    return tuple(lengths)


class PrivateAndroidMaterial:
    """Original partially received bytes remain rooted on failure or STOP."""

    def __init__(self, source, context: dict) -> None:
        from ._desktop_android_build_control import AndroidBuildInput
        require(type(source) is AndroidBuildInput and source.material is None
                and source.material_pending and source.material_receiving)
        self._source = source
        self._context = None
        self._operation = None
        self._files: dict[str, bytes] = {}
        self._scalars: dict[str, str] = {}
        self._pending = bytearray()
        self._chunk: bytes | None = None
        self._ready = self._retired = False
        source.material = self  # Before parsing, reads or constructor return.
        self._context = _encode(checked_context(context))

    def _receive(self, role: str, value: bytes) -> None:
        require(not self._ready and not self._retired and role in LIMITS
                and type(value) is bytes and 0 < len(value) <= LIMITS[role])
        if role in FILES:
            require(FILES[role] not in self._files)
            self._files[FILES[role]] = value
        else:
            require(role in SCALARS and SCALARS[role] not in self._scalars)
            try:
                text = value.decode("utf-8")
            except UnicodeError:
                require(False)
            require(bool(text) and "\0" not in text)
            self._scalars[SCALARS[role]] = text  # Never trim or substitute a password.

    def bind(self, operation) -> CapturedAndroidBuildValues:
        from .android_build_operation import AndroidBuildOperation
        require(type(operation) is AndroidBuildOperation and operation.signing is not None
                and self._operation is None and self._ready and not self._retired
                and operation.source is self._source and operation.source.operation is operation
                and self._source.material is self and _encode(checked_context(operation.request.context)) == self._context)
        self._operation = operation
        return CapturedAndroidBuildValues(self, frozenset((*self._files, *self._scalars)))

    def check(self) -> None:
        operation = self._operation
        require(operation is not None and self._ready and not self._retired
                and operation.source is self._source and self._source.material is self
                and _encode(checked_context(operation.request.context)) == self._context)
        operation.checkpoint()

    def retire(self) -> None:
        source = self._source
        source._owner()
        if self._retired:
            return
        operation = source.operation
        require(source.closed and not source.material_receiving and operation is not None
                and (self._operation is None or self._operation is operation)
                and operation.commands_settled() and operation.closed()
                and operation.signing is not None and operation.signing.inputs_closed())
        operation.signing.retire_values()
        self._retired = True
        self._pending.clear()
        self._chunk = None
        self._files.clear()
        self._scalars.clear()  # Memory release is not a secure-erasure claim.


class CapturedAndroidBuildValues(Mapping[str, str]):
    """Only scalars iterate; files never become environment/path/base64 values."""

    def __init__(self, original: PrivateAndroidMaterial, selected: frozenset[str]) -> None:
        require(type(original) is PrivateAndroidMaterial and type(selected) is frozenset
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
        require(operation.root == root and operation.guard is cancellation)
        return self._original._files.get(name) if name in self._selected else None

    def for_invocation(self, invocation) -> CapturedAndroidBuildValues:
        self._original.check()
        operation = self._original._operation
        require(operation.invocation is invocation and invocation.signing_lease is None
                and operation.signing is not None and invocation.child is operation.signing.materialization
                and invocation.child is not None and invocation.child.cancellation is operation.guard)
        return self


def read_material(source, request) -> PrivateAndroidMaterial:
    """Drain the bounded body through the existing original STOP input owner."""
    source._owner()
    require(source.guard is not None and source.active and source.request_returned
            and source.material_pending and source.material_receiving and source.material is None)
    original = PrivateAndroidMaterial(source, request.context)

    def take(length: int) -> bytes:
        require(not original._pending and 0 < length <= max(LIMITS.values()))
        while len(original._pending) < length:
            source.guard.check()
            require(source.fd is not None)
            if not source.buffer:
                try:
                    select.select([source.fd], [], [], 0.05)
                except (OSError, ValueError) as error:
                    source.stop()
                    source.guard._abort(error)
                    raise
                continue
            count = min(length - len(original._pending), len(source.buffer))
            original._pending.extend(source.buffer[:count])
            del source.buffer[:count]
        result = bytes(original._pending)
        original._chunk = result  # Retain converted bytes before the caller can lose its return.
        original._pending.clear()
        return result

    require(take(len(PREFIX)) == PREFIX)
    header = bytearray()
    while not header.endswith(b"\n"):
        require(len(header) < HEADER_LIMIT)
        header.extend(take(1))
    roles = roles_for(request.context)
    for role, length in zip(roles, parse_header(bytes(header), roles)):
        original._receive(role, take(length))
    require(take(len(SUFFIX)) == SUFFIX)
    original._ready = True
    return original
