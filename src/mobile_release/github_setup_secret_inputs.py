"""Fixed readonly saved-config custody for the genuine Setup secret operation.

No credential material, network, generic path reader or write authority. The
containing native profile reserves CONFIGURATION_WORK_BYTES before dispatch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from . import _github_connection_transport as transport
from .api import _snapshot as snapshot
from .config import ReleaseConfig, parse_config_text
from .credential_requirements import requirements, STAGES

CONFIGURATION_WORK_BYTES = 16 * 1024 * 1024
CONFIGURATION_PATH = "release/mobile-release.json"
MAX_CONFIG_BYTES = 512 * 1024
_MAX_COMPONENTS = 32
_MAX_LIVE = 40
_MAX_OPENS = 128
_MAX_ENTRIES = 4096
_MAX_CHECKPOINTS = 32
_MAX_READ_REQUESTS = 4 * 1024 * 1024
# Only supported actual record-backed canonical secrets, not policy alternatives.
_FIELDS = {
    "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": ("android", "base64"),
    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": ("android", "utf8"),
    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": ("android", "utf8"),
    "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": ("android", "base64"),
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": ("ios", "base64"),
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": ("ios", "utf8"),
    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": ("ios", "base64"),
    "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": ("ios", "base64"),
    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": ("ios", "base64"),
    "MOBILE_RELEASE_PROJECT_READ_TOKEN": ("project", "utf8"),
}


class SecretConfigurationError(ValueError):
    """Finite reason and original-cleanup veto; no paths, config or material."""
    def __init__(self, reason: str):
        self.reason = reason
        self._cleanup_unknown = False  # No original has been acquired before custody.
        super().__init__(reason)

    @property
    def cleanup_unknown(self) -> bool:
        """A failure veto, never independent evidence of successful settlement."""
        return self._cleanup_unknown


def _need(condition: bool, reason: str = "configuration-changed") -> None:
    if not condition:
        raise SecretConfigurationError(reason)


def _keys(value, expected: set[str]) -> None:
    _need(type(value) is dict and set(value) == expected)


def _uint(value, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _hex(value, length: int) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None


def _source(source: dict, selection: dict, *, kind: str = "secret") -> tuple[str, tuple[int, ...]]:
    _keys(source, {"root", "rootIdentity", "draft", "platform", "purpose", "material"})
    _keys(selection, {"kind", "mode", "stage", "requirement", "source"})
    _keys(selection["source"], {"recordId", "recordRevision", "contextRevision"})
    ref = selection["source"]
    _need(kind in ("secret", "variable"))
    _need(selection["kind"] == "environment_" + kind and selection["mode"] in ("create", "replace")
          and selection["stage"] in STAGES and _hex(ref["recordId"], 32)
          and _uint(ref["recordRevision"], 2**32 - 1) and _uint(ref["contextRevision"], 2**32 - 1))
    name = selection["requirement"]
    if kind == "secret":
        _need(type(name) is str and name in _FIELDS, "requirement-unsupported")
        platform, encoding = _FIELDS[name]
    else:
        from .github_setup_variables import VariableSelection, VARIABLE_FIELDS
        _need(type(name) is str and name in {row[0] for row in VARIABLE_FIELDS}, "requirement-unsupported")
        selected = VariableSelection.parse(selection)
        platform = selected.mapping[2]
    _need(source["platform"] == platform and source["purpose"] in ("full", "signing", "store"), "requirement-unsupported")
    _keys(source["draft"], {"bytes", "sha256"})
    _need(_uint(source["draft"]["bytes"], MAX_CONFIG_BYTES, 1) and _hex(source["draft"]["sha256"], 64))
    if kind == "secret":
        _keys(source["material"], {"encoding", "plaintextBytes"})
        _need(source["material"]["encoding"] == encoding and _uint(source["material"]["plaintextBytes"], 49152, 1), "material-too-large")
    else:
        from .github_setup_variables import MAX_VALUE_BYTES
        _keys(source["material"], {"bytes", "sha256"})
        _need(_uint(source["material"]["bytes"], MAX_VALUE_BYTES, 1), "material-too-large")
        _need(_hex(source["material"]["sha256"], 64))
    root = snapshot.validate_root(source["root"])
    _need(len(root.split("/")) - 1 <= _MAX_COMPONENTS, "resources-unavailable")
    identity = source["rootIdentity"]
    _keys(identity, {"device", "inode", "mode", "uid", "gid"})
    numbers = []
    for key in ("device", "inode"):
        value = identity[key]
        _need(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None)
        integer = int(value)
        _need(integer <= 2**64 - 1)
        numbers.append(integer)
    _need(all(_uint(identity[k], 2**32 - 1) for k in ("mode", "uid", "gid")) and stat.S_ISDIR(identity["mode"]))
    return root, (*numbers, identity["mode"], identity["uid"], identity["gid"])


def _json_prelude(raw: bytes, budget: _SecretConfigurationBudget) -> None:
    """Prospective token/depth guard, not a second semantic JSON decoder."""
    tokens = depth = 0
    index = 0
    while index < len(raw):
        if index % 4096 == 0:
            budget.check()
        c = raw[index]
        if c in b" \t\r\n,:":
            index += 1
            continue
        if c in b"]}":
            depth -= 1
            _need(depth >= 0)
            index += 1
            continue
        tokens += 1
        _need(tokens <= 8000, "resources-unavailable")
        if c in b"[{":
            depth += 1
            _need(depth <= 28, "resources-unavailable")
            index += 1
        elif c == 34:
            index += 1
            while index < len(raw):
                if index % 4096 == 0:
                    budget.check()
                c = raw[index]
                index += 1
                if c == 34:
                    break
                if c == 92:
                    index += 1
        else:
            while index < len(raw) and raw[index] not in b" \t\r\n,:[]{}\"":
                if index % 4096 == 0:
                    budget.check()
                index += 1
    _need(depth == 0)
    budget.check()


class _SecretConfigurationBudget:
    """One finite filesystem loan of the exact existing transport Budget."""
    def __init__(self, owner: transport._Budget, root: str):
        _need(type(owner) is transport._Budget and owner.profile is transport._ExchangeProfile.SETUP)
        _need(not hasattr(owner, "_secret_configuration_claimed"), "resources-unavailable")
        owner.remaining()
        # Monotone one-use reservation on the SAME owner, never renewed on exit.
        owner._secret_configuration_claimed = CONFIGURATION_WORK_BYTES
        self.owner = owner
        self.end = owner.end
        self.root = Path(root)
        self.root_fd: int | None = None
        self.handles: set[int] = set()
        self.chain: list[tuple[int | None, str, int, tuple[int, ...]]] = []
        self.opens = self.live = self.entries_seen = self.reads = self.checks = 0
        self.failed: str | None = None
        self.closed = False
        self.close_unknown = False

    def fail(self, reason: str = "configuration-changed") -> None:
        if self.failed is None:
            self.failed = reason
        raise SecretConfigurationError(self.failed)

    def remember(self, error: BaseException) -> None:
        if self.failed is None:
            self.failed = error.reason if type(error) is SecretConfigurationError else "configuration-changed"

    def check(self) -> None:
        if self.closed or self.failed is not None:
            self.fail()
        if self.owner.end != self.end or self.owner.profile is not transport._ExchangeProfile.SETUP:
            self.fail()
        try:
            self.owner.remaining()
        except Exception:
            self.fail("network-unavailable")

    checkpoint = check

    def _acquire(self) -> None:
        self.check()
        if self.opens >= _MAX_OPENS or self.live >= _MAX_LIVE:
            self.fail("resources-unavailable")
        self.opens += 1
        self.live += 1

    def open_fd(self, name, flags: int, *, parent: int | None = None) -> int:
        self._acquire()
        try:
            descriptor = os.open(name, flags, dir_fd=parent)
        except BaseException:
            self.live -= 1
            if self.failed is None:
                self.failed = "configuration-changed"
            raise
        self.handles.add(descriptor)
        return descriptor

    def close_fd(self, descriptor: int) -> None:
        if descriptor not in self.handles:
            self.fail()
        self.handles.remove(descriptor)  # Consume before the single close attempt.
        try:
            os.close(descriptor)
        except BaseException:
            self.close_unknown = True
            if self.failed is None:
                self.failed = "configuration-changed"
            raise
        else:
            self.live -= 1

    @contextmanager
    def entries(self, parent: int):
        self._acquire()
        try:
            iterator = os.scandir(parent)
        except BaseException:
            self.live -= 1
            if self.failed is None:
                self.failed = "configuration-changed"
            raise
        first: BaseException | None = None
        try:
            def bounded():
                while True:
                    self.check()
                    if self.entries_seen >= _MAX_ENTRIES:
                        self.fail("resources-unavailable")
                    # Debit even the EOF advance; no uncharged sentinel entry.
                    self.entries_seen += 1
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        return
                    yield entry
            yield bounded()
        except BaseException as error:
            first = error
            if self.failed is None:
                self.failed = "configuration-changed"
        finally:
            try:
                iterator.close()
            except BaseException as error:
                self.close_unknown = True
                if self.failed is None:
                    self.failed = "configuration-changed"
                if first is None:
                    first = error
            else:
                self.live -= 1
        if first is not None:
            raise first

    def read_request(self, amount: int) -> None:
        self.check()
        if not _uint(amount, _MAX_READ_REQUESTS, 1) or amount > _MAX_READ_REQUESTS - self.reads:
            self.fail("resources-unavailable")
        self.reads += amount

    def file_admission(self, path: Path, limit: int) -> int:
        self.check()
        if path != self.root / CONFIGURATION_PATH or limit != MAX_CONFIG_BYTES:
            self.fail()
        return MAX_CONFIG_BYTES

    def open_root(self, expected: tuple[int, ...]) -> None:
        parent = None
        for name in ("/", *str(self.root).split("/")[1:]):
            self.check()
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _need(stat.S_ISDIR(before.st_mode))
            descriptor = self.open_fd(name, snapshot._directory_flags(), parent=parent)
            identity = snapshot._named_identity(os.fstat(descriptor))
            _need(identity == snapshot._named_identity(before))
            self.chain.append((parent, name, descriptor, identity))
            parent = descriptor
        self.root_fd = parent
        actual = os.fstat(parent)
        _need((actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid) == expected)
        self.check_root()

    def check_root(self) -> None:
        self.check()
        for parent, name, descriptor, expected in self.chain:
            self.check()
            _need(snapshot._named_identity(os.fstat(descriptor)) == expected
                  and snapshot._named_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)

    def close(self) -> None:
        # All independent originals settle even after timeout or an earlier error.
        first: BaseException | None = None
        for descriptor in tuple(self.handles):
            try:
                self.close_fd(descriptor)
            except BaseException as error:
                if first is None:
                    first = error
        self.closed = True
        if first is not None:
            raise first
        _need(self.live == 0 and not self.close_unknown)


class _Observed:
    def __init__(self, budget: _SecretConfigurationBudget, reader, value: dict):
        self._budget, self._reader, self._value = budget, reader, value

    def checkpoint(self) -> None:
        try:
            self._budget.check()
            if self._budget.checks >= _MAX_CHECKPOINTS:
                self._budget.fail("resources-unavailable")
            self._budget.checks += 1
            self._budget.check_root()
            self._reader.check()
            self._budget.check()
        except BaseException:
            if self._budget.failed is None:
                self._budget.failed = "configuration-changed"
            raise

    def value(self) -> dict:
        self.checkpoint()
        return {key: dict(value) for key, value in self._value.items()}


def _digest(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def observe_secret_configuration(source: dict, selection: dict, *, budget: transport._Budget):
    """Borrow one genuine saved config until every network-stage recheck ends."""
    return _observe_configuration(source, selection, budget=budget, kind="secret")


def observe_variable_configuration(source: dict, selection: dict, *, budget: transport._Budget):
    """Same original custody, only the five actual required nonsecret fields."""
    return _observe_configuration(source, selection, budget=budget, kind="variable")


@contextmanager
def _observe_configuration(source: dict, selection: dict, *, budget: transport._Budget, kind: str):
    try:
        root, expected = _source(source, selection, kind=kind)
    except SecretConfigurationError:
        raise
    except Exception as error:
        raise SecretConfigurationError("configuration-changed") from error
    _need(snapshot.posix_snapshot_available(), "runtime-unavailable")
    custody = _SecretConfigurationBudget(budget, root)
    first: BaseException | None = None
    try:
        custody.open_root(expected)
        with snapshot.borrowed_setup_secret_reads(custody) as reader:
            raw = reader.read(CONFIGURATION_PATH, limit=MAX_CONFIG_BYTES, binary=True)
            _need(type(raw) is bytes and 0 < len(raw) <= MAX_CONFIG_BYTES)
            _json_prelude(raw, custody)
            data = parse_config_text(raw.decode("utf-8"))
            custody.check()
            # Exact existing Android/iOS native-draft comparison convention.
            canonical = json.dumps(data, sort_keys=True, ensure_ascii=False,
                                   separators=(",", ":"), allow_nan=False).encode("utf-8")
            _need(0 < len(canonical) <= MAX_CONFIG_BYTES and _digest(canonical) == source["draft"])
            config = ReleaseConfig(path=Path(root) / CONFIGURATION_PATH, root=Path(root), data=data)
            selected = requirements(config, selection["stage"], purpose=source["purpose"],
                                    platforms=() if source["platform"] == "project" else (source["platform"],))
            matching = [r for r in selected if r.name == selection["requirement"] and r.kind == kind
                        and r.stage == selection["stage"] and r.platform == source["platform"]]
            _need(len(matching) == 1, "requirement-unsupported")
            value = {"savedConfig": _digest(raw), "canonicalConfig": _digest(canonical),
                     "requirement": {"name": matching[0].name, "kind": kind, "stage": matching[0].stage,
                                     "platform": matching[0].platform}}
            # No parsed config/body retained for the network phase.
            del raw, canonical, data, config, selected, matching
            observed = _Observed(custody, reader, value)
            observed.checkpoint()
            yield observed
            observed.checkpoint()
        custody.check_root()
        custody.check()
    except BaseException as error:
        first = error
        if custody.failed is None:
            custody.failed = error.reason if type(error) is SecretConfigurationError else "configuration-changed"
    finally:
        try:
            custody.close()
        except BaseException as error:
            if first is None:
                first = error
    if first is None:
        try:
            # Known consuming closes do not grant extra success time.
            _need(budget.end == custody.end and custody.failed is None)
            budget.remaining()
        except Exception as error:
            if custody.failed is None and isinstance(error, transport.ReadFailure):
                custody.failed = "network-unavailable"
            custody.remember(error)
            first = error
    if first is not None:
        if isinstance(first, (KeyboardInterrupt, SystemExit)):
            raise first
        failure = SecretConfigurationError(custody.failed or "configuration-changed")
        # Bind only after ALL independent consuming closes above. Native/owner
        # finality remains mandatory even when this additional veto is false.
        failure._cleanup_unknown = custody.close_unknown or custody.live != 0 or bool(custody.handles)
        raise failure from first
