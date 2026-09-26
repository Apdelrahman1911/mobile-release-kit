"""Original protected Android tools; no installer, probe, runner or qualification.

The whole android-toolchain.json digest and instance come from the original
native binding. Native admission must FIRST establish its actual unprivileged
credentials, namespaces, mounts, OS profile/aliases and retained original joins.
This Python owner independently admits the named original files, not that native
boundary. Mode bits, matching devices and these DATA parsers cannot prove it.
All production availability remains subject to that separate native integration.

Launch contract v1 deliberately constructs JAVA_OPTS itself, never inherits it.
The qualified Gradle script must parse its POSIX-quoted options, including the
supported nontrivial private path spellings. Daemon and bundletool receive the
same explicit JVM home/tmp. The actual tuple must qualify those controls; this
module neither invents a supported installed version nor runs a version probe.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from .build_inputs import BuildInputError, _Directory, _FD, _cleanup_failure, _direct_refusal
from .config import ReleaseVersion
from .errors import ValidationError
from .owned_process import fatal_lifetime_error
from .toolchain_policy import BUNDLETOOL_MAX_BYTES, BUNDLETOOL_SHA256, BUNDLETOOL_VERSION

PROFILE = "android-local-linux-gnu-x86_64-v1"
TARGET = "linux-gnu-x86_64"
LAUNCH_CONTRACT = "gradle-posix-private-jvm-v1"
PREFIX = "/opt/mobile-release-kit/android/"
MANIFEST_NAME = "android-toolchain.json"
OS_SHELL, OS_EXECUTABLE_DIRECTORY = "/usr/bin/dash", "/usr/bin"
MAX_MANIFEST_BYTES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 4 * 1024**2, 512 * 1024**2, 1024**3
MAX_TOOL_FILES, MAX_OS_FILES, MAX_ENTRIES, MAX_DESCRIPTORS = 16_384, 256, 32_768, 32_768
MAX_OS_HELPERS = 128
MAX_MANIFEST_NODES = 150_000  # Closed schema maximum: 67 + 128 + 9 * (16384 + 256) = 149955.
MAX_DIRECTORY_ADVANCES = 2 * MAX_ENTRIES  # Includes each original iterator's final next attempt.
MIN_DESCRIPTOR_LIMIT = 65_536  # Admission floor, NOT a claim of ambient headroom.
MAX_DEPTH, MAX_PATH_BYTES, READ_CHUNK = 16, 512, 64 * 1024
MAX_SELECTION_BYTES, MAX_PROPERTY_LINES, MAX_PROPERTY_LINE = 512 * 1024, 4096, 4096
MAX_CHECKPOINTS = 4_000_000  # Basic/upload inspection has14/23 metadata rounds; cleanup keeps its own cutoff.
WORKERS = 2
TOOL_ROLES = {"java": "jdk/bin/java", "javac": "jdk/bin/javac", "gradle": "gradle/bin/gradle",
              "bundletool": "bundletool/bundletool.jar", "sdk": "sdk"}
AAPT2_PATH = "gradle/native/aapt2/aapt2"
JARSIGNER_PATH, KEYTOOL_PATH = "jdk/bin/jarsigner", "jdk/bin/keytool"
SELECTION_FIELDS = ("wrapper_properties", "local_properties", "root_gradle_properties",
                    "module_gradle_properties", "daemon_jvm_properties")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_INSTANCE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9_.+-]{0,63}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_+@.,=-]{1,255}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_OS_SCANDIR = os.scandir
_SCAN_REFUSALS = {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM,
                  errno.EBADF, errno.EMFILE, errno.ENFILE}


class AndroidToolError(ValidationError):
    """Fixed private-safe reason, never a path, property value or OS transcript."""

    def __init__(self, reason: str = "toolchain-mismatch") -> None:
        self.reason = reason
        super().__init__("The required Android tool profile could not be admitted")


def _need(condition: bool, reason: str = "toolchain-mismatch") -> None:
    if not condition:
        raise AndroidToolError(reason)


def _integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _text(value: object, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _keys(value: object, fields: set[str]) -> dict:
    _need(type(value) is dict and all(type(key) is str for key in value) and set(value) == fields)
    return value


def _parts(value: object, *, absolute: bool = False) -> tuple[str, ...]:
    _need(type(value) is str and 0 < len(value) <= MAX_PATH_BYTES)
    _need(value.startswith("/") if absolute else not value.startswith("/"))
    parts = tuple(value[1:].split("/") if absolute else value.split("/"))
    _need(len(parts) <= MAX_DEPTH and all(_text(part, _COMPONENT) and part not in {".", ".."}
          and not part.endswith(".") for part in parts))
    return parts


def _pairs(items) -> dict:
    result = {}
    for key, value in items:
        _need(key not in result)
        result[key] = value
    return result


def _number(text: str) -> int:
    _need(len(text.lstrip("-")) <= 16)
    value = int(text)
    _need(abs(value) <= 2**53 - 1)
    return value


def _shape(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    _need(depth <= 16 and count[0] <= MAX_MANIFEST_NODES, "input-limit")
    if type(value) is dict:
        for key, item in value.items():
            _need(type(key) is str)
            _shape(key, depth + 1, count)
            _shape(item, depth + 1, count)
    elif type(value) is list:
        for item in value:
            _shape(item, depth + 1, count)
    elif type(value) is str:
        _need(len(value) <= 4096 and len(value.encode("utf-8")) <= 4096, "input-limit")
    else:
        _need(type(value) is int and abs(value) <= 2**53 - 1)


@dataclass(frozen=True, slots=True)
class _Binding:
    root: str
    instance: str
    identity: tuple[int, int, int, int, int]
    sha256: str


def _binding(value: object) -> _Binding:
    value = _keys(value, {"schemaVersion", "profile", "root", "rootIdentity", "inventorySha256"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["profile"] == PROFILE and _text(value["inventorySha256"], _SHA))
    root = value["root"]
    _need(type(root) is str and root.startswith(PREFIX) and _text(root[len(PREFIX):], _INSTANCE))
    identity = _keys(value["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
    _need(all(_text(identity[key], _DECIMAL) and int(identity[key]) <= 2**64 - 1 for key in ("device", "inode"))
          and identity["inode"] != "0" and all(_integer(identity[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
          and identity["uid"] == 0 and stat.S_ISDIR(identity["mode"])
          and not identity["mode"] & 0o7022)
    return _Binding(root, root[len(PREFIX):],
                    (int(identity["device"]), int(identity["inode"]), identity["mode"], identity["uid"], identity["gid"]),
                    value["inventorySha256"])


@dataclass(frozen=True, slots=True)
class _FileSpec:
    path: str
    size: int
    sha256: str
    mode: int


@dataclass(frozen=True, slots=True)
class _Profile:
    binding: _Binding
    versions: tuple[tuple[str, str], ...]
    distribution_url: str
    distribution_sha256: str
    os_identity: str
    os_inventory_sha256: str
    helpers: tuple[str, ...]
    files: tuple[_FileSpec, ...]
    native_files: tuple[_FileSpec, ...]
    directories: tuple[str, ...]


def _direct_file(path: str, directory: str, suffix: str) -> bool:
    if not path.startswith(directory):
        return False
    name = path[len(directory):]
    return len(name) > len(suffix) and "/" not in name and name.endswith(suffix)


def _native_path(path: str) -> bool:
    # _file_specs first applies the shared absolute-path/component grammar.
    # These families admit only explicitly inventoried canonical regular files,
    # never directory discovery or ambient font/resolver configuration.
    return (path.startswith(("/usr/bin/", "/usr/lib/", "/usr/lib64/", "/etc/ld.so.conf.d/"))
            or path in {"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/fonts/fonts.conf",
                        "/etc/nsswitch.conf", "/etc/host.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/gai.conf"}
            or any(_direct_file(path, directory, ".conf")
                   for directory in ("/etc/fonts/conf.avail/", "/usr/share/fontconfig/conf.avail/"))
            or any(_direct_file(path, f"/usr/share/fonts/truetype/{family}/", ".ttf")
                   for family in ("dejavu", "lato", "liberation", "noto"))
            or path == "/var/cache/fontconfig/CACHEDIR.TAG"
            or re.fullmatch(r"/var/cache/fontconfig/[0-9a-f]{32}-le64\.cache-9", path) is not None)


def _file_specs(value: object, *, native: bool = False) -> tuple[_FileSpec, ...]:
    _need(type(value) is list and 1 <= len(value) <= (MAX_OS_FILES if native else MAX_TOOL_FILES), "input-limit")
    specs = []
    for item in value:
        item = _keys(item, {"path", "size", "sha256", "mode"})
        parts = _parts(item["path"], absolute=native)
        if native:
            # Canonical regular objects only. Known loader/helper aliases are
            # bound by the separate native OS profile, not followed here.
            _need(_native_path(item["path"]))
        else:
            _need(parts[0] in {"jdk", "gradle", "sdk", "bundletool"} and len(parts) >= 2)
        _need(_integer(item["size"], MAX_FILE_BYTES) and _text(item["sha256"], _SHA)
              and _integer(item["mode"], 0o777) and not item["mode"] & 0o022)
        specs.append(_FileSpec(item["path"], item["size"], item["sha256"], item["mode"]))
    paths = [spec.path for spec in specs]
    _need(paths == sorted(paths) and len(set(path.casefold() for path in paths)) == len(paths))
    return tuple(specs)


def _directories(files: tuple[_FileSpec, ...]) -> tuple[str, ...]:
    names = {item.path for item in files}
    directories = {"/".join(item.path.split("/")[:depth]) for item in files
                   for depth in range(1, len(item.path.split("/")))}
    _need(not names.intersection(directories))
    all_paths = names | directories | {MANIFEST_NAME}
    _need(len({path.casefold() for path in all_paths}) == len(all_paths)
          and len(all_paths) <= MAX_ENTRIES, "input-limit")
    return tuple(sorted(directories, key=lambda path: (path.count("/"), path)))


def _parse_manifest(raw: bytes, binding: _Binding) -> _Profile:
    """Pure bounded DATA admission. The mandatory manifest is not self-listed."""
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST_BYTES, "input-limit")
    _need(not raw.startswith(b"\xef\xbb\xbf") and hashlib.sha256(raw).hexdigest() == binding.sha256)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_number,
                           parse_float=lambda _: _need(False), parse_constant=lambda _: _need(False))
        _shape(value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AndroidToolError() from None
    value = _keys(value, {"schemaVersion", "profile", "target", "instance", "launchContract", "versions",
                          "gradleDistribution", "bundletool", "roles", "files", "osProfile"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["profile"] == PROFILE
          and value["target"] == TARGET and value["instance"] == binding.instance and value["launchContract"] == LAUNCH_CONTRACT)
    _need(_keys(value["roles"], set(TOOL_ROLES)) == TOOL_ROLES)
    versions = _keys(value["versions"], {"jdkVendor", "jdkVersion", "gradleVersion", "agpVersion",
                                         "sdkPlatform", "sdkPlatformRevision", "sdkBuildToolsVersion"})
    _need(_text(versions["jdkVendor"], _LABEL)
          and all(_text(versions[key], _VERSION) for key in versions if key not in {"jdkVendor", "sdkPlatform"})
          and type(versions["sdkPlatform"]) is str and re.fullmatch(r"android-[1-9][0-9]{0,2}", versions["sdkPlatform"]) is not None)
    distribution = _keys(value["gradleDistribution"], {"url", "sha256"})
    _need(type(distribution["url"]) is str and distribution["url"] in {
        f"https://{host}/distributions/gradle-{versions['gradleVersion']}-bin.zip"
        for host in ("services.gradle.org", "downloads.gradle.org")}
        and _text(distribution["sha256"], _SHA))
    _need(_keys(value["bundletool"], {"version", "sha256"}) ==
          {"version": BUNDLETOOL_VERSION, "sha256": BUNDLETOOL_SHA256})
    files = _file_specs(value["files"])
    by_name = {item.path: item for item in files}
    for role in ("java", "javac", "gradle", "bundletool"):
        _need(TOOL_ROLES[role] in by_name)
        item = by_name[TOOL_ROLES[role]]
        _need(item.size > 0 and (role == "bundletool" or bool(item.mode & 0o111)))
    # AGP uses this exact protected member, not a runtime extraction whose
    # loader search origins depend on an arbitrary project/cache spelling.
    _need(AAPT2_PATH in by_name and by_name[AAPT2_PATH].size > 0
          and bool(by_name[AAPT2_PATH].mode & 0o111))
    jar = by_name[TOOL_ROLES["bundletool"]]
    _need(jar.sha256 == BUNDLETOOL_SHA256 and jar.size <= BUNDLETOOL_MAX_BYTES
          and any(item.path.startswith("sdk/") for item in files))
    os_profile = _keys(value["osProfile"], {"id", "inventorySha256", "shell", "executableDirectory", "helpers", "files"})
    _need(_text(os_profile["id"], _LABEL) and _text(os_profile["inventorySha256"], _SHA)
          and os_profile["shell"] == OS_SHELL and os_profile["executableDirectory"] == OS_EXECUTABLE_DIRECTORY)
    helpers = os_profile["helpers"]
    _need(type(helpers) is list and 1 <= len(helpers) <= MAX_OS_HELPERS
          and all(_text(name, _COMPONENT) and name not in {".", ".."} for name in helpers))
    _need(helpers == sorted(set(helpers)) and {"sed", "uname", "xargs"}.issubset(helpers))
    native = _file_specs(os_profile["files"], native=True)
    native_by_name = {item.path: item for item in native}
    for path in (OS_SHELL, *(f"{OS_EXECUTABLE_DIRECTORY}/{name}" for name in helpers)):
        _need(path in native_by_name and native_by_name[path].size > 0 and bool(native_by_name[path].mode & 0o111))
    _need(sum(item.size for item in (*files, *native)) <= MAX_TOTAL_BYTES, "input-limit")
    # This external OS inventory identity includes the qualified native alias/
    # loader/credential/mount contract. A valid string here does not verify it;
    # trusted native admission must bind it before GO. The whole raw manifest
    # anchor includes both it and all selected canonical objects/roles below.
    return _Profile(binding, tuple(sorted(versions.items())), distribution["url"], distribution["sha256"],
                    os_profile["id"], os_profile["inventorySha256"], tuple(helpers), files, native, _directories(files))


def _properties(raw: bytes) -> dict[str, str]:
    r"""Bounded Java-properties subset: ASCII, comments, CRLF and literal escapes.

    Supports key=value, key:value and whitespace separators, and \\, \:, \=,
    escaped space/#/!. Continuations, Unicode/control escapes, lone CR and
    duplicate decoded keys refuse; none is silently treated as an absent option.
    """
    _need(type(raw) is bytes and len(raw) <= MAX_SELECTION_BYTES, "input-limit")
    try:
        text = raw.decode("ascii").replace("\r\n", "\n")
    except UnicodeError:
        raise AndroidToolError() from None
    _need(all(char in "\n\t" or 32 <= ord(char) < 127 for char in text))
    lines = text.split("\n")
    _need(len(lines) <= MAX_PROPERTY_LINES, "input-limit")

    def unescape(value: str) -> str:
        output, index = [], 0
        while index < len(value):
            char = value[index]
            if char == "\\":
                index += 1
                _need(index < len(value) and value[index] in "\\:= #!")
                char = value[index]
            output.append(char)
            index += 1
        return "".join(output)

    result = {}
    for line in lines:
        _need(len(line) <= MAX_PROPERTY_LINE, "input-limit")
        line = line.lstrip(" \t")
        if not line or line[0] in "#!":
            continue
        index = 0
        while index < len(line) and line[index] not in " \t:=":
            if line[index] == "\\":
                index += 1
                _need(index < len(line))
            index += 1
        key = unescape(line[:index])
        while index < len(line) and line[index] in " \t":
            index += 1
        if index < len(line) and line[index] in ":=":
            index += 1
        while index < len(line) and line[index] in " \t":
            index += 1
        value = unescape(line[index:])
        _need(0 < len(key) <= 256 and key not in result and len(result) < 1024)
        result[key] = value
    return result


def _fixed_properties(root: str) -> tuple[tuple[str, str], ...]:
    return (("org.gradle.java.home", f"{root}/jdk"),
            ("org.gradle.java.installations.paths", f"{root}/jdk"),
            ("org.gradle.java.installations.fromEnv", ""),
            ("org.gradle.java.installations.auto-detect", "false"),
            ("org.gradle.java.installations.auto-download", "false"),
            ("android.builder.sdkDownload", "false"),
            ("android.aapt2FromMavenOverride", f"{root}/{AAPT2_PATH}"),
            ("kotlin.compiler.execution.strategy", "in-process"),
            ("kotlin.daemon.enabled", "false"))


def _selection_data(data: object, profile: _Profile, *, root_module: bool) -> tuple[tuple[str, bytes | None], ...]:
    data = _keys(data, set(SELECTION_FIELDS))
    _need(all(value is None or type(value) is bytes for value in data.values()))
    if root_module:
        _need(data["root_gradle_properties"] == data["module_gradle_properties"])
    _need(sum(len(data[key]) for key in SELECTION_FIELDS if data[key] is not None
              and not (root_module and key == "module_gradle_properties")) <= MAX_SELECTION_BYTES, "input-limit")
    _need(data["wrapper_properties"] is not None and data["daemon_jvm_properties"] is None)
    wrapper = _properties(data["wrapper_properties"])
    _need(set(wrapper).issubset({"distributionUrl", "distributionSha256Sum", "distributionBase", "distributionPath",
                                "zipStoreBase", "zipStorePath", "networkTimeout", "validateDistributionUrl"})
          and wrapper.get("distributionUrl") == profile.distribution_url
          and wrapper.get("distributionSha256Sum") == profile.distribution_sha256)
    local = {} if data["local_properties"] is None else _properties(data["local_properties"])
    for key, value in local.items():
        target = key.casefold().removeprefix("systemprop.")
        _need(target not in {"android.aapt2frommavenoverride", "android.aapt2version", "android.aapt2platform"}
              and not target.startswith(("jna.", "jnidispatch.")))
        if key == "sdk.dir":
            _need(value == f"{profile.binding.root}/sdk")
        else:
            _need(not key.casefold().startswith(("sdk.", "ndk.", "cmake."))
                  and key.casefold() not in {"android.dir", "flutter.sdk", "dart.sdk"})
    fixed = dict(_fixed_properties(profile.binding.root))
    fixed.update({"org.gradle.daemon": "false", "org.gradle.vfs.watch": "false",
                  "org.gradle.parallel": "false", "org.gradle.workers.max": str(WORKERS)})
    forbidden = {"org.gradle.jvmargs", "gradle.user.home", "org.gradle.user.home", "kotlin.daemon.jvmargs",
                 "kotlin.daemon.jvm.options", "java.home", "java.io.tmpdir", "user.home", "java.library.path",
                 "sdk.dir", "ndk.dir", "cmake.dir", "android.sdk.path", "android.sdkDownload",
                 "android.aapt2Version", "android.aapt2Platform"}
    for field in ("root_gradle_properties", "module_gradle_properties"):
        properties = {} if data[field] is None else _properties(data[field])
        for key, value in properties.items():
            if key in fixed:
                _need(value == fixed[key])
            else:
                lower = key.casefold()
                _need(lower not in {name.casefold() for name in (*fixed, *forbidden)}
                      and not lower.startswith(("org.gradle.java.", "org.gradle.jvm", "kotlin.daemon.jvm",
                                                "jna.", "jnidispatch.")))
                if lower.startswith("systemprop."):
                    target = lower[len("systemprop."):]
                    _need(target not in {name.casefold() for name in (*fixed, *forbidden)}
                          and not target.startswith(("java.", "javax.", "jdk.", "sun.", "org.gradle.java.",
                                                    "org.gradle.jvm", "android.builder.sdk", "jna.", "jnidispatch.")))
    return tuple((field, data[field]) for field in SELECTION_FIELDS)


def _jvm_arguments(work: Path, *, bundletool: bool = False) -> tuple[str, ...]:
    return ("-Xms64m", "-Xmx1024m" if bundletool else "-Xmx2048m", "-XX:MaxMetaspaceSize=512m",
            "-Dfile.encoding=UTF-8", f"-Duser.home={work}", f"-Djava.io.tmpdir={work}",
            "-Djna.nosys=true", "-Djna.boot.library.path=", "-Djna.boot.library.name=jnidispatch",
            f"-Djna.tmpdir={work}")


def _identity(observed: os.stat_result, *, directory: bool = False, stable_contents: bool = True) -> tuple[int, ...]:
    _need((stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode))
          and observed.st_uid == 0 and not observed.st_mode & 0o7022
          and (directory or observed.st_nlink == 1))
    base = (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid)
    return base + ((observed.st_nlink, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
                   if stable_contents else ())


@dataclass(eq=False, slots=True)
class _Record:
    parent: int
    name: str
    slot: _FD
    directory: bool
    stable_contents: bool
    identity: tuple[int, ...] | None = None
    spec: _FileSpec | None = None


class _Ancestry(_Directory):
    """The existing no-follow ancestry with fixed operation checkpoints only."""

    def __init__(self, tools: AndroidValidationTools) -> None:
        self.tools = tools
        super().__init__(Path(tools.binding.root), tools.guard)

    def _edit_checkpoint(self) -> None:
        self.tools._point()


class _Entries:
    """One retained original bounded directory iterator, not another file owner."""

    def __init__(self, tools: AndroidValidationTools) -> None:
        self.tools = tools
        self.value = None
        self.state, self.close_state = "NEW", "NOT_ATTEMPTED"

    def acquire(self, number: int) -> None:
        self.tools._point()
        _need(self.state == "NEW")
        operation = os.scandir
        with self.tools.guard.deferred(check_on_exit=False):
            try:
                self.state = "ATTEMPTED"
                self.value = operation(number)
                _need(self.value is not None and callable(getattr(type(self.value), "__next__", None))
                      and callable(getattr(type(self.value), "close", None)), "cleanup-unknown")
                self.state = "OPEN"
            except BaseException as error:
                self.state = "NO_EFFECT" if _direct_refusal(error, operation, _OS_SCANDIR,
                    _Entries.acquire.__code__, _SCAN_REFUSALS) else "UNKNOWN"
                self.tools._remember(error)
                if self.state == "UNKNOWN":
                    self.tools._unknown(error)
                raise

    def advance(self):
        self.tools._charge("tool-directory-advances", 1, MAX_DIRECTORY_ADVANCES)
        _need(self.state == "OPEN" and self.close_state == "NOT_ATTEMPTED" and self.value is not None)
        result = next(self.value)
        self.tools._point()
        return result

    def close(self) -> None:
        self.tools._owner(active=False)
        if self.close_state == "CLOSED":
            return
        if self.close_state != "NOT_ATTEMPTED" or self.state in {"ATTEMPTED", "UNKNOWN"}:
            self.tools._unknown(AndroidToolError("cleanup-unknown"))
        with self.tools.guard.deferred(check_on_exit=False):
            try:
                self.close_state = "ATTEMPTED"
                if self.value is not None:
                    _need(self.value.close() is None, "cleanup-unknown")
                self.close_state = "CLOSED"
            except BaseException as error:
                self.close_state = "UNKNOWN"
                self.tools._remember(error)
                self.tools._unknown(error)


class AndroidValidationTools:
    """Original operation child. Constructors and argv/environment builders grant no custody."""

    def __init__(self, operation, native_binding: object) -> None:
        from .android_build_operation import AndroidBuildOperation
        _need(type(operation) is AndroidBuildOperation, "toolchain-unavailable")
        operation.owner()
        _need(operation.tools is None and operation.inputs is not None and operation.files is not None
              and not operation.close_claimed and operation.guard._android_build_source is operation.source
              and operation.source.active and operation.source.request_returned
              and not operation.source.close_claimed, "toolchain-unavailable")
        self.binding = _binding(native_binding)
        _need(self.binding == _binding(operation.request.native["toolchain"]))
        self.operation, self.guard, self.source = operation, operation.guard, operation.source
        self.request, self.inputs, self.files = operation.request, operation.inputs, operation.files
        self.release, self.task = operation.inputs.release, operation.inputs.task
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.ancestry: _Ancestry | None = None
        self.slots: list[_FD] = []
        self.records: list[_Record] = []
        self.iterators: list[_Entries] = []
        self.manifest: _Record | None = None
        self.profile: _Profile | None = None
        self._directories: dict[str, int] = {}
        self._device: int | None = None
        self._credentials: tuple[tuple[int, int, int], tuple[int, int, int]] | None = None
        self._project_data: tuple[tuple[str, bytes | None], ...] | None = None
        self._acquire_claimed = self._acquired = self._project_claimed = False
        self._signature_claimed = self._signature_ready = False
        self._close_claimed = self._close_complete = self._cleanup_mode = self._unknown_seen = False
        self._final_hash_claimed = False
        self._first_error: BaseException | None = None

    def _owner(self, *, active: bool = True) -> None:
        from .android_build_operation import AndroidBuildOperation
        operation = self.operation
        _need(type(operation) is AndroidBuildOperation and type(self) is AndroidValidationTools
              and self.pid == os.getpid() and self.thread is threading.current_thread()
              and self.thread is threading.main_thread() and operation.tools is self
              and operation.request is self.request and operation.inputs is self.inputs and operation.files is self.files
              and operation.guard is self.guard and operation.source is self.source
              and self.source.operation is operation and self.source.guard is self.guard, "toolchain-unavailable")
        operation.owner()
        _need(self.binding == _binding(self.request.native["toolchain"]) and self.inputs.release is self.release
              and self.inputs.task == self.task)
        if active:
            _need(self.guard._android_build_source is self.source and self.source.active
                  and self.source.request_returned and not self.source.close_claimed, "toolchain-unavailable")

    def _point(self) -> None:
        self._owner(active=not self._cleanup_mode)
        if self._cleanup_mode or self.guard.depth:
            self.operation.cleanup_checkpoint()
        else:
            _need(not self._close_claimed, "toolchain-unavailable")
            self.operation.charge("tool-checkpoints", 1, MAX_CHECKPOINTS)

    def _charge(self, name: str, amount: int, limit: int) -> None:
        self._point()
        self.operation.charge(name, amount, limit)

    def _remember(self, error: BaseException) -> None:
        if self._first_error is None:
            self._first_error = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)

    def _unknown(self, error: BaseException) -> None:
        self._unknown_seen = True
        self._remember(error)
        raise _cleanup_failure(self.guard, error) from None

    def _raise(self, error: BaseException) -> None:
        self._remember(error)
        fatal = fatal_lifetime_error(error, "Original Android tool lifetime did not settle")
        if fatal is not None:
            self._unknown_seen = True
            self.guard._abort(fatal)
            raise fatal from None
        if isinstance(error, AndroidToolError):
            self.operation.fail(error.reason)
            raise error  # A returning failure hook is not permission to continue.
        if isinstance(error, (OSError, BuildInputError)):
            self.operation.fail("toolchain-mismatch" if self._acquired else "toolchain-unavailable")
            raise AndroidToolError("toolchain-unavailable") from None
        raise error

    def _platform(self) -> None:
        self._point()
        _need(sys.platform == "linux" and os.uname().machine == "x86_64"
              and hasattr(os, "getresuid") and hasattr(os, "getresgid") and hasattr(os, "getxattr"), "toolchain-unavailable")
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        _need(soft == resource.RLIM_INFINITY or soft >= MIN_DESCRIPTOR_LIMIT, "toolchain-unavailable")
        ids = os.getresuid(), os.getresgid()
        _need(len(set(ids[0])) == len(set(ids[1])) == 1 and ids[0][0] != 0, "toolchain-unavailable")
        self._credentials = ids
        # Deliberately not a substitute for native capability/namespace/mount
        # admission. No /proc census, credential repair or rlimit change.

    def _absent_attributes(self, number: int, *, directory: bool) -> None:
        attributes = ("system.posix_acl_access", "security.capability")
        if directory:
            attributes += ("system.posix_acl_default",)
        for name in attributes:
            self._point()
            try:
                os.getxattr(number, name)
            except OSError as error:
                _need(error.errno == errno.ENODATA, "toolchain-unavailable")
            else:
                # Any value (even empty) refuses. Linux's fixed xattr size
                # ceiling bounds this read; no unbounded listxattr census.
                raise AndroidToolError()

    def _protected(self, number: int, *, directory: bool, stable_contents: bool) -> tuple[int, ...]:
        self._point()
        before = _identity(os.fstat(number), directory=directory, stable_contents=stable_contents)
        _need(self._device is None or before[0] == self._device)
        self._absent_attributes(number, directory=directory)
        self._point()
        _need(_identity(os.fstat(number), directory=directory, stable_contents=stable_contents) == before)
        return before

    def _new_slot(self) -> _FD:
        self._charge("tool-descriptor-slots", 1, MAX_DESCRIPTORS)
        slot = _FD(self.guard)
        self.slots.append(slot)
        return slot

    def _open_record(self, parent: int, name: str, *, directory: bool, stable_contents: bool = True,
                     spec: _FileSpec | None = None) -> _Record:
        self._point()
        _need(parent in self._directories.values())
        record = _Record(parent, name, self._new_slot(), directory, stable_contents, spec=spec)
        self.records.append(record)  # Root before the original open can fail.
        number = record.slot.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                                  (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        record.identity = self._protected(number, directory=directory, stable_contents=stable_contents)
        self._check_record(record)
        return record

    def _check_record(self, record: _Record) -> None:
        self._point()
        _need(record.slot.number is not None and record.slot.open_state == "OPEN"
              and record.slot.close_state == "NOT_ATTEMPTED" and record.identity is not None)
        current = self._protected(record.slot.number, directory=record.directory, stable_contents=record.stable_contents)
        self._point()
        named = _identity(os.stat(record.name, dir_fd=record.parent, follow_symlinks=False),
                          directory=record.directory, stable_contents=record.stable_contents)
        _need(current == record.identity == named)
        if record.spec is not None:
            _need(current[6] == record.spec.size and stat.S_IMODE(current[2]) == record.spec.mode)

    def _read(self, record: _Record, size: int, *, keep: bool = False, manifest: bool = False) -> tuple[str, bytes | None]:
        self._check_record(record)
        _need(record.identity is not None and record.identity[6] == size and record.slot.number is not None)
        self._point()
        _need(os.lseek(record.slot.number, 0, os.SEEK_SET) == 0)
        digest, blocks, remaining = hashlib.sha256(), [], size
        while remaining:
            amount = min(READ_CHUNK, remaining)
            self._charge("tool-manifest-read-bytes" if manifest else "tool-file-read-bytes", amount,
                         2 * MAX_MANIFEST_BYTES if manifest else 2 * MAX_TOTAL_BYTES)
            block = os.read(record.slot.number, amount)
            _need(type(block) is bytes and 0 < len(block) <= amount)
            digest.update(block)
            if keep:
                blocks.append(block)
            remaining -= len(block)
        self._check_record(record)
        return digest.hexdigest(), b"".join(blocks) if keep else None

    def _inventory_names(self, path: str, expected: set[str]) -> None:
        self._charge("tool-directory-iterators", 1, MAX_DESCRIPTORS)
        # One original iterator at a time; its extra live descriptor is in the
        # precharged roster. Closed iterators do not consume permanent slots.
        _need(all(item.close_state == "CLOSED" for item in self.iterators)
              and len(self.slots) + (len(self.ancestry.slots) if self.ancestry is not None else 0)
                  < MAX_DESCRIPTORS, "input-limit")
        iterator = _Entries(self)
        self.iterators.append(iterator)
        primary = None
        try:
            iterator.acquire(self._directories[path])
            names = set()
            while True:
                try:
                    entry = iterator.advance()
                except StopIteration:
                    break
                name = entry.name
                _need(type(name) is str and name in expected and name not in names)
                names.add(name)
            _need(names == expected)
        except BaseException as error:
            primary = error
            self._remember(error)
            raise
        finally:
            try:
                iterator.close()
            except BaseException as error:
                self._remember(error)
                if primary is None:
                    raise

    def acquire(self) -> None:
        self._owner()
        _need(not self._acquire_claimed and not self._close_claimed, "toolchain-unavailable")
        self._acquire_claimed = True
        try:
            self.operation.checkpoint()
            self._platform()
            self._charge("tool-descriptor-slots", len(Path(self.binding.root).parts), MAX_DESCRIPTORS)
            self.ancestry = _Ancestry(self)
            self.ancestry.acquire()
            for index, slot in enumerate(self.ancestry.slots):
                _need(slot.number is not None)
                identity = self._protected(slot.number, directory=True, stable_contents=False)
                if self._device is None:
                    self._device = identity[0]
                path = "/" if index == 0 else "/" + "/".join(Path(self.binding.root).parts[1:index + 1])
                self._directories[path] = slot.number
            _need(self._protected(self.ancestry.fd, directory=True, stable_contents=False) == self.binding.identity)
            root = self.binding.root
            self.manifest = self._open_record(self.ancestry.fd, MANIFEST_NAME, directory=False)
            _need(self.manifest.identity is not None and 0 < self.manifest.identity[6] <= MAX_MANIFEST_BYTES, "input-limit")
            self._charge("tool-manifest-reservation", 2 * self.manifest.identity[6], 2 * MAX_MANIFEST_BYTES)
            _, raw = self._read(self.manifest, self.manifest.identity[6], keep=True, manifest=True)
            _need(raw is not None)
            self.profile = _parse_manifest(raw, self.binding)
            specs = (*self.profile.files, *self.profile.native_files)
            self._charge("tool-hash-reservation", 2 * sum(item.size for item in specs), 2 * MAX_TOTAL_BYTES)
            native_directories = {"/" + "/".join(parts[:depth]) for item in self.profile.native_files
                                  for parts in (_parts(item.path, absolute=True),)
                                  for depth in range(1, len(parts))}
            # Original ancestors + manifest + all retained tool/native objects
            # and directories + one serial iterator. No headroom or reopen claim.
            roster = (len(self.ancestry.slots) + 1 + len(self.profile.directories) + len(specs)
                      + len(native_directories.difference(self._directories)) + 1)
            self._charge("tool-roster-reservation", roster, MAX_DESCRIPTORS)
            # Root contents and every derived tool directory are immutable;
            # ancestor directory timestamps need not freeze unrelated instances.
            root_record = _Record(self.ancestry.bindings[-1][0], self.ancestry.bindings[-1][1],
                                  self.ancestry.slots[-1], True, True)
            root_record.identity = self._protected(self.ancestry.fd, directory=True, stable_contents=True)
            self.records.append(root_record)
            for relative in self.profile.directories:
                path = f"{root}/{relative}"
                parent, name = path.rsplit("/", 1)
                record = self._open_record(self._directories[parent], name, directory=True)
                _need(record.slot.number is not None)
                self._directories[path] = record.slot.number
            for spec in self.profile.files:
                parent, name = f"{root}/{spec.path}".rsplit("/", 1)
                record = self._open_record(self._directories[parent], name, directory=False, spec=spec)
                _need(self._read(record, spec.size)[0] == spec.sha256)
            expected = {relative: set() for relative in ("", *self.profile.directories)}
            expected[""].add(MANIFEST_NAME)
            for relative in (*self.profile.directories, *(item.path for item in self.profile.files)):
                parent, _, name = relative.rpartition("/")
                expected[parent].add(name)
            for relative, names in expected.items():
                self._inventory_names(root if not relative else f"{root}/{relative}", names)
            for spec in self.profile.native_files:
                parts = _parts(spec.path, absolute=True)
                parent = "/"
                for name in parts[:-1]:
                    path = f"/{name}" if parent == "/" else f"{parent}/{name}"
                    if path not in self._directories:
                        record = self._open_record(self._directories[parent], name, directory=True, stable_contents=False)
                        _need(record.slot.number is not None)
                        self._directories[path] = record.slot.number
                    parent = path
                record = self._open_record(self._directories[parent], parts[-1], directory=False, spec=spec)
                _need(self._read(record, spec.size)[0] == spec.sha256)
            self._acquired = True
            self.check()
        except BaseException as error:
            self._raise(error)

    def _check_metadata(self) -> None:
        self._point()
        _need(self._credentials is not None and (os.getresuid(), os.getresgid()) == self._credentials)
        _need(self.ancestry is not None and self.profile is not None and self.manifest is not None)
        self.ancestry.check()
        for slot in self.ancestry.slots:
            _need(slot.number is not None)
            self._protected(slot.number, directory=True, stable_contents=False)
        _need(self._protected(self.ancestry.fd, directory=True, stable_contents=False) == self.binding.identity)
        for record in self.records:
            self._check_record(record)

    def check(self) -> None:
        self._owner()
        _need(self._acquired and not self._close_claimed, "toolchain-unavailable")
        try:
            # Dispatch checks never reopen or start another full-hash pass.
            self._check_metadata()
        except BaseException as error:
            self._raise(error)

    def check_project_inputs(self, data: object) -> None:
        self._owner()
        _need(self._acquired and not self._project_claimed and not self._close_claimed
              and (self.inputs.check_signer is False or self._signature_ready), "toolchain-unavailable")
        self._project_claimed = True  # A failed supply cannot be replaced/retried.
        try:
            self.check()
            _need(self.profile is not None)
            self._project_data = _selection_data(data, self.profile, root_module=self.inputs.saved.configuration.module == ":")
            self.check()
        except BaseException as error:
            self._raise(error)

    def require_signature_tools(self) -> None:
        """Once-only upload-mode admission, before project selection or Gradle.

        These are extra files of the same acquired JDK, not new manifest roles,
        PATH searches or another tool owner. Acquisition already retained and
        hashed every inventoried file; final closure rechecks those originals.
        """
        self._owner()
        _need(self._acquired and self.inputs.check_signer is True and not self._close_claimed
              and not self._signature_claimed and not self._project_claimed
              and self._project_data is None, "toolchain-unavailable")
        self._signature_claimed = True
        try:
            self.check()
            _need(self.profile is not None)
            files = {item.path: item for item in self.profile.files}
            _need(all(path in files and files[path].size > 0 and bool(files[path].mode & 0o111)
                      for path in (JARSIGNER_PATH, KEYTOOL_PATH)))
            self._signature_ready = True
        except BaseException as error:
            self._raise(error)

    def _work(self, work_path: Path) -> Path:
        self._owner()
        _need(self._acquired and self._project_data is not None and not self._close_claimed
              and (self.inputs.check_signer is False or self._signature_ready), "toolchain-unavailable")
        self.operation.checkpoint()
        from ._desktop_android_build_files import AndroidBuildFiles
        _need(type(self.files) is AndroidBuildFiles and self.files.operation is self.operation)
        expected = self.files.work_path  # Original namespace/read record check, not path authority.
        _need(type(work_path) is type(expected) and work_path == expected)
        self.check()
        return expected

    def gradle_command(self, task: str, work_path: Path) -> tuple[str, ...]:
        work = self._work(work_path)
        _need(type(task) is str and task == self.task)
        jvm = shlex.join(_jvm_arguments(work))
        controls = tuple(argument for key, value in _fixed_properties(self.binding.root)
                         for argument in (f"-D{key}={value}", f"-P{key}={value}"))
        return (OS_SHELL, f"{self.binding.root}/{TOOL_ROLES['gradle']}", "--no-daemon", "--no-watch-fs",
                "--no-parallel", "--console=plain", "--stacktrace", f"--max-workers={WORKERS}",
                "--project-cache-dir", str(work / "project-cache"), "--gradle-user-home", str(work / "gradle-home"),
                f"-Dorg.gradle.jvmargs={jvm}", f"-Duser.home={work}", f"-Djava.io.tmpdir={work}", *controls, task)

    def command_environment(self, work_path: Path, bound_release: ReleaseVersion) -> dict[str, str]:
        work = self._work(work_path)
        _need(type(bound_release) is ReleaseVersion and bound_release is self.release)
        root = self.binding.root
        return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "PATH": f"{root}/jdk/bin:{OS_EXECUTABLE_DIRECTORY}",
                "JAVA_HOME": f"{root}/jdk", "ANDROID_HOME": f"{root}/sdk", "ANDROID_SDK_ROOT": f"{root}/sdk",
                "HOME": str(work), "TMPDIR": str(work), "XDG_RUNTIME_DIR": str(work),
                "XDG_CONFIG_HOME": str(work / "xdg-config"), "XDG_CACHE_HOME": str(work / "xdg-cache"),
                "XDG_DATA_HOME": str(work / "xdg-data"), "XDG_STATE_HOME": str(work / "xdg-state"),
                "ANDROID_USER_HOME": str(work / "android-user"), "GRADLE_USER_HOME": str(work / "gradle-home"),
                "JAVA_OPTS": shlex.join(_jvm_arguments(work)),  # Fixed startup control, never ambient forwarding.
                "MOBILE_RELEASE_VERSION_NAME": bound_release.name, "MOBILE_RELEASE_BUILD_NUMBER": str(bound_release.build),
                "MOBILE_RELEASE_REQUIRE_SIGNING": "false"}

    def _inspection_input(self, snapshot_path: Path) -> tuple[Path, Path]:
        self._owner()
        _need(self._project_data is not None and not self._close_claimed, "toolchain-unavailable")
        from ._desktop_android_build_files import OriginalAndroidArtifact
        artifact = self.operation._artifact
        _need(type(artifact) is OriginalAndroidArtifact and artifact.files is self.files
              and self.files.artifact is artifact and self.files._original_artifact is artifact
              and artifact._native is True and artifact._reader is None)
        artifact.check()
        expected = artifact.path
        _need(type(snapshot_path) is type(expected) and snapshot_path == expected)
        work = self._work(self.files.work_path)
        return work, expected

    def bundletool_command(self, snapshot_path: Path) -> tuple[str, ...]:
        work, expected = self._inspection_input(snapshot_path)
        return (f"{self.binding.root}/{TOOL_ROLES['java']}", *_jvm_arguments(work, bundletool=True), "-jar",
                f"{self.binding.root}/{TOOL_ROLES['bundletool']}", "dump", "manifest", f"--bundle={expected}", "--module=base")

    def jarsigner_command(self, snapshot_path: Path) -> tuple[str, ...]:
        self._owner()
        _need(self.inputs.check_signer is True and self._signature_claimed and self._signature_ready,
              "toolchain-unavailable")
        work, expected = self._inspection_input(snapshot_path)
        return (f"{self.binding.root}/{JARSIGNER_PATH}",
                *("-J" + option for option in _jvm_arguments(work, bundletool=True)),
                "-verify", "-strict", str(expected))

    def keytool_command(self, snapshot_path: Path) -> tuple[str, ...]:
        self._owner()
        _need(self.inputs.check_signer is True and self._signature_claimed and self._signature_ready,
              "toolchain-unavailable")
        work, expected = self._inspection_input(snapshot_path)
        return (f"{self.binding.root}/{KEYTOOL_PATH}",
                *("-J" + option for option in _jvm_arguments(work, bundletool=True)),
                "-printcert", "-jarfile", str(expected))

    def close(self) -> None:
        self._owner(active=False)
        if self._close_claimed:
            if self.closed():
                return
            self._unknown(AndroidToolError("cleanup-unknown"))
        self._owner()  # A new consuming close still belongs to the installed source.
        self._close_claimed = True
        facts = self.guard.lifetime_ledger.verdict()
        if not facts.complete or not facts.contained:
            self._unknown(AndroidToolError("cleanup-unknown"))  # Original consumers retain every tool handle.
        first = None
        with self.guard.deferred(check_on_exit=False):
            self._cleanup_mode = True
            try:
                if self._acquired:
                    self._check_metadata()
                    _need(not self._final_hash_claimed and self.manifest is not None)
                    self._final_hash_claimed = True
                    _need(self._read(self.manifest, self.manifest.identity[6], manifest=True)[0] == self.binding.sha256)
                    for record in self.records:
                        if record.spec is not None:
                            _need(self._read(record, record.spec.size)[0] == record.spec.sha256)
                    self._check_metadata()
            except BaseException as error:
                first = error
                self._remember(error)
            # No new acquisition/work admission after stop. Even a failed final
            # observation cannot skip unrelated original one-attempt closes.
            slots = [*(self.ancestry.slots if self.ancestry is not None else ()), *self.slots]
            for original in (*reversed(self.iterators), *reversed(slots)):
                try:
                    original.close()
                except BaseException as error:
                    self._remember(error)
                    if first is None:
                        first = error
            self._close_complete = (not self._unknown_seen and all(slot.close_state == "CLOSED" for slot in slots)
                                    and all(item.close_state == "CLOSED" for item in self.iterators))
        if not self._close_complete:
            self._unknown(first or AndroidToolError("cleanup-unknown"))
        if first is not None:
            self._raise(first)

    def closed(self) -> bool:
        # The engine retires the original input before terminal observation.
        # Only this read-only closure predicate survives guard-slot removal;
        # original identity and every slot result remain mandatory.
        self._owner(active=False)
        slots = [*self.slots, *(self.ancestry.slots if self.ancestry is not None else ())]
        return (self._close_claimed and self._close_complete and not self._unknown_seen
                and all(slot.close_state == "CLOSED" for slot in slots)
                and all(item.close_state == "CLOSED" for item in self.iterators))
