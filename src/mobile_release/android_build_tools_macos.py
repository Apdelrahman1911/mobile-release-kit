"""Closed Darwin Android tool DATA/admission for the original AndroidValidationTools.

This module is not a runner, tool installer, process boundary or source of
qualification. SavedCommandOwner must already hold the actual protected Mac
runtime/tool/ACL/native-provider originals before the core request is released.
Only the named files and the same exact Python operation are admitted here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from . import android_build_tools as common

PROFILE = "android-registered-macos-arm64-v1"
PREFIX = "/Library/Application Support/MobileReleaseKit/android"
OS_PROFILE = "macos26-arm64-sealed-system-v1"
OS_FILES = ("/System/Library/CoreServices/SystemVersion.plist", "/bin/bash", "/bin/ls", "/bin/sh",
            "/usr/bin/basename", "/usr/bin/dirname", "/usr/bin/expr", "/usr/bin/sed", "/usr/bin/tr",
            "/usr/bin/uname", "/usr/bin/xargs")
OS_ROOTS = ("/System/Library", "/usr/lib")
HEADERS = ("registration.json", common.MANIFEST_NAME, "os-provider.json")
HEADER_LIMITS = (4096, common.MAX_MANIFEST_BYTES, 64 * 1024)
MANIFEST_BUDGET = 2 * sum(HEADER_LIMITS)
LIVE_DESCRIPTORS = 64
DESCRIPTOR_RECORDS = common.MAX_ENTRIES + 256
_COMPONENT = re.compile(r"[A-Za-z0-9_+@.,= -]{1,255}\Z")
_INSTANCE = re.compile(r"[0-9a-f]{32}\Z")
_need, _keys, _text, _integer = common._need, common._keys, common._text, common._integer


def parts(value: object, *, absolute: bool = False) -> tuple[str, ...]:
    _need(type(value) is str and 0 < len(value) <= common.MAX_PATH_BYTES)
    _need(value.startswith("/") if absolute else not value.startswith("/"))
    result = tuple(value[1:].split("/") if absolute else value.split("/"))
    _need(len(result) <= common.MAX_DEPTH and all(_text(p, _COMPONENT) and p not in {".", ".."}
          and not p.endswith((".", " ")) for p in result))
    return result


def binding(value: object) -> common._Binding:
    value = _keys(value, {"schemaVersion", "profile", "root", "rootIdentity", "inventorySha256", "selection"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 2 and value["profile"] == PROFILE)
    from ._desktop_android_build_protocol import ProtocolError, mac_toolchain_selection
    try:
        selected = mac_toolchain_selection(value["selection"])
    except ProtocolError:
        raise common.AndroidToolError() from None
    root = f'{PREFIX}/{selected["ownerUid"]}/{selected["instance"]}'
    _need(value["root"] == root and value["inventorySha256"] == selected["inventorySha256"])
    identity = _keys(value["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
    _need(all(_text(identity[key], common._DECIMAL) and int(identity[key]) <= 2**64 - 1 for key in ("device", "inode"))
          and identity["inode"] != "0" and type(identity["mode"]) is int and identity["mode"] == (stat.S_IFDIR | 0o555)
          and type(identity["uid"]) is int and type(identity["gid"]) is int and identity["uid"] == identity["gid"] == 0)
    return common._Binding(root, selected["instance"],
        (int(identity["device"]), int(identity["inode"]), identity["mode"], 0, 0),
        selected["inventorySha256"], PROFILE, tuple(sorted(selected.items())))


def _json(raw: bytes, limit: int, *, shaped: bool = True) -> dict:
    _need(type(raw) is bytes and 0 < len(raw) <= limit and not raw.startswith(b"\xef\xbb\xbf"), "input-limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=common._pairs, parse_int=common._number,
                           parse_float=lambda _: _need(False), parse_constant=lambda _: _need(False))
        if shaped:
            common._shape(value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise common.AndroidToolError() from None
    _need(type(value) is dict)
    return value


def _files(value: object) -> tuple[common._FileSpec, ...]:
    _need(type(value) is list and 1 <= len(value) <= common.MAX_TOOL_FILES, "input-limit")
    result = []
    for item in value:
        item = _keys(item, {"path", "size", "sha256", "mode"})
        components = parts(item["path"])
        _need(len(components) >= 2 and components[0] in {"jdk", "gradle", "sdk", "bundletool"}
              and _integer(item["size"], common.MAX_FILE_BYTES) and _text(item["sha256"], common._SHA)
              and type(item["mode"]) is int and item["mode"] in {0o444, 0o555})
        result.append(common._FileSpec(item["path"], item["size"], item["sha256"], item["mode"]))
    paths = [item.path for item in result]
    _need(paths == sorted(paths) and len({p.casefold() for p in paths}) == len(paths))
    return tuple(result)


def _aliases(value: object, files: tuple[common._FileSpec, ...], java_home: str) -> tuple[tuple[str, str, str], ...]:
    _need(type(value) is list and len(value) <= 128, "input-limit")
    result, members = [], {item.path for item in files}
    bundle = "/".join(java_home.split("/")[:2]) + "/"
    for item in value:
        item = _keys(item, {"path", "target", "canonical"})
        parts(item["path"])
        parts(item["canonical"])
        target = item["target"]
        _need(type(target) is str and 0 < len(target) <= 512 and not target.startswith("/")
              and item["path"].startswith(bundle) and item["canonical"].startswith(bundle))
        resolved = item["path"].split("/")[:-1]
        for component in target.split("/"):
            if component == "..":
                _need(bool(resolved))
                resolved.pop()
            elif component != ".":
                _need(_text(component, _COMPONENT) and not component.endswith((".", " ")))
                resolved.append(component)
        _need("/".join(resolved) == item["canonical"] and item["canonical"] in members)
        result.append((item["path"], target, item["canonical"]))
    _need([a[0] for a in result] == sorted(a[0] for a in result))
    return tuple(result)


def parse_profile(raw: bytes, provider_raw: bytes, record_raw: bytes, selected: common._Binding) -> common._Profile:
    _need(selected.profile == PROFILE)
    anchors = dict(selected.selection)
    _need(hashlib.sha256(raw).hexdigest() == selected.sha256
          and hashlib.sha256(provider_raw).hexdigest() == anchors["osProviderSha256"]
          and hashlib.sha256(record_raw).hexdigest() == anchors["recordSha256"])
    record = _keys(_json(record_raw, HEADER_LIMITS[0], shaped=False),
        {"schemaVersion", "profile", "target", "instance", "ownerUid", "inventorySha256", "osProviderSha256", "licenseAcknowledged"})
    _need(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1
          and record["profile"] == PROFILE and record["target"] == "macos-arm64"
          and record["instance"] == selected.instance and type(record["ownerUid"]) is int and record["ownerUid"] == anchors["ownerUid"]
          and record["inventorySha256"] == selected.sha256 and record["osProviderSha256"] == anchors["osProviderSha256"]
          and record["licenseAcknowledged"] is True)
    value = _keys(_json(raw, common.MAX_MANIFEST_BYTES),
        {"schemaVersion", "profile", "target", "instance", "launchContract", "versions", "gradleDistribution",
         "bundletool", "roles", "files", "aliases", "osProviderSha256"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["profile"] == PROFILE
          and value["target"] == "macos-arm64" and value["instance"] == selected.instance
          and value["launchContract"] == "gradle-macos-private-jvm-arm64-v1"
          and value["osProviderSha256"] == anchors["osProviderSha256"])
    roles = _keys(value["roles"], set(common.TOOL_ROLES))
    java = parts(roles["java"])
    _need(len(java) == 6 and java[0] == "jdk" and len(java[1]) > 4 and java[1].endswith(".jdk")
          and java[2:] == ("Contents", "Home", "bin", "java"))
    home = "/".join(java[:4])
    _need(roles == {"java": f"{home}/bin/java", "javac": f"{home}/bin/javac",
                   "gradle": "gradle/bin/gradle", "bundletool": "bundletool/bundletool.jar", "sdk": "sdk"})
    versions = _keys(value["versions"], {"jdkVendor", "jdkVersion", "gradleVersion", "agpVersion",
                                       "sdkPlatform", "sdkPlatformRevision", "sdkBuildToolsVersion"})
    _need(_text(versions["jdkVendor"], common._LABEL) and _text(versions["jdkVersion"], common._VERSION)
          and versions["jdkVersion"].startswith("17.")
          and all(_text(versions[key], common._VERSION) for key in versions if key not in {"jdkVendor", "sdkPlatform"})
          and type(versions["sdkPlatform"]) is str and re.fullmatch(r"android-[1-9][0-9]{0,2}", versions["sdkPlatform"]) is not None)
    distribution = _keys(value["gradleDistribution"], {"url", "sha256"})
    _need(type(distribution["url"]) is str and distribution["url"] in {
        f"https://{host}/distributions/gradle-{versions['gradleVersion']}-bin.zip"
        for host in ("services.gradle.org", "downloads.gradle.org")} and _text(distribution["sha256"], common._SHA))
    _need(_keys(value["bundletool"], {"version", "sha256"}) ==
          {"version": common.BUNDLETOOL_VERSION, "sha256": common.BUNDLETOOL_SHA256})
    files = _files(value["files"])
    members = {f.path: f for f in files}
    launch = (roles["java"], roles["javac"], roles["gradle"], common.AAPT2_PATH, f"{home}/bin/jarsigner", f"{home}/bin/keytool")
    _need(all(path in members and members[path].mode == 0o555 and members[path].size > 0 for path in launch))
    jar = members.get(roles["bundletool"])
    _need(jar is not None and jar.mode == 0o444 and 0 < jar.size <= common.BUNDLETOOL_MAX_BYTES
          and jar.sha256 == common.BUNDLETOOL_SHA256 and any(f.path.startswith("sdk/") for f in files))
    bundle = "/".join(java[:2]) + "/"
    _need(all(not f.path.startswith("jdk/") or f.path.startswith(bundle) for f in files))
    aliases = _aliases(value["aliases"], files, home)
    leaves = [*(f.path for f in files), *(a[0] for a in aliases)]
    directories = {"/".join(path.split("/")[:depth]) for path in leaves for depth in range(1, len(path.split("/")))}
    names = [*leaves, *directories, *HEADERS]
    _need(len(names) <= common.MAX_ENTRIES and len({p.casefold() for p in names}) == len(names), "input-limit")
    provider = _keys(_json(provider_raw, HEADER_LIMITS[2]),
        {"schemaVersion", "profile", "target", "shell", "executablePath", "roots", "files"})
    _need(type(provider["schemaVersion"]) is int and provider["schemaVersion"] == 1 and provider["profile"] == OS_PROFILE
          and provider["target"] == "macos-arm64" and provider["shell"] == "/bin/sh"
          and provider["executablePath"] == ["/usr/bin", "/bin"] and provider["roots"] == list(OS_ROOTS)
          and type(provider["files"]) is list and len(provider["files"]) == len(OS_FILES))
    native = []
    for item, expected in zip(provider["files"], OS_FILES):
        item = _keys(item, {"path", "size", "sha256", "mode"})
        _need(item["path"] == expected and _integer(item["size"], common.MAX_FILE_BYTES, 1)
              and _text(item["sha256"], common._SHA) and type(item["mode"]) is int
              and item["mode"] in ({0o444, 0o644} if expected.endswith(".plist") else {0o555, 0o755}))
        native.append(common._FileSpec(expected, item["size"], item["sha256"], item["mode"]))
    _need(sum(f.size for f in (*files, *native)) <= common.MAX_TOTAL_BYTES, "input-limit")
    return common._Profile(selected, tuple(sorted(versions.items())), distribution["url"], distribution["sha256"],
        OS_PROFILE, anchors["osProviderSha256"], tuple(path.rsplit("/", 1)[1] for path in OS_FILES[1:]),
        files, tuple(native), tuple(sorted(directories, key=lambda path: (path.count("/"), path))),
        home, tuple(sorted(roles.items())), aliases)


class MacAdmission:
    """Platform half of the same exact AndroidValidationTools; owns no runner."""

    record_limit = DESCRIPTOR_RECORDS
    live_limit = LIVE_DESCRIPTORS
    manifest_budget = MANIFEST_BUDGET

    def __init__(self, tools: common.AndroidValidationTools) -> None:
        self.tools = tools
        self.current_iterator: common._Entries | None = None
        self.credentials = None
        self.disposed: set[common._Record] = set()
        self.aliases: list[tuple[common._FD, str, tuple[int, ...], str]] = []
        self.ancestors: list[tuple[common._FD, tuple[int, ...]]] = []
        self.live_slots: set[common._FD] = set()
        self.headers: tuple[common._Record, ...] = ()

    def owner(self) -> None:
        _need(type(self) is MacAdmission and type(self.tools) is common.AndroidValidationTools
              and self.tools._mac is self and self.tools.binding.profile == PROFILE, "toolchain-unavailable")
        self.tools._owner(active=not self.tools._cleanup_mode)

    def platform(self) -> None:
        self.owner()
        self.tools._point()
        _need(sys.platform == "darwin" and os.uname().machine == "arm64"
              and hasattr(os.stat_result, "st_flags") and hasattr(os, "listxattr"), "toolchain-unavailable")
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        _need(soft == resource.RLIM_INFINITY or soft >= 256, "toolchain-unavailable")
        ids = os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(sorted(os.getgroups()))
        _need(ids[0] == ids[1] == dict(self.tools.binding.selection)["ownerUid"] and ids[0] != 0 and ids[2] == ids[3])
        self.credentials = ids

    def live_count(self) -> int:
        tool = self.tools
        return len(self.live_slots) + int(self.current_iterator is not None) + sum(
            slot.close_state != "CLOSED" for slot in (tool.ancestry.slots if tool.ancestry is not None else ()))

    def protected(self, number: int, *, directory: bool, stable_contents: bool) -> tuple[int, ...]:
        self.owner()
        tool = self.tools
        tool._point()
        before = common._identity(os.fstat(number), directory=directory, stable_contents=stable_contents, mac=True)
        tool._point()
        _need(common._identity(os.fstat(number), directory=directory, stable_contents=stable_contents, mac=True) == before)
        # Native owner already admitted actual APFS, same-FD ACL, sealed-provider
        # and architecture/load-path policy. Python cannot replace that proof
        # with mode bits, same-device guesses or an environment variable.
        return before

    def retire(self, record: common._Record, path: str) -> None:
        tool = self.tools
        tool._check_record(record)
        with tool.guard.deferred(check_on_exit=False):
            try:
                record.slot.close()
                _need(record.slot.close_state == "CLOSED", "cleanup-unknown")
                self.disposed.add(record)
                self.live_slots.discard(record.slot)
                if record.directory:
                    _need(tool._directories.pop(path) is not None)
            except BaseException as error:
                tool._remember(error)
                raise

    @staticmethod
    def alias_identity(value: os.stat_result) -> tuple[int, ...]:
        _need(stat.S_ISLNK(value.st_mode) and value.st_uid == value.st_gid == 0 and value.st_nlink == 1
              and 1 <= value.st_size <= 512 and type(value.st_flags) is int)
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_flags)

    def walk(self, relative: str, record: common._Record, members: dict[str, common._FileSpec],
             aliases: dict[str, tuple[str, str, str]], children: dict[str, set[str]], launch: tuple[str, ...]) -> None:
        tool = self.tools
        path = tool.binding.root + ("/" + relative if relative else "")
        tool._check_record(record)
        tool._inventory_names(path, children[relative])
        for name in sorted(children[relative]):
            tool._point()
            child = f"{relative}/{name}" if relative else name
            if not relative and name in HEADERS:
                continue
            if child in aliases:
                parent = tool._directories[path]
                before = self.alias_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                tool._point()
                target = os.readlink(name, dir_fd=parent)
                _need(target == aliases[child][1])
                self.aliases.append((record.slot, name, before, target))
                _need(self.alias_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before)
                continue
            is_directory = child in children
            spec = None if is_directory else members[child]
            original = tool._open_record(tool._directories[path], name, directory=is_directory, spec=spec)
            _need(original.identity is not None and original.identity[4] == 0
                  and stat.S_IMODE(original.identity[2]) == (0o555 if is_directory else spec.mode))
            child_path = f"{tool.binding.root}/{child}"
            if is_directory:
                _need(original.slot.number is not None)
                tool._directories[child_path] = original.slot.number
                self.walk(child, original, members, aliases, children, launch)
            else:
                _need(tool._read(original, spec.size)[0] == spec.sha256)
            if not any(p == child or p.startswith(child + "/") for p in launch):
                self.retire(original, child_path)
        tool._check_record(record)

    def acquire(self) -> None:
        self.owner()
        tool = self.tools
        self.platform()
        tool._charge("tool-descriptor-slots", len(Path(tool.binding.root).parts), DESCRIPTOR_RECORDS)
        tool.ancestry = common._Ancestry(tool)
        tool.ancestry.acquire()
        for index, slot in enumerate(tool.ancestry.slots):
            _need(slot.number is not None)
            identity = tool._protected(slot.number, directory=True, stable_contents=False)
            self.ancestors.append((slot, identity))
            path = "/" if index == 0 else "/" + "/".join(Path(tool.binding.root).parts[1:index + 1])
            tool._directories[path] = slot.number
        _need(tool._protected(tool.ancestry.fd, directory=True, stable_contents=False)[:5] == tool.binding.identity)
        root = common._Record(tool.ancestry.bindings[-1][0], tool.ancestry.bindings[-1][1], tool.ancestry.slots[-1], True, True)
        root.identity = tool._protected(tool.ancestry.fd, directory=True, stable_contents=True)
        tool.records.append(root)
        headers, data = [], []
        for name, limit in zip(HEADERS, HEADER_LIMITS):
            header = tool._open_record(tool.ancestry.fd, name, directory=False)
            headers.append(header)  # Original retained even if the following check fails.
            _need(header.identity is not None and header.identity[4] == 0
                  and stat.S_IMODE(header.identity[2]) == 0o444 and 0 < header.identity[6] <= limit, "input-limit")
            tool._charge("tool-manifest-reservation", 2 * header.identity[6], MANIFEST_BUDGET)
            _, raw = tool._read(header, header.identity[6], keep=True, manifest=True)
            _need(raw is not None)
            data.append(raw)
        self.headers = tuple(headers)
        tool.manifest = headers[1]
        tool.profile = parse_profile(data[1], data[2], data[0], tool.binding)
        profile = tool.profile
        tool._charge("tool-roster-reservation", len(profile.files) + len(profile.directories) + 128, DESCRIPTOR_RECORDS)
        tool._charge("tool-hash-reservation", 2 * sum(f.size for f in (*profile.files, *profile.native_files)), 2 * common.MAX_TOTAL_BYTES)
        roles = dict(profile.roles)
        launch = (roles["java"], roles["javac"], roles["gradle"], roles["bundletool"], common.AAPT2_PATH,
                  f"{profile.java_home}/bin/jarsigner", f"{profile.java_home}/bin/keytool")
        children = {relative: set() for relative in ("", *profile.directories)}
        children[""].update(HEADERS)
        for relative in (*profile.directories, *(f.path for f in profile.files), *(a[0] for a in profile.aliases)):
            parent, _, name = relative.rpartition("/")
            children[parent].add(name)
        self.walk("", root, {f.path: f for f in profile.files}, {a[0]: a for a in profile.aliases}, children, launch)
        for spec in profile.native_files:
            elements = parts(spec.path, absolute=True)
            parent = "/"
            for name in elements[:-1]:
                path = f"/{name}" if parent == "/" else f"{parent}/{name}"
                if path not in tool._directories:
                    original = tool._open_record(tool._directories[parent], name, directory=True, stable_contents=False)
                    _need(original.slot.number is not None)
                    tool._directories[path] = original.slot.number
                parent = path
            original = tool._open_record(tool._directories[parent], elements[-1], directory=False, spec=spec)
            _need(tool._read(original, spec.size)[0] == spec.sha256)
        tool._acquired = True
        tool.check()

    def check_metadata(self) -> None:
        self.owner()
        tool = self.tools
        tool._point()
        ids = os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(sorted(os.getgroups()))
        _need(self.credentials is not None and ids == self.credentials and tool.ancestry is not None
              and tool.profile is not None and len(self.headers) == 3)
        tool.ancestry.check()
        _need(len(self.ancestors) == len(tool.ancestry.slots))
        for (slot, expected), original in zip(self.ancestors, tool.ancestry.slots):
            _need(slot is original and slot.number is not None)
            _need(tool._protected(slot.number, directory=True, stable_contents=False) == expected)
        _need(tool._protected(tool.ancestry.fd, directory=True, stable_contents=False)[:5] == tool.binding.identity)
        for original in tool.records:
            if original in self.disposed:
                _need(original.slot.close_state == "CLOSED")
            else:
                tool._check_record(original)
        for original, name, identity, target in self.aliases:
            # A closed parent is deliberately not reopened. Native ownership/ACL
            # and complete protected census established its immutable contents.
            # Retain the original slot object, NEVER a potentially recycled fd.
            if original.close_state == "CLOSED":
                continue
            _need(original.open_state == "OPEN" and original.close_state == "NOT_ATTEMPTED" and original.number is not None)
            tool._point()
            _need(self.alias_identity(os.stat(name, dir_fd=original.number, follow_symlinks=False)) == identity)
            _need(os.readlink(name, dir_fd=original.number) == target)

    def final_hash(self) -> None:
        self.owner()
        tool = self.tools
        _need(not tool._final_hash_claimed and len(self.headers) == 3)
        tool._final_hash_claimed = True
        anchors = dict(tool.binding.selection)
        for header, expected in zip(self.headers, (anchors["recordSha256"], tool.binding.sha256, anchors["osProviderSha256"])):
            _need(tool._read(header, header.identity[6], manifest=True)[0] == expected)
        for original in tool.records:
            if original.spec is not None and original not in self.disposed:
                _need(tool._read(original, original.spec.size)[0] == original.spec.sha256)
        # There is no synthetic "rehashed" receipt for streamed/disposed files.
