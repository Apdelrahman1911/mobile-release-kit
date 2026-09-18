"""Fixed installed-tool lookup for the admitted diagnostics profiles only.

Administratively trusted installations, not executable-FD custody, signatures,
ACL/mount proof or hostile-user containment. The unchanged command owner executes
the selected absolute pathname; these finite observations cannot exclude ABA.
No project directory is opened and no PATH/custom-location search is performed.
"""
from __future__ import annotations

import os
import re
import stat
import threading
from dataclasses import dataclass
from typing import Any

from ._desktop_environment_protocol import PROFILES, ProtocolError, absolute_path, require
from .cancellation import DefaultCancellation
from .owned_process import ProcessCleanupError

_NAME = re.compile(r"[A-Za-z0-9_+\-][A-Za-z0-9._+\-]{0,127}\Z", re.ASCII)
_XCODE_APP = re.compile(r"Xcode_[0-9]{1,32}(?:\.[0-9]{1,32}){0,2}\.app\Z", re.ASCII)
_HEADER_BYTES = 8 + 8 * 32  # Largest admitted universal Mach-O table.
_CUSTODY = "Environment tool observation custody did not settle"


class ToolUnavailable(Exception):
    def __init__(self, reason: str = "unsupported-installation", *, inaccessible: bool = False) -> None:
        require(type(reason) is str and reason in {"missing-in-supported-lookup", "unsupported-installation", "unselected-installation"})
        self.reason = reason
        self.inaccessible = inaccessible
        super().__init__("Tool is unavailable in the supported lookup")


class BindingChanged(Exception):
    """An observed installation change stops the run; no replacement lookup."""


def _admit(condition: bool, reason: str = "unsupported-installation") -> None:
    if not condition:
        raise ToolUnavailable(reason)


def overlaps(left: str, right: str) -> bool:
    return (left == right or left == "/" or right == "/" or left.startswith(right + "/")
            or right.startswith(left + "/"))


def directory_allowed(value: os.stat_result, profile: str) -> bool:
    groups = {0, 80} if PROFILES[profile][0] == "macos" else {0}
    return (stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o002
            and (not value.st_mode & 0o020 or value.st_gid in groups))


def executable_allowed(value: os.stat_result) -> bool:
    return (stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
            and bool(value.st_mode & 0o100) and not value.st_mode & 0o6022 and value.st_size > 0)


def binary_header_allowed(content: bytes, profile: str, size: int) -> bool:
    """Finite ELF/Mach-O kind/architecture observation, never provenance proof."""
    if type(content) is not bytes or type(profile) is not str or profile not in PROFILES or type(size) is not int:
        return False
    host, architecture = PROFILES[profile]
    if host == "linux":
        return (len(content) >= 64 and content[:7] == b"\x7fELF\x02\x01\x01"
            and int.from_bytes(content[16:18], "little") in {2, 3}
            and int.from_bytes(content[18:20], "little") == {"x86_64": 62, "aarch64": 183}[architecture]
            and int.from_bytes(content[20:24], "little") == 1
            and int.from_bytes(content[52:54], "little") == 64 and size >= 64)
    cpu = {"x86_64": 0x01000007, "arm64": 0x0100000C}[architecture]
    if content[:4] == b"\xcf\xfa\xed\xfe":
        return (len(content) >= 32 and size >= 32 and int.from_bytes(content[4:8], "little") == cpu
                and int.from_bytes(content[12:16], "little") == 2)
    if content[:4] not in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} or len(content) < 8:
        return False
    count = int.from_bytes(content[4:8], "big")
    fat64 = content[:4] == b"\xca\xfe\xba\xbf"
    width = 32 if fat64 else 20
    if not 1 <= count <= 8 or len(content) < 8 + width * count:
        return False
    architectures: set[int] = set()
    for index in range(count):
        item = content[8 + index * width:8 + (index + 1) * width]
        current = int.from_bytes(item[:4], "big")
        offset = int.from_bytes(item[8:16 if fat64 else 12], "big")
        length = int.from_bytes(item[16:24] if fat64 else item[12:16], "big")
        alignment = int.from_bytes(item[24:28] if fat64 else item[16:20], "big")
        if (current in architectures or offset < 8 + width * count or length < 32
                or offset + length > size or alignment > 30 or offset % (1 << alignment)
                or fat64 and item[28:32] != b"\0\0\0\0"):
            return False
        architectures.add(current)
    return cpu in architectures


def tool_environment(profile: str, role: str, developer_root: str | None = None) -> dict[str, str]:
    require(type(profile) is str and profile in PROFILES and type(role) is str
        and role in {"git", "java", "javac", "xcode", "developer-selection"})
    host = PROFILES[profile][0]
    require(host == "macos" or role in {"git", "java", "javac"})
    result = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin" if host == "linux" else "/usr/bin:/bin:/usr/sbin:/sbin"}
    if role == "xcode":
        require(host == "macos" and type(developer_root) is str)
        assert isinstance(developer_root, str)
        absolute_path(developer_root)
        parts = developer_root.split("/")
        require(len(parts) == 5 and parts[:2] == ["", "Applications"] and parts[3:] == ["Contents", "Developer"]
            and (parts[2] == "Xcode.app" or _XCODE_APP.fullmatch(parts[2]) is not None))
        result.update(PATH=developer_root + "/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin", DEVELOPER_DIR=developer_root)
    return result  # Empty-origin, not inherited-and-scrubbed environment.


def _directory_facts(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _file_facts(value: os.stat_result) -> tuple[int, ...]:
    return (*_directory_facts(value), value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass(frozen=True)
class _Node:
    path: str
    kind: str
    facts: tuple[int, ...]
    target: bytes | None = None


@dataclass(frozen=True)
class ToolBinding:
    path: str
    nodes: tuple[_Node, ...]


@dataclass
class _Header:
    state: str = "NEW"
    fd: int | None = None


@dataclass
class _Scan:
    state: str = "NEW"
    iterator: Any = None


class ToolLookup:
    """Original finite header/iterator resources; never a process owner."""

    def __init__(self, profile: str, project_root: str, guard: DefaultCancellation) -> None:
        require(type(profile) is str and profile in PROFILES and type(guard) is DefaultCancellation)
        self.profile, self.project_root, self.guard = profile, absolute_path(project_root), guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.headers: list[_Header] = []
        self.scans: list[_Scan] = []

    def _origin(self) -> None:
        require(self.pid == os.getpid() and self.thread is threading.current_thread())
        self.guard._check_owner()

    def _path(self, value: str) -> str:
        absolute_path(value)
        _admit(len(value.split("/")) - 1 <= 32 and not overlaps(value, self.project_root))
        return value

    def _stat(self, path: str) -> os.stat_result:
        self._origin()
        self.guard.check()
        try:
            result = os.lstat(path)
        except FileNotFoundError:
            raise ToolUnavailable("missing-in-supported-lookup") from None
        except OSError:
            raise ToolUnavailable(inaccessible=True) from None
        self.guard.check()
        return result

    def _readlink(self, path: str) -> bytes:
        self.guard.check()
        try:
            result = os.readlink(os.fsencode(path))
        except OSError:
            raise ToolUnavailable(inaccessible=True) from None
        self.guard.check()
        _admit(type(result) is bytes and 0 < len(result) <= 4096 and b"\0" not in result)
        return result

    def _plain(self, path: str, *, directory: bool = False) -> tuple[_Node, ...]:
        self._path(path)
        components = path.split("/")[1:]
        nodes = []
        names = ["/"] + ["/" + "/".join(components[:index + 1]) for index in range(len(components))]
        for index, name in enumerate(names):
            value = self._stat(name)
            is_directory = directory or index < len(names) - 1
            _admit(directory_allowed(value, self.profile) if is_directory else executable_allowed(value))
            nodes.append(_Node(name, "directory" if is_directory else "file",
                               _directory_facts(value) if is_directory else _file_facts(value)))
        return tuple(nodes)

    def _link(self, path: str) -> tuple[tuple[_Node, ...], bytes]:
        self._path(path)
        nodes = self._plain(path.rsplit("/", 1)[0], directory=True)
        value = self._stat(path)
        _admit(stat.S_ISLNK(value.st_mode) and value.st_uid == 0)
        target = self._readlink(path)
        _admit(_file_facts(value) == _file_facts(self._stat(path)))
        return (*nodes, _Node(path, "link", _file_facts(value), target)), target

    def recheck(self, binding: ToolBinding) -> None:
        self._origin()
        require(type(binding) is ToolBinding)
        try:
            for node in binding.nodes:
                current = self._stat(node.path)
                facts = _directory_facts(current) if node.kind == "directory" else _file_facts(current)
                if facts != node.facts or node.kind == "link" and self._readlink(node.path) != node.target:
                    raise BindingChanged("Installed tool identity changed")
        except ToolUnavailable:
            raise BindingChanged("Installed tool identity could not be rechecked") from None

    def _close_header(self, slot: _Header) -> None:
        self._origin()
        if slot.state in {"NEW", "CLOSED"}:
            return
        try:
            require(slot.state == "OPEN" and type(slot.fd) is int and slot.fd >= 0)
            number, slot.fd = slot.fd, None
            slot.state = "CLOSING"
            os.close(number)
            slot.state = "CLOSED"
        except BaseException as error:
            slot.state = "UNKNOWN"
            self.guard._abort(error)
            raise ProcessCleanupError(_CUSTODY) from None

    def _header(self, binding: ToolBinding) -> None:
        self._origin()
        self.guard.check()
        require(len(self.headers) < 68)
        slot = _Header()
        self.headers.append(slot)  # Retained before the opening effect.
        expected = binding.nodes[-1].facts
        try:
            with self.guard.deferred(check_on_exit=False):
                slot.state = "ACQUIRING"
                try:
                    slot.fd = os.open(binding.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                except BaseException as error:
                    slot.state = "OPEN" if type(slot.fd) is int and slot.fd >= 0 else "UNKNOWN"
                    if slot.state == "UNKNOWN":
                        self.guard._abort(error)
                    raise
                require(type(slot.fd) is int and slot.fd >= 0)
                slot.state = "OPEN"
            self.guard.check()
            observed = os.fstat(slot.fd)
            if _file_facts(observed) != expected:
                raise BindingChanged("Installed tool changed before header observation")
            self.recheck(binding)
            content = os.read(slot.fd, _HEADER_BYTES)
            self.guard.check()
            if _file_facts(os.fstat(slot.fd)) != expected:
                raise BindingChanged("Installed tool changed during header observation")
            self.recheck(binding)
            _admit(binary_header_allowed(content, self.profile, observed.st_size))
        finally:
            # No cancelled ordinary check or new namespace probe in cleanup.
            with self.guard.deferred(check_on_exit=False):
                self._close_header(slot)

    def _file(self, path: str, prefix: tuple[_Node, ...] = ()) -> ToolBinding:
        binding = ToolBinding(path, (*prefix, *self._plain(path)))
        self._header(binding)
        return binding

    def linux_git(self) -> ToolBinding:
        require(PROFILES[self.profile][0] == "linux")
        return self._file("/usr/bin/git")

    def linux_jdk(self) -> tuple[ToolBinding, ToolBinding]:
        require(PROFILES[self.profile][0] == "linux")
        selected: list[tuple[str, tuple[_Node, ...], str]] = []
        for role in ("java", "javac"):
            first, target = self._link("/usr/bin/" + role)
            _admit(target == ("/etc/alternatives/" + role).encode("ascii"), "unselected-installation")
            second, target = self._link("/etc/alternatives/" + role)
            try:
                path = target.decode("ascii", errors="strict")
            except UnicodeError:
                raise ToolUnavailable("unselected-installation") from None
            parts = path.split("/")
            _admit(len(parts) == 7 and parts[:4] == ["", "usr", "lib", "jvm"]
                and _NAME.fullmatch(parts[4]) is not None and parts[5:] == ["bin", role], "unselected-installation")
            self._path("/usr/lib/jvm/" + parts[4])
            selected.append((path, (*first, *second), parts[4]))
        _admit(selected[0][2] == selected[1][2], "unselected-installation")
        return tuple(self._file(path, nodes) for path, nodes, _name in selected)  # type: ignore[return-value]

    def mac_selector(self) -> ToolBinding:
        require(PROFILES[self.profile][0] == "macos")
        return self._file("/usr/bin/xcode-select")

    def mac_developer(self, output: bytes) -> ToolBinding:
        require(PROFILES[self.profile][0] == "macos")
        _admit(type(output) is bytes and 0 < len(output) <= 4096)
        raw = output[:-1] if output.endswith(b"\n") else output
        _admit(bool(raw) and b"\n" not in raw and b"\r" not in raw)
        try:
            path = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ToolUnavailable() from None
        prefix: tuple[_Node, ...] = ()
        if path != "/Library/Developer/CommandLineTools":
            parts = path.split("/")
            _admit(len(parts) == 5 and parts[:2] == ["", "Applications"]
                and parts[3:] == ["Contents", "Developer"]
                and (parts[2] == "Xcode.app" or _XCODE_APP.fullmatch(parts[2]) is not None))
            self._path("/Applications/" + parts[2])
            parent = self._plain("/Applications", directory=True)
            selected = self._stat("/Applications/" + parts[2])
            if stat.S_ISLNK(selected.st_mode):
                _admit(parts[2] == "Xcode.app")
                prefix, target = self._link("/Applications/Xcode.app")
                try:
                    name = target.decode("ascii", errors="strict")
                except UnicodeError:
                    raise ToolUnavailable() from None
                name = name[len("/Applications/"):] if name.startswith("/Applications/") else name
                _admit(_XCODE_APP.fullmatch(name) is not None)
                path = "/Applications/" + name + "/Contents/Developer"
            else:
                _admit(directory_allowed(selected, self.profile))
                prefix = parent
        return ToolBinding(path, (*prefix, *self._plain(path, directory=True)))

    def mac_developer_tool(self, developer: ToolBinding, role: str) -> ToolBinding:
        require(PROFILES[self.profile][0] == "macos" and type(developer) is ToolBinding
            and role in {"git", "xcode"})
        require(role != "xcode" or developer.path != "/Library/Developer/CommandLineTools")
        self.recheck(developer)
        return self._file(developer.path + "/usr/bin/" + ("xcodebuild" if role == "xcode" else "git"), developer.nodes)

    def _close_scan(self, slot: _Scan) -> None:
        self._origin()
        if slot.state in {"NEW", "CLOSED"}:
            return
        try:
            require(slot.state == "OPEN" and slot.iterator is not None)
            iterator = slot.iterator  # Keep the original rooted if close is unknown.
            slot.state = "CLOSING"
            iterator.close()
            slot.state = "CLOSED"
            slot.iterator = None
        except BaseException as error:
            slot.state = "UNKNOWN"
            self.guard._abort(error)
            raise ProcessCleanupError(_CUSTODY) from None

    def _names(self, root: str) -> tuple[str, ...]:
        require(not self.scans)
        self.guard.check()
        slot = _Scan()
        self.scans.append(slot)
        names: list[str] = []
        try:
            with self.guard.deferred(check_on_exit=False):
                slot.state = "ACQUIRING"
                try:
                    slot.iterator = os.scandir(root)
                except BaseException as error:
                    slot.state = "OPEN" if slot.iterator is not None else "UNKNOWN"
                    if slot.state == "UNKNOWN":
                        self.guard._abort(error)
                    raise
                slot.state = "OPEN"
            while True:
                self.guard.check()
                try:
                    entry = next(slot.iterator)
                except StopIteration:
                    break
                except OSError:
                    raise ToolUnavailable("unselected-installation", inaccessible=True) from None
                _admit(len(names) < 32, "unselected-installation")
                name = entry.name
                _admit(type(name) is str and "/" not in name, "unselected-installation")
                try:
                    _admit(len(name.encode("utf-8")) <= 255, "unselected-installation")
                except UnicodeError:
                    raise ToolUnavailable("unselected-installation") from None
                names.append(name)
        finally:
            with self.guard.deferred(check_on_exit=False):
                self._close_scan(slot)
        return tuple(names)

    def mac_jdk(self) -> tuple[ToolBinding, ToolBinding]:
        require(PROFILES[self.profile][0] == "macos")
        root = "/Library/Java/JavaVirtualMachines"
        nodes = self._plain(root, directory=True)
        # An added/removed JDK must invalidate unique selection, even though
        # ordinary ancestor checks intentionally ignore directory timestamps.
        census = _Node(root, "selection-directory", _file_facts(self._stat(root)))
        base = ToolBinding(root, (*nodes, census))
        names = self._names(root)
        self.recheck(base)
        pairs: list[tuple[ToolBinding, ToolBinding]] = []
        for name in names:
            self.guard.check()
            if not name.endswith(".jdk") or _NAME.fullmatch(name[:-4]) is None:
                continue
            home = root + "/" + name + "/Contents/Home"
            try:
                pair = (self._file(home + "/bin/java", base.nodes), self._file(home + "/bin/javac", base.nodes))
            except ToolUnavailable as error:
                # Metadata-inadmissible/incomplete pairs cannot be selected.
                # No IO/cleanup/identity exception is treated as mere absence.
                if error.inaccessible:
                    raise ToolUnavailable("unselected-installation", inaccessible=True) from None
                if error.reason not in {"missing-in-supported-lookup", "unsupported-installation"}:
                    raise
                continue
            pairs.append(pair)
        self.recheck(base)
        _admit(len(pairs) == 1, "unselected-installation")
        return pairs[0]

    def close(self) -> None:
        self._origin()
        first: BaseException | None = None
        for slot in reversed(self.scans):
            try:
                self._close_scan(slot)
            except BaseException as error:
                if first is None:
                    first = error
        for slot in reversed(self.headers):
            try:
                self._close_header(slot)
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first

    @property
    def closed(self) -> bool:
        self._origin()
        return all(slot.state in {"NEW", "CLOSED"} for slot in (*self.headers, *self.scans))
