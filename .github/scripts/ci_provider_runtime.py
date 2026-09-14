"""Root-only preparation of fixed selected runtimes on a disposable Linux VM.

Imported only by the original controller, never by the copied child entry.
This changes permission bits, not runtime contents, owners, installation paths,
links, ACLs or signatures. The caller has already completed identity collision
admission and must not launch any subject after an exception or incomplete report.
Access ACLs remain unsupported; valid directory defaults are preserved exactly.
There is no command-line entrypoint, process execution or import-time operation.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import errno
import math
import os
from pathlib import PurePosixPath
import posixpath
import stat
import struct
import sys
import time


MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_OPEN = 72
MAX_ACL_BYTES = 4096
MAX_DEFAULT_ACL_BYTES = 8 * 1024**2
ROLES = ("python", "ruby", "jdk")
COMPATIBILITY_ROLES = ("python312", "python313", "python314")
ACL_NAMES = ("system.posix_acl_access", "system.posix_acl_default")
_ACL_UNCHECKED = object()


class ProviderRuntimeError(RuntimeError):
    """A finite preparation refusal; paths and provider diagnostics stay private."""


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _acl_shape(value):
    """Recognize bounded Linux POSIX-v2 data; never expose its qualifiers.

    This validates an inheritance template, not an access-ACL evaluator or
    transformer. Linux UAPI uses a little-endian version followed by HH/I
    entries; named users/groups must be unique and ordered within their class.
    """
    if type(value) is not bytes:
        return "non-bytes", "unknown"
    if len(value) > MAX_ACL_BYTES:
        return "over-bound", "over-bound"
    if len(value) < 4 or (len(value) - 4) % 8:
        return "malformed", "unknown"
    count = (len(value) - 4) // 8
    category = ("0" if count == 0 else "1-4" if count <= 4 else
                "5-16" if count <= 16 else "17-64" if count <= 64 else "65-511")
    if struct.unpack_from("<I", value)[0] != 2:
        return "unknown-version", category
    entries = tuple(struct.iter_unpack("<HHI", value[4:]))
    invalid = ("invalid-entries", category)
    if (len(entries) < 3 or entries[0][0] != 0x01 or entries[-1][0] != 0x20
            or any(tag not in {0x01, 0x02, 0x04, 0x08, 0x10, 0x20} or perm > 7
                   or (qualifier == 0xFFFFFFFF) != (tag not in {0x02, 0x08})
                   for tag, perm, qualifier in entries)):
        return invalid
    index, named = 1, False
    for tag, following in ((0x02, 0x04), (0x08, None)):
        previous = -1
        while index < len(entries) and entries[index][0] == tag:
            qualifier = entries[index][2]
            if qualifier <= previous:
                return invalid
            previous, named = qualifier, True
            index += 1
        if following is not None:
            if index >= len(entries) or entries[index][0] != following:
                return invalid
            index += 1
    if index < len(entries) and entries[index][0] == 0x10:
        index += 1
    elif named:
        return invalid
    if index != len(entries) - 1:
        return invalid
    return "linux-posix-v2", category


@dataclass
class _Node:
    role: str
    parts: tuple[str, ...]
    state: tuple
    prepared_mode: int
    children: tuple[str, ...] = ()
    link: str | None = None
    target: str | None = None
    default_acl: bytes | None = None


class _Preparation:
    def __init__(self, uid, gid, deadline, report):
        self.uid, self.gid, self.deadline, self.report = uid, gid, deadline, report
        self.roots, self.handles, self.nodes, self.external = {}, {}, {}, {}
        self.open_count = 0
        self.role = "controller"
        self.operation = "arguments"

    def note_failure(self, condition, role=None):
        if "condition" not in self.report:
            self.report.update(condition=condition, role=role or self.role)

    def refuse(self, condition):
        self.note_failure(condition)
        raise ProviderRuntimeError(condition)

    def clock(self):
        if time.monotonic() >= self.deadline:
            self.refuse("deadline")

    def call(self, operation, function, *args, **kwargs):
        # Only internal ordinary metadata APIs use this deadline/error wrapper.
        self.clock()
        self.operation = operation
        try:
            result = function(*args, **kwargs)
        except BaseException:
            self.note_failure(operation)
            raise
        self.clock()
        return result

    def count(self, field, role=None):
        self.report[field] += 1
        self.report["roles"][role or self.role][field] += 1

    @contextmanager
    def handle(self, name, *, directory=False, parent=None):
        self.clock()
        if self.open_count >= MAX_OPEN:
            self.refuse("descriptor-bound")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        role = self.role
        self.operation = "open"
        # Once acquired, custody includes the first post-open clock check.
        try:
            fd = os.open(name, flags, dir_fd=parent)
        except BaseException:
            self.note_failure("open", role)
            raise
        self.open_count += 1
        failures = []
        try:
            self.clock()
            yield fd
        except BaseException as exc:
            self.note_failure(self.operation)
            failures.append(exc)
        try:
            os.close(fd)  # Exactly one attempt, even after a body/deadline error.
        except BaseException as exc:
            self.note_failure("descriptor-close", role)
            failures.append(exc)
        self.open_count -= 1
        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup("provider operation and descriptor close failed", failures)
        self.clock()

    def note_acl_failure(self, condition, attribute, presence, value=None):
        if "condition" not in self.report:
            shape = (_acl_shape(value) if presence == "present" else
                     ("absent", "0") if presence == "absent" else ("unknown", "unknown"))
            self.report["acl"] = {"attribute": attribute, "presence": presence,
                                  "format": shape[0], "entries": shape[1]}
        self.note_failure(condition)

    def acl_state(self, fd, *, directory, expected=_ACL_UNCHECKED):
        """Access must be absent; only a directory default may be preserved.

        A default controls new-child inheritance, not existing-node authority.
        No provider nodes are created after preparation. Rechecks compare the
        original bytes OR absence, never silently adopt a changed baseline.
        """
        for attribute, name in zip(("access", "default"), ACL_NAMES):
            self.clock()
            self.operation = "acl-query"
            present = True
            try:
                value = os.getxattr(fd, name)
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    self.note_acl_failure("acl-unknown", attribute, "unknown")
                    raise
                present, value = False, None
            except BaseException:
                self.note_acl_failure("acl-query", attribute, "unknown")
                raise
            self.clock()
            if attribute == "access":
                if not present:
                    continue
                self.note_acl_failure("acl-present", attribute, "present", value)
                self.refuse("acl-present")
            if (expected is not _ACL_UNCHECKED
                    and (present != (expected is not None) or value != expected)):
                self.note_acl_failure("default-acl-drift", attribute,
                                      "present" if present else "absent", value)
                self.refuse("default-acl-drift")
            if present:
                if not directory:
                    self.note_acl_failure("default-acl-not-directory", attribute, "present", value)
                    self.refuse("default-acl-not-directory")
                if _acl_shape(value)[0] != "linux-posix-v2":
                    self.note_acl_failure("default-acl-format", attribute, "present", value)
                    self.refuse("default-acl-format")
            self.clock()
            return value

    def observed(self, fd, expected):
        current = _snapshot(self.call("descriptor-stat", os.fstat, fd))
        if current != expected:
            self.refuse("identity-or-metadata-drift")
        return current

    def mode(self, info, *, external=False):
        if info.st_uid == self.uid:
            self.refuse("subject-owned")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            self.refuse("unsupported-node")
        mask = 0o002 | (0o020 if info.st_gid == self.gid else 0)
        old = stat.S_IMODE(info.st_mode)
        new = old & ~mask
        if external and old != new:
            self.refuse("external-target-writable")
        if old != new and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            self.refuse("modified-file-has-links")
        return new

    def add(self, node):
        if self.report["inventoried"] >= MAX_NODES:
            self.refuse("inventory-bound")
        self.count("inventoried")
        self.nodes[self.path(node)] = node

    def path(self, node):
        return posixpath.join(self.roots[node.role], *node.parts)

    def children(self, fd):
        names = self.call("directory-list", os.listdir, fd)
        if (len(names) > MAX_NODES or len(set(names)) != len(names)
                or any(not isinstance(n, str) or not n or n in {".", ".."}
                       or "/" in n or "\0" in n or len(n) > 255 for n in names)):
            self.refuse("directory-inventory")
        return tuple(sorted(names))

    def inventory(self, node, fd):
        self.observed(fd, node.state)
        default = self.acl_state(fd, directory=stat.S_ISDIR(node.state[2]))
        if default is not None:
            if self.report["default_acl_bytes"] + len(default) > MAX_DEFAULT_ACL_BYTES:
                self.note_acl_failure("default-acl-byte-bound", "default", "present", default)
                self.refuse("default-acl-byte-bound")
            node.default_acl = default
            self.report["default_acl_bytes"] += len(default)
            self.report["default_acl_nodes"] += 1
        if node.prepared_mode != stat.S_IMODE(node.state[2]):
            self.count("planned")
        if stat.S_ISDIR(node.state[2]):
            node.children = self.children(fd)
            for name in node.children:
                parts = (*node.parts, name)
                if len(parts) > MAX_DEPTH or len(posixpath.join(self.roots[self.role], *parts)) > 4096:
                    self.refuse("path-depth-or-length")
                info = self.call("path-stat", os.stat, name, dir_fd=fd, follow_symlinks=False)
                state = _snapshot(info)
                if stat.S_ISLNK(info.st_mode):
                    if info.st_uid == self.uid:
                        self.refuse("subject-owned")
                    link = self.call("link-read", os.readlink, name, dir_fd=fd)
                    if not isinstance(link, str) or not link or "\0" in link or len(link) > 4096:
                        self.refuse("link-value")
                    child = _Node(self.role, parts, state, stat.S_IMODE(info.st_mode), link=link)
                    self.add(child)
                else:
                    child = _Node(self.role, parts, state, self.mode(info))
                    self.add(child)
                    with self.handle(name, directory=stat.S_ISDIR(info.st_mode), parent=fd) as child_fd:
                        self.inventory(child, child_fd)
                if _snapshot(self.call("path-stat", os.stat, name, dir_fd=fd, follow_symlinks=False)) != state:
                    self.refuse("identity-or-metadata-drift")
        self.observed(fd, node.state)

    @contextmanager
    def parent(self, node):
        """Reach only inventoried ordinary descendants through held directory FDs."""
        self.role = node.role
        root = self.nodes[self.roots[self.role]]
        current = _snapshot(self.call("path-stat", os.stat, self.roots[self.role], follow_symlinks=False))
        if current != root.state:
            self.refuse("prefix-path-drift")
        fd = self.handles[self.role]
        self.observed(fd, root.state)
        with ExitStack() as stack:
            for index, name in enumerate(node.parts[:-1]):
                path = posixpath.join(self.roots[self.role], *node.parts[:index + 1])
                directory = self.nodes[path]
                if not stat.S_ISDIR(directory.state[2]):
                    self.refuse("nonordinary-parent")
                fd = stack.enter_context(self.handle(name, directory=True, parent=fd))
                self.observed(fd, directory.state)
            yield fd

    @contextmanager
    def node_handle(self, node):
        with self.parent(node) as parent:
            if not node.parts:
                yield parent
            else:
                with self.handle(node.parts[-1], directory=stat.S_ISDIR(node.state[2]), parent=parent) as fd:
                    yield fd

    def check_link(self, node, *, initial):
        with self.parent(node) as fd:
            state = _snapshot(self.call("path-stat", os.stat, node.parts[-1], dir_fd=fd, follow_symlinks=False))
            link = self.call("link-read", os.readlink, node.parts[-1], dir_fd=fd)
            if state != node.state or link != node.link:
                self.refuse("link-drift")
            target = self.call("link-resolution", os.path.realpath, self.path(node), strict=True)
            if not initial and target != node.target:
                self.refuse("link-target-drift")
            node.target = target
            internal = any(target == p or target.startswith(p + "/") for p in self.roots.values())
            if internal:
                other = self.nodes.get(target)
                if other is None or other.link is not None:
                    self.refuse("uninventoried-internal-target")
            elif initial:
                self.check_external(target, initial=True)

    def check_external(self, path, *, initial):
        info = self.call("external-stat", os.stat, path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            self.refuse("external-target-not-regular")
        self.mode(info, external=True)
        current = _snapshot(info)
        if not initial and current != self.external[path][1]:
            self.refuse("external-target-drift")
        with self.handle(path) as fd:
            self.observed(fd, current)
            self.acl_state(fd, directory=False, expected=_ACL_UNCHECKED if initial else None)
            self.observed(fd, current)
        if initial:
            if path in self.external and self.external[path][1] != current:
                self.refuse("external-target-drift")
            if path not in self.external:
                if self.report["inventoried"] >= MAX_NODES:
                    self.refuse("inventory-bound")
                self.count("inventoried")
                self.external[path] = (self.role, current)

    def change(self, node):
        with self.node_handle(node) as fd:
            self.observed(fd, node.state)
            self.acl_state(fd, directory=stat.S_ISDIR(node.state[2]), expected=node.default_acl)
            self.observed(fd, node.state)
            self.clock()
            self.operation = "chmod"
            self.count("attempted")  # A raising fchmod may already have applied.
            try:
                os.fchmod(fd, node.prepared_mode)
            except BaseException:
                self.note_failure("chmod")
                raise
            self.clock()
            changed = _snapshot(self.call("descriptor-stat", os.fstat, fd))
            expected = (*node.state[:2], stat.S_IFMT(node.state[2]) | node.prepared_mode,
                        *node.state[3:8], changed[8])
            if changed != expected:
                self.refuse("chmod-aftereffect")
            self.acl_state(fd, directory=stat.S_ISDIR(node.state[2]), expected=node.default_acl)
            self.observed(fd, changed)
            node.state = changed
            self.count("confirmed")

    def run(self, prefixes):
        self.report["phase"] = "preinventory"
        with ExitStack() as stack:
            for role, path in prefixes:
                self.role = role
                path = str(path)
                if self.call("prefix-resolution", os.path.realpath, path, strict=True) != path:
                    self.refuse("noncanonical-prefix")
                self.roots[role] = path
                info = self.call("path-stat", os.stat, path, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    self.refuse("prefix-not-directory")
                node = _Node(role, (), _snapshot(info), self.mode(info))
                self.add(node)
                fd = stack.enter_context(self.handle(path, directory=True))
                self.handles[role] = fd
                self.inventory(node, fd)
            self.report["phase"] = "link-inventory"
            for node in self.nodes.values():
                if node.link is not None:
                    self.check_link(node, initial=True)
            # Nothing above this boundary changes ANY permission or file bytes.
            self.report["phase"] = "mutation"
            for node in self.nodes.values():
                if node.link is None and node.prepared_mode != stat.S_IMODE(node.state[2]):
                    self.change(node)
            self.report["phase"] = "recheck"
            for node in self.nodes.values():
                if node.link is not None:
                    self.check_link(node, initial=False)
                    continue
                with self.node_handle(node) as fd:
                    self.observed(fd, node.state)
                    self.acl_state(fd, directory=stat.S_ISDIR(node.state[2]), expected=node.default_acl)
                    if stat.S_ISDIR(node.state[2]) and self.children(fd) != node.children:
                        self.refuse("directory-membership-drift")
                    self.observed(fd, node.state)
            for path, (role, _state) in self.external.items():
                self.role = role
                self.check_external(path, initial=False)
            for role, path in self.roots.items():
                self.role = role
                if self.call("prefix-resolution", os.path.realpath, path, strict=True) != path:
                    self.refuse("prefix-path-drift")
            self.report["phase"] = "descriptor-close"
        self.clock()
        self.report.update(ok=True, phase="complete")


def protect_selected_runtimes(prefixes, *, uid, gid, deadline, report):
    """Prepare only the exact three or six selected prefixes before any U code.

    ``report`` is the original controller's already-published admission row.
    Attempt/confirmed counts remain truthful on every exception; no rollback or
    incomplete report can authorize a later launch. All OS effects are confined
    to this call; importing the module performs no admission or filesystem work.
    """
    if type(report) is not dict or report != {"name": "provider-runtime-permissions", "ok": False}:
        raise ProviderRuntimeError("invalid-report")
    report.update(phase="arguments", inventoried=0, planned=0, attempted=0, confirmed=0,
                  errors=0, default_acl_bytes=0, default_acl_nodes=0,
                  roles={role: {k: 0 for k in ("inventoried", "planned", "attempted", "confirmed")}
                                   for role in ROLES})
    preparation = _Preparation(uid, gid, deadline, report)
    try:
        if (sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0
                or type(uid) is not int or type(gid) is not int or not 60000 <= uid < 65000 or gid != uid
                or type(deadline) not in (int, float) or not math.isfinite(deadline)):
            preparation.refuse("root-linux-identity-or-deadline")
        if (not isinstance(prefixes, (tuple, list)) or len(prefixes) not in (3, 6)
                or any(not isinstance(row, (tuple, list)) or len(row) != 2 for row in prefixes)
                or tuple(row[0] for row in prefixes) != (
                    ROLES if len(prefixes) == 3 else ROLES + COMPATIBILITY_ROLES)):
            preparation.refuse("prefix-roles")
        # Extend only the closed, complete role set. The original transaction
        # inventories every selected prefix before its first permission effect;
        # none of its bounds, ACL rules or failure/close accounting change.
        if len(prefixes) == 6:
            report["roles"].update({role: {k: 0 for k in ("inventoried", "planned", "attempted", "confirmed")}
                                    for role in COMPATIBILITY_ROLES})
        paths = tuple(str(row[1]) for row in prefixes)
        for path in paths:
            parts = PurePosixPath(path).parts
            if (not path.startswith("/") or path.startswith("//") or "\0" in path or len(path) > 4096
                    or len(parts) < 4 or len(parts) > MAX_DEPTH or ".." in parts
                    or str(PurePosixPath(path)) != path):
                preparation.refuse("prefix-shape")
        if any(a == b or a.startswith(b + "/") or b.startswith(a + "/")
               for index, a in enumerate(paths) for b in paths[index + 1:]):
            preparation.refuse("prefix-overlap")
        preparation.run(prefixes)
    except BaseException as exc:
        preparation.note_failure(preparation.operation)
        report["ok"] = False
        pending, count = [exc], 0
        while pending:
            current = pending.pop()
            if isinstance(current, BaseExceptionGroup):
                pending.extend(current.exceptions)
            else:
                count += 1
        report["errors"] = count
        raise
