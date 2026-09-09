"""Inert selected-provider permission contracts, not hosted filesystem evidence.

Only the helper's definitions are loaded, on demand. Every reachable filesystem
and clock API is then replaced in that private module with the small provider
fixture below. No selected runtime, real descriptor, permission, process or ACL
is inspected or changed by these tests.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import functools
import importlib.util
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


@functools.lru_cache(maxsize=1)
def provider_module():
    spec = importlib.util.spec_from_file_location(
        "_mrk_pure_ci_provider_runtime", ROOT / ".github/scripts/ci_provider_runtime.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required provider preparation helper is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def _leaves(error):
    if isinstance(error, BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in _leaves(child)]
    return [error]


class _ProviderTree:
    """Only the ordinary syscalls used by this one provider transaction.

    Paths are synthetic lexical keys. Open descriptors retain their original
    node object even if a test substitutes the corresponding pathname. The fake
    fchmod changes ctime as well as permission bits, just as a real change can.
    """

    def __init__(self):
        self.uid = self.gid = 60001
        self.controller_uid = self.controller_euid = 0
        self.platform = "linux"
        self.now, self.deadline = 4.0, 10.0
        self.report = {"name": "provider-runtime-permissions", "ok": False}
        self.nodes, self.fds, self.events = {}, {}, []
        self.next_fd, self.peak_fds = 100, 0
        self.after = lambda *_: None
        self.acls, self.resolutions = {}, {}
        self.prefixes = tuple((role, Path("/synthetic/providers") / role)
                              for role in ("python", "ruby", "jdk"))
        for path in ("/", "/synthetic", "/synthetic/providers"):
            self.add(path, kind=stat.S_IFDIR)
        for role, prefix in self.prefixes:
            self.add(prefix, kind=stat.S_IFDIR)
            self.add(prefix / "bin", kind=stat.S_IFDIR)
            self.add(prefix / "bin" / {"python": "python", "ruby": "ruby", "jdk": "java"}[role])

    def add(self, path, *, kind=stat.S_IFREG, mode=0o755, uid=1001, gid=1001,
            nlink=None, target=None):
        path = str(path)
        node = SimpleNamespace(st_dev=7, st_ino=len(self.nodes) + 1000,
                               st_mode=kind | mode, st_uid=uid, st_gid=gid,
                               st_nlink=(2 if kind == stat.S_IFDIR else 1) if nlink is None else nlink,
                               st_size=32, st_mtime_ns=101, st_ctime_ns=202,
                               target=target, content=b"unchanged-provider-fixture")
        self.nodes[path] = node
        return node

    def name(self, path, dir_fd=None):
        value = PurePosixPath(path)
        if not value.is_absolute():
            if dir_fd not in self.fds:
                raise AssertionError("relative provider operation lacks an owned fake directory")
            if not stat.S_ISDIR(self.fds[dir_fd][1].st_mode):
                raise AssertionError("relative provider operation used a nondirectory handle")
            value = PurePosixPath(self.fds[dir_fd][0]) / value
        if ".." in value.parts:
            raise AssertionError("provider fixture requires normalized relative components")
        return str(value)

    def event(self, operation, path, detail=None):
        self.events.append((operation, path, detail))
        self.after(operation, path, detail)

    @staticmethod
    def metadata(node):
        return SimpleNamespace(**{name: value for name, value in vars(node).items() if name.startswith("st_")})

    def lstat(self, path, *, dir_fd=None):
        return self.stat(path, dir_fd=dir_fd, follow_symlinks=False)

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if follow_symlinks:
            raise AssertionError("provider fixture forbids implicit symlink following")
        name = self.name(path, dir_fd)
        if name not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "synthetic absent provider node")
        result = self.metadata(self.nodes[name])
        self.event("stat", name)
        return result

    def open(self, path, flags, *, dir_fd=None):
        name = self.name(path, dir_fd)
        if flags & os.O_ACCMODE != os.O_RDONLY:
            raise AssertionError("provider fixture permits only metadata/read-only handles")
        if flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError("provider fixture cannot create or modify file bytes")
        if any(not flags & flag for flag in (os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK)):
            raise AssertionError("provider handle omitted no-follow, close-on-exec or nonblocking")
        node = self.nodes[name]
        if stat.S_ISLNK(node.st_mode):
            raise OSError(errno.ELOOP, "synthetic no-follow provider link")
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(node.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, "synthetic nondirectory provider node")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd] = name, node
        self.peak_fds = max(self.peak_fds, len(self.fds))
        self.event("open", name, (fd, flags, dir_fd))
        return fd

    def fstat(self, fd):
        name, node = self.fds[fd]
        result = self.metadata(node)
        self.event("fstat", name, fd)
        return result

    def listdir(self, fd):
        name, node = self.fds[fd]
        if not stat.S_ISDIR(node.st_mode):
            raise AssertionError("provider fixture lists only owned directory handles")
        result = [PurePosixPath(path).name for path in self.nodes
                  if path != name and str(PurePosixPath(path).parent) == name]
        self.event("listdir", name, tuple(result))
        return result

    def readlink(self, path, *, dir_fd=None):
        name = self.name(path, dir_fd)
        node = self.nodes[name]
        if not stat.S_ISLNK(node.st_mode):
            raise AssertionError("provider fixture readlink requires a link")
        self.event("readlink", name, node.target)
        return node.target

    def realpath(self, path, *, strict=False):
        if strict is not True:
            raise AssertionError("provider link observation requires a strict resolution")
        name = str(path)
        result = self.resolutions.get(name, name)
        if isinstance(result, BaseException):
            raise result
        if stat.S_ISLNK(self.nodes[name].st_mode) and name not in self.resolutions:
            raise AssertionError("provider link fixture needs an explicit canonical target")
        if result not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "synthetic missing canonical target")
        self.event("realpath", name, result)
        return result

    def getxattr(self, fd, attribute):
        name, _node = self.fds[fd]
        self.event("acl", name, attribute)
        if (name, attribute) not in self.acls:
            raise OSError(errno.ENODATA, "synthetic known ACL absence")
        result = self.acls[name, attribute]
        if isinstance(result, BaseException):
            raise result
        return result

    def fchmod(self, fd, mode):
        name, node = self.fds[fd]
        node.st_mode = stat.S_IFMT(node.st_mode) | mode
        node.st_ctime_ns += 1
        self.event("fchmod", name, (fd, mode))

    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("provider descriptor close was retried or never owned")
        name, _node = self.fds.pop(fd)
        self.event("close", name, fd)

    @contextmanager
    def scope(self, module):
        names = ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY")
        api = {name: getattr(os, name) for name in names}
        api.update({name: getattr(self, name) for name in
                    ("lstat", "stat", "open", "fstat", "listdir", "readlink", "getxattr", "fchmod", "close")})
        api.update(getuid=lambda: self.controller_uid, geteuid=lambda: self.controller_euid)
        api["path"] = SimpleNamespace(realpath=self.realpath, normpath=posixpath.normpath,
                                      isabs=posixpath.isabs, join=posixpath.join)
        # An unexpected new OS effect fails attribute lookup rather than reaching
        # shared stdlib APIs or the real provider installation.
        with patch.object(module, "os", SimpleNamespace(**api)), \
             patch.object(module, "time", SimpleNamespace(monotonic=lambda: self.now)), \
             patch.object(module, "sys", SimpleNamespace(platform=self.platform)):
            yield self

    def protect(self, module, prefixes=None, **kwargs):
        arguments = dict(uid=self.uid, gid=self.gid, deadline=self.deadline, report=self.report)
        arguments.update(kwargs)
        with self.scope(module):
            return module.protect_selected_runtimes(
                self.prefixes if prefixes is None else prefixes, **arguments,
            )


class ProviderRuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.module = provider_module()

    def assert_closed_once(self, tree):
        opened = [event[2][0] for event in tree.events if event[0] == "open"]
        closed = [event[2] for event in tree.events if event[0] == "close"]
        self.assertCountEqual(closed, opened)
        self.assertEqual(len(closed), len(set(closed)))
        self.assertEqual(tree.fds, {})

    def test_complete_inventory_precedes_exact_selected_write_bit_changes(self):
        tree = _ProviderTree()
        python = "/synthetic/providers/python/bin/python"
        ruby_bin = "/synthetic/providers/ruby/bin"
        data = "/synthetic/providers/python/data"
        tree.nodes[python].st_mode = stat.S_IFREG | 0o777
        tree.nodes[ruby_bin].st_mode = stat.S_IFDIR | 0o3777
        tree.nodes[ruby_bin].st_gid = tree.gid
        tree.add(data, mode=0o6646)
        tree.nodes["/synthetic/providers/jdk/bin/java"].st_nlink = 2
        tree.add("/synthetic/providers/unselected-version", kind=stat.S_IFDIR, mode=0o777)
        tree.add("/synthetic/providers/unselected-version/tool", mode=0o777)
        original = {path: vars(node).copy() for path, node in tree.nodes.items()}

        tree.protect(self.module)

        self.assertTrue(tree.report["ok"])
        self.assertEqual(tree.report["phase"], "complete")
        expected = {python: 0o775, ruby_bin: 0o3755, data: 0o6644}
        changed = {path: detail[1] for operation, path, detail in tree.events if operation == "fchmod"}
        self.assertEqual(changed, expected)
        first_change = next(i for i, event in enumerate(tree.events) if event[0] == "fchmod")
        earlier = tree.events[:first_change]
        for _role, prefix in tree.prefixes:
            for path in original:
                if path == str(prefix) or path.startswith(str(prefix) + "/"):
                    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
                        self.assertIn(("acl", path, attribute), earlier)
            self.assertTrue(any(event[:2] == ("listdir", str(prefix / "bin")) for event in earlier))
        for path, node in tree.nodes.items():
            before = original[path]
            self.assertEqual(stat.S_IMODE(node.st_mode), expected.get(path, stat.S_IMODE(before["st_mode"])))
            for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "content"):
                self.assertEqual(getattr(node, field), before[field], (path, field))
        self.assertEqual(tree.report["inventoried"], 10)
        for field in ("planned", "attempted", "confirmed"):
            self.assertEqual(tree.report[field], 3)
            self.assertEqual({role: row[field] for role, row in tree.report["roles"].items()},
                             {"python": 2, "ruby": 1, "jdk": 0})
        self.assertEqual(tree.report["errors"], 0)
        self.assert_closed_once(tree)

    def test_late_invalid_node_prevents_every_previously_planned_change(self):
        for case in ("subject-owner", "special", "hardlink"):
            with self.subTest(case=case):
                tree = _ProviderTree()
                tree.nodes["/synthetic/providers/python/bin/python"].st_mode = stat.S_IFREG | 0o777
                late = "/synthetic/providers/jdk/zz-late-node"
                node = tree.add(late)
                if case == "subject-owner":
                    node.st_uid = tree.uid
                elif case == "special":
                    node.st_mode = stat.S_IFIFO | 0o644
                elif case == "hardlink":
                    node.st_mode, node.st_nlink = stat.S_IFREG | 0o777, 2
                before = {path: metadata.st_mode for path, metadata in tree.nodes.items()}
                with self.assertRaises(self.module.ProviderRuntimeError):
                    tree.protect(self.module)
                self.assertFalse(tree.report["ok"])
                self.assertEqual(tree.report["condition"], {"subject-owner": "subject-owned",
                    "special": "unsupported-node", "hardlink": "modified-file-has-links"}[case])
                self.assertEqual(tree.report["role"], "jdk")
                self.assertEqual((tree.report["attempted"], tree.report["confirmed"], tree.report["errors"]), (0, 0, 1))
                self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                self.assertEqual({path: metadata.st_mode for path, metadata in tree.nodes.items()}, before)
                self.assert_closed_once(tree)

    def test_internal_links_use_inventoried_nodes_and_external_files_are_never_mutated(self):
        tree = _ProviderTree()
        python = "/synthetic/providers/python/bin/python"
        tree.nodes[python].st_mode = stat.S_IFREG | 0o777
        tree.add("/synthetic/external", kind=stat.S_IFDIR)
        external = "/synthetic/external/provider-library.so"
        tree.add(external, mode=0o644, nlink=2)
        links = (("/synthetic/providers/python/python-alias", "bin/python", python),
                 ("/synthetic/providers/ruby/bin-alias", "bin", "/synthetic/providers/ruby/bin"),
                 ("/synthetic/providers/jdk/external.so", external, external))
        for name, text, resolved in links:
            tree.add(name, kind=stat.S_IFLNK, mode=0o777, target=text)
            tree.resolutions[name] = resolved
        original_external = vars(tree.nodes[external]).copy()

        tree.protect(self.module)

        self.assertTrue(tree.report["ok"])
        self.assertEqual([(path, detail[1]) for operation, path, detail in tree.events if operation == "fchmod"],
                         [(python, 0o775)])
        self.assertEqual(vars(tree.nodes[external]), original_external)
        for name, text, resolved in links:
            self.assertEqual(tree.nodes[name].target, text)
            self.assertTrue(stat.S_ISLNK(tree.nodes[name].st_mode))
            self.assertEqual(stat.S_IMODE(tree.nodes[name].st_mode), 0o777)
            self.assertIn(("realpath", name, resolved), tree.events)
            self.assertFalse(any(event[:2] == ("listdir", name) for event in tree.events))
        for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
            self.assertIn(("acl", external, attribute), tree.events)
        self.assertFalse(any(event[:2] == ("listdir", "/synthetic/external") for event in tree.events))
        self.assert_closed_once(tree)

    def test_acl_absence_requires_enodata_on_unchanged_and_external_authority_nodes(self):
        for target_kind in ("unchanged", "external"):
            for attribute, result, condition in (
                ("system.posix_acl_access", b"", "acl-present"),
                ("system.posix_acl_default", b"synthetic-unsupported-acl", "acl-present"),
                ("system.posix_acl_access", OSError(errno.EACCES, "synthetic ACL permission unknown"), "acl-unknown"),
                ("system.posix_acl_default", OSError(errno.ENOTSUP, "synthetic ACL support unknown"), "acl-unknown"),
            ):
                with self.subTest(target=target_kind, attribute=attribute, condition=condition):
                    tree = _ProviderTree()
                    python = "/synthetic/providers/python/bin/python"
                    tree.nodes[python].st_mode = stat.S_IFREG | 0o777
                    if target_kind == "unchanged":
                        target = "/synthetic/providers/jdk/bin/java"
                    else:
                        tree.add("/synthetic/external", kind=stat.S_IFDIR)
                        target = "/synthetic/external/library.so"
                        tree.add(target, mode=0o644)
                        link = "/synthetic/providers/jdk/external.so"
                        tree.add(link, kind=stat.S_IFLNK, target=target)
                        tree.resolutions[link] = target
                    tree.acls[target, attribute] = result
                    expected_type = OSError if isinstance(result, OSError) else self.module.ProviderRuntimeError
                    with self.assertRaises(expected_type) as caught:
                        tree.protect(self.module)
                    if isinstance(result, OSError):
                        self.assertIs(caught.exception, result)
                    self.assertEqual(tree.report["condition"], condition)
                    self.assertIn(("acl", target, attribute), tree.events)
                    self.assertFalse(tree.report["ok"])
                    self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                    self.assertEqual(stat.S_IMODE(tree.nodes[python].st_mode), 0o777)
                    self.assert_closed_once(tree)

    def test_unsupported_external_links_fail_before_any_internal_permission_change(self):
        for case, condition in (("directory", "external-target-not-regular"),
                                ("writable", "external-target-writable"),
                                ("subject-owned", "subject-owned"),
                                ("dangling", "link-resolution")):
            with self.subTest(case=case):
                tree = _ProviderTree()
                tree.nodes["/synthetic/providers/python/bin/python"].st_mode = stat.S_IFREG | 0o777
                tree.add("/synthetic/external", kind=stat.S_IFDIR)
                target = "/synthetic/external/provider-target"
                node = tree.add(target, kind=stat.S_IFDIR if case == "directory" else stat.S_IFREG)
                if case == "writable":
                    node.st_mode |= 0o002
                elif case == "subject-owned":
                    node.st_uid = tree.uid
                link = "/synthetic/providers/jdk/link"
                tree.add(link, kind=stat.S_IFLNK, mode=0o777, target=target)
                resolution_error = FileNotFoundError(errno.ENOENT, "synthetic dangling provider link")
                tree.resolutions[link] = resolution_error if case == "dangling" else target
                expected_type = FileNotFoundError if case == "dangling" else self.module.ProviderRuntimeError
                with self.assertRaises(expected_type) as caught:
                    tree.protect(self.module)
                if case == "dangling":
                    self.assertIs(caught.exception, resolution_error)
                self.assertEqual(tree.report["condition"], condition)
                self.assertFalse(tree.report["ok"])
                self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                self.assertFalse(any(event[:2] == ("listdir", target) for event in tree.events))
                self.assert_closed_once(tree)

    def test_reopened_node_identity_mode_and_acl_drift_prevent_mutation(self):
        for field in ("st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "acl"):
            with self.subTest(field=field):
                tree = _ProviderTree()
                target = "/synthetic/providers/python/bin/python"
                node = tree.nodes[target]
                node.st_mode = stat.S_IFREG | 0o777
                opens = 0

                def change_after_inventory(operation, path, _detail):
                    nonlocal opens
                    if operation == "open" and path == target:
                        opens += 1
                        if opens == 2:
                            if field == "acl":
                                tree.acls[target, "system.posix_acl_access"] = b"new-acl"
                            else:
                                setattr(node, field, getattr(node, field) + 1)

                tree.after = change_after_inventory
                with self.assertRaises(self.module.ProviderRuntimeError):
                    tree.protect(self.module)
                self.assertEqual(opens, 2)
                self.assertEqual(tree.report["condition"], "acl-present" if field == "acl" else "identity-or-metadata-drift")
                self.assertFalse(tree.report["ok"])
                self.assertEqual((tree.report["attempted"], tree.report["confirmed"]), (0, 0))
                self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                self.assert_closed_once(tree)

    def test_original_deadline_covers_inventory_mutation_and_final_descriptor_closes(self):
        for phase in ("before-inventory", "after-open", "inventory", "after-change", "final-close"):
            with self.subTest(phase=phase):
                tree = _ProviderTree()
                target = "/synthetic/providers/python/bin/python"
                tree.nodes[target].st_mode = stat.S_IFREG | 0o777
                if phase == "before-inventory":
                    tree.now = tree.deadline

                def expire(operation, path, detail):
                    if ((phase == "inventory" and operation == "acl" and path == target
                         and detail == "system.posix_acl_default")
                            or (phase == "after-open" and operation == "open"
                                and path == "/synthetic/providers/python")
                            or (phase == "after-change" and operation == "fchmod")
                            or (phase == "final-close" and operation == "close"
                                and tree.report["phase"] == "descriptor-close")):
                        tree.now = tree.deadline

                tree.after = expire
                with self.assertRaises((self.module.ProviderRuntimeError, BaseExceptionGroup)) as caught:
                    tree.protect(self.module)
                self.assertTrue(all(isinstance(error, self.module.ProviderRuntimeError) and str(error) == "deadline"
                                    for error in _leaves(caught.exception)))
                self.assertEqual(tree.report["condition"], "deadline")
                self.assertFalse(tree.report["ok"])
                self.assertEqual(tree.deadline, 10.0)
                self.assertEqual(tree.report["attempted"], int(phase in {"after-change", "final-close"}))
                self.assertEqual(tree.report["confirmed"], int(phase == "final-close"))
                if phase in {"before-inventory", "after-open", "inventory"}:
                    self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                if phase == "before-inventory":
                    self.assertEqual(tree.events, [])
                self.assert_closed_once(tree)

    def test_partial_fchmod_aftereffects_and_independent_close_errors_are_retained(self):
        for primary in (OSError(errno.EIO, "synthetic-private-provider-detail"), KeyboardInterrupt("synthetic interruption")):
            with self.subTest(primary=type(primary).__name__):
                tree = _ProviderTree()
                target = "/synthetic/providers/python/bin/python"
                later = "/synthetic/providers/ruby/bin/ruby"
                tree.nodes[target].st_mode = tree.nodes[later].st_mode = stat.S_IFREG | 0o777
                child_close = OSError(errno.EIO, "synthetic child descriptor close")
                root_close = OSError(errno.EIO, "synthetic prefix descriptor close")
                changed = False

                def fault(operation, path, _detail):
                    nonlocal changed
                    if operation == "fchmod" and path == target:
                        changed = True
                        raise primary
                    if changed and operation == "close":
                        if path == target:
                            raise child_close
                        if path == "/synthetic/providers/ruby":
                            raise root_close

                tree.after = fault
                with self.assertRaises(BaseExceptionGroup) as caught:
                    tree.protect(self.module)
                self.assertEqual(_leaves(caught.exception), [primary, child_close, root_close])
                self.assertEqual(tree.report["condition"], "chmod")
                self.assertEqual((tree.report["planned"], tree.report["attempted"], tree.report["confirmed"], tree.report["errors"]),
                                 (2, 1, 0, 3))
                self.assertEqual(tree.report["roles"]["python"]["attempted"], 1)
                self.assertEqual(tree.report["roles"]["ruby"]["attempted"], 0)
                self.assertEqual(stat.S_IMODE(tree.nodes[target].st_mode), 0o775)
                self.assertEqual(stat.S_IMODE(tree.nodes[later].st_mode), 0o777)
                self.assertEqual(sum(event[0] == "fchmod" for event in tree.events), 1)
                self.assertFalse(tree.report["ok"])
                self.assertNotIn("synthetic-private-provider-detail", repr(tree.report))
                self.assert_closed_once(tree)

    def test_verification_and_descriptor_close_failures_never_publish_success(self):
        for case in ("mode-aftereffect", "owner-aftereffect", "inventory-close", "child-close", "root-close"):
            with self.subTest(case=case):
                tree = _ProviderTree()
                target = "/synthetic/providers/python/bin/python"
                node = tree.nodes[target]
                node.st_mode = stat.S_IFREG | 0o777
                close_error = OSError(errno.EIO, "synthetic verified-change close failure")
                changed = False

                def fault(operation, path, _detail):
                    nonlocal changed
                    if case == "inventory-close" and operation == "close" and path == target:
                        raise close_error
                    if operation == "fchmod" and path == target:
                        changed = True
                        if case == "mode-aftereffect":
                            node.st_mode = stat.S_IFREG | 0o777  # A successful return without the required effect.
                        elif case == "owner-aftereffect":
                            node.st_uid += 1
                    if changed and operation == "close":
                        if (case == "child-close" and path == target
                                or case == "root-close" and path == "/synthetic/providers/python"):
                            raise close_error

                tree.after = fault
                expected_type = self.module.ProviderRuntimeError if case.endswith("aftereffect") else OSError
                with self.assertRaises(expected_type) as caught:
                    tree.protect(self.module)
                if not case.endswith("aftereffect"):
                    self.assertIs(caught.exception, close_error)
                self.assertEqual(tree.report["condition"], "chmod-aftereffect" if case.endswith("aftereffect") else "descriptor-close")
                self.assertEqual((tree.report["attempted"], tree.report["confirmed"], tree.report["errors"]),
                                 (int(case != "inventory-close"), int(case in {"child-close", "root-close"}), 1))
                self.assertFalse(tree.report["ok"])
                self.assertEqual(sum(event[0] == "fchmod" for event in tree.events), int(case != "inventory-close"))
                self.assert_closed_once(tree)

    def test_final_recheck_rejects_prefix_membership_link_and_external_drift(self):
        for case, condition in (("prefix-path", "prefix-path-drift"),
                                ("unchanged-file", "identity-or-metadata-drift"),
                                ("membership", "directory-membership-drift"),
                                ("link-text", "link-drift"),
                                ("link-target", "link-target-drift"),
                                ("external-file", "external-target-drift")):
            with self.subTest(case=case):
                tree = _ProviderTree()
                python = "/synthetic/providers/python/bin/python"
                tree.nodes[python].st_mode = stat.S_IFREG | 0o777
                internal_link = "/synthetic/providers/ruby/alias"
                internal_target = "/synthetic/providers/ruby/bin/ruby"
                tree.add(internal_link, kind=stat.S_IFLNK, target="bin/ruby")
                tree.resolutions[internal_link] = internal_target
                tree.add("/synthetic/external", kind=stat.S_IFDIR)
                external = "/synthetic/external/library.so"
                tree.add(external, mode=0o644)
                external_link = "/synthetic/providers/jdk/external.so"
                tree.add(external_link, kind=stat.S_IFLNK, target=external)
                tree.resolutions[external_link] = external

                def drift(operation, path, _detail):
                    if operation != "fchmod" or path != python:
                        return
                    if case == "prefix-path":
                        prefix = "/synthetic/providers/python"
                        replacement = SimpleNamespace(**vars(tree.nodes[prefix]))
                        replacement.st_ino += 1000
                        tree.nodes[prefix] = replacement
                    elif case == "unchanged-file":
                        tree.nodes["/synthetic/providers/jdk/bin/java"].st_mode |= 0o002
                    elif case == "membership":
                        tree.add("/synthetic/providers/jdk/new-uninventoried-file", mode=0o777)
                    elif case == "link-text":
                        tree.nodes[internal_link].target = "different"
                    elif case == "link-target":
                        tree.resolutions[internal_link] = external
                    elif case == "external-file":
                        tree.nodes[external].st_mtime_ns += 1

                tree.after = drift
                with self.assertRaises(self.module.ProviderRuntimeError):
                    tree.protect(self.module)
                self.assertEqual(tree.report["condition"], condition)
                self.assertEqual(tree.report["phase"], "recheck")
                self.assertEqual((tree.report["attempted"], tree.report["confirmed"]), (1, 1))
                self.assertEqual(stat.S_IMODE(tree.nodes[python].st_mode), 0o775)
                self.assertFalse(tree.report["ok"])
                self.assert_closed_once(tree)

    def test_role_scope_identity_and_finite_deadline_are_checked_before_metadata(self):
        for case, condition in (("roles", "prefix-roles"), ("overlap", "prefix-overlap"),
                                ("parent", "prefix-shape"), ("relative", "prefix-shape"),
                                ("traversal", "prefix-shape"), ("nonroot", "root-linux-identity-or-deadline"),
                                ("subject-group", "root-linux-identity-or-deadline"),
                                ("infinite", "root-linux-identity-or-deadline"),
                                ("boolean-time", "root-linux-identity-or-deadline")):
            with self.subTest(case=case):
                tree = _ProviderTree()
                prefixes, arguments = list(tree.prefixes), {}
                if case == "roles":
                    prefixes[0] = ("unselected", prefixes[0][1])
                elif case == "overlap":
                    prefixes[1] = ("ruby", prefixes[0][1] / "nested")
                elif case in {"parent", "relative", "traversal"}:
                    prefixes[0] = ("python", {"parent": "/opt", "relative": "relative/python",
                                               "traversal": "/synthetic/providers/python/../other"}[case])
                elif case == "nonroot":
                    tree.controller_uid = 1001
                elif case == "subject-group":
                    arguments["gid"] = tree.gid + 1
                else:
                    arguments["deadline"] = float("inf") if case == "infinite" else True
                with self.assertRaises(self.module.ProviderRuntimeError):
                    tree.protect(self.module, prefixes=prefixes, **arguments)
                self.assertEqual(tree.report["condition"], condition)
                self.assertFalse(tree.report["ok"])
                self.assertEqual(tree.events, [])
                self.assert_closed_once(tree)

    def test_inventory_depth_and_descriptor_bounds_fail_before_permission_changes(self):
        for constant, limit, condition in (("MAX_NODES", 5, "inventory-bound"),
                                            ("MAX_DEPTH", 4, "path-depth-or-length"),
                                            ("MAX_OPEN", 2, "descriptor-bound")):
            with self.subTest(bound=constant):
                tree = _ProviderTree()
                tree.nodes["/synthetic/providers/python/bin/python"].st_mode = stat.S_IFREG | 0o777
                if constant == "MAX_DEPTH":
                    path = Path("/synthetic/providers/jdk")
                    for component in ("a", "b", "c", "d", "e"):
                        path /= component
                        tree.add(path, kind=stat.S_IFDIR)
                with patch.object(self.module, constant, limit), self.assertRaises(self.module.ProviderRuntimeError):
                    tree.protect(self.module)
                self.assertEqual(tree.report["condition"], condition)
                self.assertFalse(tree.report["ok"])
                self.assertEqual((tree.report["attempted"], tree.report["confirmed"]), (0, 0))
                self.assertFalse(any(event[0] == "fchmod" for event in tree.events))
                self.assert_closed_once(tree)
