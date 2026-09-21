"""Actual workflow Python over inert OS metadata; no real permission changes."""
from contextlib import redirect_stdout
import ast
import builtins
import errno
import io
import json
import os
from pathlib import Path
import re
import stat
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/desktop-ubuntu-publication.yml"
BYOBU_ICON = "/usr/share/byobu/pixmaps/byobu.svg"
PREPARE = (
    "/usr/share", "/etc/gtk-3.0", "/etc/fonts", "/etc/fonts/conf.d",
    "/usr/share/fontconfig", "/usr/share/fontconfig/conf.avail", "/usr/share/fonts",
    "/usr/local/share/fonts", "/var/cache/fontconfig",
    "/usr/share/glib-2.0", "/usr/share/glib-2.0/schemas",
    "/usr/share/glvnd", "/usr/share/glvnd/egl_vendor.d", "/etc/glvnd", "/etc/glvnd/egl_vendor.d",
    "/usr/share/drirc.d", "/usr/share/X11", "/usr/share/X11/xkb", "/usr/share/X11/locale",
    "/usr/share/icons", "/usr/share/icons/Adwaita", "/usr/share/icons/hicolor",
    "/usr/share/themes", "/usr/share/themes/Adwaita", "/usr/share/mime",
    "/usr/share/hunspell", "/usr/share/hyphen",
    "/usr/share/byobu", "/usr/share/byobu/pixmaps",
)
DATA = (
    "/etc/gtk-3.0", "/etc/fonts", "/usr/share/fontconfig", "/usr/share/fonts",
    "/usr/local/share/fonts", "/var/cache/fontconfig", "/usr/share/glib-2.0/schemas",
    "/usr/share/glvnd/egl_vendor.d", "/etc/glvnd/egl_vendor.d", "/usr/share/drirc.d", "/etc/drirc",
    "/usr/share/X11/xkb", "/usr/share/X11/locale", "/usr/share/icons/Adwaita",
    "/usr/share/icons/hicolor", "/usr/share/themes/Adwaita", "/usr/share/mime/mime.cache",
    "/usr/share/hunspell", "/usr/share/hyphen",
    "/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache",
    "/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache",
    "/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache",
    BYOBU_ICON,
)
FILES = {"/etc/drirc", "/usr/share/mime/mime.cache", BYOBU_ICON,
         "/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache",
         "/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache",
         "/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache"}
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
META_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
ACCESS_ACL = "system.posix_acl_access"
DEFAULT_ACL = "system.posix_acl_default"
FILE_CAPABILITY = "security.capability"
PREPARER_MARKER = ("          sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent "
                   "/usr/bin/python3.12 -I -S -B - <<'PY'\n")


class DirectoryMetadataOS:
    """Held FDs refer to original nodes, independently of later name replacement."""
    def __init__(self):
        self.sequence, self.next_fd, self.peak = 0, 10, 0
        self.root = self.make("/", stat.S_IFDIR | 0o755)
        self.live, self.fd_flags, self.calls, self.listings = {}, {}, {}, {}
        self.opened, self.open_attempts, self.closed, self.reads, self.chmods = [], [], [], [], []
        self.chowns, self.open_details, self.attempt_details, self.close_details, self.link_reads = [], [], [], [], []
        self.xattr_calls = []
        self.hook = None
        self.uids = self.gids = (0, 0, 0)
        self.mount_raw = b"1 2 0:1 / / rw,relatime - ext4 /dev/mock rw\n"
        self.mount_reads, self.mount_closes = 0, 0
        for path in PREPARE:
            self.add(path)
        for path in DATA:
            self.add(path, stat.S_IFREG | 0o444 if path in FILES else stat.S_IFDIR | 0o755)

    def make(self, path, mode, uid=0, gid=0):
        self.sequence += 1
        return SimpleNamespace(path=path, st_dev=1, st_ino=self.sequence, st_mode=mode,
                               st_uid=uid, st_gid=gid, st_nlink=2 if stat.S_ISDIR(mode) else 1,
                               st_size=0, st_mtime_ns=1, st_ctime_ns=1, children={}, target=None, xattrs={})

    def node(self, path):
        node = self.root
        for part in path.strip("/").split("/") if path != "/" else ():
            node = node.children[part]
        return node

    def add(self, path, mode=stat.S_IFDIR | 0o755, uid=0, gid=0):
        parent, current = self.root, ""
        parts = path.strip("/").split("/")
        for part in parts[:-1]:
            current += "/" + part
            parent = parent.children.setdefault(part, self.make(current, stat.S_IFDIR | 0o755))
        node = self.make(path, mode, uid, gid)
        if parts[-1] in parent.children:
            node.children = parent.children[parts[-1]].children
        parent.children[parts[-1]] = node
        return node

    def remove(self, path):
        parent, name = path.rsplit("/", 1)
        del self.node(parent or "/").children[name]

    def link(self, path, target, uid=0, gid=0):
        node = self.add(path, stat.S_IFLNK | 0o777, uid, gid)
        node.target, node.st_size = target, len(target.encode("utf-8"))
        return node

    def call(self, operation, path):
        key = operation, path
        self.calls[key] = self.calls.get(key, 0) + 1
        if self.hook is not None:
            self.hook(operation, path, self.calls[key])

    def selected(self, name, parent):
        if parent is None:
            if name != "/":
                raise AssertionError("Only the literal root may use an absolute OS path")
            return self.root
        if type(name) is not str or not name or "/" in name or name in {".", ".."}:
            raise AssertionError("Expected one original-parent-relative name")
        try:
            return self.live[parent].children[name]
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, "Absent mock entry") from None

    def path(self, name, parent):
        return "/" if parent is None else self.live[parent].path.rstrip("/") + "/" + name

    def open(self, name, flags, *, dir_fd=None):
        if flags not in (FLAGS, FILE_FLAGS, META_FLAGS):
            raise AssertionError("Only exact directory/regular or O_PATH no-follow flags are admitted")
        if flags == META_FLAGS and dir_fd is None and self.live:
            raise AssertionError("Every previous selection's originals must close before the next root opens")
        path = self.path(name, dir_fd)
        self.open_attempts.append(path)
        self.attempt_details.append((path, flags))
        self.call("open", path)
        node = self.selected(name, dir_fd)
        if flags != META_FLAGS and not (stat.S_ISDIR(node.st_mode) if flags == FLAGS else stat.S_ISREG(node.st_mode)):
            raise OSError(errno.ELOOP if stat.S_ISLNK(node.st_mode) else errno.ENOTDIR, "Not a direct mock directory")
        fd = self.next_fd
        self.next_fd += 1
        self.live[fd] = node
        self.fd_flags[fd] = flags
        self.opened.append(fd)
        self.open_details.append((path, flags, node.st_ino))
        self.peak = max(self.peak, len(self.live))
        return fd

    @staticmethod
    def snapshot(node):
        return SimpleNamespace(**{key: getattr(node, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                                                                     "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})

    def fstat(self, fd):
        node = self.live[fd]
        self.call("fstat", node.path)
        return self.snapshot(node)

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        if follow_symlinks is not False:
            raise AssertionError("Metadata must not follow a link")
        self.call("stat", self.path(name, dir_fd))
        return self.snapshot(self.selected(name, dir_fd))

    def listdir(self, fd):
        if type(fd) is not int or fd not in self.live or self.fd_flags[fd] != FLAGS:
            raise AssertionError("Directory membership must use an original ordinary directory FD")
        node = self.live[fd]
        self.call("listdir", node.path)
        self.reads.append((node.path, node.st_ino))
        return list(self.listings.get(node.path, node.children))

    def readlink(self, name, *, dir_fd=None):
        # Linux readlinkat's empty pathname observes the retained O_PATH link
        # itself, not a newly selected name in a possibly writable directory.
        if name != "" or dir_fd not in self.live or self.fd_flags[dir_fd] != META_FLAGS:
            raise AssertionError("Link text must use the original O_PATH no-follow FD")
        node = self.live[dir_fd]
        if not stat.S_ISLNK(node.st_mode) or type(node.target) is not str:
            raise AssertionError("A selected inert link needs its truthful target")
        self.call("readlink", node.path)
        self.link_reads.append((dir_fd, node.path, node.st_ino, node.target))
        return node.target

    def getxattr(self, fd, attribute):
        # O_PATH cannot service fgetxattr. Reopening must retain the original
        # ordinary object, not query a pathname or follow a selected symlink.
        if type(fd) is not int or fd not in self.live or self.fd_flags[fd] not in (FLAGS, FILE_FLAGS):
            raise AssertionError("Guarded attributes require an original ordinary no-follow FD")
        node = self.live[fd]
        expected = (ACCESS_ACL, DEFAULT_ACL if stat.S_ISDIR(node.st_mode) else FILE_CAPABILITY)
        if attribute not in expected:
            raise AssertionError("Only the two kind-specific guarded names may be queried")
        self.xattr_calls.append((fd, node.path, node.st_ino, attribute, self.fd_flags[fd]))
        self.call("getxattr", node.path)
        if attribute not in node.xattrs:
            raise OSError(errno.ENODATA, "Mock absent guarded attribute")
        value = node.xattrs[attribute]
        if isinstance(value, BaseException):
            raise value
        return value

    def fchmod(self, fd, mode):
        if self.fd_flags[fd] == META_FLAGS:
            raise AssertionError("Diagnostic metadata originals never authorize effects")
        node = self.live[fd]
        self.call("fchmod", node.path)
        self.chmods.append((node.path, node.st_ino, mode))
        node.st_mode = stat.S_IFMT(node.st_mode) | mode
        node.st_ctime_ns += 1

    def fchown(self, fd, uid, gid):
        if self.fd_flags[fd] == META_FLAGS:
            raise AssertionError("Diagnostic metadata originals never authorize effects")
        node = self.live[fd]
        self.call("fchown", node.path)
        if (uid, gid) != (-1, 0):
            raise AssertionError("Only the fixed group normalization is admitted")
        self.chowns.append((node.path, node.st_ino, uid, gid))
        node.st_gid = gid
        node.st_ctime_ns += 1

    def open_mounts(self, path, mode):
        if path != "/proc/self/mountinfo" or mode != "rb":
            raise AssertionError("Only literal bounded kernel mount metadata may be read")
        self.mount_reads += 1
        self.call("mount-read", path)
        parent = self

        class MountReader(io.BytesIO):
            def read(self, size=-1):
                if size != (1 << 20) + 1:
                    raise AssertionError("Mount read must retain the exact original bound")
                return super().read(size)

            def close(self):
                if not self.closed:
                    parent.mount_closes += 1
                    parent.call("mount-close", path)
                super().close()

        return MountReader(self.mount_raw)

    def close(self, fd):
        # A failed mocked close is not successful-close evidence. Record the
        # sole attempt and reject the run; do not retry this numeric identity.
        node = self.live.pop(fd)
        self.close_details.append((node.path, self.fd_flags.pop(fd), node.st_ino))
        self.closed.append(fd)
        self.call("close", node.path)


class ShellDirectoryPreparationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = WORKFLOW.read_bytes()
        if len(raw) > 128 << 10:
            raise AssertionError("Workflow source exceeds this DATA read bound")
        blocks = [textwrap.dedent(part.split("          PY\n", 1)[0]) for part in raw.decode("utf-8").split(PREPARER_MARKER)[1:]]
        if len(blocks) != 2 or blocks[0] != blocks[1]:
            raise AssertionError("Compiler/native directory-preparation bodies must be identical")
        cls.inline = blocks[0]

    def run_inline(self, filesystem):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("Unexpected content or mutation API")

        namespace, output, error = {"__name__": "workflow_directory_preparation"}, io.StringIO(), None
        replacements = {name: forbidden for name in ("lstat", "read", "write", "chmod", "chown", "fchown",
                                                     "mkdir", "rmdir", "unlink", "rename", "symlink", "listxattr", "setxattr", "removexattr")}
        replacements.update({name: getattr(filesystem, name) for name in ("open", "stat", "fstat", "listdir", "readlink", "getxattr", "fchmod", "fchown", "close")})
        replacements.update(getresuid=lambda: filesystem.uids, getresgid=lambda: filesystem.gids)
        with patch.multiple(os, **replacements), patch.object(builtins, "open", filesystem.open_mounts), redirect_stdout(output):
            try:
                # Execute the actual inline imports and top-level entry, not
                # selected AST functions with a fabricated dependency namespace.
                exec(compile(self.inline, str(WORKFLOW) + ":directory-preparation", "exec"), namespace)
            except BaseException as caught:
                error = caught
        self.assertEqual(filesystem.live, {})
        self.assertEqual(filesystem.fd_flags, {})
        self.assertEqual(sorted(filesystem.closed), filesystem.opened)
        self.assertLessEqual(filesystem.peak, 24)
        self.assertEqual(filesystem.mount_reads, filesystem.mount_closes)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        return namespace, rows, error

    def refused(self, result):
        _, rows, error = result
        self.assertIsInstance(error, (SystemExit, OSError))
        if isinstance(error, SystemExit):
            self.assertEqual(error.code, 70)
        self.assertFalse(any(row.get("runtimeAdmission") is True for row in rows))
        return rows

    def closure(self, result, *, refused=False):
        _, rows, error = result
        if refused:
            self.refused(result)
        else:
            self.assertIsNone(error)
        found = [(index, row) for index, row in enumerate(rows) if row.get("scope") == "fixed-shell-data-link-closure"]
        self.assertEqual(len(found), 1)
        index, diagnostic = found[0]
        self.assertGreater(index, 0)
        self.assertEqual(rows[index - 1]["scope"], "fixed-shell-data-directory-preparation")
        self.assertIn("metadata", rows[index - 1])
        self.assertEqual(set(diagnostic), {"scope", "runtimeAdmission", "selectedCount", "examinedCount", "externalCount",
                                           "unsafeCount", "complete", "safe", "truncated", "records", "nodes", "globalError"})
        self.assertIs(diagnostic["runtimeAdmission"], False)
        for key in ("selectedCount", "examinedCount", "externalCount", "unsafeCount"):
            self.assertIs(type(diagnostic[key]), int)
            self.assertGreaterEqual(diagnostic[key], 0)
        for key in ("complete", "safe", "truncated"):
            self.assertIs(type(diagnostic[key]), bool)
        self.assertLessEqual(diagnostic["examinedCount"], diagnostic["selectedCount"])
        self.assertIsInstance(diagnostic["records"], list)
        self.assertIsInstance(diagnostic["nodes"], dict)
        self.assertLessEqual(len(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode("ascii")), 65536)
        if diagnostic["complete"]:
            self.assertEqual(diagnostic["examinedCount"], diagnostic["selectedCount"])
            self.assertFalse(diagnostic["truncated"])
            self.assertIsNone(diagnostic["globalError"])
        if diagnostic["globalError"] is not None:
            self.assertRegex(diagnostic["globalError"], r"^[a-z][a-z0-9-]{0,63}$")
            self.assertFalse(diagnostic["complete"])
        if diagnostic["safe"]:
            self.assertTrue(diagnostic["complete"])
            self.assertEqual(diagnostic["unsafeCount"], 0)
        if refused:
            self.assertFalse(diagnostic["safe"])
            self.assertEqual(rows[-1]["failedCheck"], "unhandled-data-link-closure")
            self.assertGreater(len(rows) - 1, index)
        for row in diagnostic["records"]:
            self.assertEqual(set(row), {"selectedPath", "terminalPath", "links", "externalPaths", "unsafePaths", "error", "cleanupUnknown", "authorityFailure"})
            self.assertIs(type(row["cleanupUnknown"]), bool)
            self.assertIsInstance(row["selectedPath"], str)
            self.assertTrue(row["terminalPath"] is None or isinstance(row["terminalPath"], str))
            if row["error"] is not None:
                self.assertRegex(row["error"], r"^[a-z][a-z0-9-]{0,63}$")
                self.assertFalse(diagnostic["complete"])
            if row["authorityFailure"] is not None:
                self.assertEqual(row["error"], "guarded-xattr")
                self.authority_failure(row["authorityFailure"])
            if row["error"] is not None or row["cleanupUnknown"]:
                self.assertTrue(all(target == "<redacted>" for _, target in row["links"]))
            self.assertLessEqual(len(row["links"]), 40)
            for link in row["links"]:
                self.assertIsInstance(link, list)
                self.assertEqual(len(link), 2)
                self.assertTrue(all(isinstance(value, str) for value in link))
                self.assertLessEqual(len(link[1].encode("utf-8")), 4096)
            for key in ("externalPaths", "unsafePaths"):
                self.assertEqual(row[key], sorted(set(row[key])))
                self.assertTrue(set(row[key]) <= diagnostic["nodes"].keys())
        for path, row in diagnostic["nodes"].items():
            self.assertTrue(path.startswith("/") and ".." not in path.split("/"))
            self.assertEqual(set(row), {"dev", "ino", "uid", "gid", "mode", "nlink", "size"})
            self.assertRegex(row["mode"], r"^[0-7]{6}$")
            self.assertTrue(all(type(value) is int for key, value in row.items() if key != "mode"))
        return diagnostic

    def metadata_only_under(self, filesystem, prefix):
        within = lambda path: path == prefix or path.startswith(prefix + "/")
        self.assertTrue(all(flags in (META_FLAGS, FLAGS, FILE_FLAGS)
                            for path, flags in filesystem.attempt_details if within(path)))
        # A raced ordinary reopen may be refused before its first query. Every
        # attempted reopen still needs a held path; every query needs the exact
        # original inode, never that rejected replacement.
        held, paths = set(), set()
        for path, flags, inode in filesystem.open_details:
            if not within(path):
                continue
            if flags == META_FLAGS:
                held.add((path, inode))
                paths.add(path)
            else:
                self.assertIn(path, paths)
        for _, path, inode, _, _ in filesystem.xattr_calls:
            if within(path):
                self.assertIn((path, inode), held)
        self.assertFalse(any(within(path) for path, _ in filesystem.reads))
        self.assertFalse(any(within(row[0]) for row in (*filesystem.chmods, *filesystem.chowns)))

    def authority_failure(self, observed):
        self.assertEqual(set(observed), {"path", "pathTruncated", "kind", "attribute", "result", "errno", "original",
                                         "phase", "complete", "truncated", "cleanupUnknown", "bindingUnknown", "probePerformed"})
        self.assertIsInstance(observed["path"], str)
        self.assertIn(observed["kind"], ("directory", "regular"))
        self.assertIn(observed["attribute"], (ACCESS_ACL, DEFAULT_ACL, FILE_CAPABILITY))
        self.assertIn(observed["result"], ("present", "errno", "binding-unproven"))
        self.assertTrue(observed["errno"] is None or type(observed["errno"]) is int)
        if observed["errno"] is not None:
            self.assertGreaterEqual(observed["errno"], 0)
            self.assertLessEqual(observed["errno"], 4095)
        self.assertIn(observed["phase"], ("prepare-before", "prepare-after-group", "prepare-after-mode",
                                          "metadata-census", "metadata-before", "metadata-after", "link-closure"))
        self.assertLessEqual(len(observed["path"]), 512)
        self.assertNotIn("\n", observed["path"])
        self.assertEqual(len(observed["original"]), 9)
        self.assertTrue(all(type(number) is int for number in observed["original"]))
        self.assertIs(observed["complete"], False)
        for key in ("pathTruncated", "truncated", "cleanupUnknown", "bindingUnknown", "probePerformed"):
            self.assertIs(type(observed[key]), bool)
        if observed["pathTruncated"]:
            self.assertTrue(observed["truncated"])
        if observed["result"] in {"present", "errno"}:
            self.assertTrue(observed["probePerformed"])
        else:
            self.assertTrue(observed["bindingUnknown"])
        self.assertLessEqual(len(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("ascii")), 2048)
        return observed

    def test_xattr_queries_use_kind_specific_ordinary_fds_in_census_and_link_targets(self):
        filesystem = DirectoryMetadataOS()
        directory = "/usr/share/fonts/nested"
        regular = directory + "/inert.ttf"
        selected, target = directory + "/alias.ttf", "/opt/mrk-public/face.ttf"
        filesystem.add(directory)
        filesystem.add(regular, stat.S_IFREG | 0o444)
        filesystem.add(target, stat.S_IFREG | 0o444)
        link = filesystem.link(selected, target)
        link.xattrs = {ACCESS_ACL: b"unqueried-link-value", FILE_CAPABILITY: b"unqueried-link-value"}
        outside = "/usr/share/not-selected.ttf"
        filesystem.add(outside, stat.S_IFREG | 0o444).xattrs[ACCESS_ACL] = b"unselected-value"
        diagnostic = self.closure(self.run_inline(filesystem))
        self.assertTrue(diagnostic["complete"] and diagnostic["safe"])
        for path, names, flags in ((directory, {ACCESS_ACL, DEFAULT_ACL}, FLAGS),
                                  (regular, {ACCESS_ACL, FILE_CAPABILITY}, FILE_FLAGS),
                                  ("/opt/mrk-public", {ACCESS_ACL, DEFAULT_ACL}, FLAGS),
                                  (target, {ACCESS_ACL, FILE_CAPABILITY}, FILE_FLAGS)):
            calls = [call for call in filesystem.xattr_calls if call[1] == path]
            self.assertEqual({call[3] for call in calls}, names)
            self.assertEqual({call[4] for call in calls}, {flags})
            self.assertEqual({call[2] for call in calls}, {filesystem.node(path).st_ino})
        self.assertFalse(any(path in {selected, outside} for _, path, _, _, _ in filesystem.xattr_calls))
        self.metadata_only_under(filesystem, "/opt")
        self.assertEqual(filesystem.chmods, [])
        self.assertEqual(filesystem.chowns, [])

    def test_xattr_presence_refuses_before_any_effect_on_the_original(self):
        cases = (("/etc/fonts", ACCESS_ACL, "prepare-before", True),
                 ("/etc/fonts", DEFAULT_ACL, "prepare-before", True),
                 ("/usr/local/share/fonts", ACCESS_ACL, "prepare-before", True),
                 ("/usr/share/fonts/inert.ttf", ACCESS_ACL, "metadata-census", False),
                 ("/usr/share/fonts/inert.ttf", FILE_CAPABILITY, "metadata-census", False))
        for path, attribute, phase, directory in cases:
            for value in (b"", b"never-export-this-attribute-value"):
                filesystem = DirectoryMetadataOS()
                original = filesystem.node(path) if directory else filesystem.add(path, stat.S_IFREG | 0o777)
                if directory:
                    original.st_mode = stat.S_IFDIR | 0o777
                if path == "/usr/local/share/fonts":
                    original.st_mode, original.st_gid = stat.S_IFDIR | 0o2775, 50
                original.xattrs[attribute] = value
                before = vars(filesystem.snapshot(original)).copy()
                with self.subTest(path=path, attribute=attribute, empty=not value):
                    rows = self.refused(self.run_inline(filesystem))
                    self.assertEqual(rows[-1]["failedCheck"], "guarded-xattr")
                    observed = self.authority_failure(rows[-1]["observed"])
                    self.assertEqual((observed["path"], observed["attribute"], observed["phase"]), (path, attribute, phase))
                    self.assertEqual(observed["kind"], "directory" if directory else "regular")
                    self.assertEqual(observed["result"], "present")
                    self.assertIsNone(observed["errno"])
                    self.assertTrue(observed["probePerformed"])
                    self.assertFalse(observed["bindingUnknown"] or observed["cleanupUnknown"] or observed["truncated"])
                    self.assertEqual(observed["original"], list(before.values()))
                    self.assertEqual(vars(filesystem.snapshot(original)), before)
                    self.assertEqual(filesystem.chmods, [])
                    self.assertEqual(filesystem.chowns, [])
                    self.assertNotIn("never-export-this", json.dumps(rows))

    def test_xattr_errno_is_never_absence_or_a_normalizable_condition(self):
        path = "/usr/share/fonts/inert.ttf"
        for number in (errno.EACCES, errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EBADF,
                       errno.ENOENT, errno.EIO, None, -1, 4096):
            filesystem = DirectoryMetadataOS()
            filesystem.add(path, stat.S_IFREG | 0o777).xattrs[ACCESS_ACL] = OSError(number, "private-error-marker")
            with self.subTest(errno=number):
                rows = self.refused(self.run_inline(filesystem))
                self.assertEqual(rows[-1]["failedCheck"], "guarded-xattr")
                observed = self.authority_failure(rows[-1]["observed"])
                self.assertEqual((observed["result"], observed["attribute"]), ("errno", ACCESS_ACL))
                self.assertEqual(observed["errno"], number if type(number) is int and 0 <= number <= 4095 else None)
                self.assertTrue(observed["probePerformed"])
                self.assertFalse(observed["bindingUnknown"] or observed["cleanupUnknown"])
                self.assertEqual([call[3] for call in filesystem.xattr_calls if call[1] == path], [ACCESS_ACL])
                self.assertNotIn("private-error-marker", json.dumps(rows))
                self.assertEqual(filesystem.chmods, [])

    def test_xattr_value_and_path_bounds_keep_typed_refusal_without_value_disclosure(self):
        short = "/usr/share/fonts/inert.ttf"
        long = "/usr/share/fonts/" + "/".join("a" * 200 for _ in range(3)) + "/inert.ttf"
        cases = ((short, b"private-value-marker" + b"x" * (65536 - 20), False),
                 (short, b"private-value-marker" + b"x" * (65537 - 20), True),
                 (short, None, True), (short, "private-value-marker", True), (long, b"", True))
        for path, value, truncated in cases:
            filesystem = DirectoryMetadataOS()
            filesystem.add(path, stat.S_IFREG | 0o444).xattrs[FILE_CAPABILITY] = value
            with self.subTest(path_length=len(path), value_type=type(value).__name__, truncated=truncated):
                rows = self.refused(self.run_inline(filesystem))
                observed = self.authority_failure(rows[-1]["observed"])
                self.assertEqual(observed["result"], "present")
                self.assertEqual(observed["path"], path[:512])
                self.assertEqual(observed["pathTruncated"], len(path) > 512)
                self.assertEqual(observed["truncated"], truncated)
                self.assertTrue(observed["probePerformed"])
                self.assertNotIn("private-value-marker", json.dumps(rows))
                self.assertLessEqual(len(json.dumps(rows[-1], sort_keys=True, separators=(",", ":")).encode("ascii")), 2048)
                self.assertEqual(filesystem.chmods, [])

    def test_xattr_rechecks_between_census_and_effect_and_after_group_or_mode_change(self):
        cases = (("between-passes", "/usr/share/fonts/00-inert.ttf", FILE_CAPABILITY, "metadata-before"),
                 ("prepare-mode", "/etc/fonts", DEFAULT_ACL, "prepare-after-mode"),
                 ("prepare-group", "/usr/local/share/fonts", ACCESS_ACL, "prepare-after-group"),
                 ("metadata-mode", "/usr/share/fonts/00-inert.ttf", FILE_CAPABILITY, "metadata-after"),
                 ("ancestor-before-mode", "/usr/share/fonts/00-inert.ttf", DEFAULT_ACL, "metadata-before"),
                 ("ancestor-after-mode", "/usr/share/fonts/00-inert.ttf", ACCESS_ACL, "metadata-after"))
        for change, path, attribute, phase in cases:
            filesystem = DirectoryMetadataOS()
            directory = change.startswith("prepare-")
            original = filesystem.node(path) if directory else filesystem.add(path, stat.S_IFREG | 0o777)
            if directory:
                original.st_mode = stat.S_IFDIR | 0o777
            if change == "prepare-group":
                original.st_mode, original.st_gid = stat.S_IFDIR | 0o2775, 50
            authority_path = "/usr/share/fonts" if change == "ancestor-before-mode" else "/usr" if change == "ancestor-after-mode" else path
            authority_node = filesystem.node(authority_path)
            following = "/usr/share/fonts/zz-later.ttf"
            filesystem.add(following, stat.S_IFREG | 0o777)

            def hook(operation, current, count):
                if change == "ancestor-before-mode":
                    # The first pair was the no-effect census. Introduce the
                    # ancestor attribute during the next target query, before
                    # tighten must recheck all retained ancestor descriptors.
                    if current == path and operation == "getxattr" and count == 3:
                        authority_node.xattrs[attribute] = b""
                    return
                trigger = "close" if change == "between-passes" else "fchown" if change == "prepare-group" else "fchmod"
                if current == path and operation == trigger and count == 1:
                    authority_node.xattrs[attribute] = b""

            filesystem.hook = hook
            with self.subTest(change=change):
                rows = self.refused(self.run_inline(filesystem))
                observed = self.authority_failure(rows[-1]["observed"])
                self.assertEqual((observed["path"], observed["phase"], observed["result"]), (authority_path, phase, "present"))
                self.assertTrue(observed["probePerformed"])
                mode = 0o755 if directory else 0o644
                changed_mode = change in {"prepare-mode", "metadata-mode", "ancestor-after-mode"}
                self.assertEqual(filesystem.chmods, [(path, original.st_ino, mode)]
                                 if changed_mode else [])
                self.assertEqual(filesystem.chowns, [(path, original.st_ino, -1, 0)] if change == "prepare-group" else [])
                self.assertEqual(stat.S_IMODE(filesystem.node(following).st_mode), 0o777)
                if change == "prepare-group":
                    self.assertEqual((original.st_gid, stat.S_IMODE(original.st_mode)), (0, 0o2775))
                else:
                    self.assertEqual(stat.S_IMODE(original.st_mode), mode if changed_mode else 0o777)

    def test_xattr_query_drift_preserves_the_first_result_and_original_identity(self):
        path = "/usr/share/fonts/inert.ttf"
        for change in ("name", "state", "disappearance", "present-and-name", "errno-and-name"):
            filesystem = DirectoryMetadataOS()
            original = filesystem.add(path, stat.S_IFREG | 0o444)
            before = list(vars(filesystem.snapshot(original)).values())
            if change == "present-and-name":
                original.xattrs[ACCESS_ACL] = b"private-value-marker"
            elif change == "errno-and-name":
                original.xattrs[ACCESS_ACL] = OSError(errno.EPERM, "private-error-marker")

            def hook(operation, current, count):
                if operation == "getxattr" and current == path and count == 1:
                    if change == "state":
                        original.st_size += 1
                    elif change == "disappearance":
                        filesystem.remove(path)
                    else:
                        filesystem.add(path, stat.S_IFREG | 0o444)

            filesystem.hook = hook
            with self.subTest(change=change):
                rows = self.refused(self.run_inline(filesystem))
                observed = self.authority_failure(rows[-1]["observed"])
                self.assertEqual(observed["original"], before)
                self.assertEqual(observed["result"], "present" if change == "present-and-name"
                                 else "errno" if change == "errno-and-name" else "binding-unproven")
                self.assertEqual(observed["errno"], errno.ENOENT if change == "disappearance"
                                 else errno.EPERM if change == "errno-and-name" else None)
                self.assertTrue(observed["bindingUnknown"] and observed["probePerformed"])
                self.assertFalse(observed["cleanupUnknown"])
                self.assertEqual([call[3] for call in filesystem.xattr_calls if call[1] == path], [ACCESS_ACL])
                self.assertNotIn("private-value-marker", json.dumps(rows))
                self.assertNotIn("private-error-marker", json.dumps(rows))
                self.assertEqual(filesystem.chmods, [])

    def test_xattr_ordinary_open_errors_are_typed_before_query_and_close_all_originals(self):
        for closure in (False, True):
            for number in (errno.EACCES, errno.ENOENT):
                filesystem = DirectoryMetadataOS()
                path = "/opt/mrk-public/face.ttf" if closure else "/usr/share/fonts/inert.ttf"
                original = filesystem.add(path, stat.S_IFREG | 0o444)
                if closure:
                    filesystem.link("/usr/share/fonts/00-alias.ttf", path)
                    filesystem.link("/usr/share/fonts/zz-after.ttf", path)

                def hook(operation, current, count):
                    if operation == "open" and current == path and filesystem.attempt_details[-1][1] == FILE_FLAGS:
                        raise OSError(number, "private-open-marker")

                filesystem.hook = hook
                with self.subTest(closure=closure, errno=number):
                    result = self.run_inline(filesystem)
                    if closure:
                        diagnostic = self.closure(result, refused=True)
                        self.assertEqual(diagnostic["examinedCount"], 1)
                        self.assertNotIn(("/usr/share/fonts/zz-after.ttf", META_FLAGS), filesystem.attempt_details)
                        self.metadata_only_under(filesystem, "/opt")
                    rows = self.refused(result)
                    self.assertIsInstance(result[2], SystemExit)
                    observed = self.authority_failure(rows[-1]["observed"])
                    self.assertEqual((observed["path"], observed["result"], observed["errno"]), (path, "binding-unproven", number))
                    self.assertEqual(observed["original"][1], original.st_ino)
                    self.assertTrue(observed["bindingUnknown"])
                    self.assertFalse(observed["probePerformed"] or observed["cleanupUnknown"])
                    self.assertFalse(any(call[1] == path for call in filesystem.xattr_calls))
                    self.assertNotIn("private-open-marker", json.dumps(rows))
                    self.assertEqual(filesystem.chmods, [])

    def test_xattr_link_reopen_is_bound_before_query_and_registered_before_first_fstat(self):
        for change in ("replacement-before-reopen", "first-fstat-error", "drift-during-query"):
            filesystem = DirectoryMetadataOS()
            path = "/opt/mrk-public/face.ttf"
            original = filesystem.add(path, stat.S_IFREG | 0o444)
            selected, following = "/usr/share/fonts/00-alias.ttf", "/usr/share/fonts/zz-after.ttf"
            filesystem.link(selected, path)
            filesystem.link(following, path)
            ordinary_opened = False

            def hook(operation, current, count):
                nonlocal ordinary_opened
                if current != path:
                    return
                if operation == "open" and filesystem.attempt_details[-1][1] == FILE_FLAGS:
                    ordinary_opened = True
                    if change == "replacement-before-reopen":
                        filesystem.add(path, stat.S_IFREG | 0o444)
                elif operation == "fstat" and ordinary_opened and change == "first-fstat-error":
                    ordinary_opened = False
                    raise OSError(errno.EIO, "private-fstat-marker")
                elif operation == "getxattr" and count == 1 and change == "drift-during-query":
                    filesystem.add(path, stat.S_IFREG | 0o444)

            filesystem.hook = hook
            with self.subTest(change=change):
                result = self.run_inline(filesystem)
                diagnostic = self.closure(result, refused=True)
                self.assertEqual(diagnostic["examinedCount"], 1)
                observed = self.authority_failure(diagnostic["records"][0]["authorityFailure"])
                self.assertEqual(observed, result[1][-1]["observed"])
                self.assertEqual(observed["original"][1], original.st_ino)
                self.assertEqual(observed["result"], "binding-unproven")
                self.assertEqual(observed["errno"], errno.EIO if change == "first-fstat-error" else None)
                self.assertTrue(observed["bindingUnknown"])
                self.assertEqual(observed["probePerformed"], change == "drift-during-query")
                self.assertEqual(sum(call[1] == path for call in filesystem.xattr_calls), int(change == "drift-during-query"))
                self.assertNotIn((following, META_FLAGS), filesystem.attempt_details)
                self.metadata_only_under(filesystem, "/opt")
                self.assertNotIn("private-fstat-marker", json.dumps(result[1]))
                self.assertEqual(filesystem.chmods, [])

    def test_xattr_first_failure_survives_prepare_census_and_closure_close_uncertainty(self):
        for phase, path in (("prepare-before", "/etc/fonts"), ("metadata-census", "/usr/share/fonts/inert.ttf"),
                            ("link-closure", "/opt/mrk-public/face.ttf")):
            filesystem = DirectoryMetadataOS()
            original = filesystem.node(path) if phase == "prepare-before" else filesystem.add(path, stat.S_IFREG | 0o444)
            original.xattrs[ACCESS_ACL] = b""
            if phase == "link-closure":
                filesystem.link("/usr/share/fonts/00-alias.ttf", path)
                filesystem.link("/usr/share/fonts/zz-after.ttf", path)

            def hook(operation, current, count):
                if operation == "close" and current == path and count == 1:
                    raise OSError(errno.EIO, "private-close-marker")

            filesystem.hook = hook
            with self.subTest(phase=phase):
                result = self.run_inline(filesystem)
                rows = self.refused(result)
                observed = self.authority_failure(rows[-1]["observed"])
                self.assertEqual((observed["phase"], observed["result"], observed["attribute"]), (phase, "present", ACCESS_ACL))
                self.assertTrue(observed["cleanupUnknown"] and observed["probePerformed"])
                self.assertFalse(observed["bindingUnknown"])
                if phase == "link-closure":
                    diagnostic = self.closure(result, refused=True)
                    self.assertEqual(diagnostic["examinedCount"], 1)
                    self.assertTrue(diagnostic["records"][0]["cleanupUnknown"])
                    self.assertEqual(diagnostic["records"][0]["authorityFailure"], observed)
                    self.assertNotIn(("/usr/share/fonts/zz-after.ttf", META_FLAGS), filesystem.attempt_details)
                self.assertNotIn("private-close-marker", json.dumps(rows))
                self.assertEqual(filesystem.chmods, [])
                self.assertEqual(filesystem.chowns, [])

    def test_xattr_first_failure_is_retained_when_its_closure_row_exceeds_the_receipt_bound(self):
        filesystem = DirectoryMetadataOS()
        # Ten public links share six long ancestors. This reaches exactly23
        # retained O_PATH originals plus one ordinary query FD, not a huge
        # selection fixture, and overflows only the bounded diagnostic row.
        root = "/opt/" + "/".join("d" * 250 for _ in range(6))
        terminal = root + "/" + "t" * 200 + ".ttf"
        target = filesystem.add(terminal, stat.S_IFREG | 0o444)
        target.xattrs[FILE_CAPABILITY] = b"private-value-marker"
        links = [root + "/" + str(index) + "-" + "a" * 200 for index in range(10)]
        for index, path in enumerate(links):
            filesystem.link(path, links[index + 1] if index + 1 < len(links) else terminal)
        selected, following = "/usr/share/fonts/00-alias.ttf", "/usr/share/fonts/zz-after.ttf"
        filesystem.link(selected, links[0])
        filesystem.link(following, terminal)
        result = self.run_inline(filesystem)
        diagnostic = self.closure(result, refused=True)
        self.assertEqual((diagnostic["selectedCount"], diagnostic["examinedCount"]), (2, 1))
        self.assertEqual(diagnostic["globalError"], "diagnostic-byte-bound")
        self.assertTrue(diagnostic["truncated"])
        self.assertEqual(diagnostic["records"], [])
        self.assertEqual(diagnostic["nodes"], {})
        observed = self.authority_failure(result[1][-1]["observed"])
        self.assertEqual((observed["path"], observed["attribute"], observed["result"]), (terminal[:512], FILE_CAPABILITY, "present"))
        self.assertTrue(observed["pathTruncated"] and observed["truncated"] and observed["probePerformed"])
        self.assertFalse(observed["bindingUnknown"] or observed["cleanupUnknown"])
        self.assertEqual(filesystem.peak, 24)
        self.assertNotIn((following, META_FLAGS), filesystem.attempt_details)
        self.assertNotIn("private-value-marker", json.dumps(result[1]))
        self.metadata_only_under(filesystem, "/opt")
        self.assertEqual(filesystem.chmods, [])

    def test_metadata_route_is_exact_and_excludes_all_compiler_download_and_native_steps(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        full, metadata = "refs/heads/verify/desktop-installed-shell", "refs/heads/verify/desktop-shell-host-metadata"
        self.assertIn("branches: [verify/desktop-installed-shell, verify/desktop-shell-host-metadata]\n", source)
        self.assertNotIn("workflow_dispatch:", source)
        compile_job, native_job = source.split("  native:\n", 1)
        self.assertIn("case \"$GITHUB_REF:$MRK_INSTALLED_SHELL_CASE\" in\n"
                      "            " + full + ":compile|" + metadata + ":host-metadata-only) ;;\n"
                      "            *) exit 70 ;;\n          esac", compile_job)
        self.assertIn('[[ "$HOSTING" == github-hosted && "$GITHUB_EVENT_NAME" == push ]]', compile_job)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA" ]]', compile_job)
        self.assertIn("MRK_INSTALLED_SHELL_CASE: ${{ github.ref == '" + metadata + "' && 'host-metadata-only' || 'compile' }}", compile_job)
        self.assertIn("timeout-minutes: ${{ github.ref == '" + metadata + "' && 10 || 25 }}", compile_job)
        steps = re.split(r"^      - name: ", compile_job, flags=re.MULTILINE)[1:]
        expected = {"Require one exact disposable preparation route", "Check out exact reviewed source without credentials",
                    "Select the fixed frontend compiler", "Prepare shared Ubuntu shell inputs only on this disposable runner",
                    "Prepare only fixed disposable Ubuntu DATA modes", "Prepare a fresh bounded compiler owner",
                    "Download the exact accepted A runtime as DATA", "Compile the normal shell and separate observer once without executing either",
                    "Retain original compiler evidence and shell outputs"}
        self.assertEqual({step.splitlines()[0] for step in steps}, expected)
        self.assertEqual(len(steps), len(expected))
        unguarded = {"Require one exact disposable preparation route", "Check out exact reviewed source without credentials",
                     "Prepare shared Ubuntu shell inputs only on this disposable runner", "Prepare only fixed disposable Ubuntu DATA modes"}
        for step in steps:
            name = step.splitlines()[0]
            if name in unguarded:
                self.assertNotRegex(step, r"(?m)^        if:")
            elif name.startswith("Retain "):
                self.assertIn("        if: always() && github.ref == '" + full + "' && steps.prepare.outputs.root != ''\n", step)
            else:
                self.assertIn("        if: github.ref == '" + full + "'\n", step)
        self.assertIn("    if: github.ref == '" + full + "'\n    needs: compile\n", native_job)
        self.assertIn("    timeout-minutes: 25\n", native_job)
        self.assertEqual(source.count("        timeout-minutes: 8\n"), 2)
        self.assertEqual(source.count("        timeout-minutes: 1\n"), 2)
        self.assertEqual(source.count(PREPARER_MARKER), 2)
        self.assertIn("          persist-credentials: false\n", compile_job)

    def test_actual_inline_imports_exact_rosters_and_allowed_modes(self):
        for mode in (0o755, 0o775, 0o777):
            filesystem = DirectoryMetadataOS()
            for path in PREPARE:
                filesystem.node(path).st_mode = stat.S_IFDIR | mode
            with self.subTest(mode=mode):
                namespace, rows, error = self.run_inline(filesystem)
                self.assertIsNone(error)
                self.assertIs(namespace["json"], json)
                self.assertIs(namespace["re"], re)
                self.assertEqual(namespace["PREPARE_DIRS"], PREPARE)
                expected_roots = tuple((path, "file" if path in FILES else "directory") for path in DATA)
                self.assertEqual(namespace["DATA_ROOTS"], expected_roots)
                source = WORKFLOW.parents[2] / "desktop/tools/ubuntu_publication_lifecycle.py"
                tree = ast.parse(source.read_bytes())
                actual_roots = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                                    and any(isinstance(target, ast.Name) and target.id == "SHELL_DATA_ROOTS" for target in node.targets))
                # Preparation handles only this observed file-link endpoint in
                # addition to the unchanged runtime DATA selection. Never grant
                # either Byobu directory recursive DATA scope.
                self.assertEqual(expected_roots, (*actual_roots, (BYOBU_ICON, "file")))
                self.assertEqual(len(rows), 2)
                diagnostic = self.closure((namespace, rows, error))
                self.assertEqual([diagnostic[key] for key in ("selectedCount", "examinedCount", "externalCount", "unsafeCount")], [0, 0, 0, 0])
                self.assertTrue(diagnostic["complete"] and diagnostic["safe"])
                self.assertEqual(diagnostic["records"], [])
                self.assertEqual(diagnostic["nodes"], {})
                receipt = rows[0]
                self.assertFalse(receipt["runtimeAdmission"])
                self.assertEqual(receipt["metadata"]["unsafeCount"], 0)
                self.assertEqual({row["path"] for row in receipt["prepared"]}, set(PREPARE))
                self.assertEqual([row[0] for row in filesystem.chmods], [] if mode == 0o755 else sorted(PREPARE, key=lambda path: (path.count("/"), path)))
                self.assertEqual(filesystem.chowns, [])
                for row in receipt["prepared"]:
                    self.assertEqual(row["before"]["mode"], format(stat.S_IFDIR | mode, "06o"))
                    self.assertEqual(row["after"], {**row["before"], "mode": "040755"})

    def test_observed_byobu_icon_normalizes_only_three_fixed_nodes_without_sibling_effects(self):
        selected = "/usr/share/icons/hicolor/scalable/apps/byobu.svg"
        directories = ("/usr/share/byobu", "/usr/share/byobu/pixmaps")
        for case in ("present", "no-selection", "broken-selection"):
            filesystem = DirectoryMetadataOS()
            for path in directories:
                filesystem.node(path).st_mode = stat.S_IFDIR | 0o777
            icon = filesystem.node(BYOBU_ICON)
            icon.st_mode, icon.st_size = stat.S_IFREG | 0o777, 16221
            originals = {path: filesystem.snapshot(filesystem.node(path)) for path in (*directories, BYOBU_ICON)}
            siblings = ("/usr/share/byobu/helper.sh", "/usr/share/byobu/pixmaps/other.svg")
            for path in siblings:
                filesystem.add(path, stat.S_IFREG | 0o777)
            if case != "no-selection":
                filesystem.link(selected, "../../../../byobu/pixmaps/byobu.svg")
            if case != "present":
                filesystem.remove(BYOBU_ICON)
            with self.subTest(case=case):
                result = self.run_inline(filesystem)
                diagnostic = self.closure(result, refused=case == "broken-selection")
                expected = {path: 0o755 for path in directories}
                if case == "present":
                    expected[BYOBU_ICON] = 0o644
                self.assertEqual({path: mode for path, _, mode in filesystem.chmods}, expected)
                self.assertEqual(len(filesystem.chmods), len(expected))
                self.assertEqual(filesystem.chowns, [])
                for path, mode in expected.items():
                    before, after = originals[path], filesystem.snapshot(filesystem.node(path))
                    wanted = vars(before).copy()
                    wanted.update(st_mode=stat.S_IFMT(before.st_mode) | mode, st_ctime_ns=after.st_ctime_ns)
                    self.assertEqual(vars(after), wanted)
                    self.assertEqual(mode & ~stat.S_IMODE(before.st_mode), 0)
                for path in siblings:
                    self.assertFalse(any(observed == path for _, observed in filesystem.calls))
                    self.assertEqual(stat.S_IMODE(filesystem.node(path).st_mode), 0o777)
                self.assertFalse(any(path in directories for path, _ in filesystem.reads))
                self.assertEqual(diagnostic["selectedCount"], int(case != "no-selection"))
                if case == "broken-selection":
                    self.assertFalse(diagnostic["complete"] or diagnostic["safe"])
                    self.assertEqual(diagnostic["records"][0]["error"], "unresolved-entry")
                else:
                    self.assertTrue(diagnostic["complete"] and diagnostic["safe"])
                    self.assertEqual(diagnostic["unsafeCount"], 0)
                if case != "present":
                    self.assertNotIn("byobu.svg", filesystem.node(directories[1]).children)

    def test_only_exact_root_staff_local_fonts_can_normalize_group(self):
        path = "/usr/local/share/fonts"
        for change in ("exact", "other-group", "other-mode", "other-target", "other-owner", "chown-error", "replacement"):
            filesystem = DirectoryMetadataOS()
            selected = "/usr/share/fonts" if change == "other-target" else path
            original = filesystem.node(selected)
            original.st_mode = stat.S_IFDIR | (0o775 if change == "other-mode" else 0o2775)
            original.st_gid = 51 if change == "other-group" else 50
            original.st_uid = 1 if change == "other-owner" else 0

            def hook(operation, current, count):
                if operation == "fchown" and current == selected and count == 1:
                    if change == "chown-error":
                        raise OSError(errno.EIO, "Mock group normalization failure")
                    if change == "replacement":
                        filesystem.add(selected, stat.S_IFDIR | 0o2775, gid=50)

            filesystem.hook = hook
            with self.subTest(change=change):
                result = self.run_inline(filesystem)
                if change == "exact":
                    _, rows, error = result
                    self.assertIsNone(error)
                    observed = next(row for row in rows[0]["prepared"] if row["path"] == path)
                    self.assertEqual(observed["before"]["mode"], "042775")
                    self.assertEqual(observed["before"]["gid"], 50)
                    self.assertEqual(observed["after"], {**observed["before"], "mode": "040755", "gid": 0})
                else:
                    self.refused(result)
                if change == "exact":
                    self.assertEqual(filesystem.chowns, [(selected, original.st_ino, -1, 0)])
                    self.assertEqual(filesystem.chmods, [(selected, original.st_ino, 0o755)])
                elif change == "replacement":
                    self.assertEqual(filesystem.chowns, [(selected, original.st_ino, -1, 0)])
                    self.assertEqual(filesystem.chmods, [])
                else:
                    self.assertEqual(filesystem.chowns, [])
                    self.assertEqual(filesystem.chmods, [])
                if change == "replacement":
                    self.assertEqual(filesystem.node(path).st_gid, 50)
                    self.assertEqual(filesystem.node(path).st_mode, stat.S_IFDIR | 0o2775)

    def test_target_policy_and_protected_ancestry_refuse_without_other_repairs(self):
        cases = [("/etc/fonts", mode, 0, 0) for mode in (0o700, 0o750, 0o774, 0o1777, 0o2775)]
        cases += [("/etc/fonts", 0o777, 1000, 0), ("/etc/fonts", 0o777, 0, 1000),
                  ("/usr", 0o777, 0, 0), ("/usr", 0o755, 1, 0)]
        for path, mode, uid, gid in cases:
            filesystem = DirectoryMetadataOS()
            node = filesystem.node(path)
            node.st_mode, node.st_uid, node.st_gid = stat.S_IFDIR | mode, uid, gid
            with self.subTest(path=path, mode=mode, uid=uid, gid=gid):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(filesystem.chmods, [])
        for kind in (stat.S_IFLNK, stat.S_IFREG):
            filesystem = DirectoryMetadataOS()
            filesystem.node("/etc/fonts").st_mode = kind | 0o777
            with self.subTest(kind=kind):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(filesystem.chmods, [])
        for field in ("uids", "gids"):
            filesystem = DirectoryMetadataOS()
            setattr(filesystem, field, (0, 1000, 0))
            with self.subTest(credentials=field):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(filesystem.opened, [])

    def test_optional_absence_does_not_create_a_target_and_share_is_required(self):
        filesystem = DirectoryMetadataOS()
        filesystem.remove("/etc/glvnd")
        filesystem.remove("/usr/share/themes/Adwaita")
        _, rows, error = self.run_inline(filesystem)
        self.assertIsNone(error)
        prepared = {row["path"]: row for row in rows[0]["prepared"]}
        self.assertEqual(prepared["/etc/glvnd/egl_vendor.d"], {"path": "/etc/glvnd/egl_vendor.d", "absentAt": "/etc/glvnd"})
        self.assertEqual(prepared["/usr/share/themes/Adwaita"]["absentAt"], "/usr/share/themes/Adwaita")
        self.assertEqual(filesystem.chmods, [])
        filesystem = DirectoryMetadataOS()
        filesystem.remove("/usr/share")
        self.refused(self.run_inline(filesystem))
        self.assertEqual(filesystem.chmods, [])

    def test_original_target_replacement_and_close_failures_cannot_report_success(self):
        for operation in ("stat", "fchmod", "close", "fstat"):
            filesystem = DirectoryMetadataOS()
            original = filesystem.node("/etc/fonts")
            original.st_mode = stat.S_IFDIR | 0o777

            def hook(called, path, count):
                if called == operation and path == "/etc/fonts" and count == 1:
                    if operation in {"stat", "fchmod"}:
                        filesystem.add(path, stat.S_IFDIR | 0o777)
                    else:
                        raise OSError(errno.EIO, "Mock original operation failure")

            filesystem.hook = hook
            with self.subTest(operation=operation):
                self.refused(self.run_inline(filesystem))
                if operation == "fchmod":
                    self.assertEqual(filesystem.chmods, [("/etc/fonts", original.st_ino, 0o755)])
                    self.assertEqual(filesystem.node("/etc/fonts").st_mode, stat.S_IFDIR | 0o777)
                elif operation in {"stat", "fstat"}:
                    self.assertEqual(filesystem.chmods, [])

    def test_metadata_walk_uses_original_fds_without_content_or_target_directory_reads(self):
        filesystem = DirectoryMetadataOS()
        filesystem.add("/usr/share/fonts/nested")
        filesystem.add("/usr/share/fonts/nested/inert.ttf", stat.S_IFREG | 0o444)
        filesystem.link("/usr/share/fonts/nested/alias.ttf", "inert.ttf")
        filesystem.link("/usr/share/fonts/second-alias.ttf", "nested/inert.ttf")
        result = self.run_inline(filesystem)
        _, rows, error = result
        self.assertIsNone(error)
        self.assertEqual(rows[0]["metadata"]["unsafeCount"], 0)
        self.assertIn("/usr/share/fonts/nested", {path for path, _ in filesystem.reads})
        for path in ("/usr/share/fonts/nested/inert.ttf", "/usr/share/fonts/nested/alias.ttf", "/usr/share/fonts/second-alias.ttf"):
            self.assertIn((path, META_FLAGS), filesystem.attempt_details)
            allowed = (META_FLAGS, FILE_FLAGS) if path.endswith("/inert.ttf") else (META_FLAGS,)
            self.assertTrue(all(flags in allowed for selected, flags in filesystem.attempt_details if selected == path))
        self.assertTrue(any(path == "/usr/share/fonts/nested/inert.ttf" and flags == FILE_FLAGS
                            for path, flags in filesystem.attempt_details))
        diagnostic = self.closure(result)
        self.assertEqual([diagnostic[key] for key in ("selectedCount", "examinedCount", "externalCount", "unsafeCount")], [2, 2, 0, 0])
        self.assertTrue(diagnostic["complete"] and diagnostic["safe"])
        self.assertEqual(diagnostic["records"], [])
        self.assertEqual(filesystem.chmods, [])

    def test_metadata_replacements_disappearance_and_membership_drift_retire_originals(self):
        path = "/usr/share/fonts/late"
        for change in ("before-open-link", "after-open-name", "during-list-link", "member-missing", "membership", "ancestor", "close", "list-error"):
            filesystem = DirectoryMetadataOS()
            original = filesystem.add(path)
            filesystem.add(path + "/inert.ttf", stat.S_IFREG | 0o444)

            def hook(operation, selected, count):
                if selected == path and count == 1:
                    if change == "before-open-link" and operation == "open":
                        filesystem.add(path, stat.S_IFLNK | 0o777)
                    elif change == "after-open-name" and operation == "fstat":
                        filesystem.add(path)
                    elif change == "during-list-link" and operation == "listdir":
                        filesystem.add(path, stat.S_IFLNK | 0o777)
                    elif change == "ancestor" and operation == "listdir":
                        filesystem.add("/usr")
                    elif (change, operation) in {("close", "close"), ("list-error", "listdir")}:
                        raise OSError(errno.EIO, "Mock original metadata operation failure")
                if change == "membership" and operation == "listdir" and selected == path and count == 2:
                    filesystem.add(path + "/new.ttf", stat.S_IFREG | 0o444)
                if change == "member-missing" and operation == "stat" and selected == path + "/inert.ttf" and count == 1:
                    filesystem.remove(selected)

            filesystem.hook = hook
            with self.subTest(change=change):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(filesystem.chmods, [])
                reads = [inode for selected, inode in filesystem.reads if selected == path]
                if change in {"before-open-link", "after-open-name", "list-error"}:
                    self.assertEqual(reads, [])
                else:
                    self.assertTrue(reads)
                    self.assertEqual(set(reads), {original.st_ino})

    def test_unsupported_metadata_refuses_before_descendant_normalization(self):
        filesystem = DirectoryMetadataOS()
        for index in range(70):
            mode, uid = ((stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o555, 0), (stat.S_IFIFO | 0o644, 0),
                         (stat.S_IFLNK | 0o777, 1), (stat.S_IFDIR | 0o755, 1))[index % 5]
            filesystem.add("/usr/share/fonts/unsafe-" + str(index).zfill(2), mode, uid)
        path = "/usr/share/fonts"
        for _ in range(16):
            path += "/" + "a" * 40
            filesystem.add(path)
        filesystem.node(path).st_mode = stat.S_IFDIR | 0o777
        rows = self.refused(self.run_inline(filesystem))
        self.assertEqual(len(rows), 2)
        metadata = rows[0]["metadata"]
        self.assertEqual(metadata["unsafeCount"], 71)
        self.assertEqual(len(metadata["unsafe"]), 64)
        self.assertTrue(metadata["unsafeListTruncated"])
        self.assertEqual(metadata["unsafe"][0]["path"], path[:512])
        self.assertTrue(metadata["unsafe"][0]["pathTruncated"])
        self.assertLessEqual(len(json.dumps(rows[0], sort_keys=True, separators=(",", ":")).encode("ascii")), 65536)
        self.assertEqual(rows[1]["failedCheck"], "unhandled-unsafe-data-metadata")
        self.assertEqual(filesystem.chmods, [])

    def test_fixed_data_descendants_lose_only_write_and_execute_bits(self):
        filesystem = DirectoryMetadataOS()
        root = "/usr/share/fonts/nested"
        filesystem.add(root, stat.S_IFDIR | 0o777)
        filesystem.add(root + "/read-only", stat.S_IFDIR | 0o555)
        expected = {root: 0o755}
        for mode in (0o644, 0o664, 0o666, 0o555, 0o755, 0o775, 0o777):
            path = root + "/file-" + oct(mode)
            filesystem.add(path, stat.S_IFREG | mode)
            if mode != 0o644:
                expected[path] = mode & ~0o133
        for index in range(70):
            path = root + "/more-" + str(index)
            filesystem.add(path, stat.S_IFREG | 0o777)
            expected[path] = 0o644
        outside = "/usr/share/not-shell-data.sh"
        filesystem.add(outside, stat.S_IFREG | 0o777)
        alias = root + "/alias.ttf"
        filesystem.link(alias, "file-0o644")
        originals = {path: filesystem.snapshot(filesystem.node(path)) for path in expected}
        _, rows, error = self.run_inline(filesystem)
        self.assertIsNone(error)
        self.assertEqual({path: mode for path, _, mode in filesystem.chmods}, expected)
        self.assertEqual(len(filesystem.chmods), len(expected))
        for path, mode in expected.items():
            item, before = filesystem.node(path), originals[path]
            self.assertEqual(item.st_ino, before.st_ino)
            self.assertEqual((item.st_size, item.st_mtime_ns), (before.st_size, before.st_mtime_ns))
            self.assertEqual(stat.S_IMODE(item.st_mode), mode)
            self.assertEqual(mode & ~stat.S_IMODE(before.st_mode), 0)
        self.assertEqual(stat.S_IMODE(filesystem.node(root + "/read-only").st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(filesystem.node(outside).st_mode), 0o777)
        self.assertNotIn(outside, filesystem.open_attempts)
        self.assertIn((alias, META_FLAGS), filesystem.attempt_details)
        self.assertTrue(all(flags == META_FLAGS for path, flags in filesystem.attempt_details if path == alias))
        metadata = rows[0]["metadata"]
        self.assertEqual(metadata["unsafeCount"], 0)
        self.assertEqual(metadata["unsupportedCount"], 0)
        self.assertEqual(metadata["changedCount"], len(expected))
        self.assertEqual(len(metadata["changed"]), 64)
        self.assertTrue(metadata["changedListTruncated"])
        self.assertFalse(rows[0]["runtimeAdmission"])
        self.assertEqual(filesystem.chowns, [])

    def test_typed_roots_owners_hardlinks_and_special_modes_cannot_expand_effects(self):
        for path in sorted(FILES):
            filesystem = DirectoryMetadataOS()
            filesystem.add(path)
            filesystem.add(path + "/not-admitted", stat.S_IFREG | 0o777)
            with self.subTest(file_root=path):
                rows = self.refused(self.run_inline(filesystem))
                self.assertEqual(rows[-1]["failedCheck"], "data-root-kind")
                self.assertNotIn(path + "/not-admitted", filesystem.open_attempts)
                self.assertEqual(filesystem.chmods, [])
        for change in ("uid", "gid", "hardlink", "symlink-hardlink", "special", "setuid", "unknown-mode", "device"):
            filesystem = DirectoryMetadataOS()
            item = filesystem.add("/usr/share/fonts/not-admitted", stat.S_IFREG | 0o777)
            if change in {"uid", "gid"}:
                setattr(item, "st_" + change, 1)
            elif change in {"hardlink", "symlink-hardlink"}:
                item.st_nlink = 2
                if change == "symlink-hardlink":
                    item.st_mode = stat.S_IFLNK | 0o777
            elif change == "special":
                item.st_mode = stat.S_IFIFO | 0o644
            elif change == "setuid":
                item.st_mode |= 0o4000
            elif change == "unknown-mode":
                item.st_mode = stat.S_IFREG | 0o606
            else:
                item.st_dev = 2
            with self.subTest(change=change):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(filesystem.chmods, [])

    def test_original_regular_metadata_and_ancestry_are_checked_around_effects(self):
        path = "/usr/share/fonts/changed.ttf"
        for change in ("before-open-link", "original-name", "hardlink", "size", "mtime", "ctime", "ancestor", "after-name", "after-size", "close"):
            filesystem = DirectoryMetadataOS()
            original = filesystem.add(path, stat.S_IFREG | 0o777)

            def hook(operation, current, count):
                if change == "close" and operation == "close" and current == path and filesystem.chmods:
                    # Census now also opens ordinary files for fgetxattr. Keep
                    # this existing case specifically on the post-effect close.
                    raise OSError(errno.EIO, "Mock original file-close uncertainty")
                if current == path and count == 1:
                    if change == "before-open-link" and operation == "open":
                        filesystem.add(path, stat.S_IFLNK | 0o777)
                    if operation == "fstat":
                        if change == "original-name":
                            filesystem.add(path, stat.S_IFREG | 0o777)
                        elif change in {"hardlink", "size", "mtime", "ctime"}:
                            attr = {"hardlink": "st_nlink", "size": "st_size", "mtime": "st_mtime_ns", "ctime": "st_ctime_ns"}[change]
                            setattr(original, attr, getattr(original, attr) + 1)
                        elif change == "ancestor":
                            filesystem.add("/usr/share/fonts")
                    if operation == "fchmod":
                        if change == "after-name":
                            filesystem.add(path, stat.S_IFREG | 0o777)
                        elif change == "after-size":
                            original.st_size += 1

            filesystem.hook = hook
            with self.subTest(change=change):
                self.refused(self.run_inline(filesystem))
                if change in {"after-name", "after-size", "close"}:
                    self.assertEqual(filesystem.chmods, [(path, original.st_ino, 0o644)])
                else:
                    self.assertEqual(filesystem.chmods, [])
                if change == "after-name":
                    self.assertEqual(filesystem.node(path).st_mode, stat.S_IFREG | 0o777)

    def test_kernel_mount_baseline_excludes_aliases_and_is_never_refreshed(self):
        cases = {
            "ancestor": b"3 1 0:1 /other /usr rw - ext4 /dev/mock rw\n",
            "same-device-bind": b"3 1 0:1 /other /usr/share/fonts/nested rw - ext4 /dev/mock rw\n",
            "file-bind": b"3 1 0:1 /other /etc/drirc rw - ext4 /dev/mock rw\n",
            "duplicate-root": b"3 1 0:1 / / rw - ext4 /dev/mock rw\n",
            "idmap": b"3 1 0:1 /other /elsewhere rw idmapped:1 - ext4 /dev/mock rw\n",
            "escape": b"3 1 0:1 /other /bad\\041name rw - ext4 /dev/mock rw\n",
        }
        for change in (*cases, "device", "filesystem", "oversize", "before-effect", "after-effect"):
            filesystem = DirectoryMetadataOS()
            filesystem.node("/etc/fonts").st_mode = stat.S_IFDIR | 0o777
            if change in cases:
                filesystem.mount_raw += cases[change]
            elif change == "device":
                filesystem.mount_raw = filesystem.mount_raw.replace(b"0:1", b"0:2")
            elif change == "filesystem":
                filesystem.mount_raw = filesystem.mount_raw.replace(b"ext4", b"overlay")
            elif change == "oversize":
                filesystem.mount_raw += b"x" * (1 << 20)

            def hook(operation, path, count):
                if (change == "before-effect" and operation == "mount-read" and count == 2
                    or change == "after-effect" and operation == "fchmod" and count == 1):
                    filesystem.mount_raw += b"3 1 0:1 /other /elsewhere rw - ext4 /dev/mock rw\n"

            filesystem.hook = hook
            with self.subTest(change=change):
                self.refused(self.run_inline(filesystem))
                self.assertEqual(len(filesystem.chmods), 1 if change == "after-effect" else 0)

    def test_metadata_membership_depth_and_total_entry_bounds_close_all_fds(self):
        for change in ("members", "grammar", "depth", "entries"):
            filesystem = DirectoryMetadataOS()
            if change == "members":
                filesystem.listings["/usr/share/fonts"] = ["n" + str(index) for index in range(8193)]
            elif change == "grammar":
                filesystem.listings["/usr/share/fonts"] = ["unsafe/member"]
            elif change == "depth":
                path = "/usr/share/fonts"
                for _ in range(17):
                    path += "/nested"
                    filesystem.add(path)
            else:
                for bucket in range(4):
                    for index in range(8192):
                        filesystem.add("/usr/share/fonts/bucket-" + str(bucket) + "/n" + str(index), stat.S_IFREG | 0o444)
            with self.subTest(change=change):
                rows = self.refused(self.run_inline(filesystem))
                self.assertEqual(rows[-1]["failedCheck"], "metadata-membership-bound-grammar" if change in {"members", "grammar"}
                                 else "metadata-entry-depth-bound")
                self.assertEqual(filesystem.chmods, [])

    def test_safe_internal_absolute_relative_and_external_multihop_links_use_original_metadata_only(self):
        filesystem = DirectoryMetadataOS()
        filesystem.add("/usr/share/fonts/nested")
        filesystem.add("/usr/share/fontconfig/source.ttf", stat.S_IFREG | 0o444)
        filesystem.link("/usr/share/fonts/absolute.ttf", "/usr/share/fontconfig/source.ttf")
        filesystem.link("/usr/share/fonts/nested/relative.ttf", "../../fontconfig/source.ttf")
        filesystem.link("/usr/share/fonts/internal-hop.ttf", "absolute.ttf")
        selected = "/usr/share/fonts/external.ttf"
        intermediate, terminal = "/etc/alternatives/mrk-font", "/opt/mrk-public/face.ttf"
        filesystem.link(selected, intermediate)
        filesystem.link(intermediate, "/opt/mrk-public/links/../face.ttf")
        filesystem.add("/opt/mrk-public/links", stat.S_IFDIR | 0o555)
        filesystem.add(terminal, stat.S_IFREG | 0o444)
        filesystem.add("/opt/mrk-public/not-selected.sh", stat.S_IFREG | 0o777)

        diagnostic = self.closure(self.run_inline(filesystem))
        self.assertEqual([diagnostic[key] for key in ("selectedCount", "examinedCount", "externalCount", "unsafeCount")], [4, 4, 1, 0])
        self.assertTrue(diagnostic["complete"] and diagnostic["safe"])
        self.assertFalse(diagnostic["truncated"])
        self.assertEqual(len(diagnostic["records"]), 1)
        row = diagnostic["records"][0]
        self.assertEqual(row["selectedPath"], selected)
        self.assertEqual(row["terminalPath"], terminal)
        self.assertEqual(row["links"], [[selected, intermediate], [intermediate, "/opt/mrk-public/links/../face.ttf"]])
        self.assertEqual(row["unsafePaths"], [])
        self.assertIsNone(row["error"])
        self.assertFalse(row["cleanupUnknown"])
        self.assertEqual(diagnostic["nodes"][terminal]["mode"], "100444")
        self.assertEqual(sum(path == "/opt/mrk-public" and flags == META_FLAGS for path, flags, _ in filesystem.open_details), 1)
        self.assertEqual({path for _, path, _, _ in filesystem.link_reads}, {
            "/usr/share/fonts/absolute.ttf", "/usr/share/fonts/nested/relative.ttf",
            "/usr/share/fonts/internal-hop.ttf", selected, intermediate})
        for prefix in ("/etc/alternatives", "/opt"):
            self.metadata_only_under(filesystem, prefix)
        self.assertFalse(any(path == "/opt/mrk-public/not-selected.sh" for _, path in filesystem.calls))
        self.assertEqual(filesystem.chmods, [])
        self.assertEqual(filesystem.chowns, [])

    def test_complete_multitarget_unsafe_roster_deduplicates_without_external_effects(self):
        filesystem = DirectoryMetadataOS()
        icons = "/usr/share/icons/hicolor/scalable/apps"
        first, second = "/usr/share/vendor-a", "/usr/share/vendor-b"
        filesystem.add(first, stat.S_IFDIR | 0o777)
        filesystem.add(first + "/art", stat.S_IFDIR | 0o775)
        middle = filesystem.link(first + "/current", "art")
        middle.st_nlink = 2
        target_a, target_b = first + "/art/icon.svg", second + "/icon.svg"
        filesystem.add(target_a, stat.S_IFREG | 0o644)
        filesystem.add(second, stat.S_IFDIR | 0o755, uid=1000, gid=1000)
        filesystem.add(target_b, stat.S_IFREG | 0o777).st_nlink = 2
        filesystem.add(first + "/unselected.sh", stat.S_IFREG | 0o777)
        filesystem.link(icons + "/alpha.svg", first + "/current/icon.svg")
        filesystem.link(icons + "/beta.svg", target_b)
        filesystem.link(icons + "/gamma.svg", target_a)
        unsafe = {first, first + "/art", first + "/current", second, target_b}
        originals = {path: filesystem.snapshot(filesystem.node(path)) for path in (*unsafe, target_a)}

        diagnostic = self.closure(self.run_inline(filesystem), refused=True)
        self.assertEqual([diagnostic[key] for key in ("selectedCount", "examinedCount", "externalCount", "unsafeCount")], [3, 3, 3, 5])
        self.assertTrue(diagnostic["complete"])
        self.assertFalse(diagnostic["safe"] or diagnostic["truncated"])
        rows = {row["selectedPath"]: row for row in diagnostic["records"]}
        self.assertEqual(set(rows), {icons + "/" + name + ".svg" for name in ("alpha", "beta", "gamma")})
        self.assertEqual(rows[icons + "/alpha.svg"]["terminalPath"], target_a)
        self.assertEqual(rows[icons + "/alpha.svg"]["links"], [
            [icons + "/alpha.svg", first + "/current/icon.svg"], [first + "/current", "art"]])
        self.assertEqual(rows[icons + "/gamma.svg"]["terminalPath"], target_a)
        self.assertEqual(set().union(*(set(row["unsafePaths"]) for row in rows.values())), unsafe)
        self.assertTrue(all(row["error"] is None and not row["cleanupUnknown"] for row in rows.values()))
        self.assertEqual(diagnostic["nodes"][first]["mode"], "040777")
        self.assertEqual(diagnostic["nodes"][target_b]["mode"], "100777")
        self.assertEqual(diagnostic["nodes"][target_b]["nlink"], 2)
        self.assertEqual(diagnostic["nodes"][second]["uid"], 1000)
        self.assertEqual(diagnostic["nodes"][second]["gid"], 1000)
        for path, before in originals.items():
            self.assertEqual(vars(filesystem.snapshot(filesystem.node(path))), vars(before))
        for prefix in (first, second):
            self.metadata_only_under(filesystem, prefix)
        self.assertFalse(any(path == first + "/unselected.sh" for _, path in filesystem.calls))
        self.assertEqual(filesystem.chmods, [])
        self.assertEqual(filesystem.chowns, [])

    def test_unresolved_private_nonregular_and_loop_rosters_are_incomplete_without_disclosure(self):
        cases = {"missing": "unresolved-entry", "private": "private-target-scope",
                 "typed-file-descendant": "private-target-scope",
                 "directory": "nonregular-terminal", "fifo": "nonregular-terminal", "device": "nonregular-terminal",
                 "regular-before-private": "non-directory-component", "loop-before-private": "link-bound",
                 "grammar": "link-grammar"}
        for change, code in cases.items():
            filesystem = DirectoryMetadataOS()
            selected, after = "/usr/share/fonts/00-alias.ttf", "/usr/share/fonts/zz-after.ttf"
            root, terminal = "/usr/share/vendor", "/usr/share/vendor/target.ttf"
            filesystem.add(root)
            target = terminal
            if change == "private":
                target = "/home/private-marker/.credential"
                filesystem.add(target, stat.S_IFREG | 0o444)
            elif change == "typed-file-descendant":
                target = "/etc/drirc/child"

                def replace_file_root(operation, path, count):
                    if operation == "readlink" and path == selected and count == 1:
                        # The real top-level preparation already observed the
                        # typed file root. Its later directory replacement must
                        # not turn that exact public name into subtree scope.
                        filesystem.add("/etc/drirc", stat.S_IFDIR | 0o755)
                        filesystem.add("/etc/drirc/child", stat.S_IFREG | 0o444)

                filesystem.hook = replace_file_root
            elif change in {"directory", "fifo", "device"}:
                kind = {"directory": stat.S_IFDIR, "fifo": stat.S_IFIFO, "device": stat.S_IFCHR}[change]
                filesystem.add(terminal, kind | 0o644)
                if change == "directory":
                    filesystem.add(terminal + "/not-selected", stat.S_IFREG | 0o444)
            elif change == "regular-before-private":
                filesystem.add(terminal, stat.S_IFREG | 0o444)
                target += "/../../home/private-marker"
            elif change == "loop-before-private":
                filesystem.link(terminal, "other.ttf")
                filesystem.link(root + "/other.ttf", "target.ttf")
                target += "/../../home/private-marker"
            elif change == "grammar":
                target = root + "/invalid target"
            filesystem.link(selected, target)
            filesystem.add("/opt/after/ok.ttf", stat.S_IFREG | 0o444)
            filesystem.link(after, "/opt/after/ok.ttf")

            with self.subTest(change=change):
                result = self.run_inline(filesystem)
                diagnostic = self.closure(result, refused=True)
                self.assertEqual(diagnostic["selectedCount"], 2)
                self.assertEqual(diagnostic["examinedCount"], 2)
                self.assertFalse(diagnostic["complete"] or diagnostic["safe"] or diagnostic["truncated"])
                self.assertIsNone(diagnostic["globalError"])
                rows = {row["selectedPath"]: row for row in diagnostic["records"]}
                self.assertEqual(rows[selected]["error"], code)
                self.assertFalse(rows[selected]["cleanupUnknown"])
                self.assertEqual(rows[after]["terminalPath"], "/opt/after/ok.ttf")
                self.assertIsNone(rows[after]["error"])
                self.assertNotIn("private-marker", json.dumps(result[1]))
                self.assertFalse(any(path == "/home" or path.startswith("/home/") for _, path in filesystem.calls))
                for prefix in (root, "/opt"):
                    self.metadata_only_under(filesystem, prefix)
                if change == "directory":
                    self.assertFalse(any(path == terminal + "/not-selected" for _, path in filesystem.calls))
                if change == "typed-file-descendant":
                    self.assertTrue(stat.S_ISDIR(filesystem.node("/etc/drirc").st_mode))
                    self.assertFalse(any(path == "/etc/drirc/child" for _, path in filesystem.calls))
                    self.assertNotIn("/etc/drirc/child", json.dumps(result[1]))
                self.assertEqual(filesystem.chmods, [])
                self.assertEqual(filesystem.chowns, [])

    def test_closure_original_drift_and_unknown_close_stop_before_another_selection(self):
        cases = {"selected-before-open": "selected-link-changed", "selected-during-readlink": "original-changed",
                 "terminal-name": "original-changed", "terminal-state": "original-changed", "ancestor-name": "original-changed",
                 "mount": "mount-changed", "device": "wrong-device", "close": "original-close-unknown",
                 "error-and-close": "private-target-scope", "between-selections": None}
        for change, code in cases.items():
            filesystem = DirectoryMetadataOS()
            root, target = "/opt/mrk-data", "/opt/mrk-data/face.ttf"
            original = filesystem.add(target, stat.S_IFREG | 0o444)
            selected = "/usr/share/fonts/00-alias.ttf"
            following, last = "/usr/share/fonts/10-next.ttf", "/usr/share/fonts/zz-after.ttf"
            first_link = filesystem.link(selected, "/home/private-marker/.credential" if change == "error-and-close" else target)
            filesystem.link(following, target)
            filesystem.link(last, target)
            if change == "device":
                original.st_dev = 2
            drift_injected = False

            def hook(operation, path, count):
                nonlocal drift_injected
                if path == selected and count == 1:
                    if change == "selected-before-open" and operation == "open":
                        filesystem.link(selected, root + "/replacement.ttf")
                    if change == "selected-during-readlink" and operation == "readlink":
                        filesystem.link(selected, "/home/private-marker/.credential")
                    if change == "error-and-close" and operation == "close":
                        raise OSError(errno.EIO, "Mock first failure plus original close uncertainty")
                if path == target:
                    if operation == "fstat" and count == 1:
                        if change == "terminal-name":
                            filesystem.add(target, stat.S_IFREG | 0o444)
                        elif change == "ancestor-name":
                            filesystem.add(root)
                        elif change == "mount":
                            filesystem.mount_raw += b"3 1 0:1 /other /elsewhere rw - ext4 /dev/mock rw\n"
                    if change == "terminal-state" and operation == "fstat" and count == 2:
                        original.st_size += 1
                    if operation == "close" and count == 1:
                        if change == "close":
                            raise OSError(errno.EIO, "Mock original metadata close uncertainty")
                    if (operation == "close" and change == "between-selections"
                            and filesystem.close_details[-1][1] == META_FLAGS and not drift_injected):
                        # The temporary ordinary fgetxattr FD closes earlier;
                        # inject once, after the first retained O_PATH close.
                        drift_injected = True
                        original.st_size += 1

            filesystem.hook = hook
            with self.subTest(change=change):
                result = self.run_inline(filesystem)
                diagnostic = self.closure(result, refused=True)
                self.assertEqual(diagnostic["selectedCount"], 3)
                self.assertEqual(diagnostic["examinedCount"], 2 if change == "between-selections" else 1)
                self.assertFalse(diagnostic["complete"] or diagnostic["safe"] or diagnostic["truncated"])
                row = diagnostic["records"][0]
                self.assertEqual(row["selectedPath"], selected)
                self.assertEqual(row["error"], code)
                self.assertEqual(row["cleanupUnknown"], change in {"close", "error-and-close"})
                self.assertNotIn((last, META_FLAGS), filesystem.attempt_details)
                if change != "between-selections":
                    self.assertNotIn((following, META_FLAGS), filesystem.attempt_details)
                    self.assertIsNone(diagnostic["globalError"])
                else:
                    self.assertEqual(diagnostic["globalError"], "between-selection-drift")
                    self.assertEqual(diagnostic["nodes"][target]["size"], 0)
                    self.assertEqual(filesystem.node(target).st_size, 1)
                if change == "selected-during-readlink":
                    observed = [(inode, text) for _, path, inode, text in filesystem.link_reads if path == selected]
                    self.assertTrue(observed)
                    self.assertTrue(all(inode == first_link.st_ino and text == target for inode, text in observed))
                self.assertNotIn("private-marker", json.dumps(result[1]))
                self.assertFalse(any(path == "/home" or path.startswith("/home/") for _, path in filesystem.calls))
                self.metadata_only_under(filesystem, "/opt")
                self.assertEqual(filesystem.chmods, [])
                self.assertEqual(filesystem.chowns, [])

    def test_external_mount_intercepts_are_refused_before_target_metadata_operations(self):
        for point in ("/opt", "/opt/mrk-data", "/opt/mrk-data/face.ttf"):
            filesystem = DirectoryMetadataOS()
            selected, target = "/usr/share/fonts/alias.ttf", "/opt/mrk-data/face.ttf"
            filesystem.add(target, stat.S_IFREG | 0o444)
            filesystem.link(selected, target)
            filesystem.mount_raw += ("3 1 0:1 /other " + point + " rw - ext4 /dev/mock rw\n").encode("ascii")
            with self.subTest(mount=point):
                diagnostic = self.closure(self.run_inline(filesystem), refused=True)
                self.assertEqual(diagnostic["examinedCount"], 1)
                self.assertFalse(diagnostic["complete"])
                self.assertEqual(diagnostic["records"][0]["error"], "mounted-target")
                self.assertFalse(any(path == point or path.startswith(point + "/") for _, path in filesystem.calls))
                self.metadata_only_under(filesystem, "/opt")
                self.assertEqual(filesystem.chmods, [])
                self.assertEqual(filesystem.chowns, [])

    def test_closure_fd_component_selection_link_text_and_diagnostic_byte_bounds(self):
        for change in ("fds", "components", "link-text", "diagnostic-bytes", "selections"):
            filesystem = DirectoryMetadataOS()
            selected = "/usr/share/fonts/alias.ttf"
            if change == "fds":
                target = "/opt/" + "/".join("deep-" + str(index) for index in range(30)) + "/face.ttf"
                filesystem.add(target, stat.S_IFREG | 0o444)
                filesystem.link(selected, target + "/../../home/private-marker")
            elif change == "components":
                filesystem.add("/opt/mrk-data/nested")
                filesystem.add("/opt/mrk-data/face.ttf", stat.S_IFREG | 0o444)
                filesystem.link(selected, "/opt/mrk-data/" + "nested/../" * 129 + "face.ttf")
            elif change == "link-text":
                filesystem.link(selected, "/usr/share/vendor/" + "x" * 4096 + "/../../home/private-marker")
            elif change == "diagnostic-bytes":
                for index in range(256):
                    target = "/opt/mrk-data/" + str(index).zfill(3) + "-" + "a" * 140 + ".ttf"
                    filesystem.add(target, stat.S_IFREG | 0o444)
                    filesystem.link("/usr/share/fonts/alias-" + str(index).zfill(3), target)
            else:
                filesystem.add("/usr/share/fonts/inert.ttf", stat.S_IFREG | 0o444)
                for index in range(4097):
                    filesystem.link("/usr/share/fonts/alias-" + str(index).zfill(4), "inert.ttf")

            with self.subTest(bound=change):
                result = self.run_inline(filesystem)
                if change == "selections":
                    rows = self.refused(result)
                    self.assertEqual(rows[-1]["failedCheck"], "metadata-link-count-bound")
                    self.assertFalse(any(flags == META_FLAGS for _, flags in filesystem.attempt_details))
                else:
                    diagnostic = self.closure(result, refused=True)
                    self.assertFalse(diagnostic["complete"] or diagnostic["safe"])
                    if change == "diagnostic-bytes":
                        self.assertEqual(diagnostic["selectedCount"], 256)
                        self.assertGreater(diagnostic["examinedCount"], 1)
                        self.assertLess(diagnostic["examinedCount"], diagnostic["selectedCount"])
                        self.assertTrue(diagnostic["truncated"])
                        self.assertEqual(diagnostic["globalError"], "diagnostic-byte-bound")
                        self.assertTrue(diagnostic["records"] and diagnostic["nodes"])
                    else:
                        self.assertEqual(diagnostic["examinedCount"], 1)
                        self.assertEqual(diagnostic["records"][0]["error"], {
                            "fds": "fd-bound", "components": "component-bound", "link-text": "link-grammar"}[change])
                        self.assertIsNone(diagnostic["globalError"])
                    if change == "fds":
                        self.assertEqual(sum(flags == META_FLAGS for _, flags in filesystem.attempt_details), 24)
                    self.assertNotIn("private-marker", json.dumps(result[1]))
                    self.assertFalse(any(path == "/home" or path.startswith("/home/") for _, path in filesystem.calls))
                self.metadata_only_under(filesystem, "/opt")
                self.assertEqual(filesystem.chmods, [])
                self.assertEqual(filesystem.chowns, [])


if __name__ == "__main__":
    unittest.main()
