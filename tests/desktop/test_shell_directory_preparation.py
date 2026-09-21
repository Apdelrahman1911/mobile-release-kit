"""Actual workflow Python over inert OS metadata; no real permission changes."""
from contextlib import redirect_stdout
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
)
FILES = {"/etc/drirc", "/usr/share/mime/mime.cache", *DATA[-3:]}
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class DirectoryMetadataOS:
    """Held FDs refer to original nodes, independently of later name replacement."""
    def __init__(self):
        self.sequence, self.next_fd, self.peak = 0, 10, 0
        self.root = self.make("/", stat.S_IFDIR | 0o755)
        self.live, self.calls, self.listings = {}, {}, {}
        self.opened, self.open_attempts, self.closed, self.reads, self.chmods = [], [], [], [], []
        self.chowns = []
        self.hook = None
        self.uids = self.gids = (0, 0, 0)
        for path in PREPARE:
            self.add(path)
        for path in DATA:
            self.add(path, stat.S_IFREG | 0o444 if path in FILES else stat.S_IFDIR | 0o755)

    def make(self, path, mode, uid=0, gid=0):
        self.sequence += 1
        return SimpleNamespace(path=path, st_dev=1, st_ino=self.sequence, st_mode=mode,
                               st_uid=uid, st_gid=gid, children={})

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
        if flags != FLAGS:
            raise AssertionError("Directory opens require the exact no-follow flags")
        path = self.path(name, dir_fd)
        self.open_attempts.append(path)
        self.call("open", path)
        node = self.selected(name, dir_fd)
        if not stat.S_ISDIR(node.st_mode):
            raise OSError(errno.ELOOP if stat.S_ISLNK(node.st_mode) else errno.ENOTDIR, "Not a direct mock directory")
        fd = self.next_fd
        self.next_fd += 1
        self.live[fd] = node
        self.opened.append(fd)
        self.peak = max(self.peak, len(self.live))
        return fd

    @staticmethod
    def snapshot(node):
        return SimpleNamespace(**{key: getattr(node, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")})

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
        if type(fd) is not int or fd not in self.live:
            raise AssertionError("Directory membership must use an original FD")
        node = self.live[fd]
        self.call("listdir", node.path)
        self.reads.append((node.path, node.st_ino))
        return list(self.listings.get(node.path, node.children))

    def fchmod(self, fd, mode):
        node = self.live[fd]
        self.call("fchmod", node.path)
        self.chmods.append((node.path, node.st_ino, mode))
        node.st_mode = stat.S_IFMT(node.st_mode) | mode

    def fchown(self, fd, uid, gid):
        node = self.live[fd]
        self.call("fchown", node.path)
        if (uid, gid) != (-1, 0):
            raise AssertionError("Only the fixed group normalization is admitted")
        self.chowns.append((node.path, node.st_ino, uid, gid))
        node.st_gid = gid

    def close(self, fd):
        # A failed mocked close is not successful-close evidence. Record the
        # sole attempt and reject the run; do not retry this numeric identity.
        node = self.live.pop(fd)
        self.closed.append(fd)
        self.call("close", node.path)


class ShellDirectoryPreparationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = WORKFLOW.read_bytes()
        if len(raw) > 65536:
            raise AssertionError("Workflow source exceeds this DATA read bound")
        marker = "          sudo /usr/bin/python3.12 -I -S -B - <<'PY'\n"
        blocks = [textwrap.dedent(part.split("          PY\n", 1)[0]) for part in raw.decode("utf-8").split(marker)[1:]]
        if len(blocks) != 2 or blocks[0] != blocks[1]:
            raise AssertionError("Compiler/native directory-preparation bodies must be identical")
        cls.inline = blocks[0]

    def run_inline(self, filesystem):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("Unexpected content, link-target or mutation API")

        namespace, output, error = {"__name__": "workflow_directory_preparation"}, io.StringIO(), None
        replacements = {name: forbidden for name in ("lstat", "read", "readlink", "write", "chmod", "chown", "fchown",
                                                     "mkdir", "rmdir", "unlink", "rename", "symlink")}
        replacements.update({name: getattr(filesystem, name) for name in ("open", "stat", "fstat", "listdir", "fchmod", "fchown", "close")})
        replacements.update(getresuid=lambda: filesystem.uids, getresgid=lambda: filesystem.gids)
        with patch.multiple(os, **replacements), redirect_stdout(output):
            try:
                # Execute the actual inline imports and top-level entry, not
                # selected AST functions with a fabricated dependency namespace.
                exec(compile(self.inline, str(WORKFLOW) + ":directory-preparation", "exec"), namespace)
            except BaseException as caught:
                error = caught
        self.assertEqual(filesystem.live, {})
        self.assertEqual(sorted(filesystem.closed), filesystem.opened)
        self.assertLessEqual(filesystem.peak, 24)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        return namespace, rows, error

    def refused(self, result):
        _, rows, error = result
        self.assertIsInstance(error, (SystemExit, OSError))
        if isinstance(error, SystemExit):
            self.assertEqual(error.code, 70)
        self.assertFalse(any(row.get("runtimeAdmission") is True for row in rows))
        return rows

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
                self.assertEqual(namespace["DATA_ROOTS"], DATA)
                self.assertEqual(len(rows), 1)
                receipt = rows[0]
                self.assertFalse(receipt["runtimeAdmission"])
                self.assertEqual(receipt["metadata"]["unsafeCount"], 0)
                self.assertEqual({row["path"] for row in receipt["prepared"]}, set(PREPARE))
                self.assertEqual([row[0] for row in filesystem.chmods], [] if mode == 0o755 else sorted(PREPARE, key=lambda path: (path.count("/"), path)))
                self.assertEqual(filesystem.chowns, [])
                for row in receipt["prepared"]:
                    self.assertEqual(row["before"]["mode"], format(stat.S_IFDIR | mode, "06o"))
                    self.assertEqual(row["after"], {**row["before"], "mode": "040755"})

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
                if change in {"exact", "replacement"}:
                    self.assertEqual(filesystem.chowns, [(selected, original.st_ino, -1, 0)])
                    self.assertEqual(filesystem.chmods, [(selected, original.st_ino, 0o755)])
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

    def test_metadata_walk_uses_original_directory_fds_without_content_or_link_reads(self):
        filesystem = DirectoryMetadataOS()
        filesystem.add("/usr/share/fonts/nested")
        filesystem.add("/usr/share/fonts/nested/inert.ttf", stat.S_IFREG | 0o444)
        filesystem.add("/usr/share/fonts/nested/alias.ttf", stat.S_IFLNK | 0o777)
        filesystem.add("/usr/share/fonts/directory-alias", stat.S_IFLNK | 0o777)
        _, rows, error = self.run_inline(filesystem)
        self.assertIsNone(error)
        self.assertEqual(rows[0]["metadata"]["unsafeCount"], 0)
        self.assertIn("/usr/share/fonts/nested", {path for path, _ in filesystem.reads})
        for path in ("/usr/share/fonts/nested/inert.ttf", "/usr/share/fonts/nested/alias.ttf", "/usr/share/fonts/directory-alias"):
            self.assertNotIn(path, filesystem.open_attempts)
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

    def test_unhandled_metadata_is_bounded_and_never_added_to_chmod_roster(self):
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


if __name__ == "__main__":
    unittest.main()
