from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import cli
from mobile_release import init_transaction as tx
from mobile_release.errors import ValidationError


def fixture(root: Path, *, force: bool = False, platforms: tuple[str, ...] = ("android",)) -> list[str]:
    if "android" in platforms:
        (root / "app").mkdir()
        (root / "app/build.gradle.kts").write_text(
            'plugins { id("com.android.application") }\n'
            'android { defaultConfig { applicationId = "com.example.reader" } }\n'
        )
    if "ios" in platforms:
        project = root / "Product.xcodeproj"
        project.mkdir()
        (project / "project.pbxproj").write_text("PRODUCT_BUNDLE_IDENTIFIER = com.example.reader;\n")
    templates = root / "templates"
    templates.mkdir()
    for name in ("a.yml", "z.yml"):
        (templates / name).write_text(
            "uses: __MOBILE_RELEASE_KIT_REPOSITORY__/.github/workflows/reusable.yml@__MOBILE_RELEASE_KIT_SHA__\n"
        )
    (root / ".gitignore").write_bytes(b"build/\r\n# exact existing bytes\r\n")
    (root / ".gitignore").chmod(0o600)
    if force:
        config = root / "release/mobile-release.json"
        config.parent.mkdir()
        config.write_bytes(b"original config\r\n")
        config.chmod(0o600)
        for name in ("a.yml", "z.yml"):
            caller = root / ".github/workflows" / name
            caller.parent.mkdir(parents=True, exist_ok=True)
            caller.write_bytes(b"original caller " + name.encode() + b"\n")
            caller.chmod(0o640)
    if "android" in platforms:
        title = root / "release/store/android/en-US/title.txt"
        title.parent.mkdir(parents=True, exist_ok=True)
        title.write_bytes(b"Owner's existing title\r\n")
        title.chmod(0o600)
    return ["init", "--root", str(root), "--apply", "--template-dir", str(templates),
            "--tooling-repository", "example/mobile-release-kit", "--tooling-sha", "a" * 40] + (["--force"] if force else [])


def invoke(argv: list[str]) -> tuple[int, str, str]:
    output, error = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        code = cli.main(argv)
    return code, output.getvalue(), error.getvalue()


def snapshot(root: Path) -> dict[str, tuple]:
    result = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] in tx.STATE_NAMES:
            continue
        value = path.lstat()
        result[relative.as_posix()] = (
            stat.S_IFMT(value.st_mode), stat.S_IMODE(value.st_mode), value.st_ino,
            os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None,
        )
    return result


@contextlib.contextmanager
def boundaries(callback):
    """Instrument real IO boundaries, never replace a successful operation."""
    sequence = []

    def wrap(kind, function, label=lambda *args: ""):
        def wrapped(*args, **kwargs):
            event = {"kind": kind, "label": label(*args), "success": False}
            sequence.append(event)
            index = len(sequence) - 1
            callback(index, event, "before")
            result = function(*args, **kwargs)
            event["success"] = True
            callback(index, event, "after")
            return result
        return wrapped

    rename = tx._rename_function()
    real_open = os.open
    created_open = wrap("open-create", real_open, lambda name, *_: str(name))

    def open_file(path, flags, *args, **kwargs):
        return (created_open if flags & os.O_CREAT else real_open)(path, flags, *args, **kwargs)

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(tx, "_rename_function", return_value=wrap(
            "rename", rename, lambda _sfd, source, _dfd, dest: f"{source}>{dest}")))
        stack.enter_context(patch.object(tx, "_fsync", wrap("fsync", tx._fsync)))
        for name in ("mkdir", "unlink", "rmdir"):
            stack.enter_context(patch.object(tx.os, name, wrap(name, getattr(os, name), lambda name, *_: str(name))))
        stack.enter_context(patch.object(tx.os, "write", wrap("write", os.write)))
        stack.enter_context(patch.object(tx.os, "open", open_file))
        yield sequence


class InitTransactionTests(unittest.TestCase):
    def assert_no_state(self, root: Path) -> None:
        self.assertFalse(any((root / name).exists() for name in tx.STATE_NAMES))

    def assert_complete(self, root: Path, *, force: bool = False) -> None:
        config = json.loads((root / "release/mobile-release.json").read_text())
        self.assertEqual(config["schemaVersion"], 1)
        for name in ("a.yml", "z.yml"):
            self.assertIn("example/mobile-release-kit/", (root / ".github/workflows" / name).read_text())
        ignore = (root / ".gitignore").read_bytes()
        self.assertTrue(ignore.startswith(b"build/\r\n# exact existing bytes\r\n"))
        self.assertTrue(all(line.encode() in ignore.splitlines() for line in tx.IGNORE_LINES))
        if config["android"]["enabled"]:
            self.assertEqual((root / "release/store/android/en-US/title.txt").read_bytes(), b"Owner's existing title\r\n")
        if force:
            self.assertEqual(stat.S_IMODE((root / "release/mobile-release.json").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / ".github/workflows/a.yml").stat().st_mode), 0o640)

    def test_real_native_directory_no_replace_and_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with tx.InitWorkspace(root) as workspace:
                (root / "a").mkdir()
                (root / "b").mkdir()
                a, b = (root / "a").stat().st_ino, (root / "b").stat().st_ino
                with self.assertRaises(FileExistsError):
                    workspace.rename(workspace.fd, "a", workspace.fd, "b")
                self.assertEqual((root / "a").stat().st_ino, a)
                self.assertEqual((root / "b").stat().st_ino, b)
                workspace.rename(workspace.fd, "a", workspace.fd, "new")
                self.assertEqual((root / "new").stat().st_ino, a)

    def test_single_combined_platforms_and_idempotent_force_preserve_existing_files(self) -> None:
        for platforms in (("android",), ("ios",), ("android", "ios")):
            with self.subTest(platforms=platforms), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True, platforms=platforms)
                code, output, error = invoke(args)
                self.assertEqual(code, 0, error)
                report = json.loads(output)
                self.assertIn("release/mobile-release.json", report["updated"])
                self.assert_complete(root, force=True)
                before = snapshot(root)
                self.assertEqual(invoke(args)[0], 0)
                self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)
                self.assertEqual(json.loads(invoke(["init", "--root", str(root), "--recover"])[1])["recovery"], "no-op")

    def test_every_real_write_boundary_before_and_after_failure_is_transactional(self) -> None:
        # Includes stage writes, directory creation/publication, backup moves,
        # every fsync, commit marker, cleanup handoff and each cleanup suffix.
        for force in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=force)
                with boundaries(lambda *_: None) as recorded:
                    self.assertEqual(invoke(args)[0], 0)
                schedule = [dict(event) for event in recorded]
            commit_index = next(i for i, event in enumerate(schedule)
                                if event["kind"] == "rename" and event["label"] == "commit.pending>COMMITTED")
            self.assertGreater(len(schedule), 70)
            for index, event in enumerate(schedule):
                for when in ("before", "after"):
                    if when == "after" and not event["success"]:
                        continue  # Expected EEXIST probe did not take effect.
                    with self.subTest(force=force, index=index, event=event, when=when), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary).resolve()
                        args = fixture(root, force=force)
                        before = snapshot(root)
                        injected = []

                        def fail(current, actual, phase):
                            if current == index and phase == when and not injected:
                                self.assertEqual((actual["kind"], actual["label"]), (event["kind"], event["label"]))
                                injected.append(True)
                                raise OSError(errno.ENOSPC, "synthetic disk failure")

                        with boundaries(fail):
                            code, output, error = invoke(args)
                        self.assertTrue(injected)
                        self.assertEqual(code, 2, error)
                        self.assertEqual(output, "")
                        self.assert_no_state(root)
                        committed = index > commit_index or (index == commit_index and when == "after")
                        if committed:
                            self.assert_complete(root, force=force)
                            self.assertIn("committed", error)
                        else:
                            self.assertEqual(snapshot(root), before)

    def leave_pending(self, args: list[str]) -> None:
        interrupted = []

        def stop(_index, event, when):
            if event["kind"] == "rename" and event["label"] == "new-0>mobile-release.json" and when == "after" and not interrupted:
                interrupted.append(True)
                raise OSError("synthetic upload of local file completed before failure")

        with boundaries(stop), patch.object(tx.InitWorkspace, "recover", side_effect=OSError("synthetic unavailable recovery")):
            code, output, error = invoke(args)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertTrue(interrupted)
        self.assertIn("automatic recovery incomplete", error)

    def test_every_rollback_and_cleanup_boundary_can_fail_then_resume_without_lost_originals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.leave_pending(fixture(root, force=True))
            with boundaries(lambda *_: None) as recorded:
                self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 0)
            schedule = [dict(event) for event in recorded]
        self.assertTrue(any(e["label"] == "old-0>mobile-release.json" for e in schedule))
        for index, event in enumerate(schedule):
            for when in ("before", "after"):
                with self.subTest(index=index, event=event, when=when), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    args = fixture(root, force=True)
                    before = snapshot(root)
                    self.leave_pending(args)
                    injected = []

                    def stop(current, actual, phase):
                        if current == index and phase == when and not injected:
                            self.assertEqual((actual["kind"], actual["label"]), (event["kind"], event["label"]))
                            injected.append(True)
                            raise OSError(errno.EIO, "synthetic recovery failure")

                    request = ["init", "--root", str(root), "--recover"]
                    with boundaries(stop):
                        code, output, _ = invoke(request)
                    self.assertTrue(injected)
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    # Original inode/content must remain at its final or backup
                    # location even while recovery cannot complete.
                    surviving = {p.stat().st_ino: p for p in root.rglob("*") if p.is_file()}
                    for kind, mode, inode, data in before.values():
                        if kind == stat.S_IFREG:
                            self.assertIn(inode, surviving)
                            self.assertEqual(surviving[inode].read_bytes(), data)
                            self.assertEqual(stat.S_IMODE(surviving[inode].stat().st_mode), mode)
                    code, _, error = invoke(request)
                    self.assertEqual(code, 0, error)
                    self.assertEqual(snapshot(root), before)
                    self.assert_no_state(root)

    def test_persistent_recovery_and_cleanup_failures_never_report_success(self) -> None:
        for committed in (False, True):
            with self.subTest(committed=committed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True)
                before = snapshot(root)
                if committed:
                    self.kill_at(root, "apply", "rename", f"{tx.READY}>{tx.CLEANUP}")
                else:
                    self.leave_pending(args)

                def fail(_index, event, when):
                    if when == "before" and ((committed and event["kind"] == "unlink")
                                              or (not committed and event["label"] == "mobile-release.json>new-0")):
                        raise OSError(errno.EACCES, "synthetic persistent failure")

                for _ in range(3):
                    with boundaries(fail):
                        code, output, _ = invoke(["init", "--root", str(root), "--recover"])
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertTrue(any((root / name).exists() for name in tx.STATE_NAMES))
                self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 0)
                if committed:
                    self.assert_complete(root, force=True)
                else:
                    self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)

    def test_final_readback_failure_and_keyboard_interrupt_restore_original_inodes(self) -> None:
        for error_type in (OSError, KeyboardInterrupt):
            with self.subTest(error=error_type), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True)
                before = snapshot(root)
                real = tx.InitWorkspace._locations
                injected = []

                def verify(workspace, fd, plan, *, final=None):
                    real(workspace, fd, plan, final=final)
                    if final == "new" and not injected:
                        injected.append(True)
                        raise error_type("synthetic verification interruption")

                with patch.object(tx.InitWorkspace, "_locations", verify):
                    code, output, error = invoke(args)
                self.assertEqual(code, 130 if error_type is KeyboardInterrupt else 2, error)
                self.assertEqual(output, "")
                self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)

    def test_path_collisions_aliases_and_unsafe_preserved_metadata_fail_before_writes(self) -> None:
        for name in (".gitignore", ".github", ".Github/workflows/other.yml", ".git/config",
                     ".GIT/config", tx.READY + "/config", tx.PREPARING.upper() + "/config"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True) + ["--config", name]
                before = snapshot(root)
                code, output, _ = invoke(args)
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root)
            store = root / "release/store"
            store.rename(root / "other-store")
            store.symlink_to(root / "other-store", target_is_directory=True)
            before = snapshot(root)
            self.assertEqual(invoke(args)[0], 2)
            self.assertEqual(snapshot(root), before)
            self.assert_no_state(root)

    def test_derived_ignore_bytes_cannot_adopt_a_later_editor_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root)
            original = tx.InitWorkspace.apply
            edited = b"intervening owner edit\n"

            def apply(workspace, changes):
                (root / ".gitignore").write_bytes(edited)
                return original(workspace, changes)

            with patch.object(tx.InitWorkspace, "apply", apply):
                self.assertEqual(invoke(args)[0], 2)
            self.assertEqual((root / ".gitignore").read_bytes(), edited)
            self.assertFalse((root / "release/mobile-release.json").exists())
            self.assert_no_state(root)

    def test_no_force_rejects_config_or_caller_created_before_authoritative_observation(self) -> None:
        for target in ("release/mobile-release.json", ".github/workflows/a.yml", ".github/workflows/z.yml"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root)
                (root / target).parent.mkdir(parents=True, exist_ok=True)
                observe, owner_state = tx.InitWorkspace.observe, []

                def observed(workspace, path, **kwargs):
                    if path == target and not owner_state:
                        file = root / target
                        file.parent.mkdir(parents=True, exist_ok=True)
                        file.write_bytes(b"owner file appeared before the snapshot")
                        owner_state.append(snapshot(root))
                    return observe(workspace, path, **kwargs)

                with patch.object(tx.InitWorkspace, "observe", observed):
                    code, output, error = invoke(args)
                self.assertTrue(owner_state)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("refusing to overwrite", error)
                self.assertEqual(snapshot(root), owner_state[0])
                self.assert_no_state(root)

    def test_special_root_and_ancestor_modes_are_rejected_before_any_private_state(self) -> None:
        for relative in (".", "release", ".github/workflows"):
            for special in (0o1000, 0o2000, 0o4000):
                with self.subTest(path=relative, mode=oct(special)), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    args = fixture(root, force=True)
                    target = root / relative
                    mode = stat.S_IMODE(target.stat().st_mode) | special
                    target.chmod(mode)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                    before = snapshot(root)
                    code, output, error = invoke(args)
                    self.assertEqual((code, output), (2, ""))
                    self.assertIn("special directory permission bits", error)
                    self.assertEqual(snapshot(root), before)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                    self.assert_no_state(root)

    def test_ignore_read_and_generated_bounds_agree_and_success_is_force_idempotent(self) -> None:
        lines = b"".join(line.encode() + b"\n" for line in tx.IGNORE_LINES)
        limit = 1024**2
        for size, present, success in ((limit - len(lines), False, True),
                                      (limit - len(lines) + 1, False, False),
                                      (limit, False, False), (limit + 1, False, False),
                                      (limit, True, True)):
            with self.subTest(size=size, present=present), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root)
                body_size = size - (len(lines) if present else 0)
                original = b"#" + b"x" * (body_size - 2) + b"\n" + (lines if present else b"")
                (root / ".gitignore").write_bytes(original)
                before = snapshot(root)
                code, output, error = invoke(args)
                self.assertEqual(code, 0 if success else 2, error)
                if success:
                    after = snapshot(root)
                    self.assertLessEqual((root / ".gitignore").stat().st_size, limit)
                    self.assertEqual(invoke(args + ["--force"])[0], 0)
                    self.assertEqual(snapshot(root), after)
                    self.assertTrue((root / ".gitignore").read_bytes().startswith(original))
                else:
                    self.assertEqual(output, "")
                    self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)

    def test_discovery_and_preview_ignore_every_reserved_namespace_and_portable_alias(self) -> None:
        for name in tx.STATE_NAMES:
            for spelling in (name, name.upper(), name.replace("s", "\u017f")):
                with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    fixture(root)
                    private_project = root / spelling / "Synthetic.xcodeproj"
                    private_project.mkdir(parents=True)
                    (private_project / "project.pbxproj").write_text("PRODUCT_BUNDLE_IDENTIFIER = com.example.privatejournal;\n")
                    before = snapshot(root)
                    code, output, error = invoke(["init", "--root", str(root)])
                    self.assertEqual(code, 0, error)
                    report = json.loads(output)
                    self.assertNotIn("ios", report["discovery"])
                    self.assertFalse(report["proposedConfiguration"]["ios"]["enabled"])
                    self.assertNotIn("com.example.privatejournal", output)
                    self.assertEqual(snapshot(root), before)

    def test_cleanup_rechecks_inter_item_old_fd_edits_and_replacements(self) -> None:
        for kind in ("old-fd", "replacement"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True)
                handle = os.open(root / ".github/workflows/a.yml", os.O_RDWR)
                edited = []

                def change(_index, event, when):
                    if event["kind"] == "unlink" and event["label"] == "old-0" and when == "after" and not edited:
                        backup = root / tx.CLEANUP / "old-1"
                        if kind == "old-fd":
                            os.pwrite(handle, b"OWNER'S LATER SAVE", 0)
                        else:
                            backup.rename(root / "saved-original-caller")
                            backup.write_bytes(b"owner replacement between cleanup entries")
                        edited.append((backup.stat().st_ino, backup.read_bytes()))

                try:
                    with boundaries(change):
                        code, output, error = invoke(args)
                    self.assertEqual((code, output), (2, ""))
                    self.assertIn("recovery conflict", error)
                    self.assertTrue(edited)
                    backup = root / tx.CLEANUP / "old-1"
                    self.assertEqual((backup.stat().st_ino, backup.read_bytes()), edited[0])
                    if kind == "old-fd":
                        self.assertGreater(os.fstat(handle).st_nlink, 0)
                    proof = snapshot(root / tx.CLEANUP)
                    self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 2)
                    self.assertEqual(snapshot(root / tx.CLEANUP), proof)
                finally:
                    os.close(handle)

    def test_cleanup_does_not_adopt_a_replaced_private_directory_on_automatic_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root, force=True)
            replaced = []

            def replace(_index, event, when):
                if event["kind"] == "unlink" and event["label"] == "old-0" and when == "after" and not replaced:
                    (root / tx.CLEANUP).rename(root / "detached-journal")
                    (root / tx.CLEANUP).mkdir(mode=0o700)
                    replaced.append((root / tx.CLEANUP).stat().st_ino)

            with boundaries(replace):
                code, output, error = invoke(args)
            self.assertEqual((code, output), (2, ""))
            self.assertIn("recovery conflict", error)
            self.assertTrue(replaced)
            self.assertEqual((root / tx.CLEANUP).stat().st_ino, replaced[0])
            self.assertEqual(list((root / tx.CLEANUP).iterdir()), [])
            self.assertEqual((root / "detached-journal/old-1").read_bytes(), b"original caller a.yml\n")
            # Preserve the test editor's directory and restore the authentic
            # namespace before asking a fresh invocation to finish cleanup.
            (root / tx.CLEANUP).rename(root / "saved-owner-directory")
            (root / "detached-journal").rename(root / tx.CLEANUP)
            self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 0)
            self.assert_complete(root, force=True)
            self.assert_no_state(root)

    def test_cleanup_control_replacement_is_not_silently_adopted_after_plan_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root, force=True)
            replaced = []

            def replace(_index, event, when):
                if event["kind"] == "unlink" and event["label"] == "plan.json" and when == "after" and not replaced:
                    marker = root / tx.CLEANUP / "COMMITTED"
                    marker.write_bytes(marker.read_bytes() + b" \n")
                    replaced.append(marker.read_bytes())

            with boundaries(replace):
                code, output, error = invoke(args)
            self.assertEqual((code, output), (2, ""))
            self.assertIn("recovery conflict", error)
            self.assertTrue(replaced)
            self.assertEqual((root / tx.CLEANUP / "COMMITTED").read_bytes(), replaced[0])
            self.assertTrue((root / tx.CLEANUP / "header.json").is_file())

    def test_source_replacement_after_precheck_is_restored_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root, force=True)
            source = root / "release/mobile-release.json"
            user = b"atomic editor replacement\n"
            replaced = []
            real_factory = tx._rename_function

            def factory():
                native = real_factory()

                def rename(sfd, name, dfd, dest):
                    if name == "mobile-release.json" and dest.startswith("old-") and not replaced:
                        replacement = root / "replacement"
                        replacement.write_bytes(user)
                        os.replace(replacement, source)  # AFTER production's final source precheck.
                        replaced.append(source.stat().st_ino)
                    return native(sfd, name, dfd, dest)
                return rename

            with patch.object(tx, "_rename_function", factory):
                code, output, error = invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("preserve", error)
            self.assertEqual(source.read_bytes(), user)
            self.assertEqual(source.stat().st_ino, replaced[0])
            self.assertEqual((root / ".github/workflows/a.yml").read_bytes(), b"original caller a.yml\n")
            self.assertTrue((root / tx.READY).is_dir())

    def test_old_writable_descriptor_conflict_is_preserved_and_force_does_not_truncate_hardlinks(self) -> None:
        for mutate in (False, True):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True)
                config = root / "release/mobile-release.json"
                other = root / "unrelated-hardlink"
                os.link(config, other)
                handle = os.open(config, os.O_WRONLY)
                changed = []

                def inject(_index, event, when):
                    if mutate and event["kind"] == "rename" and event["label"].startswith("mobile-release.json>old-") and when == "after" and not changed:
                        changed.append(True)
                        os.write(handle, b"owner-fd-edited!")

                try:
                    with boundaries(inject):
                        code, _, _ = invoke(args)
                finally:
                    os.close(handle)
                if mutate:
                    self.assertEqual(code, 2)
                    self.assertTrue(other.read_bytes().startswith(b"owner-fd-edited!"))
                    self.assertEqual(config.stat().st_ino, other.stat().st_ino)
                else:
                    self.assertEqual(code, 0)
                    self.assertEqual(other.read_bytes(), b"original config\r\n")
                    self.assertNotEqual(config.stat().st_ino, other.stat().st_ino)

    def test_unsupported_native_primitive_keeps_preview_portable_and_apply_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root)
            before = snapshot(root)
            with patch.object(tx, "_rename_function", side_effect=ValidationError("exclusive rename unavailable")):
                self.assertEqual(invoke(["init", "--root", str(root)])[0], 0)
                self.assertEqual(invoke(args)[0], 2)
            self.assertEqual(snapshot(root), before)
            self.assert_no_state(root)

    def test_exdev_has_no_copy_fallback_and_restores_the_original_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = fixture(root, force=True)
            before = snapshot(root)
            failed = []

            def inject(_index, event, when):
                if event["label"] == "new-0>mobile-release.json" and when == "before" and not failed:
                    failed.append(True)
                    raise OSError(errno.EXDEV, "synthetic unsupported mount")

            with boundaries(inject):
                code, output, _ = invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertTrue(failed)
            self.assertEqual(snapshot(root), before)
            self.assert_no_state(root)

    def test_added_content_and_changed_parent_conflict_without_deleting_user_work(self) -> None:
        for change in ("addition", "parent-symlink"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
                root = Path(temporary).resolve()
                external = Path(outside).resolve()
                (external / "owner.txt").write_bytes(b"outside the transaction")
                args = fixture(root)
                before = snapshot(root)
                external_before = snapshot(external)
                self.leave_pending(args)
                journal = root / tx.READY
                if change == "addition":
                    (root / ".github/owner.txt").write_bytes(b"unrelated addition")
                else:
                    (root / "release").rename(root / "detached-release")
                    (root / "release").symlink_to(external, target_is_directory=True)
                edited, proof = snapshot(root), snapshot(journal)
                request = ["init", "--root", str(root), "--recover"]
                code, output, _ = invoke(request)
                self.assertEqual((code, output), (2, ""))
                self.assertEqual(snapshot(root), edited)
                self.assertEqual(snapshot(journal), proof)
                self.assertEqual(snapshot(external), external_before)
                if change == "addition":
                    # Save the owner's test edit rather than deleting it to
                    # make the transaction pass.
                    (root / ".github/owner.txt").rename(external / "saved-owner.txt")
                else:
                    (root / "release").unlink()  # Test-owned symlink only.
                    (root / "detached-release").rename(root / "release")
                self.assertEqual(invoke(request)[0], 0)
                self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)

    def test_source_parent_swapped_inside_rename_never_writes_through_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root, external = Path(temporary).resolve(), Path(outside).resolve()
            args = fixture(root, force=True)
            before = snapshot(root)
            (external / "mobile-release.json").write_bytes(b"unrelated outside config")
            external_before = snapshot(external)
            swapped = []
            native = tx._rename_function()

            def rename(sfd, source, dfd, destination):
                if (source, destination) == ("mobile-release.json", "old-0") and not swapped:
                    (root / "release").rename(root / "detached-release")
                    (root / "release").symlink_to(external, target_is_directory=True)
                    swapped.append(True)
                return native(sfd, source, dfd, destination)

            with patch.object(tx, "_rename_function", return_value=rename):
                code, output, _ = invoke(args)
            self.assertEqual((code, output), (2, ""))
            self.assertTrue(swapped)
            self.assertEqual(snapshot(external), external_before)
            self.assertEqual((root / tx.READY / "old-0").read_bytes(), b"original config\r\n")
            (root / "release").unlink()
            (root / "detached-release").rename(root / "release")
            self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 0)
            self.assertEqual(snapshot(root), before)

    def test_new_file_and_empty_directory_destination_races_never_replace_the_owner(self) -> None:
        for directory in (False, True):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root)
                raced = []
                native = tx._rename_function()

                def rename(sfd, source, dfd, destination):
                    target = source.startswith("directory-") and destination == ".github" if directory else source == "new-0"
                    if target and not raced:
                        if directory:
                            os.mkdir(destination, dir_fd=dfd)
                        else:
                            handle = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dfd)
                            try:
                                os.write(handle, b"owner's newly created file")
                            finally:
                                os.close(handle)
                        raced.append(os.stat(destination, dir_fd=dfd).st_ino)
                    return native(sfd, source, dfd, destination)

                with patch.object(tx, "_rename_function", return_value=rename):
                    code, output, _ = invoke(args)
                self.assertEqual((code, output), (2, ""))
                self.assertTrue(raced)
                destination = root / (".github" if directory else "release/mobile-release.json")
                self.assertEqual(destination.stat().st_ino, raced[0])
                if directory:
                    self.assertEqual(list(destination.iterdir()), [])
                else:
                    self.assertEqual(destination.read_bytes(), b"owner's newly created file")
                state = snapshot(root)
                self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 2)
                self.assertEqual(snapshot(root), state)

    def test_source_replacement_during_retirement_preserves_user_edit_and_original_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.leave_pending(fixture(root, force=True))
            native, replaced = tx._rename_function(), []
            source_path = root / "release/mobile-release.json"

            def rename(sfd, source, dfd, destination):
                if (source, destination) == ("mobile-release.json", "new-0") and not replaced:
                    replacement = root / "owner-replacement"
                    replacement.write_bytes(b"new owner edit during rollback")
                    os.replace(replacement, source_path)
                    replaced.append(source_path.stat().st_ino)
                return native(sfd, source, dfd, destination)

            with patch.object(tx, "_rename_function", return_value=rename):
                code, output, _ = invoke(["init", "--root", str(root), "--recover"])
            self.assertEqual((code, output), (2, ""))
            self.assertTrue(replaced)
            self.assertEqual(source_path.stat().st_ino, replaced[0])
            self.assertEqual(source_path.read_bytes(), b"new owner edit during rollback")
            self.assertEqual((root / tx.READY / "old-0").read_bytes(), b"original config\r\n")

    def test_journal_handoff_source_replacement_is_compensated_including_non_directories(self) -> None:
        for old, new in ((tx.PREPARING, tx.READY), (tx.READY, tx.CLEANUP)):
            with self.subTest(handoff=(old, new)), tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
                root, external = Path(temporary).resolve(), Path(outside).resolve()
                args = fixture(root, force=True)
                before = snapshot(root)
                (external / "owner").write_bytes(b"external file")
                outside_before = snapshot(external)
                native, replaced = tx._rename_function(), []

                def rename(sfd, source, dfd, destination):
                    if (source, destination) == (old, new) and not replaced:
                        (root / old).rename(root / "detached-state")
                        (root / old).symlink_to(external, target_is_directory=True)
                        replaced.append(True)
                    return native(sfd, source, dfd, destination)

                with patch.object(tx, "_rename_function", return_value=rename):
                    code, output, _ = invoke(args)
                self.assertEqual((code, output), (2, ""))
                self.assertTrue(replaced)
                self.assertTrue((root / old).is_symlink())
                self.assertFalse((root / new).exists())
                self.assertEqual(snapshot(external), outside_before)
                (root / old).unlink()
                (root / "detached-state").rename(root / old)
                code, _, error = invoke(["init", "--root", str(root), "--recover"])
                self.assertEqual(code, 0, error)
                if old == tx.PREPARING:
                    self.assertEqual(snapshot(root), before)
                else:
                    self.assert_complete(root, force=True)
                self.assert_no_state(root)

    @contextlib.contextmanager
    def stopped_child(self, root: Path, mode: str, kind: str, label: str, when: str = "after"):
        process = subprocess.Popen(
            [sys.executable, "-P", str(Path(__file__).resolve()), "--child", str(root), mode, kind, label, when],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(30), "child never reached its real filesystem checkpoint")
            line = process.stdout.readline()
            self.assertEqual(line, b"CHECKPOINT\n", f"child exited early: {line!r}")
            yield process
        finally:
            # A failed leader can leave descendants holding pipes/locks. This
            # session belongs only to this fixture; never kill by process name.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
            deadline = time.monotonic() + 5
            while True:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                self.assertLess(time.monotonic(), deadline, "owned test process group survived cleanup")
                time.sleep(0.02)

    def kill_at(self, root: Path, mode: str, kind: str, label: str, when: str = "after") -> None:
        with self.stopped_child(root, mode, kind, label, when) as process:
            os.killpg(process.pid, signal.SIGKILL)
            self.assertEqual(process.wait(timeout=10), -signal.SIGKILL)

    def test_real_termination_in_each_phase_then_fresh_process_recovery(self) -> None:
        points = [
            ("mkdir", tx.PREPARING, False),
            ("rename", f"{tx.PREPARING}>{tx.READY}", False),
            ("rename", "mobile-release.json>old-0", False),
            ("rename", "new-0>mobile-release.json", False),
            ("rename", "commit.pending>COMMITTED", True),
            ("rename", f"{tx.READY}>{tx.CLEANUP}", True),
            ("unlink", "old-0", True),
            ("unlink", "plan.json", True),
            ("rmdir", tx.CLEANUP, True),
        ]
        for kind, label, committed in points:
            with self.subTest(point=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture(root, force=True)
                before = snapshot(root)
                self.kill_at(root, "apply", kind, label)
                result = subprocess.run([sys.executable, "-P", "-m", "mobile_release", "init", "--root", str(root), "--recover"],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                if committed:
                    self.assert_complete(root, force=True)
                else:
                    self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)
                self.assertEqual(json.loads(invoke(["init", "--root", str(root), "--recover"])[1])["recovery"], "no-op")

    def test_recovery_itself_can_be_killed_and_lock_rejects_concurrent_commands(self) -> None:
        for kind, label in (("rename", "mobile-release.json>new-0"),
                            ("rename", "old-0>mobile-release.json"),
                            ("rename", "rollback.pending>ROLLED_BACK"),
                            ("rename", f"{tx.READY}>{tx.CLEANUP}"),
                            ("unlink", "new-0"), ("unlink", "header.json")):
            with self.subTest(point=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = fixture(root, force=True)
                before = snapshot(root)
                with self.stopped_child(root, "apply", "rename", "new-0>mobile-release.json") as process:
                    current = snapshot(root)
                    for request in (args, ["init", "--root", str(root), "--recover"]):
                        code, output, error = invoke(request)
                        self.assertEqual(code, 2)
                        self.assertIn("another init/recovery", error)
                        self.assertEqual(output, "")
                        self.assertEqual(snapshot(root), current)
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                self.kill_at(root, "recover", kind, label)
                code, _, error = invoke(["init", "--root", str(root), "--recover"])
                self.assertEqual(code, 0, error)
                self.assertEqual(snapshot(root), before)
                self.assert_no_state(root)

    def test_recovery_rejects_corruption_extra_content_and_unrelated_user_edits(self) -> None:
        for mutation in ("duplicate", "unknown", "wrong-root", "lost-stage", "extra-private", "owner-file"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture(root, force=True)
                self.kill_at(root, "apply", "rename", "new-0>mobile-release.json")
                journal = root / tx.READY
                plan_path = journal / "plan.json"
                if mutation == "duplicate":
                    data = plan_path.read_bytes()
                    plan_path.write_bytes(data.replace(b'{"directories":', b'{"schemaVersion":1,"directories":', 1))
                elif mutation == "unknown":
                    plan = json.loads(plan_path.read_text()); plan["unknown"] = True
                    plan_path.write_text(json.dumps(plan))
                elif mutation == "wrong-root":
                    header = json.loads((journal / "header.json").read_text()); header["root"]["inode"] += 1
                    (journal / "header.json").write_text(json.dumps(header))
                elif mutation == "lost-stage":
                    next(journal.glob("new-*")).unlink()
                elif mutation == "extra-private":
                    (journal / "not-owned").write_bytes(b"preserve me")
                else:
                    (root / "release/mobile-release.json").write_bytes(b"intervening user edit")
                before = snapshot(root)
                saved_backup = (journal / "old-0").read_bytes()
                code, output, _ = invoke(["init", "--root", str(root), "--recover"])
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertEqual(snapshot(root), before)
                self.assertEqual((journal / "old-0").read_bytes(), saved_backup)

    def test_malformed_recovery_contracts_are_read_only_and_never_authorize_outside_paths(self) -> None:
        mutations = ("truncated-header", "truncated-plan", "unsafe-path", "duplicate-path", "reserved-path",
                     "wrong-type", "negative-size", "huge-size", "bad-hash", "extra-directory", "oversized-plan",
                     "symlink-backup", "special-file-mode", "public-journal-mode", "mutually-terminal")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
                root, external = Path(temporary).resolve(), Path(outside).resolve()
                self.leave_pending(fixture(root, force=True))
                (external / "owner").write_bytes(b"unrelated file")
                journal = root / tx.READY
                path = journal / "plan.json"
                plan = json.loads(path.read_bytes())
                if mutation == "truncated-header":
                    (journal / "header.json").write_bytes(b'{"schemaVersion":')
                elif mutation == "truncated-plan":
                    path.write_bytes(b'{"files":[')
                elif mutation == "oversized-plan":
                    path.write_bytes(b" " * (tx.MAX_CONTROL_BYTES + 1))
                elif mutation == "symlink-backup":
                    (journal / "old-0").rename(journal / "saved-original")
                    (journal / "old-0").symlink_to(external / "owner")
                elif mutation == "special-file-mode":
                    (journal / "old-0").chmod(0o4600)
                elif mutation == "public-journal-mode":
                    journal.chmod(0o755)
                elif mutation == "mutually-terminal":
                    (journal / "commit.pending").rename(journal / "COMMITTED")
                    (journal / "rollback.pending").rename(journal / "ROLLED_BACK")
                else:
                    if mutation == "unsafe-path":
                        plan["files"][0]["path"] = "../owner"
                    elif mutation == "duplicate-path":
                        plan["files"][1]["path"] = plan["files"][0]["path"]
                    elif mutation == "reserved-path":
                        plan["files"][0]["path"] = tx.CLEANUP + "/owner"
                    elif mutation == "wrong-type":
                        plan["files"][0]["before"]["inode"] = True
                    elif mutation == "negative-size":
                        plan["files"][0]["before"]["size"] = -1
                    elif mutation == "huge-size":
                        plan["files"][0]["before"]["size"] = tx.MAX_FILE_BYTES + 1
                    elif mutation == "bad-hash":
                        plan["files"][0]["before"]["sha256"] = "not-a-sha"
                    elif mutation == "extra-directory":
                        plan["directories"].append(plan["directories"][0])
                    path.write_text(json.dumps(plan))
                before, private_before, outside_before = snapshot(root), snapshot(journal), snapshot(external)
                code, output, _ = invoke(["init", "--root", str(root), "--recover"])
                self.assertEqual((code, output), (2, ""))
                self.assertEqual(snapshot(root), before)
                self.assertEqual(snapshot(journal), private_before)
                self.assertEqual(snapshot(external), outside_before)

    def test_cleanup_rejects_corrupt_terminal_after_data_and_plan_are_gone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture(root, force=True)
            self.kill_at(root, "apply", "unlink", "plan.json")
            journal = root / tx.CLEANUP
            self.assertEqual({p.name for p in journal.iterdir()}, {"header.json", "COMMITTED"})
            marker = journal / "COMMITTED"
            original = marker.read_bytes()
            marker.write_bytes(b'{"incomplete":')
            before, private_before = snapshot(root), snapshot(journal)
            code, output, _ = invoke(["init", "--root", str(root), "--recover"])
            self.assertEqual((code, output), (2, ""))
            self.assertEqual(snapshot(root), before)
            self.assertEqual(snapshot(journal), private_before)
            marker.write_bytes(original)
            self.assertEqual(invoke(["init", "--root", str(root), "--recover"])[0], 0)
            self.assert_complete(root, force=True)
            self.assert_no_state(root)

    def test_committed_recovery_preserves_later_user_edits_and_needs_no_templates_or_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture(root, force=True)
            self.kill_at(root, "apply", "rename", "commit.pending>COMMITTED")
            (root / "release/mobile-release.json").write_bytes(b"post-commit user edits")
            with patch.object(cli, "_init_proposal", side_effect=AssertionError("must not discover")), patch.object(
                cli, "_find_template_dir", side_effect=AssertionError("must not load templates")
            ):
                code, output, error = invoke(["init", "--root", str(root), "--recover"])
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["recovery"], "committed-cleanup")
            self.assertEqual((root / "release/mobile-release.json").read_bytes(), b"post-commit user edits")
            self.assert_no_state(root)


def child() -> None:
    root, mode, kind, label, when = Path(sys.argv[2]), *sys.argv[3:]
    signal.alarm(45)  # Last-resort self-limit; the parent also owns/kills the group.
    stopped = []

    def checkpoint(_index, event, phase):
        if (event["kind"], event["label"], phase) == (kind, label, when) and not stopped:
            stopped.append(True)
            print("CHECKPOINT", flush=True)
            sys.stdin.buffer.read(1)

    arguments = ["init", "--root", str(root), "--recover"] if mode == "recover" else [
        "init", "--root", str(root), "--apply", "--force", "--template-dir", str(root / "templates"),
        "--tooling-repository", "example/mobile-release-kit", "--tooling-sha", "a" * 40,
    ]
    with boundaries(checkpoint):
        raise SystemExit(cli.main(arguments))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child()
    else:
        unittest.main()
