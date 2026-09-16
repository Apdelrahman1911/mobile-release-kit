"""Focused app-private producer contracts; source-only until reviewed execution.

All filesystem effects are confined to synthetic test-owned roots. Commands,
threads, signals and native build/signing tools are vetoed, not exercised.
The modeled different UID is not a native UID/case-alias verification claim.
"""
from __future__ import annotations

import errno
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import build_inputs as inputs
from mobile_release import cancellation as cancellation_module
from mobile_release import ios, tooling
from mobile_release.config import load_config
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError, ProcessError
from mobile_release.provenance import copy_immutable_file, write_evidence
from mobile_release.reporting import Report

from .evidence_helpers import fixture_chain
from .helpers import android_config, ios_config, write_project


@contextmanager
def _umask(value):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


class AppPrivateProducerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-private-producer-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.serial = 0
        for name in ("kill", "killpg", "fork", "execve", "pipe"):
            veto = patch.object(command.os, name, side_effect=AssertionError("unexpected process effect"))
            veto.start(); self.addCleanup(veto.stop)
        for target, name in ((command.native, "create"), (command.threading.Thread, "start"),
                             (command.subprocess, "Popen"), (cancellation_module.signal, "signal")):
            veto = patch.object(target, name, side_effect=AssertionError("unexpected worker or signal setter"))
            veto.start(); self.addCleanup(veto.stop)

    def fixture(self, *, platform="android"):
        self.serial += 1
        app = self.root / str(self.serial)
        app.mkdir(mode=0o700)
        config = load_config(write_project(app, android_config() if platform == "android" else ios_config(),
                                           platform=platform))
        guard = inputs.DefaultCancellation(ProcessCleanupError, "synthetic producer owner")
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        return config, guard

    def snapshot(self, root):
        result = {}
        for path in (root, *sorted(root.rglob("*"))):
            observed = path.lstat()
            result[path.relative_to(root).as_posix()] = (
                observed.st_ino, observed.st_uid, observed.st_mode,
                path.read_bytes() if stat.S_ISREG(observed.st_mode) else
                os.readlink(path) if stat.S_ISLNK(observed.st_mode) else None,
            )
        return result

    def produce(self, config, guard, kind):
        private = config.root / ".mobile-release"
        if kind == "report":
            Report("doctor").emit(output=private / "reports/doctor.json", root=config.root,
                                  output_format="json", stream=io.StringIO(), cancellation=guard)
        elif kind in ("evidence", "store-evidence"):
            directory = "evidence" if kind == "evidence" else "store"
            write_evidence(private / directory / "candidate.json", fixture_chain()["candidate"],
                           app_root=config.root, cancellation=guard)
        elif kind == "copy":
            source = config.root / "synthetic-source"
            if not source.exists():
                source.write_bytes(b"synthetic immutable bytes")
            copy_immutable_file(source, private / "evidence/copy.bin", app_root=config.root,
                                cancellation=guard)
        else:
            with tooling.private_build_directory(config, "android", cancellation=guard) as owner:
                owner.check()

    def test_first_producers_create_0700_before_later_store_admission(self):
        for mask in (0o022, 0o077):
            for producer in ("report", "evidence", "copy", "build"):
                with self.subTest(mask=mask, producer=producer), _umask(mask):
                    config, guard = self.fixture()
                    self.produce(config, guard, producer)
                    private = config.root / ".mobile-release"
                    inode = private.stat().st_ino
                    self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                    self.assertFalse((private / "store").exists())
                    for path in private.rglob("*"):
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode),
                                         0o700 if path.is_dir() else 0o600)
                    with inputs.store_private_namespace(config.root, cancellation=guard) as owner:
                        self.assertEqual(owner.components, (".mobile-release", "store"))
                        self.assertEqual(owner.path.stat().st_mode & 0o777, 0o700)
                        self.assertEqual(private.stat().st_ino, inode)
                    self.assertTrue(owner.closed())

    def test_safe_reuse_keeps_root_copy_identity_and_fixed_role_collisions(self):
        config, guard = self.fixture()
        with inputs.app_private_role(config.root, role="empty-root", cancellation=guard) as root:
            self.assertEqual(len(root.slots), 1)
            inode = root.path.stat().st_ino
        self.produce(config, guard, "report")
        report = config.root / ".mobile-release/reports/doctor.json"
        self.produce(config, guard, "report")
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.produce(config, guard, "copy")
        copy = config.root / ".mobile-release/evidence/copy.bin"
        copy_inode = copy.stat().st_ino
        self.produce(config, guard, "copy")
        self.assertEqual(copy.stat().st_ino, copy_inode)
        self.produce(config, guard, "evidence")
        before = self.snapshot(config.root)
        with self.assertRaises(ValidationError):
            self.produce(config, guard, "evidence")
        self.assertEqual(self.snapshot(config.root), before)
        with self.assertRaisesRegex(ValidationError, "must be empty"):
            with inputs.app_private_role(config.root, role="empty-root", cancellation=guard):
                self.fail("populated staging root accepted")
        with inputs.app_private_role(config.root, role="android-handoff", cancellation=guard) as handoff:
            inputs._publish_private_file(handoff, "app-release.aab", iter((b"synthetic",)))
        handoff_before = self.snapshot(config.root / ".mobile-release/handoff")
        for role in ("android-handoff", "ios-handoff"):
            with self.assertRaisesRegex(ValidationError, "already exists"):
                with inputs.app_private_role(config.root, role=role, cancellation=guard):
                    self.fail("existing handoff parent was reused")
        self.assertEqual(self.snapshot(config.root / ".mobile-release/handoff"), handoff_before)
        self.assertEqual((config.root / ".mobile-release").stat().st_ino, inode)

    def test_incompatible_roots_and_fixed_parents_refuse_without_mutation(self):
        cases = [(producer, ".mobile-release", condition)
                 for producer in ("report", "evidence", "copy", "build")
                 for condition in ("0755", "symlink", "file", "different-uid")]
        cases += [(producer, path, "0755") for producer, path in (
            ("report", ".mobile-release/reports"), ("store-evidence", ".mobile-release/store"),
            ("build", ".mobile-release/build"), ("build", ".mobile-release/build/android"))]
        for producer, relative, condition in cases:
            with self.subTest(producer=producer, relative=relative, condition=condition):
                config, guard = self.fixture()
                (config.root / "synthetic-source").write_bytes(b"synthetic immutable bytes")
                target = config.root / relative
                current = config.root
                for name in Path(relative).parts[:-1]:
                    current /= name
                    current.mkdir(mode=0o700)
                if condition == "file":
                    target.write_bytes(b"preserve incompatible file")
                elif condition == "symlink":
                    destination = config.root / "synthetic-foreign"
                    destination.mkdir(mode=0o700)
                    (destination / "keep").write_bytes(b"preserve foreign bytes")
                    target.symlink_to(destination, target_is_directory=True)
                else:
                    target.mkdir(mode=0o700)
                    target.chmod(0o755 if condition == "0755" else 0o700)
                before = self.snapshot(config.root)
                expected_uid = os.geteuid() + (1 if condition == "different-uid" else 0)
                with patch.object(inputs.os, "geteuid", return_value=expected_uid), self.assertRaises(
                        (ValidationError, OSError, ProcessError)):
                    self.produce(config, guard, producer)
                self.assertEqual(self.snapshot(config.root), before)

    def test_fixed_build_reset_retains_live_original_target_and_preserves_replacement(self):
        for replace_target in (False, True):
            with self.subTest(replace_target=replace_target):
                config, guard = self.fixture()
                target = config.root / ".mobile-release/build/android"
                with inputs._app_private_directory(target, app_root=config.root, cancellation=guard) as owner:
                    inode = owner.path.stat().st_ino
                    (owner.path / "old").mkdir()
                    (owner.path / "old/mapping.txt").write_bytes(b"old synthetic mapping")
                    sibling = owner.path.parent / "ios"
                    sibling.mkdir(mode=0o700)
                    (sibling / "keep").write_bytes(b"other platform output")
                actual_remove = tooling.shutil.rmtree
                effects = []

                def remove(name, *, dir_fd):
                    self.assertEqual(os.fstat(dir_fd).st_ino, inode)
                    effects.append(name)
                    if replace_target:
                        target.rename(target.with_name("saved-original"))
                        target.mkdir(mode=0o700)
                        (target / "foreign").write_bytes(b"preserve replacement")
                    return actual_remove(name, dir_fd=dir_fd)

                remove.avoids_symlink_attacks = actual_remove.avoids_symlink_attacks
                with patch.object(tooling.shutil, "rmtree", remove):
                    if replace_target:
                        with self.assertRaises((ValidationError, ProcessError)):
                            with tooling.private_build_directory(config, "android", cancellation=guard):
                                self.fail("replacement became output custody")
                        self.assertEqual((target / "foreign").read_bytes(), b"preserve replacement")
                    else:
                        with tooling.private_build_directory(config, "android", cancellation=guard) as live:
                            self.assertEqual(live.path.stat().st_ino, inode)
                            self.assertEqual(list(live.path.iterdir()), [])
                            inputs._publish_private_file(live, "fresh", iter((b"new",)))
                        self.assertTrue(live.closed())
                self.assertEqual(effects, ["old"])
                self.assertEqual((sibling / "keep").read_bytes(), b"other platform output")

    def test_root_only_after_effect_unknown_preserves_namespace_and_closes_known_slots(self):
        for cut in ("mkdir", "open"):
            with self.subTest(cut=cut):
                config, guard = self.fixture()
                owner = inputs._StoreNamespace(config.root, guard, include_store=False)
                actual_mkdir, actual_open = os.mkdir, inputs._FD.open

                def mkdir(name, mode=0o777, *, dir_fd=None):
                    result = actual_mkdir(name, mode, dir_fd=dir_fd)
                    if cut == "mkdir" and name == ".mobile-release":
                        raise OSError("synthetic lost creation return")
                    return result

                def opening(slot, name, *args, **kwargs):
                    result = actual_open(slot, name, *args, **kwargs)
                    if cut == "open" and name == ".mobile-release":
                        raise OSError("synthetic lost descriptor handoff")
                    return result

                with patch.object(inputs.os, "mkdir", mkdir), patch.object(inputs._FD, "open", opening), self.assertRaises(
                        (OSError, ValidationError, ProcessError)):
                    with inputs._scope(owner, guard, False):
                        self.fail("unknown root acquisition yielded")
                self.assertEqual(len(owner.slots), 1)
                self.assertFalse(owner.closed())
                self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED"
                                    for slot in (*owner.parent.slots, *owner.slots)))
                self.assertTrue((config.root / ".mobile-release").is_dir())
                self.assertFalse((config.root / ".mobile-release/store").exists())

    def test_private_writer_failure_has_no_output_and_preserves_original_interruption(self):
        config, guard = self.fixture()
        original = KeyboardInterrupt("synthetic chunk interruption")

        def blocks():
            yield b"unfinished synthetic output"
            raise original

        with self.assertRaises(KeyboardInterrupt) as caught:
            with inputs.app_private_role(config.root, role="reports", cancellation=guard) as owner:
                inputs._publish_private_file(owner, "never.json", blocks())
        self.assertIs(caught.exception, original)
        self.assertEqual(list((config.root / ".mobile-release/reports").iterdir()), [])
        self.assertTrue(owner.closed())

    def test_private_publication_remains_anchored_when_parent_is_replaced_at_link(self):
        config, guard = self.fixture()
        actual_link = os.link
        saved = config.root / ".mobile-release/saved-reports"
        with self.assertRaises((ValidationError, ProcessError)):
            with inputs.app_private_role(config.root, role="reports", cancellation=guard) as owner:
                parent_inode = owner.path.stat().st_ino

                def link(source, target, *, src_dir_fd, dst_dir_fd, follow_symlinks):
                    self.assertEqual(os.fstat(src_dir_fd).st_ino, parent_inode)
                    self.assertEqual(src_dir_fd, dst_dir_fd)
                    owner.path.rename(saved)
                    owner.path.mkdir(mode=0o700)
                    (owner.path / "foreign").write_bytes(b"preserve foreign report")
                    return actual_link(source, target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                                       follow_symlinks=follow_symlinks)

                with patch.object(inputs.os, "link", link):
                    inputs._publish_private_file(owner, "never-authorized.json", iter((b"synthetic",)))
        self.assertEqual((config.root / ".mobile-release/reports/foreign").read_bytes(),
                         b"preserve foreign report")
        self.assertFalse((config.root / ".mobile-release/reports/never-authorized.json").exists())
        self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED"
                            for slot in (*owner.parent.slots, *owner.slots)))
        self.assertFalse(owner.closed())

    def test_private_copy_lost_link_return_cannot_become_matching_copy_success(self):
        config, guard = self.fixture()
        source = config.root / "source.bin"
        source.write_bytes(b"synthetic immutable copy")
        destination = config.root / ".mobile-release/evidence/copy.bin"
        actual_link = os.link
        attempts = []

        def link(source, target, *, src_dir_fd, dst_dir_fd, follow_symlinks):
            attempts.append(target)
            actual_link(source, target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                        follow_symlinks=follow_symlinks)
            raise FileExistsError(errno.EEXIST, "synthetic lost link return")

        with patch.object(inputs.os, "link", link), self.assertRaises(ProcessError) as failure:
            copy_immutable_file(source, destination, app_root=config.root, cancellation=guard)
        self.assertTrue(failure.exception.fatal)
        self.assertEqual(attempts, [destination.name])
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(list(destination.parent.iterdir()), [destination])
        self.assertEqual(destination.stat().st_nlink, 1)
        with self.assertRaises(ProcessError):
            guard.check()

        # A separate invocation may still admit a genuinely preexisting exact
        # copy. It is not a repair of the previous invocation's lost receipt.
        inode = destination.stat().st_ino
        fresh = inputs.DefaultCancellation(ProcessCleanupError, "synthetic fresh copy owner")
        fresh._installation, fresh._activated, fresh.depth = "INSTALLED", True, 0
        with patch.object(inputs.os, "link", side_effect=AssertionError("retry republished exact bytes")):
            copy_immutable_file(source, destination, app_root=config.root, cancellation=fresh)
        self.assertEqual(destination.stat().st_ino, inode)
        fresh.check()

    def test_report_publication_preserves_absent_and_existing_dispatch_substitutions(self):
        for existing in (False, True):
            for kind in ("file", "symlink", "directory"):
                with self.subTest(existing=existing, kind=kind):
                    config, guard = self.fixture()
                    actual_link, actual_rename = os.link, inputs._rename_function()
                    target_name = "report.json"
                    observed, calls = {}, []
                    with self.assertRaises((ValidationError, OSError)):
                        with inputs.app_private_role(config.root, role="reports", cancellation=guard) as owner:
                            parent = owner.fd
                            target = owner.path / target_name
                            if existing:
                                inputs._publish_private_file(owner, target_name, iter((b"original report",)))
                            (owner.path / "foreign-source").write_bytes(b"preserved foreign source")

                            def substitute():
                                if existing:
                                    actual_rename(parent, target_name, parent, "saved-original")
                                if kind == "file":
                                    target.write_bytes(b"preserved foreign report")
                                elif kind == "symlink":
                                    target.symlink_to("foreign-source")
                                else:
                                    target.mkdir(mode=0o700)
                                    (target / "keep").write_bytes(b"preserved foreign directory")
                                value = target.lstat()
                                observed["binding"] = (value.st_dev, value.st_ino, value.st_mode, value.st_uid)

                            def rename(source_fd, source, destination_fd, destination):
                                calls.append((source, destination))
                                if source == target_name:
                                    substitute()
                                return actual_rename(source_fd, source, destination_fd, destination)

                            def link(source, destination, *, src_dir_fd, dst_dir_fd, follow_symlinks):
                                if not existing:
                                    substitute()
                                return actual_link(source, destination, src_dir_fd=src_dir_fd,
                                                   dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks)

                            factory = (patch.object(inputs, "_rename_function", return_value=rename) if existing else
                                       patch.object(inputs, "_rename_function",
                                                    side_effect=AssertionError("absent report was retired")))
                            with factory, patch.object(inputs.os, "link", link), patch.object(
                                    inputs.os, "replace", side_effect=AssertionError("unconditional replacement")):
                                inputs._publish_private_file(owner, target_name, iter((b"new report",)), replace=True)
                    value = target.lstat()
                    self.assertEqual((value.st_dev, value.st_ino, value.st_mode, value.st_uid), observed["binding"])
                    if kind == "file":
                        self.assertEqual(target.read_bytes(), b"preserved foreign report")
                    elif kind == "symlink":
                        self.assertEqual(os.readlink(target), "foreign-source")
                    else:
                        self.assertEqual((target / "keep").read_bytes(), b"preserved foreign directory")
                    if existing:
                        self.assertEqual((owner.path / "saved-original").read_bytes(), b"original report")
                        self.assertEqual(len(calls), 2)  # One retirement, one exclusive restoration.
                    else:
                        self.assertEqual(calls, [])
                    self.assertFalse(any(path.name.startswith(".mrk-") for path in owner.path.iterdir()))
                    self.assertTrue(owner.closed())

    def test_report_return_losses_latch_failure_and_close_original_without_replay(self):
        for cut in ("retire", "retire-keyboard", "retire-system-exit", "link", "link-collision",
                    "restore", "unlink", "close-original"):
            with self.subTest(cut=cut):
                config, guard = self.fixture()
                actual_rename, actual_link = inputs._rename_function(), os.link
                actual_open, actual_close, actual_unlink = inputs._FD.open, os.close, os.unlink
                target_name = "report.json"
                record = {"renames": [], "links": 0, "original_closes": 0, "retired_unlinks": 0}
                interruption = (KeyboardInterrupt("synthetic retirement interruption") if cut == "retire-keyboard" else
                                SystemExit(0) if cut == "retire-system-exit" else None)
                with self.assertRaises(type(interruption) if interruption is not None else ProcessError) as failure:
                    with inputs.app_private_role(config.root, role="reports", cancellation=guard) as owner:
                        inputs._publish_private_file(owner, target_name, iter((b"original report",)))

                        def opening(slot, name, *args, **kwargs):
                            number = actual_open(slot, name, *args, **kwargs)
                            if name == target_name:
                                record["original_slot"], record["original_fd"] = slot, number
                            return number

                        def rename(source_fd, source, destination_fd, destination):
                            record["renames"].append((source, destination))
                            result = actual_rename(source_fd, source, destination_fd, destination)
                            if ((cut.startswith("retire") and source == target_name)
                                    or (cut == "restore" and source.startswith(".mrk-retired-"))):
                                if interruption is not None:
                                    raise interruption
                                raise OSError("synthetic lost exclusive rename return")
                            return result

                        def link(source, destination, *, src_dir_fd, dst_dir_fd, follow_symlinks):
                            record["links"] += 1
                            if cut == "restore":
                                raise OSError("synthetic publication refusal before effect")
                            if cut == "link-collision":
                                (owner.path / destination).write_bytes(b"preserved late foreign report")
                            result = actual_link(source, destination, src_dir_fd=src_dir_fd,
                                                 dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks)
                            if cut == "link":
                                raise FileExistsError(errno.EEXIST, "synthetic lost publication return")
                            return result

                        def unlink(name, *, dir_fd=None):
                            result = actual_unlink(name, dir_fd=dir_fd)
                            if str(name).startswith(".mrk-retired-"):
                                record["retired_unlinks"] += 1
                                if cut == "unlink":
                                    raise OSError("synthetic lost old-report unlink return")
                            return result

                        def close(number):
                            result = actual_close(number)
                            if number == record.get("original_fd"):
                                record["original_closes"] += 1
                                if cut == "close-original":
                                    raise OSError("synthetic lost original report close return")
                            return result

                        with patch.object(inputs, "_rename_function", return_value=rename), patch.object(
                                inputs._FD, "open", opening), patch.object(inputs.os, "link", link), patch.object(
                                inputs.os, "unlink", unlink), patch.object(inputs.os, "close", close):
                            inputs._publish_private_file(owner, target_name, iter((b"new report",)), replace=True)
                if interruption is not None:
                    self.assertIs(failure.exception, interruption)
                else:
                    self.assertTrue(failure.exception.fatal)
                self.assertTrue(guard.lifetime_ledger.verdict().fatal)
                self.assertEqual(record["original_closes"], 1)
                self.assertIsNone(record["original_slot"].number)
                self.assertEqual(record["original_slot"].close_state,
                                 "UNKNOWN" if cut == "close-original" else "CLOSED")
                self.assertEqual(len(record["renames"]), 2 if cut == "restore" else 1)
                self.assertEqual(record["links"], 0 if cut.startswith("retire") else 1)
                self.assertEqual(record["retired_unlinks"], int(cut in ("unlink", "close-original")))
                retired_name = record["renames"][0][1]
                if interruption is None:
                    self.assertIn(retired_name, str(failure.exception))
                retired = owner.path / retired_name
                target = owner.path / target_name
                if cut.startswith("retire") or cut in ("link", "link-collision"):
                    self.assertEqual(retired.read_bytes(), b"original report")
                else:
                    self.assertFalse(retired.exists())
                if cut.startswith("retire"):
                    self.assertFalse(target.exists())
                else:
                    expected = (b"original report" if cut == "restore" else
                                b"preserved late foreign report" if cut == "link-collision" else b"new report")
                    self.assertEqual(target.read_bytes(), expected)
                    self.assertEqual(target.stat().st_nlink, 1)
                self.assertFalse(any(path.name.startswith(".mrk-") and path != retired
                                     for path in owner.path.iterdir()))
                with self.assertRaises(ProcessError):
                    guard.check()
                self.assertTrue(owner.closed())  # Namespace FDs close despite the separate writer failure.

    def test_report_replacement_publishes_changed_complete_payload_without_residuals(self):
        config, guard = self.fixture()
        destination = config.root / ".mobile-release/reports/doctor.json"
        for command_name in ("before", "after"):
            Report(command_name).emit(output=destination, root=config.root, output_format="json",
                                      stream=io.StringIO(), cancellation=guard)
            self.assertEqual(json.loads(destination.read_bytes())["command"], command_name)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(list(destination.parent.iterdir()), [destination])
            if command_name == "before":
                original_inode = destination.stat().st_ino
        self.assertNotEqual(destination.stat().st_ino, original_inode)
        guard.check()

    def test_signed_ios_default_borrows_original_guard_before_private_output_and_commands(self):
        config, guard = self.fixture(platform="ios")
        session = SimpleNamespace(assert_owner=lambda: None, cancellation=guard)
        calls = []

        def run(argv, _root, _timeout, *, cancellation=None, signing_session=None, **kwargs):
            self.assertIs(cancellation, guard)
            self.assertIs(signing_session, session)
            guard.check()
            calls.append(argv)
            if "-archivePath" in argv:
                Path(argv[argv.index("-archivePath") + 1]).mkdir(exist_ok=True)
            if "-exportPath" in argv:
                output = Path(argv[argv.index("-exportPath") + 1])
                output.mkdir()
                (output / "synthetic.ipa").write_bytes(b"synthetic not signed IPA")

        with patch.object(ios, "sys", SimpleNamespace(platform="darwin")), patch.object(ios, "_run_checked", run), patch.dict(
                os.environ, {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": "SYNTHETIC-PROFILE"}):
            result = ios.run_ios_build(config, signed=True, signing_session=session)
            self.assertEqual(result["ios-ipa"].read_bytes(), b"synthetic not signed IPA")
            self.assertEqual(len(calls), 2)
            other, foreign = self.fixture(platform="ios")
            with self.assertRaisesRegex(ValidationError, "cancellation differs"):
                ios.run_ios_build(other, signed=True, signing_session=session, cancellation=foreign)
            self.assertFalse((other.root / ".mobile-release").exists())
            self.assertEqual(len(calls), 2)

    def test_public_custom_destinations_stay_generic_and_private_spelling_is_not_guessed(self):
        config, guard = self.fixture()
        with _umask(0o022):
            public = config.root / "public"
            write_evidence(public / "candidate.json", fixture_chain()["candidate"],
                           app_root=config.root, cancellation=guard)
            Report("custom").emit(output=public / "reports/custom.txt", root=config.root,
                                  stream=io.StringIO(), cancellation=guard)
            elsewhere = self.root / "unrelated/.mobile-release"
            copy_immutable_file(public / "candidate.json", elsewhere / "copy.json", app_root=config.root,
                                cancellation=guard)
            self.assertEqual(public.stat().st_mode & 0o777, 0o755)
            self.assertEqual((public / "reports").stat().st_mode & 0o777, 0o755)
            self.assertEqual(elsewhere.stat().st_mode & 0o777, 0o755)
            self.assertFalse((config.root / ".mobile-release").exists())

    def test_overrestrictive_umask_and_aliased_private_root_do_not_get_repaired(self):
        for condition in ("umask", "alias", "parent-traversal"):
            with self.subTest(condition=condition):
                config, guard = self.fixture()
                if condition == "umask":
                    with _umask(0o777), self.assertRaises((ValidationError, OSError, ProcessError)):
                        with inputs.app_private_namespace(config.root, cancellation=guard):
                            self.fail("incompatible created directory was chmodded/adopted")
                    private = config.root / ".mobile-release"
                    self.assertEqual(private.stat().st_mode & 0o777, 0)
                    private.chmod(0o700)  # Fixture-owned disposal only, not product recovery.
                else:
                    directory = config.root / (".Mobile-Release/reports" if condition == "alias" else
                                                "elsewhere/../.mobile-release/reports")
                    with self.assertRaisesRegex(ValidationError, "alias|traversal"):
                        with inputs._app_private_directory(directory, app_root=config.root,
                                                           cancellation=guard):
                            self.fail("unsafe lexical destination accepted")
                    self.assertFalse((config.root / ".mobile-release").exists())
