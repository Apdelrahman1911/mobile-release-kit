"""Tiny genuine source/ZIP custody with inert Git only; no build/Store/native."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from mobile_release import local_release_source as S, local_release_metadata as M
from mobile_release import build_inputs as B
from mobile_release.config import default_config_data
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError


class LocalMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mrk-local-metadata-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir(mode=0o700)
        data = default_config_data({"android": {"applicationId": "com.example.reader"}})
        data["source"]["localStoreEnabled"] = True
        data["android"].update(enabled=True, identityStatus="approved",
            externalTrack={"kind": "closed", "name": "beta"}, uploadCertificateSha256="ab" * 32)
        self.config = json.dumps(data).encode()
        self.version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        self.metadata = self.root / data["metadata"]["root"]
        self.selected = self.metadata / "android/en-US/title.txt"
        self.tracked = {S.CONFIG_PATH: self.config, data["version"]["source"]: self.version,
            ".gitignore": b".mobile-release/\n",
            self.selected.relative_to(self.root).as_posix(): b"Reviewed title\n",
            (self.metadata / "android/en-US/.gitkeep").relative_to(self.root).as_posix(): b""}
        for name, body in self.tracked.items():
            self.write(self.root / name, body)
        for name, body in {"config": b"[core]\nrepositoryformatversion=0\nbare=false\n",
            "HEAD": b"ref: refs/heads/main\n", "refs/heads/main": b"a" * 40 + b"\n",
            "index": b"inert-index-actual-original"}.items():
            self.write(self.root / ".git" / name, body)
        for name in ("objects/info", "info"):
            (self.root / ".git" / name).mkdir(parents=True, mode=0o700)

    def write(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
        path.chmod(0o600)

    def command(self, argv, **kwargs):
        rows = [(name.encode(), hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest().encode())
                for name, body in sorted(self.tracked.items())]
        if "config" in argv:
            body = b"core.repositoryformatversion\n0\0core.bare\nfalse\0"
        elif "rev-parse" in argv:
            body = b"a" * 40 + b"\n" + b"b" * 40 + b"\n"
        elif "ls-tree" in argv:
            body = b"".join(b"100644 blob " + blob + b"\t" + name + b"\0" for name, blob in rows)
        elif "--stage" in argv:
            body = b"".join(b"100644 " + blob + b" 0\t" + name + b"\0" for name, blob in rows)
        elif "ls-files" in argv:
            body = b"".join(b"H " + name + b"\0" for name, _ in rows)
        else:
            self.assertIn("status", argv)
            body = b""
        return SimpleNamespace(args=argv, returncode=0, stdout=body, stderr=b"")

    @contextmanager
    def subject(self):
        with patch.object(S, "run_owned", side_effect=self.command):
            with B.invocation_custody(self.root, mode="build") as invocation:
                with invocation.project(signing_lease=None):
                    invocation.project_owner.ensure_meta()
                    source = S.LocalSourceObservation(invocation, self.config, self.version, S._now() + 60, None)
                    metadata = M.LocalMetadataSource(source)
                    self.last_metadata = metadata
                    with S._retain_source(source):
                        yield source, metadata

    def scratch(self, source, metadata):
        scratch = B.FiniteScratch("store-metadata", source.guard, self.root / ".mobile-release")
        quote = metadata.reserve(scratch)
        self.assertLessEqual(quote["ownedDescriptors"], 256)
        self.assertGreater(quote["assemblyBytes"], 2 * M.MAX_ARCHIVE_SIZE)
        return scratch

    def test_owned_archive_exact_default_bytes_and_no_store_binding(self):
        with self.subject() as (source, metadata):
            scratch = self.scratch(source, metadata)
            with B._scope(scratch, source.guard, False):
                selected = scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                owned = scratch.require(selected).read_bytes()
                self.assertIs(selected._owner, scratch)
                self.assertIsNone(scratch._lane_binding)
                self.assertTrue(metadata.closed)
                self.assertTrue(all(it.close_state == "closed" for it in metadata.iterators))
                self.assertEqual(source.calls, 7)
                with B.finite_scratch(layout="store-metadata", cancellation=source.guard,
                                      parent=self.root / ".mobile-release") as ordinary:
                    default = ordinary.metadata_archive(self.metadata, platform="android")
                    self.assertEqual(owned, ordinary.require(default).read_bytes())
                with zipfile.ZipFile(io.BytesIO(owned)) as archive:
                    self.assertEqual(archive.namelist(), ["android/en-US/title.txt"])
                    self.assertEqual(archive.read(archive.namelist()[0]), b"Reviewed title\n")
            self.assertFalse(scratch._path.exists())

    def test_changed_omitted_extra_directory_link_and_mode_refuse(self):
        for change in ("changed", "omitted", "ignored-extra", "empty-dir", "link", "executable"):
            with self.subTest(change=change):
                original = self.selected.read_bytes()
                extra = self.selected.parent / "extra.txt"
                empty = self.selected.parent / "empty"
                try:
                    with self.subject() as (source, metadata):
                        scratch = self.scratch(source, metadata)
                        with B._scope(scratch, source.guard, False):
                            if change == "changed": self.selected.write_bytes(b"Not committed\n")
                            elif change == "omitted": self.selected.unlink()
                            elif change == "ignored-extra": self.write(extra, b"ignored")
                            elif change == "empty-dir": empty.mkdir()
                            elif change == "link":
                                self.selected.unlink(); self.selected.symlink_to(".gitkeep")
                            else: self.selected.chmod(0o700)
                            with self.assertRaises((ValidationError, OSError)):
                                scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                            self.assertFalse(scratch.snapshots)
                            self.assertTrue(metadata.failed)
                finally:
                    if self.selected.is_symlink(): self.selected.unlink()
                    self.write(self.selected, original)
                    if extra.exists(): extra.unlink()
                    if empty.exists(): empty.rmdir()

    def test_postpublication_leaf_parent_roster_changes_veto_token(self):
        for change in ("leaf", "parent", "roster"):
            with self.subTest(change=change):
                moved = self.selected.parent.with_name("old-locale")
                extra = self.selected.parent / "extra.txt"
                try:
                    with self.subject() as (source, metadata):
                        scratch = self.scratch(source, metadata)
                        publish = scratch._publish
                        def after(*args, **kwargs):
                            result = publish(*args, **kwargs)
                            if change == "leaf": self.selected.write_bytes(b"After publication\n")
                            elif change == "parent":
                                self.selected.parent.rename(moved)
                                self.write(self.selected, b"Reviewed title\n")
                            else: self.write(extra, b"extra")
                            return result
                        with B._scope(scratch, source.guard, False):
                            with patch.object(scratch, "_publish", side_effect=after), self.assertRaises(ValidationError):
                                scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                            self.assertIn("metadata", scratch.snapshots)  # Published original, never accepted return.
                            self.assertTrue(metadata.failed)
                        self.assertFalse(scratch._path.exists())
                finally:
                    if moved.exists():
                        self.selected.unlink(); self.selected.parent.rmdir(); moved.rename(self.selected.parent)
                    if extra.exists(): extra.unlink()
                    self.write(self.selected, b"Reviewed title\n")

    def test_last_original_status_return_cannot_hide_metadata_mutation(self):
        for change in ("leaf", "parent", "roster", "borrowed-ancestor"):
            with self.subTest(change=change):
                moved = self.selected.parent.with_name("old-locale")
                release = self.root / "release"
                old_release = self.root / "old-release"
                extra = self.selected.parent / "extra.txt"
                try:
                    with self.subject() as (source, metadata):
                        scratch = self.scratch(source, metadata)
                        command = self.command
                        def after(argv, **kwargs):
                            result = command(argv, **kwargs)
                            if "status" in argv:
                                if change == "leaf": self.selected.write_bytes(b"Late original status\n")
                                elif change == "parent":
                                    self.selected.parent.rename(moved)
                                    self.write(self.selected, b"Reviewed title\n")
                                elif change == "roster": self.write(extra, b"late extra")
                                else:
                                    release.rename(old_release)
                                    release.mkdir()
                            return result
                        with B._scope(scratch, source.guard, False):
                            with patch.object(S, "run_owned", side_effect=after), self.assertRaises(ValidationError):
                                scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                            self.assertEqual(source.calls, 7)  # Same original six+one; no second query.
                            self.assertTrue(metadata.failed)
                            if old_release.exists(): release.rmdir(); old_release.rename(release)
                        self.assertFalse(scratch._path.exists())
                finally:
                    if old_release.exists(): release.rmdir(); old_release.rename(release)
                    if moved.exists():
                        self.selected.unlink(); self.selected.parent.rmdir(); moved.rename(self.selected.parent)
                    if extra.exists(): extra.unlink()
                    self.write(self.selected, b"Reviewed title\n")

    def test_row_budget_and_suffix_refuse_before_scratch(self):
        with patch.object(M, "MAX_ROWS_BYTES", 1), self.assertRaises(S.LocalSourceError):
            with self.subject(): self.fail("over-budget source admitted")
        name = (self.metadata / "android/en-US/tool.sh").relative_to(self.root).as_posix()
        self.tracked[name] = b"not executable"
        self.write(self.root / name, self.tracked[name])
        with self.assertRaises(S.LocalSourceError):
            with self.subject(): self.fail("unsupported source admitted")

    def test_reservation_is_original_preacquisition_and_composition_stays_closed(self):
        with self.subject() as (source, metadata):
            scratch = B.FiniteScratch("store-metadata", source.guard, self.root / ".mobile-release")
            with patch.object(source, "_composition", object(), create=True), self.assertRaises(M.LocalMetadataError):
                metadata.reserve(scratch)
            self.assertFalse(scratch.created)
            with B._scope(scratch, source.guard, False), self.assertRaises(M.LocalMetadataError):
                metadata.reserve(scratch)

    def test_count_directory_fd_and_file_byte_quotes_refuse_before_publication(self):
        for cap in ("MAX_FILE_COUNT", "MAX_DIRECTORIES"):
            with self.subTest(cap=cap), patch.object(M, cap, 1), self.assertRaises(S.LocalSourceError):
                with self.subject(): self.fail("source quote overflow admitted")
        with self.subject() as (source, metadata):
            scratch = B.FiniteScratch("store-metadata", source.guard, self.root / ".mobile-release")
            with patch.object(M, "MAX_FDS", 1), self.assertRaises(M.LocalMetadataError):
                metadata.reserve(scratch)
            self.assertFalse(scratch.created)
        with self.subject() as (source, metadata):
            scratch = self.scratch(source, metadata)
            with B._scope(scratch, source.guard, False):
                with self.selected.open("r+b") as handle:
                    handle.truncate(M.MAX_FILE_SIZE + 1)
                with self.assertRaises(M.LocalMetadataError):
                    scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                self.assertFalse(scratch.snapshots)

    def test_cancel_after_publication_never_returns_snapshot(self):
        with self.assertRaises((KeyboardInterrupt, ProcessCleanupError, ValidationError)):
            with self.subject() as (source, metadata):
                scratch = self.scratch(source, metadata)
                publish = scratch._publish
                def after(*args, **kwargs):
                    result = publish(*args, **kwargs)
                    source.guard.cancelled = True
                    return result
                with B._scope(scratch, source.guard, False), patch.object(scratch, "_publish", side_effect=after):
                    scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                    self.fail("cancelled snapshot returned")
        self.assertTrue(self.last_metadata.failed)

    def test_original_leaf_close_unknown_vetoes_and_is_not_retried(self):
        consumed = []
        original_close = os.close
        with self.assertRaises((ProcessCleanupError, ValidationError)):
            with self.subject() as (source, metadata):
                scratch = self.scratch(source, metadata)
                def close(number):
                    if metadata.leaf is not None and any(slot.number == number for slot in metadata.leaf.descriptors):
                        self.fail("Reader retires numeric slot before consuming close")
                    # The Reader deliberately clears slot.number before os.close.
                    if metadata.leaf is not None and any(slot.state == "CLOSING" for slot in metadata.leaf.descriptors):
                        self.assertFalse(consumed)
                        consumed.append(number)
                        original_close(number)
                        raise OSError("inert lost close return")
                    return original_close(number)
                with B._scope(scratch, source.guard, False), patch.object(os, "close", side_effect=close):
                    scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                    self.fail("unknown original close returned snapshot")
        self.assertEqual(len(consumed), 1)
        self.assertTrue(self.last_metadata.failed)
        self.assertTrue(all(slot.state == "CLOSED" for slot in self.last_metadata.reader.descriptors))

    def test_iterator_lost_close_return_is_absorbing_and_other_originals_close(self):
        closes = []
        with self.assertRaises((ProcessCleanupError, ValidationError, RuntimeError)):
            with self.subject() as (source, metadata):
                scratch = self.scratch(source, metadata)
                original_scandir = os.scandir
                class LostClose:
                    def __init__(self, number): self.original = original_scandir(number)
                    def __iter__(self): return self
                    def __next__(self): return next(self.original)
                    def close(self):
                        closes.append(1)
                        self.original.close()
                        raise OSError("inert lost iterator close")
                with B._scope(scratch, source.guard, False), patch.object(os, "scandir", side_effect=LostClose):
                    scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                    self.fail("unknown iterator returned snapshot")
        self.assertEqual(closes, [1])
        self.assertTrue(self.last_metadata.failed)
        self.assertTrue(all(slot.state == "CLOSED" for slot in self.last_metadata.reader.descriptors))

    def test_absent_selected_tree_exact_empty_zip_and_late_addition_refuses(self):
        for path in (self.selected, self.selected.parent / ".gitkeep"):
            del self.tracked[path.relative_to(self.root).as_posix()]
            path.unlink()
        self.selected.parent.rmdir(); (self.metadata / "android").rmdir()
        for late in (False, True):
            with self.subTest(late=late), self.subject() as (source, metadata):
                scratch = self.scratch(source, metadata)
                publish = scratch._publish
                def after(*args, **kwargs):
                    result = publish(*args, **kwargs)
                    if late: (self.metadata / "android").mkdir()
                    return result
                try:
                    with B._scope(scratch, source.guard, False), patch.object(scratch, "_publish", side_effect=after):
                        if late:
                            with self.assertRaises(M.LocalMetadataError):
                                scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                        else:
                            snapshot = scratch.metadata_archive(self.metadata, platform="android", _source=metadata)
                            with zipfile.ZipFile(scratch.require(snapshot)) as archive:
                                self.assertEqual(archive.namelist(), [])
                finally:
                    if late: (self.metadata / "android").rmdir()
