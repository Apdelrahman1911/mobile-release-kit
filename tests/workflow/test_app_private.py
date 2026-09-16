"""Focused local filesystem workflow closure; no process or Store fixture runs."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
import zipfile
from contextlib import chdir, contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import build_inputs as inputs
from mobile_release import workflow
from mobile_release.build_inputs import app_private_namespace, store_private_namespace
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError
from mobile_release.provenance import seal

from .test_workflow_recovery import FakeGitHub, Lifecycle, context, private_fixture_directory


@contextmanager
def scoped_umask(value):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


class AppPrivateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-app-private-workflow-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.guard = self.inert_guard()
        original_owner = inputs.cancellation_owner

        def borrow(requested, error, message):
            return original_owner(self.guard if requested is None else requested, error, message)

        owner = patch.object(inputs, "cancellation_owner", side_effect=borrow)
        owner.start(); self.addCleanup(owner.stop)
        for name in ("kill", "killpg", "fork", "execve", "pipe"):
            veto = patch.object(command.os, name, side_effect=AssertionError("unexpected process effect"))
            veto.start(); self.addCleanup(veto.stop)
        for target, name in ((command.native, "create"), (command.threading.Thread, "start"),
                             (command.subprocess, "Popen"), (workflow.signal, "signal")):
            veto = patch.object(target, name, side_effect=AssertionError("unexpected worker or signal setter"))
            veto.start(); self.addCleanup(veto.stop)

    def inert_guard(self):
        # Reuse the library producer tests' explicit zero-handler model. This
        # family does not claim real signal installation or process evidence.
        guard = inputs.DefaultCancellation(ProcessCleanupError, "synthetic workflow owner")
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        return guard

    def app(self, name="app"):
        root = self.root / name
        root.mkdir()
        self.guard = self.inert_guard()
        return root

    def write(self, path, data=b"fixture", mode=0o600):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            value = path.lstat()
            body = path.read_bytes() if stat.S_ISREG(value.st_mode) else os.readlink(path) if path.is_symlink() else None
            result[path.relative_to(self.root).as_posix()] = (value.st_dev, value.st_ino, value.st_uid, value.st_mode, body)
        return result

    def assert_private(self, app):
        private = app / ".mobile-release"
        for path in (private, *private.rglob("*")):
            self.assertFalse(path.is_symlink())
            self.assertEqual(0o700 if path.is_dir() else 0o600, stat.S_IMODE(path.stat().st_mode), str(path))

    def assert_subsequent_store(self, app):
        private = app / ".mobile-release"
        before = private.stat().st_ino
        self.assertFalse((private / "store").exists())
        with store_private_namespace(app) as owner:
            owner.check()
            self.assertEqual(0o700, stat.S_IMODE((private / "store").stat().st_mode))
        self.assertEqual(before, private.stat().st_ino)

    def build(self, app, platform):
        source = app / ".mobile-release/build" / platform
        reports = app / ".mobile-release/reports"
        private_fixture_directory(app, source)
        private_fixture_directory(app, reports)
        self.write(source / ("app-release.aab" if platform == "android" else "app.ipa"), b"already-validated-package")
        self.write(reports / f"signing-{platform}.json", b'{"fixture":"already-validated"}\n')
        if platform == "android":
            self.write(source / "mapping.txt", b"original mapping")
            self.write(source / "native-symbols.zip", b"original symbol bytes")
        else:
            archive = source / "archive.xcarchive"
            (archive / "Products/Applications/Fixture.app").mkdir(parents=True)
            (archive / "Empty").mkdir()
            self.write(archive / "Products/Applications/Fixture.app/Fixture", b"original executable", 0o755)
            self.write(archive / "Products/Applications/Fixture.app/Info.plist", b"original plist", 0o644)
            symbols = source / "dsyms/Fixture.app.dSYM/Contents/Resources/DWARF"
            symbols.mkdir(parents=True)
            self.write(symbols / "Fixture", b"original dwarf", 0o644)
        return source

    def test_local_empty_root_command_has_no_release_context_and_no_store(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                app = self.app(str(mask))
                with scoped_umask(mask), patch.object(workflow.Context, "current", side_effect=AssertionError("authentication reached")), \
                        patch.object(workflow.Transport, "run", side_effect=AssertionError("transport reached")):
                    self.assertEqual(0, workflow.main(["prepare-app-private", "--app-root", str(app), "--role", "empty-root"]))
                self.assertEqual([], list((app / ".mobile-release").iterdir()))
                self.assert_private(app)
                self.assert_subsequent_store(app)

    def test_empty_root_rejects_nonempty_0755_symlink_file_and_wrong_owner_without_mutation(self):
        for kind in ("nonempty", "0755", "symlink", "file", "uid"):
            with self.subTest(kind=kind):
                app = self.app(kind)
                private = app / ".mobile-release"
                if kind == "file":
                    self.write(private)
                elif kind == "symlink":
                    outside = self.root / "outside"
                    outside.mkdir(mode=0o700)
                    private.symlink_to(outside, target_is_directory=True)
                else:
                    private.mkdir(mode=0o755 if kind == "0755" else 0o700)
                    if kind == "0755":
                        private.chmod(0o755)  # Deliberately incompatible, independent of the enclosing umask.
                        self.assertEqual(0o755, stat.S_IMODE(private.stat().st_mode))
                    if kind == "nonempty":
                        self.write(private / "retained.json")
                before = self.snapshot()
                if kind == "uid":
                    uid = os.geteuid()
                    with patch("mobile_release.build_inputs.os.geteuid", return_value=uid + 1), self.assertRaises(ValidationError):
                        workflow.prepare_app_private(app)
                else:
                    with self.assertRaises((ValidationError, OSError)):
                        workflow.prepare_app_private(app)
                self.assertEqual(before, self.snapshot())

    def test_deferred_report_schema_private_mode_and_original_live_guard(self):
        app = self.app()
        original_publish = workflow._publish_private_file
        observations = []
        with scoped_umask(0o022), app_private_namespace(app) as original:
            def publish(owner, name, blocks, **options):
                owner.check()
                self.assertIs(original.cancellation, owner.cancellation)
                self.assertEqual(0o700, stat.S_IMODE(os.fstat(owner.fd).st_mode))
                observations.append(name)
                return original_publish(owner, name, blocks, **options)
            with patch.object(workflow, "_publish_private_file", side_effect=publish):
                workflow.write_deferred_report(app, "android", cancellation=original.cancellation)
                workflow.write_deferred_report(app, "android", cancellation=original.cancellation)
            original.check()
        report = app / ".mobile-release/reports/build-validation-deferred-android.json"
        self.assertEqual({"schemaVersion": 1, "platform": "android", "status": "deferred",
                          "reason": "source.projectReadTokenRequired is true",
                          "nextValidation": "Protected candidate preflight or a local preflight with credentials"}, json.loads(report.read_bytes()))
        self.assertEqual([report.name, report.name], observations)
        self.assert_private(app)
        self.assert_subsequent_store(app)

    def test_deferred_command_is_a_first_producer_and_needs_no_authentication(self):
        app = self.app()
        with scoped_umask(0o022), patch.object(workflow.Context, "current", side_effect=AssertionError("authentication reached")), \
                patch.object(workflow.Transport, "run", side_effect=AssertionError("transport reached")):
            self.assertEqual(0, workflow.main(["write-deferred-report", "--app-root", str(app), "--platform", "ios"]))
        self.assert_private(app)
        self.assertEqual("ios", json.loads((app / ".mobile-release/reports/build-validation-deferred-ios.json").read_bytes())["platform"])
        self.assert_subsequent_store(app)

    def test_unsafe_reports_parent_is_not_repaired_or_replaced(self):
        app = self.app()
        private_fixture_directory(app, app / ".mobile-release")
        reports = app / ".mobile-release/reports"
        reports.mkdir(mode=0o755)
        reports.chmod(0o755)
        self.assertEqual(0o755, stat.S_IMODE(reports.stat().st_mode))
        self.write(reports / "build-validation-deferred-android.json", b"retained original")
        before = self.snapshot()
        with patch.object(workflow, "_publish_private_file") as publish, self.assertRaises(ValidationError):
            workflow.write_deferred_report(app, "android")
        publish.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_android_copy_and_checksums_run_before_the_original_role_exits(self):
        app = self.app()
        self.build(app, "android")
        roles, validated = [], []
        original_role, original_validate = workflow.app_private_role, workflow._validate_handoff

        @contextmanager
        def role(*args, **options):
            with original_role(*args, **options) as owner:
                roles.append(owner)
                try:
                    yield owner
                finally:
                    roles.pop()

        def validate(path, platform, *args):
            self.assertEqual(1, len(roles))
            roles[0].check()
            self.assertEqual(roles[0].path, path)
            validated.append(platform)
            return original_validate(path, platform, *args)

        with scoped_umask(0o022), patch.object(workflow, "app_private_role", side_effect=role), \
                patch.object(workflow, "_validate_handoff", side_effect=validate), \
                patch.object(workflow.Context, "current", side_effect=AssertionError("authentication reached")):
            self.assertEqual(0, workflow.main(["normalize-handoff", "--app-root", str(app), "--platform", "android"]))
        self.assertEqual(["android"], validated)
        output = app / ".mobile-release/handoff/android"
        self.assertEqual({"app-release.aab", "mapping.txt", "native-symbols.zip", "validation-report.json", "SHA256SUMS"}, {p.name for p in output.iterdir()})
        self.assertEqual(b"original mapping", (output / "mapping.txt").read_bytes())
        self.assert_private(app)
        self.assert_subsequent_store(app)

    def test_ios_keep_parent_archives_retain_bytes_permissions_and_empty_directories(self):
        app = self.app()
        with scoped_umask(0o022):
            source = self.build(app, "ios")
            workflow.normalize_handoff(app, "ios")
        output = app / ".mobile-release/handoff/ios"
        for archive_name, parent in (("archive.zip", "archive.xcarchive"), ("dsyms.zip", "dsyms")):
            with zipfile.ZipFile(output / archive_name) as archive:
                expected = {parent + "/"} | {parent + "/" + p.relative_to(source / parent).as_posix() + ("/" if p.is_dir() else "") for p in (source / parent).rglob("*")}
                self.assertEqual(expected, set(archive.namelist()))
                for member in archive.infolist():
                    path = source / member.filename
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), stat.S_IMODE(member.external_attr >> 16))
                    if not member.is_dir():
                        self.assertEqual(path.read_bytes(), archive.read(member))
                    self.assertFalse(member.filename.startswith("__MACOSX/"))
        for path in output.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        workflow._validate_handoff(output, "ios")
        self.assert_subsequent_store(app)

    def test_handoff_parent_collision_refuses_even_a_different_platform(self):
        for platform, other in (("android", "ios"), ("ios", "android")):
            app = self.app(platform)
            self.build(app, platform)
            occupied = app / ".mobile-release/handoff" / other
            private_fixture_directory(app, occupied)
            self.write(occupied / "retained")
            before = self.snapshot()
            with self.assertRaises(ValidationError):
                workflow.normalize_handoff(app, platform)
            self.assertEqual(before, self.snapshot())

    def test_unsafe_fixed_build_parent_refuses_before_any_handoff_publication(self):
        app = self.app()
        source = self.build(app, "android")
        source.parent.chmod(0o755)  # An incompatible fixture, never production repair.
        self.assertEqual(0o755, stat.S_IMODE(source.parent.stat().st_mode))
        before = self.snapshot()
        with patch.object(workflow, "_private_file_writer") as writer, self.assertRaises(ValidationError):
            workflow.normalize_handoff(app, "android")
        writer.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_archive_symlink_is_never_followed_or_published(self):
        app = self.app()
        source = self.build(app, "ios")
        outside = self.root / "outside-payload"
        self.write(outside, b"must never be archived")
        (source / "archive.xcarchive/foreign").symlink_to(outside)
        before = outside.stat().st_ino, outside.read_bytes()
        with self.assertRaises(ValidationError):
            workflow.normalize_handoff(app, "ios")
        self.assertEqual(before, (outside.stat().st_ino, outside.read_bytes()))
        self.assertFalse((app / ".mobile-release/handoff/ios/archive.zip").exists())
        self.assertFalse((app / ".mobile-release/handoff/ios/SHA256SUMS").exists())

    def test_workflow_writers_create_all_private_parents_under_0022(self):
        source = self.root / "source"
        source.mkdir()
        self.write(source / "input.json", b"original")
        archive = self.root / "input.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("nested/input.json", b"original")
        for kind in ("json", "directory", "tree", "zip"):
            app = self.app(kind)
            output = app / ".mobile-release/staging/candidate/android"
            with scoped_umask(0o022):
                if kind == "json":
                    workflow._write_json(output / "value.json", {"fixture": True}, app_root=app)
                elif kind == "directory":
                    workflow._new_directory(output, app_root=app)
                elif kind == "tree":
                    workflow._copy_tree(source, output, app_root=app)
                else:
                    workflow._extract_zip(archive, output, workflow.MAX_EVIDENCE, app_root=app)
            self.assert_private(app)
            self.assert_subsequent_store(app)

    def test_private_writers_refuse_0755_root_without_mutating_it(self):
        source = self.root / "source"
        source.mkdir()
        self.write(source / "input.json")
        archive = self.root / "input.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("input.json", b"fixture")
        for kind in ("json", "directory", "tree", "zip"):
            app = self.app(kind)
            private = app / ".mobile-release"
            private.mkdir(mode=0o755)
            private.chmod(0o755)
            self.assertEqual(0o755, stat.S_IMODE(private.stat().st_mode))
            output = app / ".mobile-release/output"
            before = self.snapshot()
            with self.assertRaises(ValidationError):
                if kind == "json":
                    workflow._write_json(output / "value.json", {}, app_root=app)
                elif kind == "directory":
                    workflow._new_directory(output, app_root=app)
                elif kind == "tree":
                    workflow._copy_tree(source, output, app_root=app)
                else:
                    workflow._extract_zip(archive, output, workflow.MAX_EVIDENCE, app_root=app)
            self.assertEqual(before, self.snapshot())

    def test_external_destination_named_mobile_release_stays_generic(self):
        app = self.app()
        external = self.root / "external"
        external.mkdir(mode=0o755)
        external.chmod(0o755)
        self.assertEqual(0o755, stat.S_IMODE(external.stat().st_mode))
        named = external / ".mobile-release"
        named.mkdir(mode=0o755)
        named.chmod(0o755)
        self.assertEqual(0o755, stat.S_IMODE(named.stat().st_mode))
        before = named.stat().st_ino
        workflow._write_json(named / "candidate.json", {}, app_root=app)
        workflow._new_directory(named / "package", app_root=app)
        workflow._copy_tree(named / "package", named / "copied", app_root=app)
        self.assertEqual(before, named.stat().st_ino)
        self.assertEqual(0o755, stat.S_IMODE(named.stat().st_mode))
        self.assertFalse((app / ".mobile-release").exists())

    def resolution(self):
        selected = context()
        resolution = self.root / "resolution"
        resolution.mkdir(mode=0o700)
        payload = resolution / "artifacts/android"
        payload.mkdir(parents=True)
        self.write(payload / "app-release.aab", b"original")
        self.write(payload / "validation-report.json", b"{}")
        checksums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(payload.iterdir()))
        self.write(payload / "SHA256SUMS", checksums.encode("ascii"))
        files = workflow._files(resolution, maximum=workflow.MAX_HANDOFF)
        value = {"documentType": "workflow-resolution", "schemaVersion": 1,
                 "stage": selected.stage, "platform": selected.platform, "repository": dict(selected.repository),
                 "dispatch": dict(selected.authority), "jobKey": selected.current_job, "mode": "prepare",
                 "source": {"commit": "2" * 40, "tree": "3" * 40, "ref": "refs/heads/main"},
                 "authorizationRunId": selected.authority["runId"], "evidenceRunId": "", "evidenceArtifactId": "",
                 "files": [{"path": name, "size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for name, p in sorted(files.items())]}
        workflow._write_json(resolution / "resolution.json", seal(value))
        return resolution, selected

    def test_stage_first_run_reacquires_custody_and_keeps_authenticated_layout(self):
        app = self.app()
        resolution, selected = self.resolution()
        with scoped_umask(0o022), patch.object(workflow, "_verify_checkout") as checkout:
            workflow.stage_resolution(resolution, app, selected)
        checkout.assert_called_once()
        self.assertEqual(b"original", (app / ".mobile-release/artifacts/android/app-release.aab").read_bytes())
        self.assertTrue((app / ".mobile-release/operation").is_dir())
        self.assert_private(app)
        before = self.snapshot()
        with patch.object(workflow, "_verify_checkout"), self.assertRaises(ValidationError):
            workflow.stage_resolution(resolution, app, selected)
        self.assertEqual(before, self.snapshot())
        self.assert_subsequent_store(app)

    def test_stage_refuses_incompatible_root_after_authentication_without_writes(self):
        app = self.app()
        private = app / ".mobile-release"
        private.mkdir(mode=0o755)
        private.chmod(0o755)
        self.assertEqual(0o755, stat.S_IMODE(private.stat().st_mode))
        resolution, selected = self.resolution()
        before = self.snapshot()
        with patch.object(workflow, "_verify_checkout") as checkout, self.assertRaises(ValidationError):
            workflow.stage_resolution(resolution, app, selected)
        checkout.assert_called_once()
        self.assertEqual(before, self.snapshot())

    def test_actual_sealing_and_final_packaging_bind_private_destination(self):
        api = FakeGitHub()
        with scoped_umask(0o022):
            lifecycle = Lifecycle(self.root, api)
            selected, app, intent = lifecycle.prepare("candidate")
            destination = app / ".mobile-release/package/candidate/android"
            # The actual YAML passes app/.mobile-release/package/... relative
            # to the workspace, not relative to the explicit app root again.
            with chdir(self.root):
                package = lifecycle.finish("candidate", selected, app, intent,
                                           destination=destination.relative_to(self.root)).absolute()
        self.assertEqual(destination, package)
        self.assertTrue((package / "workflow-provenance.json").is_file())
        self.assert_private(app)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            workflow._new_directory(destination, app_root=app)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
