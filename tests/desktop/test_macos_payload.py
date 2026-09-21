"""Focused DATA tests: no subprocess, signals, native SDK, runtime or network.

Imports only the inert publisher module. Fixtures are small ordinary task-owned
files or text/tar headers. Even successful owner doubles are DATA, never native
settlement evidence. Execute this file only after SOURCE/COMMAND acceptance.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("mrk_macos_payload_data", SOURCE / "desktop/tools/macos_payload.py")
assert spec is not None and spec.loader is not None
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def archive_bytes(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, kind in members:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = kind, 0o755, 1234567890
            if kind == tarfile.REGTYPE:
                info.size = 6
                archive.addfile(info, io.BytesIO(b"INERT\n"))
            else:
                info.linkname = "../outside"
                archive.addfile(info)
    return result.getvalue()


def native_text(commands):
    # Text expected from otool, not actual Mach-O/native qualification.
    return "/inert/native-copy:\n" + "".join(
        f"Load command {index}\n          cmd {name}\n      cmdsize 64\n" + fields + "\n"
        for index, (name, fields) in enumerate(commands))


BUILD_VERSION = ("LC_BUILD_VERSION", "     platform 1\n        minos 26.0\n          sdk 26.0\n       ntools 1")


def library(name, kind="LC_LOAD_DYLIB"):
    return kind, "         name " + name + " (offset 24)"


def job_double(root, *, result=None, verdict=None):
    # Deliberately bypass Job.__init__: no source/core owner import or install.
    job = payload.Job.__new__(payload.Job)
    job.root, job.records, job.failed, job.evidence_bytes = root, [], False, 0
    job.end, job.hard, job.environment = 100.0, 130.0, {"LANG": "C"}
    job.clock = SimpleNamespace(check=Mock(), phase="closed", expired=False)
    verdict = verdict or SimpleNamespace(complete=True, fatal=False, commands=1,
                                        command_contained=True, profile_calls=0)
    job.guard = SimpleNamespace(handler_state="RESTORED", lifetime_ledger=SimpleNamespace(verdict=lambda: verdict))
    job.run_owned = Mock(return_value=result or SimpleNamespace(returncode=0, stdout=b"inert\n", stderr=b""))
    return job


class MacOSPayloadDataTests(unittest.TestCase):
    def test_deadline_allocation_reserves_original_tail_without_renewal(self):
        self.assertEqual(payload.command_timeout(100, 94.1), 2)
        self.assertEqual(payload.command_timeout(100, 95.1), 1)
        self.assertEqual(payload.command_timeout(2000, 0), 720)
        for end, now in ((100, 96.1), (100, 100), (float("inf"), 0), (100, float("nan"))):
            with self.subTest(end=end, now=now), self.assertRaises(payload.Refused):
                payload.command_timeout(end, now)

    def test_only_native_upstream_make_defaults_are_augmented(self):
        original = "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E\nPYTHON_FOR_FREEZE=./_bootstrap_python\n"
        self.assertEqual(payload.no_bytecode_make(original), [
            "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B", "PYTHON_FOR_FREEZE=./_bootstrap_python -B"])
        for changed in (original.replace("./$(BUILDPYTHON) -E", "./python -E"),
                        original.replace("./_bootstrap_python", "/inert/cross-python"),
                        original + "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E\n"):
            with self.subTest(changed=changed), self.assertRaises(payload.Refused):
                payload.no_bytecode_make(changed)
        for suffix in ("", ".exe"):
            self.assertEqual(payload.build_executable("BUILDPYTHON=python$(BUILDEXE)\nBUILDEXE=" + suffix + "\n"), "python" + suffix)
        with self.assertRaises(payload.Refused):
            payload.build_executable("BUILDPYTHON=python$(BUILDEXE)\nBUILDEXE=/alternate\n")
        setup = (SOURCE / "desktop/tools/cpython_macos_setup.local").read_text()
        self.assertIn("_ctypes/malloc_closure.c", setup)
        self.assertIn("_scproxy", payload.setup_names(setup)["disabled"])
        for name in payload.HACL:
            self.assertIn(f"Modules/_hacl/libHacl_{name}.a", setup)
        recipe = inspect.getsource(payload.build)
        for flag in ("--without-mimalloc", "--disable-framework", "--disable-shared", "--with-ensurepip=no",
                     "--with-openssl-rpath=no", "no-autoload-config", "no-module", "PYTHONSTRICTEXTENSIONBUILD"):
            self.assertIn(flag, recipe + inspect.getsource(payload.prepare_tools))
        self.assertNotIn('tools["curl"]', recipe)

    def test_generated_builtin_roster_is_parsed_not_a_linux_count(self):
        text = 'struct _inittab _PyImport_Inittab[] = {\n /* source comment */\n {"sys", NULL},\n {"_ssl", PyInit__ssl},\n {0, 0}\n};'
        self.assertEqual(payload.builtin_table(text), {"sys", "_ssl"})
        for bad in (text.replace('{0, 0}', '{"sys", NULL}, {0, 0}'),
                    text.replace('/* source comment */', '#if SOMETHING\n#endif')):
            with self.assertRaises(payload.Refused):
                payload.builtin_table(bad)

    def test_generated_configuration_uses_one_actual_pybuilddir_not_root_guess(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            python_build = root / "cpython"
            relative = "build/lib.macosx-26.0-arm64-3.14"
            generated = python_build / relative
            generated.mkdir(parents=True)
            pointer = python_build / "pybuilddir.txt"
            pointer.write_text(relative + "\n", encoding="ascii")
            (python_build / "build-details.json").write_bytes(b"WRONG ROOT FILE\n")
            contents = {"build-details.json": b'{"location":"actual generated directory"}\n',
                        "_sysconfigdata__darwin_darwin.py": b"build_time_vars = {}\n",
                        "_sysconfig_vars__darwin_darwin.json": b"{}\n"}
            for leaf, body in contents.items():
                (generated / leaf).write_bytes(body)
            selected = payload.generated_configuration(python_build)
            self.assertEqual(selected, {leaf: generated / leaf for leaf in contents})
            # Both consumers use the same selection, even if the routing file
            # is later changed. No build/owner/native function is executed.
            pointer.write_text("invalid after selection\n", encoding="ascii")
            for destination in (root / "evidence/configuration", root / "payload/python/lib/python3.14"):
                for leaf, source in selected.items():
                    payload.copy_file(source, destination / leaf)
                    self.assertEqual((destination / leaf).read_bytes(), contents[leaf])
            (python_build / "not-a-directory").write_bytes(b"ordinary inert file\n")
            for invalid in ("../outside", "/absolute", "build//lib", "build/./lib", "build/../lib",
                            ".", "build/", "build\\lib", "not-a-directory/lib", "build/" + "a" * 1024):
                with self.subTest(invalid=invalid), self.assertRaises(payload.Refused):
                    pointer.write_text(invalid + "\n", encoding="ascii")
                    payload.generated_configuration(python_build)
            pointer.write_text(relative + "\n", encoding="ascii")
            duplicate = generated / "_sysconfigdata_duplicate.py"
            duplicate.write_bytes(b"{}\n")
            with self.assertRaises(payload.Refused):
                payload.generated_configuration(python_build)
            duplicate.unlink()
            (generated / "build-details.json").unlink()
            with self.assertRaises(FileNotFoundError):
                payload.generated_configuration(python_build)
            self.assertEqual((python_build / "build-details.json").read_bytes(), b"WRONG ROOT FILE\n")

    def test_checked_in_source_ca_and_notice_pins_are_coherent(self):
        inputs = payload.load_inputs(SOURCE)
        self.assertEqual([row["id"] for row in inputs["sources"]], ["cpython", "zlib", "openssl"])
        self.assertEqual(inputs["sources"][0]["sha256"],
                         "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81")
        with self.assertRaises(payload.Refused):
            json.loads('{"schemaVersion":1,"schemaVersion":1}', object_pairs_hook=payload.pairs)

    def test_streaming_copy_preserves_bytes_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            source, destination = root / "source", root / "copy"
            original = b"INERT\n" * (payload.CHUNK // 6 + 1)
            source.write_bytes(original)
            row = payload.copy_file(source, destination, mode=0o755)
            self.assertEqual(row, {"size": len(original), "sha256": hashlib.sha256(original).hexdigest()})
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
            with self.assertRaises(FileExistsError):
                payload.copy_file(source, destination)
            self.assertEqual(destination.read_bytes(), original)

    def test_original_reader_closes_once_and_refuses_changed_input(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            source = Path(name) / "input"
            source.write_bytes(b"INERT\n")
            close = payload.os.close
            with patch.object(payload.os, "close", wraps=close) as observed:
                with self.assertRaisesRegex(RuntimeError, "inert consumer"):
                    payload.read_stream(source, 64, Mock(side_effect=RuntimeError("inert consumer")))
                self.assertEqual(observed.call_count, 1)
            with self.assertRaises(payload.Refused):
                payload.read_stream(source, 64, lambda _: source.write_bytes(b"changed and longer\n"))

    def test_pinned_archive_bytes_are_used_and_original_timestamps_survive(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            body = archive_bytes([("fixed/configure", tarfile.REGTYPE)])
            source = root / "archive"
            source.write_bytes(body)
            pin = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(), "root": "fixed"}
            real_read = payload.read_file
            def read_then_change(path, limit, poll):
                result = real_read(path, limit, poll)
                path.write_bytes(b"changed pathname after checked read")
                return result
            with patch.object(payload, "read_file", side_effect=read_then_change):
                rows = payload.extract_source(source, pin, root / "extracted")
            self.assertEqual((root / "extracted/configure").read_bytes(), b"INERT\n")
            self.assertEqual((root / "extracted/configure").stat().st_mtime_ns, 1234567890000000000)
            self.assertEqual(rows[0]["originalMode"], 0o755)

    def test_archive_traversal_aliases_and_link_headers_never_escape(self):
        cases = ([('fixed/../outside', tarfile.REGTYPE)],
                 [('fixed/Name', tarfile.REGTYPE), ('fixed/name', tarfile.REGTYPE)],
                 [('fixed/link', tarfile.SYMTYPE)])
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                root = Path(name)
                body = archive_bytes(members)
                (root / "archive").write_bytes(body)
                pin = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(), "root": "fixed"}
                with self.assertRaises(payload.Refused):
                    payload.extract_source(root / "archive", pin, root / "extracted")
                self.assertFalse((root / "outside").exists())

    def test_thin_arm64_header_and_complete_load_correspondence(self):
        root = Path("/inert/task")
        commands = [BUILD_VERSION, library("/usr/lib/dyld", "LC_LOAD_DYLINKER"),
                    library("/usr/lib/libSystem.B.dylib"),
                    *(library(str(root / "deps/lib" / name)) for name in payload.DYLIBS)]
        header = "/inert/native-copy:\nMach header\nmagic cputype cpusubtype caps filetype ncmds sizeofcmds flags\nMH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 5 2000 NOUNDEFS\n"
        count = payload.macho_header(header, "EXECUTE")
        original = payload.library_commands(native_text(commands), count)
        changes, expected = payload.relocation(original, 0, root)
        self.assertEqual(set(changes.values()), {"@executable_path/../lib/" + n for n in payload.DYLIBS})
        self.assertIsNone(expected["id"])
        dylib = payload.library_commands(native_text([BUILD_VERSION,
            library(str(root / "deps/lib/libcrypto.3.dylib"), "LC_ID_DYLIB"),
            library("/usr/lib/libSystem.B.dylib")]), 3)
        self.assertEqual(payload.relocation(dylib, 1, root)[1]["id"], "@rpath/libcrypto.3.dylib")
        for bad in (header.replace("ARM64", "X86_64"), "Fat headers\n" + header,
                    header.replace("EXECUTE", "DYLIB")):
            with self.assertRaises(payload.Refused):
                payload.macho_header(bad, "EXECUTE")
        for bad_commands in ([BUILD_VERSION, library("/inert/lib", "LC_LOAD_WEAK_DYLIB")],
                             [BUILD_VERSION, ("LC_DYLD_ENVIRONMENT", "name DYLD_LIBRARY_PATH=/inert (offset 12)")],
                             [BUILD_VERSION, library("/a"), library("/a")]):
            with self.assertRaises(payload.Refused):
                payload.library_commands(native_text(bad_commands), len(bad_commands))
        for bad in (dict(original, dependencies=["/usr/local/lib/libssl.3.dylib"]),
                    dict(original, id="unexpected"), dict(original, rpaths=["/usr/local/lib"])):
            with self.assertRaises(payload.Refused):
                payload.relocation(bad, 0, root)

    def test_failed_or_unsettled_original_result_latches_no_later_command(self):
        for fail_call in (False, True):
            with self.subTest(fail_call=fail_call), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                root = Path(name)
                verdict = SimpleNamespace(complete=False, fatal=True, commands=0, command_contained=False, profile_calls=0)
                job = job_double(root, verdict=verdict)
                if fail_call:
                    job.run_owned.side_effect = RuntimeError("inert original failure")
                with patch.object(payload.time, "monotonic", return_value=10), \
                     patch.object(payload.shutil, "disk_usage", return_value=SimpleNamespace(free=3 * 1024**3)):
                    with self.assertRaises((RuntimeError, payload.Refused)):
                        job.run("inert-original", ["/not-executed"])
                    with self.assertRaises(payload.Refused):
                        job.run("never-dispatched", ["/not-executed"])
                self.assertTrue(job.failed)
                self.assertEqual(job.run_owned.call_count, 1)
                self.assertEqual(job.records[0]["status"], "failed")
                self.assertFalse((root / "evidence").exists())

    def test_success_data_requires_original_finality_and_persisted_output_budget(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            job = job_double(root)
            with patch.object(payload.time, "monotonic", return_value=10), \
                 patch.object(payload.shutil, "disk_usage", return_value=SimpleNamespace(free=3 * 1024**3)):
                self.assertEqual(job.run("inert-original", ["/not-executed"]), b"inert\n")
            self.assertEqual(job.evidence_bytes, 6)
            self.assertTrue(payload.original_settled(job))
            job.guard.handler_state = "UNKNOWN"
            self.assertFalse(payload.original_settled(job))
            job.guard.handler_state = "RESTORED"
            job.records[0]["originalFinality"] = False
            self.assertFalse(payload.original_settled(job))
            job.evidence_bytes = payload.EVIDENCE_LIMIT
            with self.assertRaises(payload.Refused):
                job.retain("no-room", b"x")
            self.assertFalse((root / "evidence/no-room").exists())

    def test_cleanup_never_adopts_a_different_task_root(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            job = job_double(root)
            job.root_identity = (-1, -1)
            with patch.object(payload, "original_settled", return_value=True), \
                 patch.object(payload.shutil, "rmtree") as remove:
                remove.avoids_symlink_attacks = True
                with self.assertRaises(payload.Refused):
                    payload.remove_disposable(job)
                remove.assert_not_called()
            self.assertTrue(root.is_dir())

    def test_final_archive_preserves_executable_mode_and_never_executes_payload(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            payload.write_file(root / "payload/python/bin/python3", b"INERT, NOT AN EXECUTABLE\n", 0o755)
            job = SimpleNamespace(root=root, hard=100)
            with patch.object(payload.time, "monotonic", return_value=1):
                result = payload.archive_payload(job)
            self.assertEqual(result["sha256"], hashlib.sha256((root / "payload.tar").read_bytes()).hexdigest())
            with tarfile.open(root / "payload.tar", "r") as archive:
                members = archive.getmembers()
                self.assertEqual([m.name for m in members], ["payload/python/bin/python3"])
                self.assertEqual(members[0].mode, 0o755)
                with archive.extractfile(members[0]) as body:
                    self.assertEqual(body.read(), b"INERT, NOT AN EXECUTABLE\n")

    def test_single_native_workflow_and_fixed_clean_request_route(self):
        workflow = (SOURCE / ".github/workflows/desktop-macos-payload.yml").read_text()
        self.assertIn("runs-on: macos-26", workflow)
        self.assertNotIn("matrix:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("ci_foundation.py", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("desktop/tools/macos_payload.py", workflow)
        self.assertEqual(payload.REQUEST_SHIM, 'exec "$1" -I -S -B "$2" "$3" < "$4"')
        self.assertIn("assert sys.prefix == str(p / 'python')", payload.SMOKE)
        self.assertIn("assert sys._is_gil_enabled()", payload.SMOKE)
        self.assertIn("assert set(os.environ) ==", payload.SMOKE)


if __name__ == "__main__":
    unittest.main()
