"""Focused DATA/filesystem contracts; never launch a compiler/native/process test.

Run only through the admitted test owner. Synthetic archives are small ordinary
files in a test-owned TemporaryDirectory; no upstream archive, network, command,
tool/SDK discovery, source build or supplier activation occurs here.
"""
from __future__ import annotations

from contextlib import contextmanager
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILD = load("_mrk_darwin_build_test_data", "macos_cpython_source_build.py")
PROBE = load("_mrk_darwin_probe_test_data", "macos_cpython_source_probe.py")


@contextmanager
def scratch():
    with tempfile.TemporaryDirectory(prefix="mrk-darwin-source-data-") as name:
        path = Path(name)
        try:
            yield path
        finally:
            # Only this original test directory, never a project/cache path.
            for directory, children, _ in os.walk(path, followlinks=False):
                os.chmod(directory, 0o700)
                for child in children:
                    selected = Path(directory) / child
                    if not selected.is_symlink():
                        os.chmod(selected, 0o700)


def make_configuration(exe=".exe", multiarch="darwin"):
    prefix, sdk = Path("/private/task/prefix"), Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")
    values = {
        "BUILDEXE": exe, "BUILDPYTHON": "python$(BUILDEXE)", "VERSION": "3.14", "MACHDEP": "darwin",
        "ABIFLAGS": "", "PY_ENABLE_SHARED": "0", "CC": "/Apple/clang", "PYTHON_FOR_REGEN": "/chosen/python3",
        "LIBEXPAT_A": "Modules/expat/libexpat.a", "MODULE_ZLIB_LDFLAGS": str(prefix / "lib/libz.a"),
        "CONFIGURE_CFLAGS": BUILD.compiler_flags(sdk), "CONFIGURE_CPPFLAGS": "",
        "CONFIGURE_LDFLAGS": BUILD.linker_flags(sdk) + " -L" + str(prefix / "lib"),
        "MACOSX_DEPLOYMENT_TARGET": "26.0",
        "MODBUILT_NAMES": " ".join(BUILD.BOOTSTRAP + BUILD.OPTIONAL), "MODSHARED_NAMES": "",
        "MODDISABLED_NAMES": " ".join(BUILD.DISABLED),
        "MODULE__CTYPES_CFLAGS": "-fno-strict-overflow -I" + str(sdk / "usr/include/ffi") + " -DUSING_APPLE_OS_LIBFFI=1 -DUSING_MALLOC_CLOSURE_DOT_C=1",
        "MODULE__CTYPES_LDFLAGS": "-lffi -ldl",
        "MODULE_PYEXPAT_CFLAGS": "-I$(srcdir)/Modules/expat",
        "MODULE_PYEXPAT_LDFLAGS": "-lm $(LIBEXPAT_A)",
        "MODULE__SCPROXY_LDFLAGS": "-framework SystemConfiguration -framework CoreFoundation",
        "MODULE__SSL_CFLAGS": "-I" + str(prefix / "include"),
        "MODULE__SSL_LDFLAGS": "-L" + str(prefix / "lib") + " -lssl -lcrypto", "MULTIARCH": multiarch,
    }
    required = "WITH_PYMALLOC HAVE_FORK HAVE_POSIX_SPAWN HAVE_SYS_RESOURCE_H HAVE_WAITPID HAVE_POLL HAVE_SOCKETPAIR HAVE_FFI_PREP_CIF_VAR HAVE_FFI_PREP_CLOSURE_LOC HAVE_FFI_CLOSURE_ALLOC".split()
    setup = (ROOT / "desktop/tools/macos_cpython_source_setup.local").read_bytes().replace(b"@MRK_PREFIX@", str(prefix).encode())
    names = BUILD.BOOTSTRAP + BUILD.INTRINSIC + BUILD.OPTIONAL
    files = {"Makefile": "".join(key + "=" + value + "\n" for key, value in values.items()).encode(),
        "pyconfig.h": "".join("#define " + key + " 1\n" for key in required).encode(),
        "Modules/config.c": ("struct _inittab _PyImport_Inittab[] = {\n" +
            "".join('{"' + name + '", init_' + name + "},\n" for name in names) + "{0, 0}\n};\n").encode(),
        "Modules/Setup.local": setup}
    return files, prefix, sdk


def mach_o(*, dylib=b"/usr/lib/libSystem.B.dylib", minimum=26 << 16, extra=b""):
    def named(command, header_size, name):
        size = (header_size + len(name) + 1 + 7) & ~7
        head = struct.pack("<III", command, size, header_size)
        return head + b"\0" * (header_size - len(head)) + name + b"\0" * (size - header_size - len(name))

    commands = [named(0xE, 12, b"/usr/lib/dyld"), named(0xC, 24, dylib),
        struct.pack("<IIIIII", 0x32, 24, 1, minimum, 26 << 16, 0),
        struct.pack("<IIQQ", 0x80000028, 24, 0, 0),
        struct.pack("<IIII", 0x1D, 16, 0, 0)]
    if extra:
        commands.append(extra)
    body = b"".join(commands)
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x100000C, 0, 2, len(commands), len(body), 0, 0) + body


def archive_fixture(component="zlib", *, trailer=b"", compression_trailer=b"", body=b"public source\n"):
    prefix, logical = "Fixture-1", "/work/inputs/sources/" + component + "/"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in (prefix, prefix + "/Lib"):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(item)
        item = tarfile.TarInfo(prefix + "/Lib/source with spaces.py")
        item.size, item.mode, item.mtime = len(body), 0o644, 1700000000
        archive.addfile(item, io.BytesIO(body))
    raw = buffer.getvalue() + trailer
    compressed = (lzma.compress(raw) if component == "cpython" else gzip.compress(raw, mtime=0)) + compression_trailer
    source = SimpleNamespace(component=component, size=len(compressed), sha256=BUILD.digest(compressed), original_prefix=logical)
    rows = {"Lib/source with spaces.py": {"path": logical + "Lib/source with spaces.py", "size": len(body),
                                            "sha256": BUILD.digest(body), "mode": 0o644}}
    provenance = {"archiveRoot": prefix, "archive": {"size": len(compressed), "sha256": source.sha256},
        "decodedTar": {"size": len(raw), "sha256": BUILD.digest(raw)},
        "directories": [{"path": logical.rstrip("/")}, {"path": logical + "Lib"}],
        "modeProjection": {"directories": {str(0o755): 0o755}, "files": {str(0o644): 0o644}}}
    return source, compressed, rows, provenance


def parser_instance(path, source, rows, provenance):
    instance = BUILD.Build.__new__(BUILD.Build)  # No native host/owner acquisition.
    instance.private = path
    (path / "archives").mkdir(mode=0o700)
    (path / "sources").mkdir(mode=0o700)
    instance.check = lambda: None
    instance.deadline = time.monotonic() + 10
    instance.source_rows = {source.component: rows}
    instance.source_trees = {}
    instance.provenance = {source.component: provenance}
    return instance


class MacPythonSourceBuildTests(unittest.TestCase):
    def test_configuration_keeps_darwin_ffi_scproxy_static_archives_and_generated_names(self):
        for suffix, multiarch in ((".exe", "darwin"), ("", "")):
            files, prefix, sdk = make_configuration(suffix, multiarch)
            result = BUILD.python_configuration(files, prefix, sdk, "/Apple/clang", "/chosen/python3")
            self.assertEqual(result["executable"], "python" + suffix)
            self.assertEqual(result["generated"], ["_sysconfigdata__darwin_" + multiarch + ".py",
                "_sysconfig_vars__darwin_" + multiarch + ".json", "build-details.json"])
            self.assertEqual(len(result["builtins"]), 61)
        files, prefix, sdk = make_configuration()
        mutations = [
            ("Makefile", b"BUILDEXE=.exe", b"BUILDEXE=/other/python"),
            ("Makefile", b"MODSHARED_NAMES=", b"MODSHARED_NAMES=_ssl"),
            ("Makefile", b"-DUSING_APPLE_OS_LIBFFI=1", b"-DWRONG_FFI=1"),
            ("Makefile", b"-fno-strict-overflow -I", b"-fstrict-overflow -I"),
            ("Makefile", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl -lprivate"),
            ("Makefile", b"MACOSX_DEPLOYMENT_TARGET=26.0", b"MACOSX_DEPLOYMENT_TARGET=15.0"),
            ("Makefile", b"-lm $(LIBEXPAT_A)", b"-lexpat"),
            ("Makefile", b"-framework SystemConfiguration", b"-framework Unselected"),
            ("Makefile", b"PYTHON_FOR_REGEN=/chosen/python3", b"PYTHON_FOR_REGEN=python3"),
            ("pyconfig.h", b"#define HAVE_FFI_PREP_CIF_VAR 1", b"/* feature absent */"),
            ("Modules/Setup.local", b"/lib/libssl.a", b"/lib/libssl.dylib"),
            ("Modules/Setup.local", b"_ctypes/malloc_closure.c", b""),
        ]
        for name, old, new in mutations:
            with self.subTest(name=name, mutation=old):
                changed = {**files, name: files[name].replace(old, new)}
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration(changed, prefix, sdk, "/Apple/clang", "/chosen/python3")

    def test_macho_refuses_foreign_deployment_loader_injection_and_truncation(self):
        self.assertEqual(PROBE.macho(mach_o())["architecture"], "arm64")
        wrong_cpu = bytearray(mach_o())
        struct.pack_into("<i", wrong_cpu, 4, 0x1000007)
        for body in (bytes(wrong_cpu), mach_o(minimum=25 << 16), mach_o(dylib=b"@rpath/libssl.dylib"),
                     mach_o(extra=struct.pack("<IIQ", 0x8000001C, 16, 0)), mach_o()[:-1],
                     b"\xca\xfe\xba\xbe" + mach_o()[4:]):
            with self.subTest(prefix=body[:8]):
                with self.assertRaises(PROBE.ProbeRefused):
                    PROBE.macho(body)

    def test_inventory_does_not_admit_aliases_modes_or_unbound_shapes(self):
        source = SimpleNamespace(original_prefix="/work/inputs/sources/cpython/")
        row = {"path": source.original_prefix + "Lib/source with spaces.py", "size": 1,
               "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o644}
        self.assertEqual(list(BUILD.inventory(BUILD.canonical({"files": [row]}), source)), ["Lib/source with spaces.py"])
        bad = [[{**row, "path": source.original_prefix + "../escape"}], [{**row, "mode": 0o777}],
               [{**row, "size": True}], [row, row], [row, {**row, "path": row["path"].upper()}]]
        for rows in bad:
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.inventory(BUILD.canonical({"files": rows}), source)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.decode(b'{"files":[],"files":[]}')

    def test_original_result_deadline_and_finality_are_not_success_defaults(self):
        self.assertEqual(BUILD.remaining(10.9, 5.2, 9), 5)
        for deadline, now in ((10.0, 10.0), (10.0, 9.1), (float("nan"), 1)):
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.remaining(deadline, now)
        argv = ["fixed", "argument"]
        self.assertTrue(BUILD.original_result(subprocess.CompletedProcess(argv, 0, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, False, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, 0, "", b""), argv))
        good = dict(failure=None, entered=2, returned=2, ledger={"complete": True, "fatal": False, "contained": True},
                    handlers="RESTORED", scratch_retired=True, data_finality=True)
        self.assertTrue(BUILD.public_eligible(**good))
        for changes in (dict(failure={"type": "earlier-failure"}), dict(returned=1), dict(entered=True),
                        dict(handlers="UNKNOWN"), dict(scratch_retired=False), dict(data_finality=False),
                        dict(ledger={"complete": 1, "fatal": False, "contained": True}),
                        dict(ledger={"complete": True, "fatal": False, "contained": None})):
            self.assertFalse(BUILD.public_eligible(**{**good, **changes}))
        state, closes, original = BUILD.DataFinality(), [], object()
        with self.assertRaises(ValueError):
            with state.acquiring(lambda: original, closes.append) as captured:
                self.assertIs(captured, original)
                self.assertFalse(state.known)
                raise ValueError("known failed read")
        self.assertTrue(state.known)
        self.assertEqual(closes, [original])

        def ambiguous_close(captured):
            self.assertIs(captured, original)
            raise OSError("injected original close failure")

        with self.assertRaises(OSError):
            with state.acquiring(lambda: original, ambiguous_close):
                pass
        state.close(lambda: closes.append("unrelated-close"))
        self.assertFalse(state.known)  # A later successful close cannot repair it.
        self.assertFalse(BUILD.public_eligible(**{**good, "data_finality": state.known}))
        lost = BUILD.DataFinality()

        def constructor_result_loss():
            self.assertFalse(lost.known)  # Armed before constructor dispatch.
            raise OSError("injected acquisition result loss")

        with self.assertRaises(OSError):
            with lost.acquiring(constructor_result_loss, closes.append):
                self.fail("unreturned acquisition entered body")
        with lost.acquiring(lambda: original, closes.append):
            pass
        self.assertFalse(lost.known)  # No repair by an independent acquisition.
        self.assertTrue(BUILD.DATA.known)  # Faults used separate inert DATA state.

    def test_real_small_source_projection_preserves_bytes_modes_and_inventory(self):
        for component in ("cpython", "zlib"):
            source, compressed, rows, provenance = archive_fixture(component)
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                parser.extract(source, compressed)
                projected = root / "sources" / component / "Lib/source with spaces.py"
                self.assertEqual(projected.read_bytes(), b"public source\n")
                self.assertEqual(projected.stat().st_mode & 0o777, 0o444)
                self.assertEqual(projected.stat().st_mtime_ns, 1700000000 * 1000000000)
                self.assertEqual((projected.parent.stat().st_mode & 0o777), 0o555)

    def test_real_small_source_projection_refuses_crc_tail_and_body_mismatch(self):
        cases = [archive_fixture(compression_trailer=gzip.compress(b"unselected")),
                 archive_fixture(trailer=b"x" * 512), archive_fixture()]
        source, compressed, rows, provenance = cases[-1]
        cases[-1] = (source, compressed, {name: {**row, "sha256": "0" * 64} for name, row in rows.items()}, provenance)
        for source, compressed, rows, provenance in cases:
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                with self.assertRaises((BUILD.BuildRefused, zlib.error)):
                    parser.extract(source, compressed)
        source, compressed, rows, provenance = archive_fixture()
        changed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
        source.size, source.sha256 = len(changed), BUILD.digest(changed)
        provenance["archive"] = {"size": len(changed), "sha256": source.sha256}
        with scratch() as root:
            with self.assertRaises(zlib.error):
                parser_instance(root, source, rows, provenance).extract(source, changed)

    def test_retained_tar_preserves_exact_supplier_modes_and_readback(self):
        with scratch() as root:
            supplier = root / "supplier"
            (supplier / "python/bin").mkdir(mode=0o700, parents=True)
            (supplier / "python/lib").mkdir(mode=0o700)
            rows = []
            for name, body, mode in (("python/bin/python3", b"not-executable-test-data", 0o555),
                                     ("python/lib/fixture.txt", b"public fixture", 0o444)):
                rows.append({"path": name, **BUILD.write(supplier / name, body, mode)})
            BUILD.seal(supplier)
            result = BUILD.supplier_tar(supplier, root / "supplier.tar", rows, deadline=time.monotonic() + 10)
            self.assertEqual(result["files"], 2)
            self.assertTrue(result["modePreservation"])
            self.assertEqual(BUILD.digest((root / "supplier.tar").read_bytes()), result["sha256"])
            self.assertEqual(list(BUILD.tree_rows(supplier, maximum=1024, max_files=3).values()), rows)

if __name__ == "__main__":
    unittest.main()
