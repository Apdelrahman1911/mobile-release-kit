"""Focused INERT source-authoring fixtures; run only after separate review.

No compiler, shell, native query, archive extraction, candidate import, process,
network, installed runtime or real owner is invoked. ELF headers are synthetic
DATA without executable code. File cases use only owned TemporaryDirectory
leaves; process seams are mocks. Authored here, not executed during authoring.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import shlex
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


I = load("source_inputs_fixture", "desktop/tools/cpython_static_inputs.py")
R = load("source_recipe_fixture", "desktop/tools/cpython_source_recipe.py")
B = load("source_root_fixture", "desktop/tools/cpython_static_builder_data.py")
P = load("source_copy_fixture", "desktop/tools/prepare_cpython_static_payload.py")


def record(path, raw=b"INERT DATA\n"):
    return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def lock_shape_fixture():
    """Input-shape DATA only; no files, approval pin or build are admitted."""
    core = [record(I.CORE_ROOT / name) for name in sorted(I.SOURCE_CORE_HANDOFFS | {"src/mobile_release/__init__.py"})]
    ca = next(row for row in core if row["path"].endswith("/desktop/github-ca.pem"))
    ca.update(size=I.SOURCE_CA[0], sha256=I.SOURCE_CA[1])
    sources = []
    for name, (version, size, hashed, url) in sorted(I.SOURCE_ARCHIVES.items()):
        sources.append({"id": name, "version": version,
            "archive": {"path": "/inert/" + name + ".archive", "size": size, "sha256": hashed}, "url": url,
            "root": str(I.SOURCE_ROOT / name), "inventory": record("/inert/" + name + ".inventory"), "patches": []})
    return {"schema": I.SOURCE_LOCK_SCHEMA, "profile": I.SOURCE_PROFILE, "state": "sealed-inputs-only",
        "target": I.TARGET, "rootfs": record("/inert/rootfs"), "hostInputs": record("/inert/host-inputs"),
        "sources": sources, "coreSourceFiles": core,
        "recipeFiles": [record(Path(I.__file__).parent / name) for name in sorted(I.SOURCE_BUILD_FILES)],
        "environment": I.SOURCE_ENV, "configuration": I.source_configuration()}


def generated_config():
    names = sorted((*I.BOOTSTRAP_MODULES, *I.INTRINSIC_MODULES, *I.SOURCE_STATIC_MODULES))
    config = ('struct _inittab _PyImport_Inittab[] = {\n' +
              ''.join('{"' + name + '", inert_init},\n' for name in names) + '{0, 0}\n};\n').encode()
    assignments = {
        "MODBUILT_NAMES": " ".join((*I.BOOTSTRAP_MODULES, *I.SOURCE_STATIC_MODULES)),
        "MODSHARED_NAMES": "", "MODDISABLED_NAMES": " ".join(I.SOURCE_DISABLED_MODULES),
        "VERSION": "3.14", "MACHDEP": "linux", "MULTIARCH": "x86_64-linux-gnu", "HOST_GNU_TYPE": "x86_64-pc-linux-gnu",
        "ABIFLAGS": "", "PY_ENABLE_SHARED": "0", "CC": I.SOURCE_TOOLS["cc"],
        "CONFIGURE_CFLAGS": I.FIXED_ENV["CFLAGS"], "CONFIGURE_CFLAGS_NODIST": "",
        "CONFIGURE_LDFLAGS": "-L/work/deps/lib", "CONFIGURE_LDFLAGS_NODIST": "",
        "MODULE_ZLIB_LDFLAGS": "/work/deps/lib/libz.a", "MODULE__CTYPES_LDFLAGS": "/work/deps/lib/libffi.a -ldl",
        "MODULE_PYEXPAT_CFLAGS": "-I$(srcdir)/Modules/expat", "MODULE_PYEXPAT_LDFLAGS": "-lm $(LIBEXPAT_A)",
        "MODULE_PYEXPAT_DEPS": "$(LIBEXPAT_HEADERS) $(LIBEXPAT_A)", "LIBEXPAT_A": "Modules/expat/libexpat.a",
        "MODULE__SSL_CFLAGS": "-I/work/deps/include", "MODULE__SSL_LDFLAGS": "-L/work/deps/lib  -lssl -lcrypto",
        "CONFIG_ARGS": " ".join(shlex.quote(arg) for arg in I.SOURCE_PYTHON_CONFIGURE)}
    header = b"".join(("#define " + name + " 1\n").encode() for name in (
        "WITH_PYMALLOC", "HAVE_FORK", "HAVE_POSIX_SPAWN", "HAVE_SYS_RESOURCE_H", "HAVE_WAITPID",
        "HAVE_PIPE2", "HAVE_POLL", "HAVE_SOCKETPAIR"))
    setup = (ROOT / "desktop/tools/cpython_source_setup.local").read_bytes()
    return {"Modules/config.c": config, "Makefile": "".join(k + "=" + v + "\n" for k, v in assignments.items()).encode(),
            "pyconfig.h": header, "Modules/Setup.local": setup}, setup, b'#define PY_VERSION "3.14.7"\n'


def elf(name="python", *, runpath=None, extra_needed=()):
    """Not a program: only finite ELF dynamic/header framing in memory."""
    raw, strings = bytearray(1024), bytearray(b"\0")
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", raw, 16, 3, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 2)

    def text(value):
        position = len(strings)
        strings.extend(value.encode() + b"\0")
        return position

    needed = ["libc.so.6"]
    if name == "python":
        needed += list(I.SOURCE_LIBRARIES)
    elif name == "libssl.so.3":
        needed += ["libcrypto.so.3"]
    entries = [(1, text(n)) for n in (*needed, *extra_needed)]
    entries.append((29, text(runpath or ("$ORIGIN/../lib" if name == "python" else "$ORIGIN"))))
    if name != "python":
        entries.append((14, text(name)))
    entries += [(5, 0x400000 + 512), (10, len(strings)), (0, 0)]
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0, len(raw), len(raw), 4096)
    struct.pack_into("<IIQQQQQQ", raw, 120, 2, 4, 256, 0x400000 + 256, 0, len(entries) * 16, len(entries) * 16, 8)
    for index, entry in enumerate(entries):
        struct.pack_into("<qQ", raw, 256 + index * 16, *entry)
    raw[512:512 + len(strings)] = strings
    return bytes(raw)


def output_fixture():
    rows, bodies = [], {}

    def add(name, raw, origin):
        bodies[name] = raw
        rows.append({**record(name, raw), "mode": 0o755 if name == "python/bin/python3" else 0o644, "origin": origin})

    add("python/bin/python3", elf(), {"kind": "source-built", "path": "/work/build/cpython/python", "producerPhase": "python-build"})
    for name in I.SOURCE_LIBRARIES:
        add("python/lib/" + name, elf(name), {"kind": "source-built", "path": "/work/build/openssl/" + name, "producerPhase": "openssl-build"})
    for name in I.SOURCE_GENERATED_NAMES:
        add("python/lib/python3.14/" + name, b"INERT generated DATA\n", {"kind": "source-built",
            "path": "/work/build/cpython/build/lib.linux-x86_64-3.14/" + name, "producerPhase": "python-build"})
    for name in ("os.py", "encodings/__init__.py", "ssl.py", "socket.py", "ctypes/__init__.py",
                 "xml/__init__.py", "xml/parsers/__init__.py", "xml/parsers/expat.py"):
        add("python/lib/python3.14/" + name, b"# INERT source; never imported\n", {"kind": "source-projected",
            "path": "/work/inputs/sources/cpython/Lib/" + name, "producerPhase": "authenticated-source"})
    add("python/LICENSE.txt", b"INERT notice\n", {"kind": "source-projected", "path": "/work/inputs/sources/cpython/LICENSE",
        "producerPhase": "authenticated-source"})
    for name, raw, rule in P._GENERATED:
        add(name, raw, {"kind": "generated-landmark", "rule": rule})
    return {"schema": I.SOURCE_OUTPUT_SCHEMA, "profile": I.SOURCE_PROFILE, "target": I.TARGET["triple"],
        "inputLockSha256": "1" * 64, "hostInputsSha256": "2" * 64, "rootfsSha256": "3" * 64,
        "result": record("source-result.json"), "stage": {"sourcePrefix": "/work/stage",
        "files": sorted(rows, key=lambda r: r["path"]), "directories": sorted(P._ancestors(bodies)), "omissions": []}}, bodies


def coverage_fixture():
    possible = {"gcc-13@13.3.0-6ubuntu2~24.04.1", "gcc-14@14.2.0-4ubuntu2~24.04.1",
                "glibc@2.39-0ubuntu8.9", "linux@6.8.0-139.139", "libxcrypt@1:4.4.36-4build1"}
    ids = sorted(possible | {"inert-build-tool-" + str(i) + "@1" for i in range(80)})
    roots, packages, systems = [], [], []
    for index, sid in enumerate(ids):
        artifacts = [{"bytes": 1, "sha256": "4" * 64,
                      "url": "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/inert-source"}]
        roots.append({"id": sid, "artifacts": artifacts})
        names = [f"inert-{index}-{n}:amd64=1" for n in range(2 if index < 66 else 1)]
        packages.extend({"id": name, "sourceId": sid} for name in names)
        systems.append({"sourceId": sid, "packageIds": names, "artifacts": artifacts,
            "classification": "possible-incorporation" if sid in possible else "build-only",
            "notices": ["NOTICE.fixture.txt"] if sid in possible else [], "conditions": ["INERT condition, no legal clearance"]})
    native = []
    for name, version, archive, scope in (
        ("cpython", "3.14.7", "cpython", ["."]), ("expat", "2.8.2", "cpython", ["Include/pyexpat.h", "Modules/expat/", "Modules/pyexpat.c"]),
        ("hacl", "bundled-in-cpython-3.14.7", "cpython", ["Modules/_hacl/"]), ("libffi", "3.4.8", "libffi", ["."]),
        ("openssl", "3.5.8", "openssl", ["."]), ("zlib", "1.3.2", "zlib", ["."])):
        native.append({"id": name, "version": version, "archiveSha256": I.SOURCE_ARCHIVES[archive][2], "scope": scope,
                       "notices": ["NOTICE.fixture.txt"], "conditions": ["INERT condition, no source/notice acceptance"]})
    union = sorted(possible | {r["id"] for r in native})
    expat_file = record("EXPAT.fixture.txt", b"X" * 1144)
    next(r for r in native if r["id"] == "expat")["notices"] = ["EXPAT.fixture.txt", "NOTICE.fixture.txt"]
    doc = {"coverage": "closed-input-conservative-superset", "sourceAvailabilityNotice": "SOURCE-AVAILABILITY.txt",
           "bundledExpatNotice": {"member": "Python-3.14.7/Modules/expat/COPYING", "file": expat_file},
           "systemSources": systems, "nativeSources": native, "outputCoverage": [{"path": name, "components": union}
            for name in ("python/bin/python3", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3")]}
    return doc, {"sources": roots, "packages": packages}, {"EXPAT.fixture.txt": expat_file,
        **{name: record(name) for name in ("NOTICE.fixture.txt", "SOURCE-AVAILABILITY.txt")}}


class SourceProfileTests(unittest.TestCase):
    def test_source_data_names_survive_inventory_and_tree_checks(self):
        examples = {"cpython": ("Mac/Icons/Disk Image.icns", "Mac/Icons/Python Folder.icns"),
                    "libffi": ("m4/lt~obsolete.m4",), "openssl": ("inert source~.txt",),
                    "zlib": ("inert source~.txt",)}
        for identifier, leaves in examples.items():
            root = Path("/work/inputs/sources") / identifier
            names = sorted(str(root / name) for name in leaves)
            rows = [{**record(name), "mode": 0o644} for name in names]
            raw = I.canonical({"files": rows})
            source = {"root": str(root), "inventory": record("/inert/inventory.json", raw)}
            with self.subTest(source=identifier), patch.object(I, "source_bound", return_value=raw):
                self.assertEqual(list(I.source_inventory(source)), names)
                with self.assertRaises(I.InputError):
                    I.source_inventory({**source, "root": "/work/inputs/sources/another"})
            # No real /work access: run original tree/path/file checks over
            # synthetic entries. Filename syntax alone never grants membership.
            files = [Path(name) for name in names]
            with patch.object(I, "ordinary_directory"), \
                 patch.object(Path, "iterdir", return_value=iter(files)), \
                 patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_nlink=1)):
                self.assertEqual(I.ordinary_tree(root), dict(zip(names, files)))
        prefix = "/work/inputs/sources/cpython/"
        for name in (prefix + "../escaped file", prefix + "double//spaced name", prefix + "bad\tname",
                     prefix + "bad\\name", prefix + "$(command)", "/work/inputs/sources/unknown/spaced name",
                     "/work/inputs/core-source/spaced name", "/work/inputs/recipe/spaced name", "/arbitrary~path"):
            with self.subTest(name=name), self.assertRaises(I.InputError):
                I.absolute(name)

    def test_closed_entries_refuse_before_paths_or_owner_import(self):
        admission = I._source_admission()
        pins = {"APPROVED_SOURCE_LOCK_SHA256", "APPROVED_SOURCE_EXECUTION_REVIEW_SHA256", "APPROVED_SOURCE_CORE_INPUTS_SHA256"}
        self.assertEqual({name for name in vars(admission) if not name.startswith("__")}, pins)
        self.assertTrue(all(not hasattr(I, name) for name in pins))
        for name in pins:
            value = getattr(admission, name)
            if value is not None:
                self.assertEqual(I.sha(value), value)
        closed_admission = SimpleNamespace(**{name: None for name in pins})
        self.assertEqual(set(I.SOURCE_BUILD_FILES), {"cpython_source_recipe.py", "cpython_source_setup.local",
            "cpython_static_inputs.py", "cpython_static_builder_data.py", "prepare_cpython_static_payload.py",
            "prepare_cpython_source_payload.py"})
        self.assertNotIn("cpython_source_admission.py", I.SOURCE_BUILD_FILES)
        lock = lock_shape_fixture()
        self.assertIs(I.source_lock_shape(lock), lock)
        for field in ("executionReview", "admission"):
            with self.assertRaises(I.InputError):
                I.source_lock_shape({**lock, field: record("/inert/forbidden-back-edge")})
        raw_lock = I.canonical(lock)
        raw_review = I.canonical({"inputLockSha256": I.digest(raw_lock),
            "coreInputsSha256": I.digest(I.canonical(lock["coreSourceFiles"])), "scope": "INERT prerequisite E, not approval"})
        review = I.source_execution_review(raw_review, I.digest(raw_review))
        self.assertEqual(review, record("/work/inputs/source-execution-review.json", raw_review))
        # L can be frozen before E and A exist. This later A is inert DATA only:
        # no gate value is patched, imported, written or passed to a build entry.
        root_data = I.canonical({"lock": I.digest(raw_lock), "review": review["sha256"]})
        self.assertNotEqual(I.digest(root_data), I.digest(raw_lock))
        self.assertEqual(I.canonical(I.source_lock_shape(lock)), raw_lock)
        with self.assertRaises(I.InputError):
            I.source_execution_review(raw_review + b" ", review["sha256"])
        with self.assertRaises(I.InputError):
            I.source_execution_review(b"[]\n", I.digest(b"[]\n"))
        with patch.object(I, "_source_admission", return_value=closed_admission), \
                patch.object(I, "source_read", side_effect=AssertionError("read")):
            with self.assertRaises(I.InputError):
                I.load_source_lock(Path("/does-not-exist"))
        with patch.object(R.I, "_source_admission", return_value=closed_admission), \
                patch.object(R, "_owner_modules", side_effect=AssertionError("owner import")):
            with self.assertRaises(R.I.InputError):
                R.build(Path("/does-not-exist"))
        with patch.object(P, "_absolute", side_effect=AssertionError("path access")):
            with self.assertRaises(P.PayloadError):
                P.prepare_source(*(Path("/does-not-exist") for _ in range(9)))
        with patch.object(B, "APPROVED_ROOT_REQUEST_SHA256", None), \
                patch.object(B.I, "source_read", side_effect=AssertionError("read")):
            with self.assertRaises(B.I.InputError):
                B.materialize_source_root(*(Path("/does-not-exist") for _ in range(3)))

    def test_exact_rosters_preserve_legacy_and_disable_unneeded_modules(self):
        self.assertEqual(len(I.SOURCE_STATIC_MODULES), 23)
        self.assertEqual(len(I.SOURCE_DISABLED_MODULES), 55)
        self.assertEqual(len(set(I.BOOTSTRAP_MODULES + I.INTRINSIC_MODULES + I.SOURCE_STATIC_MODULES)), 60)
        self.assertEqual(len(I.STATIC_MODULES), 19)
        self.assertTrue({"_hashlib", "_elementtree"} <= set(I.SOURCE_DISABLED_MODULES))
        self.assertTrue({"_socket", "_ssl", "pyexpat", "resource"} <= set(I.DISABLED_MODULES))

    def test_generated_full_table_not_upstream_partial_count(self):
        files, setup, patchlevel = generated_config()
        self.assertEqual(len(I.source_configuration_names(files["Modules/config.c"], files["Makefile"])), 60)
        with self.assertRaises(I.InputError):
            I.configuration_names(files["Modules/config.c"], files["Makefile"])
        with self.assertRaises(I.InputError):
            I.source_configuration_names(files["Modules/config.c"].replace(b'{"_contextvars", inert_init},\n', b""), files["Makefile"])

    def test_material_configuration_refuses_abi_and_internal_expat_drift(self):
        files, setup, patchlevel = generated_config()
        self.assertEqual(len(I.source_material_configuration(files, setup, patchlevel)), 60)
        changes = (("pyconfig.h", files["pyconfig.h"] + b"#define Py_GIL_DISABLED 1\n"),
                   ("Makefile", files["Makefile"].replace(b"-lm $(LIBEXPAT_A)", b"-lexpat")),
                   ("Makefile", files["Makefile"].replace(b"-lssl -lcrypto", b"-lssl")),
                   ("Modules/Setup.local", setup + b"_hashlib _hashopenssl.c\n"))
        for name, data in changes:
            with self.subTest(name=name), self.assertRaises(I.InputError):
                I.source_material_configuration({**files, name: data}, setup, patchlevel)

    def test_fixed_fourteen_operations_keep_required_generators(self):
        phases = R.fixed_phases()
        self.assertEqual([p["name"] for p in phases], list(I.SOURCE_PHASES))
        self.assertEqual(sum(bool(p["argv"]) for p in phases), 12)
        self.assertEqual(phases[12]["argv"][-4:], ["python", "platform", "checksharedmods", "build-details.json"])
        self.assertIn("Modules/expat/libexpat.a", phases[11]["argv"])
        self.assertIn("PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B", phases[12]["argv"])
        self.assertIn("PYTHON_FOR_FREEZE=./_bootstrap_python -B", phases[12]["argv"])
        self.assertNotIn("LD_LIBRARY_PATH", phases[12]["environment"])
        self.assertFalse(any(word in {"altinstall", "libinstall", "compileall", "strip"} for p in phases for word in p["argv"]))

    def test_absolute_deadline_uses_positive_integer_floor(self):
        self.assertEqual(R.remaining_seconds(3_999_999_999, 1_000_000_000), 2)
        for now in (3_000_000_001, 4_000_000_000):
            with self.assertRaises(R.I.InputError):
                R.remaining_seconds(4_000_000_000, now)

    def test_same_original_owner_guard_and_budget_for_all_native_phases(self):
        owner = SimpleNamespace(run_owned=Mock(side_effect=lambda args, **kw: SimpleNamespace(args=args, returncode=0, stdout=b"", stderr=b"")))
        guard = SimpleNamespace(check=Mock())
        with patch.object(R.time, "monotonic_ns", side_effect=(i * R.NS for i in range(1, 300))), \
             patch.object(R.I, "source_write", side_effect=lambda path, raw, mode=0o600: record(path, raw)), \
             patch.object(R.I, "source_capture_configuration", return_value=[]), \
             patch.object(R.I, "source_openssl_layout", return_value=record("/work/receipts/" + R.I.SOURCE_OPENSSL_LAYOUT_DATA)), \
             patch.object(R.I, "source_project", return_value=record("/work/receipts/source-projection.json")):
            result = R._run_phases({"_digest": "1" * 64}, owner, guard, 2400 * R.NS)
        self.assertEqual(len(result), 14)
        calls = owner.run_owned.call_args_list
        self.assertEqual(len(calls), 12)
        self.assertGreater(calls[0].kwargs["timeout"], calls[-1].kwargs["timeout"])
        for call in calls:
            self.assertIs(call.kwargs["cancellation"], guard)
            self.assertIsNone(call.kwargs["execution_scope"])
            self.assertIsNone(call.kwargs["journal_binding"])
            self.assertIsNone(call.kwargs["on_start"])
            self.assertFalse(call.kwargs["text"])
            self.assertFalse(call.kwargs["cleanup"])

    def test_layout_data_and_phase_persist_without_filename_collision(self):
        # Exercise the real DATA producer and real exclusive phase writes.
        # These tiny synthetic ELF headers contain no executable code; no
        # compiler, loader, source recipe or native owner is invoked.
        with tempfile.TemporaryDirectory(prefix="mrk-source-layout-") as temporary:
            root = Path(temporary)
            receipts = root / "receipts"
            receipts.mkdir()
            for directory in (root / "build/openssl", root / "deps/lib"):
                directory.mkdir(parents=True)
                for name in R.I.SOURCE_LIBRARIES:
                    (directory / name).write_bytes(elf(name))
            projections = tuple(str(root / path) for path in
                                ("build/cpython/lib", "build/lib", "stage/python/lib"))
            with patch.object(R.I, "WORK", root), patch.object(R.I, "RECEIPTS", receipts), \
                    patch.object(R.I, "SOURCE_LAYOUT_ROOTS", projections), \
                    patch.object(R.time, "monotonic_ns", return_value=2 * R.NS):
                data = R.I.source_openssl_layout()
                original_data = Path(data["path"]).read_bytes()
                phase = next(row for row in R.fixed_phases() if row["name"] == "openssl-layout")
                result, retained = R._persist_phase(
                    {"_digest": "1" * 64}, phase, None, R.NS, 10 * R.NS, [data], 0)
                self.assertEqual(Path(data["path"]).read_bytes(), original_data)
                self.assertEqual(result["path"], "openssl-layout.json")
                self.assertEqual(Path(data["path"]).name, R.I.SOURCE_OPENSSL_LAYOUT_DATA)
                self.assertNotEqual(Path(data["path"]).name, result["path"])
                document = R.I.decode((receipts / result["path"]).read_bytes())
                self.assertEqual(document["dataFiles"], [{**data, "path": R.I.SOURCE_OPENSSL_LAYOUT_DATA}])
                self.assertEqual(document["state"], "complete")
                self.assertEqual(document["kind"], "data")
                self.assertIsNone(document["originalExitCode"])
                self.assertEqual(retained, 0)
                self.assertEqual(sorted(path.name for path in receipts.iterdir()), sorted((
                    R.I.SOURCE_OPENSSL_LAYOUT_DATA, "openssl-layout.json",
                    "openssl-layout.stderr", "openssl-layout.stdout")))

    def test_original_nonzero_stops_once_after_persisting_failure(self):
        owner = SimpleNamespace(run_owned=Mock(side_effect=lambda args, **kw: SimpleNamespace(args=args, returncode=7, stdout=b"out", stderr=b"err")))
        writes = []

        def save(path, raw, mode=0o600):
            writes.append((path, raw))
            return record(path, raw)

        with patch.object(R.time, "monotonic_ns", return_value=R.NS), patch.object(R.I, "source_write", side_effect=save):
            with self.assertRaises(R.I.InputError):
                R._run_phases({"_digest": "1" * 64}, owner, SimpleNamespace(check=lambda: None), 2400 * R.NS)
        owner.run_owned.assert_called_once()
        self.assertEqual(R.I.decode(writes[-1][1])["originalExitCode"], 7)
        self.assertEqual(R.I.decode(writes[-1][1])["state"], "failed-or-late")

    def test_write_failure_cannot_advance_or_retry(self):
        owner = SimpleNamespace(run_owned=Mock(side_effect=lambda args, **kw: SimpleNamespace(args=args, returncode=0, stdout=b"", stderr=b"")))
        with patch.object(R.time, "monotonic_ns", return_value=R.NS), patch.object(R.I, "source_write", side_effect=OSError("inert refusal")):
            with self.assertRaises(OSError):
                R._run_phases({"_digest": "1" * 64}, owner, SimpleNamespace(check=lambda: None), 2400 * R.NS)
        owner.run_owned.assert_called_once()

    def test_pybuilddir_is_data_not_shell_or_an_escape(self):
        self.assertEqual(I.source_pybuilddir(b"build/lib.linux-x86_64-3.14\n"), "build/lib.linux-x86_64-3.14")
        for raw in (b"/tmp/elsewhere\n", b"build/../elsewhere\n", b"build/$(bad)\n", b"build/x\nbuild/y\n", b"build/x"):
            with self.subTest(raw=raw), self.assertRaises(I.InputError):
                I.source_pybuilddir(raw)

    def test_projection_keeps_xml_tls_and_deterministically_omits_caches(self):
        for name in ("ssl.py", "socket.py", "xml/parsers/expat.py", "encodings/utf_8.py"):
            self.assertEqual(I.source_stdlib_destination(name), ("python/lib/python3.14/" + name, None))
        for name in ("test/test_ssl.py", "ensurepip/__init__.py", "tkinter/__init__.py", "turtle.py", "__pycache__/os.pyc", "data.pyo"):
            self.assertIsNone(I.source_stdlib_destination(name)[0])
        with self.assertRaises(I.InputError):
            I.source_stdlib_destination("test/unexpected.so")

    def test_elf_metadata_only_checks_private_runpath_and_dependencies(self):
        for name in ("python", *I.SOURCE_LIBRARIES):
            self.assertTrue(I.source_elf(elf(name), name)["notALoaderQualification"])
        for raw in (elf(runpath="/work/deps/lib"), elf(extra_needed=("libz.so.1",)), elf()[:80]):
            with self.assertRaises(I.InputError):
                I.source_elf(raw, "python")

    def test_source_output_names_original_producer_not_an_install_or_link_id(self):
        document, _ = output_fixture()
        self.assertEqual(P._source_output_inventory(P._canonical(document)), document)
        with self.assertRaises(P.PayloadError):
            P._output_inventory(P._canonical(document))

    def test_cross_profile_or_fabricated_projection_refuses(self):
        document, _ = output_fixture()
        for kind in ("profile", "installed", "link", "generator"):
            changed = copy.deepcopy(document)
            if kind == "profile":
                changed["profile"] = I.PROFILE
            else:
                row = next(r for r in changed["stage"]["files"] if r["path"] == "python/bin/python3")
                if kind == "installed":
                    row["origin"]["kind"] = "installed-file"
                elif kind == "link":
                    row["origin"]["originalLinkId"] = "link-000000"
                else:
                    row["origin"]["producerPhase"] = "python-install"
            with self.subTest(kind=kind), self.assertRaises(P.PayloadError):
                P._source_output_inventory(P._canonical(changed))

    def test_complete_conservative_coverage_is_not_selected_member_attribution(self):
        document, rootfs, notices = coverage_fixture()
        P._source_coverage(document, rootfs, notices)
        self.assertEqual(len(document["systemSources"]), 85)
        self.assertEqual(len(rootfs["packages"]), 151)

    def test_source_notice_version_uapi_and_obligation_gaps_refuse(self):
        original, rootfs, notices = coverage_fixture()
        for kind in ("source", "notice", "expat", "uapi", "libxcrypt", "conditions", "artifact"):
            document = copy.deepcopy(original)
            if kind == "source":
                document["systemSources"].pop()
            elif kind == "notice":
                document["nativeSources"][0]["notices"] = ["not-present"]
            elif kind == "expat":
                document["nativeSources"][1]["version"] = "2.8.4"
            elif kind in {"uapi", "libxcrypt"}:
                prefix = "linux@" if kind == "uapi" else "libxcrypt@"
                row = next(r for r in document["systemSources"] if r["sourceId"].startswith(prefix))
                row.update(classification="build-only", notices=[])
            elif kind == "conditions":
                document["nativeSources"][0]["conditions"] = []
            else:
                document["systemSources"][0]["artifacts"][0]["sha256"] = "0" * 64
            with self.subTest(kind=kind), self.assertRaises(P.PayloadError):
                P._source_coverage(document, rootfs, notices)

    def test_ordinary_projection_copy_preserves_bytes_and_existing_limits(self):
        document, bodies = output_fixture()
        license_row = record("license", bodies["python/LICENSE.txt"])
        policy = P._SourcePolicy("1" * 64, "2" * 64, "3" * 64, license_row["size"], license_row["sha256"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for row in document["stage"]["files"]:
                path = root / row["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bodies[row["path"]])
                path.chmod(row["mode"])
            items = P._source_stage_items(root, document, policy)
            self.assertEqual({item.path: item.content for item in items}, bodies)
            P._preflight_items(items)
        self.assertEqual(len(P.RESERVED_PAYLOAD_FILES), 8)
        self.assertEqual(P.RESERVED_ENTRIES, 9)
        self.assertEqual(P.RESOURCE_BYTE_HEADROOM, 64 << 20)

    def test_checked_source_write_readback_and_no_adoption(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ordinary"
            raw = b"INERT source byte preservation\x00\xff\n"
            self.assertEqual(I.source_write(path, raw), record(path, raw))
            self.assertEqual(I.source_read(path), raw)
            with self.assertRaises(FileExistsError):
                I.source_write(path, raw)
            with patch.object(I.os, "write", return_value=0):
                with self.assertRaises(I.InputError):
                    I.source_write(Path(temp) / "partial", raw)
            self.assertTrue((Path(temp) / "partial").exists())

    def test_archive_aliases_are_lexical_bounded_data(self):
        entries = {"bin": {"type": "symlink", "target": "usr/bin"},
                   "usr/bin/sh": {"type": "symlink", "target": "dash"}}
        self.assertEqual(B.resolve_path("/bin/sh", entries), "usr/bin/dash")
        for entries in ({"x": {"type": "symlink", "target": "../../outside"}},
                        {"x": {"type": "symlink", "target": "x"}}):
            with self.assertRaises(B.I.InputError):
                B.resolve_path("x", entries)
        class BoundedMember:
            def __init__(self, body):
                self.body, self.offset, self.calls = body, 0, []
            def read(self, size):
                if not 0 < size <= B.CHUNK:
                    raise AssertionError("unbounded member read")
                self.calls.append(size)
                block = self.body[self.offset:self.offset + size]
                self.offset += len(block)
                return block
        # No tarfile/archive extraction: only a >CHUNK in-memory member DATA
        # stream through the exact production read loop and original ceiling.
        raw = b"X" * (B.CHUNK + 17)
        stream = BoundedMember(raw)
        self.assertEqual(B._selected_body(stream, len(raw)), raw)
        self.assertEqual(stream.calls, [B.CHUNK, 17, 1])
        self.assertEqual(B._selected_body(BoundedMember(b""), 0), b"")
        for body in (raw[:-1], raw + b"X"):
            with self.assertRaises(B.I.InputError):
                B._selected_body(BoundedMember(body), len(raw))
        with self.assertRaises(B.I.InputError):
            B.ForwardReader(BoundedMember(raw), len(raw)).read(B.CHUNK + 1)

    def test_root_policy_removes_cache_and_fake_installed_state_not_tool_bodies(self):
        for name in ("usr/lib/python3.12/__pycache__/os.pyc", "etc/ld.so.cache", "etc/ld.so.preload", "var/lib/dpkg/status"):
            self.assertIsNotNone(B.omitted(name))
        self.assertIsNone(B.omitted("usr/bin/x86_64-linux-gnu-gcc-13"))
        self.assertIsNone(B.omitted("usr/lib/gcc/x86_64-linux-gnu/13/libgcc.a"))
        self.assertEqual(B.root_directories([], []), {"etc", "dev", "proc", "work"})
        self.assertEqual(B.root_directories([{"name": "usr/lib/inert"}], []), {"etc", "dev", "proc", "work", "usr", "usr/lib"})
        for name in ("dev", "proc/inert", "work/inert"):
            with self.assertRaises(B.I.InputError):
                B.root_directories([{"name": name}], [])
        with self.assertRaises(B.I.InputError):
            B.root_directories([], [{"name": "inert-alias", "target": "work/occupied"}])
        self.assertEqual((B.PUBLIC_SELECTION_BYTES, B.PUBLIC_SELECTION_SHA256),
            (150507, "9166c3b1fe0d00d5ae6c093603d161f6eba1c71fa5f9129966428cb93b883ea4"))
        self.assertEqual(B.MEMBER_SELECTION_LINEAGE_SHA256,
            "ccff4af92ac1d0d2e5a65c34e8508f40007f77c42c8e0c55a4a23a8e9b5714fd")
        # Negative envelope only; no forged positive member plan/root is used.
        with self.assertRaises(B.I.InputError):
            B.root_plan({"schema": "mrk-private-tool-member-plan-1", "fileCount": 8758, "bodyBytes": 580511397,
                "aliases": [None] * 551, "lineage": {"selectionSha256": B.PUBLIC_SELECTION_SHA256}})


if __name__ == "__main__":
    unittest.main()
