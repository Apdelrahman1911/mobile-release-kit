"""Focused DATA/custody tests; never install, sign, mount or invoke Cargo.

Native fixture execution remains a separate Mac-only original in the dedicated
route. These tests exercise genuine adapter and existing Operation methods with
small owned files, not a replacement owner or a synthetic native-pass receipt.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_tool(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = load_tool("mrk_app_absence_test_adapter", "macos_app_absence_fixture.py")
HELPER = load_tool("mrk_app_absence_test_operation", "macos_android_helper_package.py")
NOW = 1_000_000_000


def state():
    return {"started": NOW, "observed": NOW, "workSeconds": 10, "hardSeconds": 20,
            "pendingRoot": None, "pendingCut": None, "mount": None, "outputs": [], "roots": []}


def call_row(role, **changes):
    return dict({"role": role, "returncode": 0, "returned": True, "capturesSettled": True}, **changes)


def inert_operation(phase=None):
    return SimpleNamespace(app_absence=state(), app_absence_api=HELPER,
        phase=phase or FIXTURE.PREPARE, environment={"GITHUB_REF": FIXTURE.REF}, errors=[], calls=[], stager_io_pending=None,
        package_settled=lambda: True)


@contextlib.contextmanager
def file_operation():
    """Real descriptor registry/read/close, without the native owner's entry."""
    with tempfile.TemporaryDirectory(prefix="mrk-app-absence-data-") as directory:
        op = HELPER.Operation.__new__(HELPER.Operation)
        op.work = Path(directory)
        op.work_entry = op.source_entry = None
        op.entries, op.errors, op.calls = [], [], []
        op.entry_registry, op.directories = {}, {}
        op.app_absence, op.app_absence_api = state(), HELPER
        op.store_signing = None
        op.stager_io_pending = None
        try:
            fd = os.open(directory, HELPER.READ_FLAGS | os.O_DIRECTORY)
            op.work_entry = op.register(fd, "work-root", "directory")
            op.work_entry["identity"] = HELPER.directory_identity(os.fstat(fd))
            yield op
        finally:
            for entry in reversed(op.entries):
                op.close(entry)
            if op.errors or any(not entry["closed"] for entry in op.entries):
                raise AssertionError("fixture original closes not known")


def cargo_rows(checkout, target_root, target):
    package = checkout / "desktop/src-tauri"
    rows = []
    for name, source, kind, executable in (
            (FIXTURE.FIXTURE_EXECUTABLE, "src/bin/macos_install.rs", ["bin"],
             str(target_root / target / "release" / FIXTURE.FIXTURE_EXECUTABLE)),
            ("mobile_release_desktop", "src/lib.rs", ["lib"], None)):
        rows.append({"reason": "compiler-artifact",
            "package_id": "path+" + package.as_uri() + "#mobile-release-kit-desktop@0.1.2",
            "manifest_path": str(package / "Cargo.toml"),
            "features": ["macos-installed-app-absence-fixture"],
            "target": {"name": name, "kind": kind, "crate_types": kind,
                       "src_path": str(package / source), "edition": "2021"},
            "profile": {"test": False, "debug_assertions": False, "opt_level": "3"},
            "executable": executable, "fresh": False,
            "filenames": [executable] if executable else [str(target_root / "libmobile_release_desktop.rlib")]})
    return rows + [{"reason": "build-finished", "success": True}]


def encoded_rows(rows):
    return b"".join(json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n" for row in rows)


def phase_value(phase):
    binding = {"fixtureSource": "1" * 40, "productSource": "1" * 40,
        "runId": "123", "runAttempt": "1", "target": FIXTURE.TARGETS[0]}
    binding.update({key: "2" * 64 for key in FIXTURE.BINDING_FIELDS if key not in binding})
    value = dict(binding, schemaVersion=1, kind="app-absence-phase-observation", phase=phase,
        baselineSha256="3" * 64, recordSha256=("3" if phase == "baseline" else "4") * 64,
        proof={key: True for key in FIXTURE.PROOFS[phase]}, originalOuterExitRequired=True,
        systemServiceExitClaimed=False, productReady=False)
    op = inert_operation()
    op.app_absence.update(nativeBinding=binding, baselineSha256="3" * 64)
    return op, value


def marker(value):
    return b"MRK_MACOS_APP_ABSENCE_RESULT=" + json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def thin_inventory(stager, count=4300):
    selection = stager.source_build_selection(stager.ARM_TARGET)
    executable = {"app/"+name for name in (stager.ENTRY_BINARY, stager.APP_BINARY, stager.VAULT_HELPER)}
    app = {name: (b"inert-app:"+name.encode(), 0o555 if name in executable else 0o444)
           for name in (*executable, "app/Contents/Info.plist", "app/"+stager.PAYLOAD_INFO)}
    files = {**app, "runtime/python/bin/python3": (b"inert-python", 0o555),
             "runtime/manifest.json": (b"inert-manifest", 0o444)}
    files.update({"runtime/store/"+name: (b"inert-store", 0o555 if name in ("bin/ruby", "bin/bundle") else 0o444)
                  for name in stager.STORE_RUNTIME_REQUIRED})
    # >4096 complete rows, >1MiB inventory, but only five actual app files.
    files.update({"runtime/store/data/"+"x"*110+f"/leaf-{i:05d}.txt": (b"x", 0o444) for i in range(count)})
    manifest = stager.digest(files["runtime/manifest.json"][0])
    document = {"schemaVersion": 1, "release": selection.release, "runtimeManifestSha256": manifest,
                "files": [{"path": name, "size": len(body), "sha256": stager.digest(body), "executable": mode == 0o555}
                          for name, (body, mode) in sorted(files.items())]}
    inventory = stager.canonical(document)
    rows = stager.observation_inventory_bytes(inventory, stager.digest(inventory), manifest, selection=selection)
    return selection, inventory, rows, app


def thin_tree(root, files):
    root.mkdir(mode=0o755)
    for name, (body, mode) in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_bytes(body); path.chmod(mode)
    (root/"input/runtime").mkdir(mode=0o555)
    for path in root.rglob("*"):
        if path.is_dir(): path.chmod(0o555)
    root.chmod(0o755)


@contextlib.contextmanager
def writable_tree():
    # Only our synthetic directories are made writable for TemporaryDirectory.
    with tempfile.TemporaryDirectory(prefix="mrk-thin-projection-") as name:
        root = Path(name)
        try: yield root
        finally:
            for path in root.rglob("*"):
                if path.is_dir() and not path.is_symlink(): path.chmod(0o700)


class ThinRestoreProjectionData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stager = load_tool("thin_restore_stager", "stage_macos_installed.py")

    def test_full_inventory_retained_thin_quote_and_exact_app_data(self):
        stager = self.stager
        selection, inventory, rows, app = thin_inventory(stager)
        self.assertGreater(len(rows), 4096); self.assertGreater(len(inventory), FIXTURE.MIB)
        self.assertEqual(set(FIXTURE.app_rows(rows)), set(app))
        with self.assertRaisesRegex(ValueError, "script-quote"):
            FIXTURE.script_quote(rows, 1024, len(inventory))
        quote = FIXTURE.script_quote(FIXTURE.app_rows(rows), 1024, len(inventory))
        self.assertLess(quote, FIXTURE.PRODUCT_LIMIT)
        self.assertGreater(quote, FIXTURE.script_quote(FIXTURE.app_rows(rows), 1024, FIXTURE.MIB))
        program = b"inert-program"
        scripts = {"postinstall": (FIXTURE.CUT_POSTINSTALL, 0o555), "mrk-macos-install": (program, 0o555),
                   "input/"+stager.INSTALLATION_INVENTORY_NAME: (inventory, 0o444),
                   **{"input/"+name: value for name, value in app.items()}}
        stager.app_absence_scripts_data(scripts, stager.digest(program), stager.digest(inventory),
                                       restore_cut="app-write", selection=selection)
        for fault in ("missing-app", "app-bytes", "runtime-leaf", "wrong-purpose", "inventory-anchor"):
            bad = dict(scripts); name = "input/"+next(iter(app))
            cut, anchor = "app-write", stager.digest(inventory)
            if fault == "missing-app": del bad[name]
            elif fault == "app-bytes": bad[name] = (b"changed", bad[name][1])
            elif fault == "runtime-leaf": bad["input/runtime/extra"] = (b"x", 0o444)
            elif fault == "wrong-purpose": cut = None
            else: anchor = "0"*64
            with self.subTest(fault=fault), self.assertRaises(stager.Refused):
                stager.app_absence_scripts_data(bad, stager.digest(program), anchor, restore_cut=cut, selection=selection)

    def test_actual_copy_and_post_keep_full_inventory_without_runtime_leaf_reads(self):
        stager = self.stager
        selection, inventory, rows, app = thin_inventory(stager)
        for fault in (None, "source-app", "copied-app", "runtime-nonempty", "runtime-replaced"):
            with self.subTest(fault=fault), file_operation() as op, patch.object(FIXTURE, "clock", return_value=NOW):
                op.stager, op.target = stager, stager.ARM_TARGET
                op.environment = {"MRK_MACOS_INSTALL_INVENTORY_SHA256": stager.digest(inventory),
                    "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": stager.digest(b"inert-manifest")}
                source = op.work/"input"; source.mkdir()
                for name, (body, mode) in app.items():
                    path = source/name; path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body); path.chmod(mode)
                (source/"runtime").mkdir(); (source/"runtime/not-copied").write_bytes(b"omitted not newly verified")
                (source/stager.INSTALLATION_INVENTORY_NAME).write_bytes(inventory)
                (source/stager.INSTALLATION_INVENTORY_NAME).chmod(0o444)
                destination = FIXTURE.tree_directory(op, op.work_entry, "projected", create=True)
                with patch.object(FIXTURE, "selected", return_value=selection):
                    original, admitted = FIXTURE.input_rows(op)
                opened = []
                leaf = FIXTURE.tree_leaf
                def observed(_op, parent, name, row):
                    opened.append(name); return leaf(_op, parent, name, row)
                try:
                    with patch.object(FIXTURE, "tree_leaf", side_effect=observed):
                        FIXTURE.copy_input(op, destination, original, admitted)
                        self.assertEqual((op.work/"projected"/stager.INSTALLATION_INVENTORY_NAME).read_bytes(), inventory)
                        self.assertEqual(list((op.work/"projected/runtime").iterdir()), [])
                        for name, (body, mode) in app.items():
                            self.assertEqual((op.work/"projected"/name).read_bytes(), body)
                            self.assertEqual(stat.S_IMODE((op.work/"projected"/name).stat().st_mode), mode)
                        self.assertEqual(stat.S_IMODE((op.work/"projected/runtime").stat().st_mode), 0o555)
                        if fault in ("source-app", "copied-app"):
                            path = (source if fault == "source-app" else op.work/"projected")/next(iter(app))
                            path.chmod(0o600); path.write_bytes(b"changed")
                        elif fault == "runtime-nonempty":
                            path = op.work/"projected/runtime"; path.chmod(0o700)
                            (path/"extra").write_bytes(b"x"); path.chmod(0o555)
                        elif fault == "runtime-replaced":
                            (source/"runtime").rename(op.work/"prior-runtime"); (source/"runtime").mkdir()
                        if fault is None: FIXTURE.input_post(op)
                        else:
                            with self.assertRaises((ValueError, HELPER.Refused)): FIXTURE.input_post(op)
                    self.assertNotIn("not-copied", opened)
                finally:
                    for path in op.work.rglob("*"):
                        if path.is_dir(): path.chmod(0o700)

    def test_empty_runtime_tree_is_only_fixed_nonshipping_purpose(self):
        stager = self.stager
        files = {"postinstall": (FIXTURE.POSTINSTALL, 0o555), "input/app/Contents/data": (b"x", 0o444)}
        with writable_tree() as root:
            scripts = root/"scripts"; thin_tree(scripts, files)
            self.assertEqual(stager.tree(scripts, packager=True, app_absence=True), files)
            for kwargs in ({"packager": True}, {"app_absence": True}, {"packager": True, "app_absence": 1},
                           {"packager": True, "app_absence": True, "mac_store_prefix": "input/runtime/store"}):
                with self.subTest(kwargs=kwargs), self.assertRaises(stager.Refused): stager.tree(scripts, **kwargs)
            runtime = scripts/"input/runtime"; runtime.chmod(0o700)
            (runtime/"extra").write_bytes(b"x"); (runtime/"extra").chmod(0o444); runtime.chmod(0o555)
            with self.assertRaisesRegex(stager.Refused, "runtime-empty"):
                stager.tree(scripts, packager=True, app_absence=True)

    def test_real_original_and_root_cpio_audits_keep_exact_thin_projection(self):
        import test_macos_e2_native_fixture as archive_data
        import test_macos_launcher_staging as image_data
        stager = self.stager
        selection, inventory, rows, app = thin_inventory(stager)
        program = image_data.binary(stager.ARM_TARGET)
        files = {"postinstall": (FIXTURE.CUT_POSTINSTALL, 0o555), "mrk-macos-install": (program, 0o555),
                 "input/"+stager.INSTALLATION_INVENTORY_NAME: (inventory, 0o444),
                 **{"input/"+name: value for name, value in app.items()}}
        info = (f'<pkg-info identifier="{stager.PACKAGE_ID}-app-absence-fixture" version="{selection.package_version}" '
                'install-location="/" auth="root"><scripts><postinstall file="postinstall"/></scripts></pkg-info>').encode()
        def package(owner, fault=None):
            data = dict(files)
            if fault == "app-drift": data["input/"+next(iter(app))] = (b"changed", 0o444)
            if fault == "runtime-leaf": data["input/runtime/extra"] = (b"x", 0o444)
            dirs = stager.directories(data) | {"input/runtime"}
            if fault == "runtime-missing": dirs.remove("input/runtime")
            if fault == "empty-extra": dirs.add("input/extra")
            entries = [(".", stat.S_IFDIR|0o755, b"", *owner, 1)]
            entries += [(name, stat.S_IFDIR|0o555, b"", *owner, 1) for name in sorted(dirs)]
            entries += [(name, stat.S_IFREG|mode, body, *owner, 1) for name, (body, mode) in sorted(data.items())]
            return archive_data.InstallerContextTests.xar({"PackageInfo":info, "Scripts":archive_data.cpio(entries)})
        with writable_tree() as root:
            scripts = root/"scripts"; thin_tree(scripts, files)
            original, final = root/"original.pkg", root/"final.pkg"
            original.write_bytes(package((os.getuid(), os.getgid())))
            final.write_bytes(package((0, 0)))
            args = SimpleNamespace(target=stager.ARM_TARGET, restore_cut="app-write", scripts=scripts,
                original_package=original, package=final, expected_program=stager.digest(program), expected_inventory=stager.digest(inventory))
            compact = stager.app_absence_original_command(args)
            self.assertEqual(compact["rows"]["input/runtime"], {"size":None, "sha256":None, "mode":0o555})
            result = stager.app_absence_final_command(args, compact)
            self.assertEqual(result["qualification"], "nonshipping-app-absence-fixture-not-installed")
            for fault in ("app-drift", "runtime-leaf", "runtime-missing", "empty-extra"):
                with self.subTest(fault=fault):
                    final.write_bytes(package((0, 0), fault))
                    with self.assertRaises(stager.Refused): stager.app_absence_final_command(args, compact)
                    original.write_bytes(package((os.getuid(), os.getgid()), fault))
                    with self.assertRaises(stager.Refused): stager.app_absence_original_command(args)
            with self.assertRaises(stager.Refused): stager.original_package(scripts, original, selection=selection)
            with self.assertRaises(stager.Refused):
                stager.original_package(scripts, original, selection=selection, app_absence=True, store_runtime=True)


class MacAppAbsenceFixtureData(unittest.TestCase):
    def test_candidate_acquisition_materializes_full_p_and_exact_thin_tree(self):
        import sys
        import io
        import resource
        import time
        for bad in (None, "deep84", "deep96", "unlimited", "app", "roster", "mode", "quote", "external", "unknown", "book-error", "os-limit", "close"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp); work.chmod(0o700); (work / "resume-carrier").mkdir(mode=0o700)
                inventory = b"inert full signed inventory of 5001 leaves"
                app = b"inert application leaf"
                app_path = "app/" + "d/" * 14 + "program" if bad in ("deep84", "deep96") else "app/Contents/program"
                successful = bad in (None, "deep84", "deep96", "unlimited")
                rows = {"runtime/store/gem/f" + str(i):dict(size=1,sha256="f"*64,executable=False) for i in range(5000)}
                rows[app_path] = dict(size=len(app),sha256=hashlib.sha256(app).hexdigest(),executable=True)
                originals = {name:(body,0o444) for name,body in (("Install.pkg",b"unchanged signed P"),("producer.json",b"descriptor"),("producer.sig",b"signature"))}
                origin = {key:dict(name=name,bytes=len(originals[name][0]),sha256=hashlib.sha256(originals[name][0]).hexdigest())
                          for key,name in (("package","Install.pkg"),("descriptor","producer.json"),("signature","producer.sig"))}
                origin.update(inventorySha256=hashlib.sha256(inventory).hexdigest(),runtimeManifestSha256="c"*64)
                stage = SimpleNamespace(INSTALL_COMPONENT="component",INSTALLATION_INVENTORY_NAME="install-inventory.json",MAX_BYTES=512<<20,
                    observation_inventory_bytes=lambda *a,**k:rows,
                    install_product_members=lambda *a,**k: self.fail("duplicate full product decode"),
                    cpio_members=lambda *a,**k: self.fail("duplicate CPIO window"))
                scripts = {"input/" + app_path: (b"changed" if bad=="app" else app, 0o444 if bad=="mode" else 0o555)}
                if bad == "roster": scripts["input/runtime/extra"] = (b"x", 0o444)
                app_scripts = MappingProxyType(scripts)
                now=time.monotonic_ns()
                session=SimpleNamespace(purpose="acquire-restore",package_api=HELPER,fixture_api=FIXTURE,stager=stage,
                    acquisition_result={},installer_entered=False,calls=[],point=lambda:None,origin=origin,
                    selection=SimpleNamespace(),allocation_budget=lambda *a:None,decode_fixture_scripts=lambda body,live:body,candidate_root=work,
                    work=work/"resume-carrier",helper_source="a"*40,run_id="1",run_attempt="1",target=FIXTURE.TARGETS[0],
                    clock=SimpleNamespace(started=now,check=lambda:time.monotonic_ns()),
                    quota=SimpleNamespace(reserved=24575 if bad=="quote" else 96,
                        books=[SimpleNamespace(errors=["inert error"] if bad=="book-error" else [],
                            entries=[dict(fd=1,closed=False) for _ in range(97 if bad=="external" else 96 if bad=="deep96" else 84 if bad=="deep84" else 60)])]))
                if bad == "unknown": session.quota.books[0].entries[0].update(fd=None,closed=False)
                register=HELPER.Operation.register
                peak=[0]
                def registering(op,*args,**kwargs):
                    entry=register(op,*args,**kwargs)
                    peak[0]=max(peak[0],len([row for row in op.entries if row["fd"] is not None]))
                    return entry
                diagnostic=io.StringIO()
                close=HELPER.Operation.close
                def closing(op,entry):
                    close(op,entry)
                    if bad=="close" and entry.get("name")=="program":
                        entry["closed"]=False;op.errors.append(dict(stage="close",type="OSError"))
                with patch.dict(sys.modules,{HELPER.__name__:HELPER}),patch.object(HELPER.Operation,"close",closing), \
                        patch.object(HELPER.Operation,"register",registering), \
                        patch.object(resource,"getrlimit",return_value=(-1,-1) if bad=="unlimited" else (159,256) if bad=="os-limit" else (256,256)), \
                        contextlib.redirect_stderr(diagnostic):
                    if not successful:
                        with self.assertRaises(ValueError): HELPER.candidate_materialize(session, originals, inventory, app_scripts)
                        if bad in ("app","roster","mode","quote","external","unknown","book-error","os-limit"):self.assertEqual(set(p.name for p in work.iterdir()),{"resume-carrier"})
                        if bad=="close":self.assertTrue((work/"android-helper-prepare-app-absence").exists())
                    else:
                        HELPER.candidate_materialize(session, originals, inventory, app_scripts)
                        self.assertEqual((work/"input/install-inventory.json").read_bytes(),inventory)
                        self.assertEqual((work/"input"/app_path).read_bytes(),app)
                        self.assertEqual((work/"input"/app_path).stat().st_mode&0o777,0o555)
                        self.assertEqual(list((work/"input/runtime").iterdir()),[])
                        for name,(body,_) in originals.items():self.assertEqual((work/"candidate-producer"/name).read_bytes(),body)
                        self.assertFalse((work/"android-helper-prepare-app-absence").exists())
                        self.assertLessEqual(peak[0],19)
                        if bad in ("deep84","deep96"):
                            self.assertEqual(peak[0],19)
                            self.assertGreater(peak[0]+len(session.quota.books[0].entries),96)
                if bad in ("quote","os-limit"):
                    line=diagnostic.getvalue()
                    self.assertTrue(line.startswith("MRK_CANDIDATE_MATERIALIZE_ADMISSION="))
                    facts=json.loads(line.split("=",1)[1])
                    self.assertEqual(facts["liveLimit"],128)
                    self.assertEqual(facts["lifetimeLimit"],24576)
                    self.assertEqual(facts["osRequired"],160)
                    self.assertTrue(all(type(value) is int for value in facts.values()))
                    self.assertNotIn(str(work),line)
                else: self.assertEqual(diagnostic.getvalue(),"")
                # This test owns all small inert data, including refused output.
                for path in work.rglob("*"):
                    if path.is_dir():path.chmod(0o700)

    def test_candidate_sequential_builder_closes_only_completed_private_originals(self):
        for fault in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp); work.chmod(0o700)
                op = HELPER.Operation(None, work, work, FIXTURE.PREPARE, dict(GITHUB_SHA="a"*40, GITHUB_WORKFLOW_SHA="a"*40, GITHUB_RUN_ID="1", GITHUB_RUN_ATTEMPT="1", GITHUB_WORKFLOW_REF="inert"), None)
                op.open(); op.app_absence_api = HELPER; op.app_absence_module = FIXTURE
                op.app_absence = state(); op.candidate_restore_context = {"inert": True}
                shared = FIXTURE.mkdir(op, op.work_entry, "input")
                roots = [FIXTURE.mkdir(op, op.work_entry, "app-absence-" + name) for name in ("prepared", "scripts")]
                for parent in roots:
                    leaf = FIXTURE.output(op, parent, "inert", b"preserved bytes")
                    op.app_absence["roots"].append((parent, {"inert"}))
                FIXTURE.output(op, op.work_entry, "app-absence-original.pkg", b"inert original archive")
                op.app_absence["inputCopies"] = (shared, roots[1], {}, {})
                paths = {path: path.read_bytes() for path in work.rglob("*") if path.is_file()}
                before = len(op.entries)
                close = op.close
                def closing(entry):
                    close(entry)
                    if fault and entry.get("name") == "app-absence-original.pkg":
                        entry["closed"] = False
                        op.errors.append({"stage": "close", "type": "OSError"})
                try:
                    with patch.object(FIXTURE, "clock"), patch.object(FIXTURE, "input_post"), \
                         patch.object(op, "package_post"), patch.object(op, "close", side_effect=closing):
                        if fault:
                            with self.assertRaisesRegex(ValueError, "candidate-builder-close-unknown"):
                                HELPER.candidate_builder_retire(op, None)
                            self.assertTrue(op.app_absence["outputs"])
                            self.assertTrue(op.app_absence["roots"])
                            self.assertIn("inputCopies", op.app_absence)
                        else:
                            HELPER.candidate_builder_retire(op, None)
                            self.assertEqual(op.app_absence["outputs"], [])
                            self.assertEqual(op.app_absence["roots"], [])
                            self.assertNotIn("inputCopies", op.app_absence)
                            self.assertTrue(all(e["closed"] for e in op.entries if e not in
                                                (op.work_entry, op.target_entry, shared)))
                    self.assertEqual(len(op.entries), before)
                    self.assertIsNotNone(shared["fd"])
                    self.assertEqual({path:path.read_bytes() for path in paths}, paths)
                finally:
                    for entry in reversed(op.entries): close(entry)

    def test_candidate_sequential_preparation_never_advances_after_unknown_close(self):
        for fault in (None, "app-write"):
            op = inert_operation(); op.phase = FIXTURE.PREPARE; op.entries = []
            op.candidate_restore_context = {}; op.app_absence_api = HELPER; op.environment["GITHUB_REF"] = "candidate-ref"
            op.receipt = {}; op.app_absence.update(future={})
            events = []
            def build(owner, cut=None):
                events.append(("build", cut)); return {"fixturePackageBytes": 32, "fixturePackageSha256": "a" * 64}
            def retire(owner, cut):
                events.append(("closed", cut))
                if fault == cut and cut is not None: raise ValueError("candidate-builder-close-unknown")
            with patch.object(FIXTURE, "input_rows", return_value=(None, {"app/leaf": {"size":1}})), \
                 patch.object(FIXTURE, "prepare_one", side_effect=build), \
                 patch.object(HELPER, "candidate_builder_retire", side_effect=retire), patch.object(FIXTURE, "reserve"):
                if fault:
                    with self.assertRaisesRegex(ValueError, "candidate-builder-close-unknown"): FIXTURE.prepare(op)
                    self.assertEqual(events, [("build", None), ("closed", None), ("build", fault), ("closed", fault)])
                    self.assertNotIn("appAbsencePreparation", op.receipt)
                else:
                    FIXTURE.prepare(op)
                    self.assertEqual(events, [event for cut in (None, *FIXTURE.CUTS)
                                              for event in (("build", cut), ("closed", cut))])
                    self.assertEqual(op.app_absence["future"]["cutCopies"], 96)
        FIXTURE.recovery_builder_quote_data(1, 2, 3, 80, 75, sequential=True)
        FIXTURE.recovery_builder_quote_data(1, 17, 15, 96, 96, sequential=True)  #141, inside160.
        with self.assertRaisesRegex(ValueError, "restore-chain-complete-original-quote"):
            FIXTURE.recovery_builder_quote_data(1, 2, 3, 70, 64)
        with self.assertRaisesRegex(ValueError, "restore-chain-bootstrap-original-quote"):
            FIXTURE.recovery_builder_quote_data(1, 17, 15, 97, 97, sequential=True)
        with self.assertRaisesRegex(ValueError, "restore-chain-lifetime-original-quote"):
            FIXTURE.recovery_builder_quote_data(1024, 17, 15, 96, 96, sequential=True)
        import resource
        blocked = SimpleNamespace(candidate_restore_context={}, environment={"MRK_MACOS_PACKAGE_ROLE":"ordinary-image"},
            phase=FIXTURE.PREPARE, app_absence={})
        with patch.object(FIXTURE,"recovery_mode",return_value=True), \
                patch.object(resource,"getrlimit",return_value=(191,256)), \
                patch.object(FIXTURE,"input_rows") as acquire:
            with self.assertRaisesRegex(ValueError,"restore-chain-os-fd-limit"): FIXTURE.prepare(blocked)
            acquire.assert_not_called()

    def test_fixed_bindings_layout_and_stricter_script_quote(self):
        FIXTURE.fixed_binding_and_layout_data_checks()
        FIXTURE.ownership_and_finality_data_checks()
        current = ("producer-tests", "producer-build", "producer-emitter", "distribution-create", "distribution-sign",
            "distribution-verify-signature", "distribution-verify-image", "observation-create", "observation-sign",
            "observation-verify-signature", "observation-verify-image", "distribution-attach", "installer-log-cursor",
            "installer", "installer-log-capture", "distribution-detach")
        expected = ("producer-tests", "producer-build", "producer-emitter", "app-absence-image-create", "app-absence-image-verify",
            "app-absence-baseline-attach", "distribution-create", "distribution-sign", "distribution-verify-signature",
            "distribution-verify-image", "observation-create", "observation-sign", "observation-verify-signature",
            "observation-verify-image", "distribution-attach", "installer-log-cursor", "app-absence-baseline", "installer",
            "installer-log-capture", "distribution-detach", "app-absence-baseline-detach")
        self.assertEqual(FIXTURE.package_roles(current), expected)
        for bad in (current[1:], ("producer-build",) + current[1:], (current[1], current[0]) + current[2:],
                    current[:2] + ("foreign",) + current[3:], current[:-1], current + (current[0],)):
            with self.subTest(roster=bad), self.assertRaises(ValueError): FIXTURE.package_roles(bad)
        quote = FIXTURE.script_quote({"core.zip": {"size": 1024}}, 1024, FIXTURE.MIB)
        self.assertLess(quote, FIXTURE.PRODUCT_LIMIT)
        # The abstract six-file DATA ceiling does not widen the actual route's
        # unchanged 512-MiB archive readers. Numeric quote: no large allocation.
        rows = [{"name": name, "bytes": 100, "sha256": "5" * 64, "mode": 0o444, "links": 1}
                for name in FIXTURE.CARRIER_NAMES]
        for row in rows:
            if row["name"] in FIXTURE.PHASE_NAMES:
                row["bytes"] = FIXTURE.PRODUCT_LIMIT + 1
        self.assertEqual(FIXTURE.transport_layout_data(rows)["fixtureBytes"], FIXTURE.PRODUCT_LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "app-absence-fixture-ineligible"):
            FIXTURE.script_quote({"core.zip": {"size": FIXTURE.PRODUCT_LIMIT}}, 1024, FIXTURE.MIB)
        binding = {"fixtureSource": "1" * 40, "productSource": "1" * 40,
            "runId": "123", "runAttempt": "1", "target": FIXTURE.TARGETS[0]}
        split=dict(binding,productSource="2"*40)
        self.assertEqual(FIXTURE.binding_data(split),split)
        self.assertEqual(FIXTURE.baseline_name_data(split),FIXTURE.baseline_name_data(binding))
        legacy=dict(GITHUB_SHA=binding['fixtureSource'],MRK_MACOS_INSTALL_SOURCE_COMMIT=binding['productSource'],
            GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(FIXTURE.source_binding(legacy,FIXTURE.TARGETS[0]),binding)
        with self.assertRaisesRegex(ValueError,'fixture-same-source'):
            FIXTURE.source_binding(dict(legacy,MRK_MACOS_INSTALL_SOURCE_COMMIT='2'*40),FIXTURE.TARGETS[0])
        for changes in ({"productSource": "0" * 40}, {"productSource":None}, {"runId": "0123"},
                        {"runAttempt": True}, {"target": "linux"}, {"extra": "path"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                FIXTURE.binding_data(dict(binding, **changes))

    def test_cargo_selection_is_same_source_exact_graph_and_terminal(self):
        checkout, target_root = Path("/owned/checkout"), Path("/owned/target")
        for target in FIXTURE.TARGETS:
            rows = cargo_rows(checkout, target_root, target)
            expected = target_root / target / "release" / FIXTURE.FIXTURE_EXECUTABLE
            self.assertEqual(FIXTURE.artifact_data(encoded_rows(rows), checkout, target_root, target, package_version="0.1.2"), expected)
            current = copy.deepcopy(rows)
            for row in current[:2]: row["package_id"] = row["package_id"].replace("@0.1.2", "@0.1.3")
            self.assertEqual(FIXTURE.artifact_data(encoded_rows(current), checkout, target_root, target,
                package_version="0.1.3"), expected)
            for stale in (rows, [current[0], rows[1], current[2]]):
                with self.assertRaises(ValueError):
                    FIXTURE.artifact_data(encoded_rows(stale), checkout, target_root, target, package_version="0.1.3")
            mutations = []
            for where, key, value in ((0, "features", ["macos-installed-entry"]),
                                      (0, "executable", "/unrelated/fixture"),
                                      (0, "package_id", "path+file:///other#mobile-release-kit-desktop@0.1.1"),
                                      (0, "package_id", "path+file:///other#mobile-release-kit-desktop@0.1.2"),
                                      (0, "package_id", rows[0]["package_id"].replace("@0.1.2", "@0.1.1")),
                                      (2, "success", False)):
                changed = copy.deepcopy(rows); changed[where][key] = value; mutations.append(changed)
            changed = copy.deepcopy(rows); changed[0]["profile"]["test"] = True; mutations.append(changed)
            changed = copy.deepcopy(rows); changed[0]["target"]["src_path"] = "/other/bin.rs"; mutations.append(changed)
            mutations.extend((rows[:-1], rows + [rows[-1]], [rows[-1]] + rows[:-1], rows[:1] + rows))
            extra = copy.deepcopy(rows[0]); extra["target"]["name"] = "unrequested"
            mutations.append(rows[:-1] + [extra, rows[-1]])
            for changed in mutations:
                with self.subTest(target=target, changed=changed), self.assertRaises(ValueError):
                    FIXTURE.artifact_data(encoded_rows(changed), checkout, target_root, target, package_version="0.1.2")
            for body in (encoded_rows(rows).rstrip(b"\n"),
                         encoded_rows(rows).replace(b'"success":true', b'"success":true,"success":true')):
                with self.assertRaises(ValueError):
                    FIXTURE.artifact_data(body, checkout, target_root, target, package_version="0.1.2")

    def test_phase_marker_is_unique_complete_bound_and_pending_outer_exit(self):
        for phase in FIXTURE.PROOFS:
            op, value = phase_value(phase)
            line = marker(value)
            for stdout, stderr in ((line, b""), (b"", b"installer: " + line)):
                result = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
                self.assertEqual(FIXTURE.phase_observation(op, result, phase), value)
            for stdout, stderr, code in ((line + line, b"", 0), (line, line, 0),
                    (line.rstrip(b"\n"), b"", 0), (b"", b"", 0),
                    (b"bad\x01: " + line, b"", 0), (b"bad" + line, b"", 0),
                    (line, b"", 1), (line, b"", None), (line, b"", False)):
                with self.subTest(phase=phase, code=code), self.assertRaises(ValueError):
                    FIXTURE.phase_observation(op, SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr), phase)
            changes = ({"runId": "124"}, {"productReady": True}, {"systemServiceExitClaimed": True},
                       {"originalOuterExitRequired": False}, {"schemaVersion": True},
                       {"privatePath": "/private/fixture"}, {"baselineSha256": "6" * 64})
            for change in changes:
                with self.subTest(phase=phase, change=change), self.assertRaises(ValueError):
                    FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=marker(dict(value, **change)), stderr=b""), phase)
            bad = copy.deepcopy(value); bad["proof"][next(iter(bad["proof"]))] = 1
            with self.assertRaises(ValueError):
                FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=marker(bad), stderr=b""), phase)
            duplicate = line.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1')
            with self.assertRaises(ValueError):
                FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=duplicate, stderr=b""), phase)

    def test_original_order_failure_pending_and_original_deadlines(self):
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW):
            self.assertEqual(FIXTURE.PREPARE_ROLES[:3],
                ("app-absence-build", "app-absence-data-tests", "app-absence-adhoc"))
            op = inert_operation()
            FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[0])
            op.calls.append(call_row(FIXTURE.PREPARE_ROLES[0]))
            FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[1])
            for change in ({"returncode": 1}, {"returncode": None}, {"returncode": False},
                           {"returned": False}, {"capturesSettled": False}):
                op.calls[:] = [call_row(FIXTURE.PREPARE_ROLES[0]), call_row(FIXTURE.PREPARE_ROLES[1], **change)]
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "exact-original-order"):
                    FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[2])
            op.calls[:] = [call_row(role) for role in FIXTURE.PREPARE_ROLES[:2]]
            op.errors.append({"stage": "previous"})
            with self.assertRaises(ValueError):
                FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[2])
            op = inert_operation(FIXTURE.RESTORE)
            op.calls.append(call_row(FIXTURE.RESTORE_ROLES[0]))
            FIXTURE.dispatch(op, "app-absence-withdraw")
            self.assertEqual(op.app_absence["pendingRoot"], "app-absence-withdraw")
            self.assertFalse(FIXTURE.finish_ready(op))
            op.calls.append(call_row("app-absence-withdraw", capturesSettled=False))
            with self.assertRaises(ValueError):
                FIXTURE.returned(op, "app-absence-withdraw")
            self.assertEqual(op.app_absence["pendingRoot"], "app-absence-withdraw")
            op.calls[-1]["capturesSettled"] = True
            FIXTURE.returned(op, "app-absence-withdraw")
            self.assertTrue(FIXTURE.finish_ready(op))
            op.app_absence["mount"] = {"entered": True, "detached": False}
            self.assertFalse(FIXTURE.finish_ready(op))
            op.app_absence["mount"]["detached"] = True
            self.assertTrue(FIXTURE.finish_ready(op))
            op = inert_operation()
            def failed_io():
                raise OSError("fixture synthetic read failure")
            with self.assertRaises(OSError):
                FIXTURE.io(op, "read", failed_io)
            self.assertEqual(op.stager_io_pending, "app-absence-read")
            self.assertFalse(FIXTURE.finish_ready(op))
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW + 10_000_000_000):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.clock(op)
            self.assertEqual(FIXTURE.clock(op, work=False), NOW + 10_000_000_000)
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW + 20_000_000_000):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.clock(op, work=False)
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW - 1):
            with self.assertRaises(ValueError):
                FIXTURE.clock(op)
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", side_effect=(NOW, NOW + 10_000_000_000)):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.io(op, "post", lambda: b"complete bytes alone are not finality")
        self.assertEqual(op.stager_io_pending, "app-absence-post")

    def test_copy_has_real_original_post_exclusive_destination_and_consumed_close(self):
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW), file_operation() as op:
            body = b"small credential-free fixture\n"
            source = FIXTURE.output(op, op.work_entry, "source", body)
            expected = hashlib.sha256(body).hexdigest()
            self.assertEqual(FIXTURE.original_hash(op, source), expected)
            target = FIXTURE.copy(op, source, op.work_entry, "copied", 1024)
            self.assertEqual(op.read(target), body)
            self.assertEqual(stat.S_IMODE(os.fstat(target["fd"]).st_mode), 0o444)
            self.assertEqual(len(op.app_absence["outputs"]), 2)
            FIXTURE.post(op)
            with self.assertRaises(FileExistsError):
                FIXTURE.copy(op, source, op.work_entry, "copied", 1024)
            self.assertEqual(op.read(target), body)
            with self.assertRaisesRegex(ValueError, "copy-bound"):
                FIXTURE.copy(op, source, op.work_entry, "oversize", len(body) - 1)
            self.assertFalse((op.work / "oversize").exists())
            # Name replacement cannot be laundered through an unchanged open FD.
            os.rename("source", "withdrawn", src_dir_fd=op.work_entry["fd"], dst_dir_fd=op.work_entry["fd"])
            replacement = FIXTURE.output(op, op.work_entry, "source", body)
            self.assertNotEqual(replacement["identity"][1], source["identity"][1])
            with self.assertRaisesRegex(ValueError, "original-post"):
                FIXTURE.original_hash(op, source)
            op.close(target)
            self.assertIsNone(target["fd"])
            self.assertTrue(target["closed"])
            with self.assertRaisesRegex(ValueError, "original-closed"):
                FIXTURE.original_hash(op, target)
            op.close(target)  # Consumed originals never close a reused numeric FD.
            self.assertEqual(op.read(replacement), body)

    def test_native_data_result_requires_all_six_exact_names_and_genuine_zero(self):
        names = tuple("installer::worker::app_absence_fixture::tests::" + name for name in (
            "fixed_transport_and_same_source_bindings",
            "initial_fresh_install_and_same_gate_not_name_only",
            "output_quote_and_original_exit_finality_are_separate",
            "actual_restore_requires_new_app_and_exact_initial_history",
            "exclusive_rename_metadata_and_record_bounds_are_not_identity_reset",
            "phase_observations_are_pending_outer_exit_and_keep_private_fields_private"))
        self.assertEqual(FIXTURE.NATIVE_DATA_TESTS, names)
        lines = [b"running 6 tests"] + [("test " + name + " ... ok").encode("ascii") for name in reversed(names)]
        lines.append(b"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.125s")
        stdout = b"\n".join(lines) + b"\n"
        stderr = b"   Compiling credential-free fixture\n"
        result = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        value = FIXTURE.native_data_tests_result(result)
        self.assertEqual(set(value["methodNames"]), set(names))
        self.assertEqual((value["testCount"], value["passed"], value["failed"], value["ignored"], value["filteredCount"]), (6, 6, 0, 0, 4))
        self.assertEqual(value["stdoutSha256"], hashlib.sha256(stdout).hexdigest())
        self.assertEqual(value["stderrSha256"], hashlib.sha256(stderr).hexdigest())
        self.assertIs(value["productReady"], False)
        changed = []
        changed.append(b"\n".join(lines[:1] + lines[2:]) + b"\n")
        changed.append(b"\n".join(lines[:2] + [lines[1]] + lines[3:]) + b"\n")
        changed.extend((stdout + lines[1] + b"\n", stdout + lines[-1] + b"\n", stdout.rstrip(b"\n"),
            stdout.replace(b" ... ok", b" ... FAILED", 1), stdout.replace(b" ... ok", b" ... ignored", 1),
            stdout.replace(names[0].encode(), b"installer::worker::app_absence_fixture::tests::unexpected"),
            stdout.replace(b"running 6 tests", b"running 5 tests"),
            stdout.replace(b"0 ignored", b"1 ignored"), stdout.replace(b"0 failed", b"1 failed"),
            stdout.replace(b"0.125s", b"nans"), stdout.replace(b"0.125s", b"1440.001s")))
        for index, body in enumerate(changed):
            with self.subTest(index=index), self.assertRaises(ValueError):
                FIXTURE.native_data_tests_result(SimpleNamespace(returncode=0, stdout=body, stderr=stderr))
        with self.assertRaisesRegex(ValueError, "data-tests-original"):
            FIXTURE.native_data_tests_result(SimpleNamespace(returncode=0, stdout=stdout,
                stderr=b"x" * (4 * FIXTURE.MIB - len(stdout) + 1)))
        for code in (False, True, None, 1, -1):
            with self.subTest(code=code), self.assertRaises(ValueError):
                FIXTURE.native_data_tests_result(SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr))

    def test_baseline_identity_matches_held_parent_not_assumed_wheel_group(self):
        # Filesystem ports are inert DATA here: the separate real stager parent
        # admission protects the system path. This checks the adapter's binding
        # to that admitted original, not a claim of root filesystem qualification.
        op, observed = phase_value("baseline")
        native = op.app_absence["nativeBinding"]
        op.app_absence["binding"] = {key: native[key] for key in
            ("fixtureSource", "productSource", "runId", "runAttempt", "target")}
        parent = {"device": 9, "inode": 10, "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 80}
        private = {"device": 9, "inode": 11, "mode": stat.S_IFDIR | 0o700, "uid": 0, "gid": 0}
        value = {"schemaVersion": 1, "kind": "app-absence-baseline", "binding": native,
            "rootNonce": "7" * 32, "parentIdentity": parent, "privateIdentity": private,
            "siblingCensusSha256": "8" * 64, "siblingCount": 1, "rootAbsent": True,
            "transportState": "pending-original-exit"}
        def identity_stat(row):
            return SimpleNamespace(st_dev=row["device"], st_ino=row["inode"],
                st_mode=row["mode"], st_uid=row["uid"], st_gid=row["gid"])
        def read(candidate, *, parent_after=None):
            body = json.dumps(candidate, separators=(",", ":")).encode("ascii") + b"\n"
            before = SimpleNamespace(st_dev=9, st_ino=12, st_mode=stat.S_IFREG | 0o444,
                st_nlink=1, st_uid=0, st_gid=0, st_size=len(body), st_mtime_ns=1, st_ctime_ns=2)
            events = []
            @contextlib.contextmanager
            def channel(_root):
                events.append("entered")
                try:
                    yield 73, "MobileReleaseKit"
                finally:
                    events.append("closed")
            op.stager = SimpleNamespace(INSTALL_ROOT="inert-system-path", installer_channel_parent=channel,
                read_at=lambda fd, name, limit: (body, before),
                maintenance_json=lambda data, limit: HELPER.tool_json(data))
            with patch.object(FIXTURE.os, "stat", return_value=before), \
                    patch.object(FIXTURE.os, "fstat", side_effect=(identity_stat(parent), identity_stat(parent_after or parent))):
                try:
                    result = FIXTURE.baseline_read(op, hashlib.sha256(body).hexdigest())
                finally:
                    self.assertEqual(events, ["entered", "closed"])
            self.assertEqual(set(result), {"bytes", "sha256", "identity"})
            self.assertEqual(result["bytes"], len(body))
            return result
        self.assertEqual(read(value)["identity"][1], 12)
        for key, field, replacement in (("parentIdentity", "gid", 0), ("parentIdentity", "inode", 13),
                ("privateIdentity", "gid", 80), ("privateIdentity", "mode", stat.S_IFDIR | 0o755),
                ("privateIdentity", "device", 14), ("privateIdentity", "uid", 501)):
            candidate = copy.deepcopy(value); candidate[key][field] = replacement
            with self.subTest(key=key, field=field), self.assertRaises(ValueError):
                read(candidate)
        with self.assertRaisesRegex(ValueError, "baseline-original-post"):
            read(value, parent_after=dict(parent, inode=13))

class RestoreChainFixtureData(unittest.TestCase):
    def test_fixed_cut_artifact_graphs_and_nine_file_quote_both_targets(self):
        FIXTURE.recovery_builder_quote_data(100,20,4,10,29)  # Exactly96 live quote.
        for values in ((100,20,4,10,30),(1002,0,0,0,0),(1,1,16,0,0),(True,1,1,0,0)):
            with self.assertRaisesRegex(ValueError,'complete-original-quote'): FIXTURE.recovery_builder_quote_data(*values)
        checkout, target_root = Path('/owned/source'), Path('/owned/target')
        for target in FIXTURE.TARGETS:
            for cut in (None,) + FIXTURE.CUTS:
                rows = cargo_rows(checkout, target_root, target)
                features = (['macos-installed-app-absence-fixture', 'macos-installed-restore-chain-observer'] if cut is None
                            else ['macos-installed-installer', 'macos-installed-restore-' + cut + '-fixture'])
                for row in rows[:2]: row['features'] = features[:]
                program = FIXTURE.FIXTURE_EXECUTABLE if cut is None else 'mrk-macos-install'
                rows[0]['target']['name'] = program
                expected = target_root / target / 'release' / program
                rows[0]['executable'] = str(expected); rows[0]['filenames'] = [str(expected)]
                self.assertEqual(FIXTURE.artifact_data(encoded_rows(rows), checkout, target_root, target, cut=cut, recovery=True, package_version="0.1.2"), expected)
                current = copy.deepcopy(rows)
                for row in current[:2]: row['package_id'] = row['package_id'].replace('@0.1.2', '@0.1.3')
                self.assertEqual(FIXTURE.artifact_data(encoded_rows(current), checkout, target_root, target,
                    cut=cut, recovery=True, package_version='0.1.3'), expected)
                with self.assertRaises(ValueError):
                    FIXTURE.artifact_data(encoded_rows(rows), checkout, target_root, target,
                        cut=cut, recovery=True, package_version='0.1.3')
                for wrong in (['macos-installed-installer'], features + ['desktop-shell'], ['macos-installed-app-absence-fixture']):
                    changed = copy.deepcopy(rows); changed[0]['features'] = wrong
                    with self.assertRaises(ValueError):
                        FIXTURE.artifact_data(encoded_rows(changed), checkout, target_root, target, cut=cut, recovery=True, package_version="0.1.2")
                with self.assertRaises(ValueError): FIXTURE.artifact_data(encoded_rows(rows), checkout, target_root, target, package_version="0.1.2")
        rows = [{'name': n, 'bytes': 100, 'sha256': '5'*64, 'mode': 0o444, 'links': 1}
                for n in FIXTURE.CARRIER_NAMES + FIXTURE.CUT_PACKAGES]
        self.assertEqual(FIXTURE.transport_layout_data(rows, recovery=True)['fileCount'], 9)
        for wrong in (rows[:-1], rows+[rows[-1]], rows[:6]):
            with self.assertRaises(ValueError): FIXTURE.transport_layout_data(wrong, recovery=True)
        with self.assertRaises(ValueError): FIXTURE.transport_layout_data(rows)
        for row in rows:
            if row['name'].endswith('.pkg'): row['bytes'] = FIXTURE.PRODUCT_LIMIT
        with self.assertRaisesRegex(ValueError, 'image-content-bound'): FIXTURE.transport_layout_data(rows, recovery=True)

    def test_cut_scripts_pin_independently_authenticated_ordinary_product(self):
        stager = load_tool('mrk_restore_chain_stager', 'stage_macos_installed.py')
        selection, inventory, full, app = thin_inventory(stager)
        program = b'inert-program'
        rows = {'postinstall': (FIXTURE.CUT_POSTINSTALL, 0o555), 'mrk-macos-install': (program, 0o555),
                'input/'+stager.INSTALLATION_INVENTORY_NAME: (inventory, 0o444),
                **{'input/'+name: value for name, value in app.items()}}
        for cut in FIXTURE.CUTS:
            stager.app_absence_scripts_data(rows, FIXTURE.digest(program), FIXTURE.digest(inventory), restore_cut=cut)
            wrong = dict(rows); wrong['postinstall'] = (FIXTURE.CUT_POSTINSTALL.replace(b'"$p"', b'"$1"'), 0o555)
            with self.assertRaises(stager.Refused):
                stager.app_absence_scripts_data(wrong, FIXTURE.digest(program), FIXTURE.digest(inventory), restore_cut=cut)
        for cut in (None, 'any', True):
            with self.assertRaises(stager.Refused):
                stager.app_absence_scripts_data(rows, FIXTURE.digest(program), FIXTURE.digest(inventory), restore_cut=cut)

        observer = dict(rows)
        observer['postinstall'] = (FIXTURE.POSTINSTALL, 0o555)
        del observer['mrk-macos-install']
        observer[FIXTURE.FIXTURE_EXECUTABLE] = (program, 0o555)
        stager.app_absence_scripts_data(observer, FIXTURE.digest(program), FIXTURE.digest(inventory))
        for script, base_rows, cut in ((FIXTURE.POSTINSTALL, observer, None),
                                      (FIXTURE.CUT_POSTINSTALL, rows, FIXTURE.CUTS[0])):
            wrong = dict(base_rows)
            wrong['postinstall'] = (script.replace(b'cd -P "$scripts"', b'cd "$scripts"'), 0o555)
            with self.assertRaises(stager.Refused):
                stager.app_absence_scripts_data(wrong, FIXTURE.digest(program), FIXTURE.digest(inventory), restore_cut=cut)

        # Real shell, inert helper only: physical input spelling and unchanged
        # package derivation precede the unchanged native nofollow/type policy.
        with tempfile.TemporaryDirectory(prefix="mrk-app-absence-hook-") as directory:
            root = Path(directory).resolve()
            physical = root / "physical scripts"; physical.mkdir()
            alias = root / "logical scripts"; alias.symlink_to(physical, target_is_directory=True)
            (physical / "input").mkdir()
            stub = (b'#!/bin/sh\n[ "$#" -eq 2 ] || exit 98\n'
                    b'printf "%s\\n" "$1" "$2"\numask\nexit 23\n')
            environment = {"PATH": "/usr/bin:/bin"}
            for script, executable, package, expected in (
                    (FIXTURE.POSTINSTALL, FIXTURE.FIXTURE_EXECUTABLE,
                     "/Volumes/Fixed Carrier/MRK-AppAbsence-Baseline.pkg",
                     "/Volumes/Fixed Carrier/MRK-AppAbsence-Baseline.pkg"),
                    (FIXTURE.CUT_POSTINSTALL, "mrk-macos-install",
                     "/Volumes/Fixed Carrier/MRK-Restore-AppWrite.pkg", "/Volumes/Fixed Carrier/Install.pkg")):
                hook = physical / "postinstall"; hook.write_bytes(script); hook.chmod(0o555)
                helper = physical / executable; helper.write_bytes(stub); helper.chmod(0o555)
                for invocation, cwd in ((str(alias / "postinstall"), root), ("./postinstall", alias)):
                    returned = subprocess.run(["/bin/sh", invocation, package, "/", "/"],
                        cwd=cwd, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=5, check=False)
                    self.assertEqual(returned.returncode, 23)
                    self.assertEqual(returned.stderr, b"")
                    lines = returned.stdout.splitlines()
                    self.assertEqual(lines[:2], [str(physical / "input").encode(), expected.encode()])
                    self.assertEqual(len(lines), 3)
                    self.assertEqual(int(lines[2], 8), 0o077)
                wrong_entry = physical / "other"; wrong_entry.write_bytes(script); wrong_entry.chmod(0o555)
                for invocation, arguments in (
                        (str(wrong_entry), [package, "/", "/"]),
                        (str(hook), [package, "/", "/not-root"]),
                        (str(hook), ["relative.pkg", "/", "/"]),
                        (str(hook), [])):
                    returned = subprocess.run(["/bin/sh", invocation, *arguments], cwd=root,
                        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
                    self.assertEqual(returned.returncode, 1)
                    self.assertEqual((returned.stdout, returned.stderr), (b"", b""))
                hook.unlink(); helper.unlink(); wrong_entry.unlink()

    def test_whole_fixed_chain_requires_each_observer_and_preserves_ambiguous_failure(self):
        # Actual adapter order/dispatch/return/proof/finish functions. Only the
        # existing native call and readonly final filesystem POST are inert.
        for fault in (None, 'current-candidate', 'unknown-cut', 'bad-proof', 'cut-zero', 'cut-two'):
            with self.subTest(fault=fault), patch.object(FIXTURE.time, 'monotonic_ns', return_value=NOW):
                op, template = phase_value('verify')
                op.phase = FIXTURE.RESTORE; op.environment['GITHUB_REF'] = FIXTURE.RECOVERY_REF
                op.work = Path('/owned/work'); op.app_absence['complete'] = False
                expected_mount = op.work/'app-absence-mount'
                if fault == 'current-candidate':
                    op.candidate_restore_context = {}; op.target = FIXTURE.TARGETS[1]
                    op.environment.update(GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
                    op.app_absence['binding'] = dict(fixtureSource='1'*40,productSource='1'*40,
                        runId='123',runAttempt='1',target=op.target)
                    expected_mount = FIXTURE.candidate_mount_path(op,'app-absence-restore-attach')
                    op.app_absence['mount'] = dict(protected=True,path=expected_mount,role='app-absence-restore-attach',
                        entered=True,detached=False)
                fails = fault not in (None, 'current-candidate')
                op.app_absence['preparationSha256'] = '6'*64; op.receipt = {}
                op.calls = [call_row('app-absence-restore-attach'), call_row('app-absence-withdraw')]
                events = []
                def native(role, argv, **kwargs):
                    FIXTURE.dispatch(op, role); events.append(role)
                    self.assertEqual(argv[:5], ['/usr/bin/sudo','-n','--','/usr/sbin/installer','-pkg'])
                    self.assertEqual(Path(argv[5]).parent, expected_mount)
                    if role == 'app-absence-cut-app-write' and fault == 'unknown-cut':
                        raise RuntimeError('inert unresolved native original')
                    cut = role in ['app-absence-cut-'+c for c in FIXTURE.CUTS]
                    status = (0 if fault == 'cut-zero' else 2 if fault == 'cut-two' else 1) if cut else 0
                    # Same exact extra return predicate used by existing owner.
                    if cut and status != 1:
                        op.calls.append(call_row(role, returncode=status))
                        FIXTURE.returned(op, role)
                        self.fail('unexpected cut return admitted')
                    body = b''
                    phase = role.removeprefix('app-absence-')
                    if phase in FIXTURE.RECOVERY_PHASES:
                        index = FIXTURE.RECOVERY_PHASES.index(phase); value = copy.deepcopy(template)
                        value['phase'] = phase
                        value['proof'] = dict(step=index, initialHistoryPreserved=True, runtimeUnchanged=True,
                            withdrawnAppVerified=True, partialAppConserved=True, recordReadback=True,
                            ordinaryRetryComplete=index==3, originalOuterExitRequired=True)
                        if fault == 'bad-proof': value['proof']['partialAppConserved'] = False
                        body = marker(value)
                    op.calls.append(call_row(role, returncode=status)); FIXTURE.returned(op, role)
                    return SimpleNamespace(returncode=status, stdout=body, stderr=b'')
                op.package_call = native
                previous = {'binding': op.app_absence['nativeBinding'], 'baselineSha256':'3'*64, 'baselineOriginal':{'held':True}}
                def detached(_op, role):
                    FIXTURE.dispatch(_op, role); events.append(role); _op.calls.append(call_row(role)); FIXTURE.returned(_op, role)
                    if _op.app_absence['mount'] is not None: _op.app_absence['mount']['detached'] = True
                with patch.object(FIXTURE, 'reserve'), patch.object(FIXTURE, 'post'), \
                     patch.object(FIXTURE, 'baseline_read', return_value={'held':True}), patch.object(FIXTURE, 'detach', side_effect=detached):
                    if fails:
                        with self.assertRaises((ValueError, RuntimeError)):
                            FIXTURE.recovery_restore(op, SimpleNamespace(package=expected_mount/'Install.pkg'), previous, b'baseline', '7'*64, {})
                        self.assertFalse(op.app_absence['complete']); self.assertFalse(FIXTURE.finish_ready(op))
                        self.assertNotIn('app-absence-cut-own-attempt', events)
                    else:
                        FIXTURE.recovery_restore(op, SimpleNamespace(package=expected_mount/'Install.pkg'), previous, b'baseline', '7'*64, {})
                        self.assertEqual(tuple(e['role'] for e in op.calls), FIXTURE.roles(op))
                        self.assertTrue(FIXTURE.finish_ready(op)); self.assertTrue(op.receipt['restoreChain']['nativeRecoveredReadback'])
                        self.assertFalse(op.receipt['restoreChain']['nonrootExportCensusClaimed'])
                        self.assertFalse(op.receipt['restoreChain']['productReady'])
        for ref, phase, role, code in ((FIXTURE.REF, FIXTURE.RESTORE,'app-absence-cut-app-write',1),
                (FIXTURE.RECOVERY_REF,FIXTURE.PREPARE,'app-absence-cut-app-write',1),
                (FIXTURE.RECOVERY_REF,FIXTURE.RESTORE,'app-absence-install',1),
                (FIXTURE.RECOVERY_REF,FIXTURE.RESTORE,'app-absence-cut-app-write',True)):
            op = inert_operation(phase); op.environment['GITHUB_REF'] = ref
            self.assertFalse(FIXTURE.cut_return_data(op,role,code))

    def test_candidate_fixture_mount_binds_protected_parent_and_actual_root_argv(self):
        # Real original FDs, namespace mutation, roster/POST and consuming closes.
        # Only macOS metadata/API and the existing native command are inert ports;
        # no mount, Installer, sudo or signing executes on this host.
        for fault in (None, "root-owner", "group-write", "collision", "unknown-attach",
                      "wrong-device", "post-name", "native-one", "detach-one", "detach-post"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-fixture-mount-") as temporary:
                root = Path(temporary); system = root / "system"; system.mkdir(mode=0o755)
                volumes = system / "Volumes"; volumes.mkdir(mode=0o755)
                work = root / "work"; work.mkdir(mode=0o700)
                environment = dict(GITHUB_SHA="a"*40, GITHUB_WORKFLOW_SHA="a"*40,
                    GITHUB_WORKFLOW_REF="inert", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
                    MRK_MACOS_PACKAGE_ROLE="ordinary-image")
                op = HELPER.Operation(SimpleNamespace(), root, work, "candidate-baseline", environment, None)
                op.app_absence, op.app_absence_api = state(), HELPER
                op.app_absence["binding"] = dict(fixtureSource="b"*40, productSource="b"*40,
                    runId="123", runAttempt="1", target=op.target)
                op.candidate_restore_context = {"helperSource":"a"*40}
                op.package_clock = lambda: NOW
                op.package_settled = lambda: True
                role = "app-absence-baseline-attach"
                expected = FIXTURE.candidate_mount_path(op, role)
                self.assertEqual(expected.parent, Path("/Volumes"))
                self.assertEqual(len(expected.name), len("MRK-AppAbsence-") + 32)
                for bad_role in ("distribution-attach", "app-absence-restore-attach"):
                    with self.assertRaisesRegex(ValueError,"candidate-fixture-mount-role"):
                        FIXTURE.candidate_mount_path(op,bad_role)
                op.environment["GITHUB_RUN_ATTEMPT"] = "2"
                with self.assertRaisesRegex(ValueError,"candidate-fixture-mount-binding"):
                    FIXTURE.candidate_mount_path(op,role)
                op.environment["GITHUB_RUN_ATTEMPT"] = "1"
                own = volumes / expected.name
                sentinel = object(); op.transport_mount = sentinel
                original_open, original_stat, original_lstat, original_fstat = os.open, os.stat, os.lstat, os.fstat
                def path_for_fd(fd): return Path(os.readlink("/proc/self/fd/" + str(fd)))
                def metadata(info, path):
                    # Exact public Darwin-only scalar port. All identities,
                    # bytes, mode mutation and links otherwise come from real FDs.
                    fields = {name:getattr(info,name) for name in dir(info) if name.startswith("st_")}
                    mounted = path == own or own in path.parents
                    fields.update(st_uid=501 if fault == "root-owner" and path == volumes else 0,
                        st_gid=80 if path == volumes else 0, st_dev=72 if mounted else 71,
                        st_flags=1048576 if path == system else 0)
                    if fault == "group-write" and path == volumes: fields["st_mode"] |= 0o020
                    return SimpleNamespace(**fields)
                def opened(path, flags, *args, **kwargs):
                    return original_open(system if path == "/" else path, flags, *args, **kwargs)
                def stated(path, *args, **kwargs):
                    full = path_for_fd(kwargs["dir_fd"]) / path if kwargs.get("dir_fd") is not None else Path(path)
                    return metadata(original_stat(path, *args, **kwargs), full)
                def fstated(fd): return metadata(original_fstat(fd), path_for_fd(fd))
                def lstated(path, *args, **kwargs):
                    actual = system if path == "/" else Path(path)
                    return metadata(original_lstat(actual, *args, **kwargs), actual)
                def filesystem(fd):
                    mounted = path_for_fd(fd) == own
                    return dict(typeName="hfs" if mounted else "apfs", flags=0x1001 if mounted else 0x1000,
                        mountOn=str(expected) if mounted else str(path_for_fd(fd)),
                        mountFrom="/dev/wrong" if mounted and fault == "wrong-device" else "/dev/disk-test" if mounted else "/dev/system")
                op.removal_api = SimpleNamespace(filesystem=filesystem)
                op.removal_host_module = SimpleNamespace()
                op.removal_acl = lambda entry, info: info.st_flags  # Existing empty-ACL observer is a native port.
                op.stager = SimpleNamespace(distribution_mount_data=lambda stdout,stderr,code,path:
                    "/dev/disk-test" if code == 0 and path == expected else self.fail("wrong mount parser path"))
                rows = {name:{"bytes":len(name.encode()),"sha256":FIXTURE.digest(name.encode())}
                        for name in FIXTURE.carrier_names(op)}
                if fault == "collision": own.mkdir()
                op.calls = [call_row("app-absence-image-create"), call_row("app-absence-image-verify")]
                commands = []; captured = []
                def native(name, argv, **kwargs):
                    FIXTURE.dispatch(op, name); commands.append((name, argv))
                    if name == role:
                        self.assertEqual(argv[argv.index("-mountpoint")+1], str(expected))
                        if fault == "unknown-attach": raise RuntimeError("inert native custody unknown")
                        own.mkdir(mode=0o755)
                        for leaf in rows:
                            (own/leaf).write_bytes(leaf.encode()); (own/leaf).chmod(0o444)
                    elif name == "app-absence-baseline":
                        self.assertEqual(argv[:5], ["/usr/bin/sudo","-n","--","/usr/sbin/installer","-pkg"])
                        self.assertEqual(argv[5], str(expected / FIXTURE.PHASE_NAMES[0]))
                    else:
                        self.assertEqual(name, "app-absence-baseline-detach")
                        self.assertEqual(argv, ["/usr/bin/hdiutil","detach","/dev/disk-test"])
                    code = int((name == "app-absence-baseline" and fault == "native-one")
                               or (name.endswith("-detach") and fault == "detach-one"))
                    op.calls.append(call_row(name, returncode=code))
                    if code: raise HELPER.Refused("original-nonzero-" + name)
                    if name.endswith("-detach"):
                        for leaf in rows: (own/leaf).unlink()
                        own.rmdir()
                        if fault == "detach-post": volumes.chmod(0o750)
                    FIXTURE.returned(op,name)
                    return SimpleNamespace(returncode=0,stdout=b"inert",stderr=b"")
                op.package_call = native
                with patch.object(FIXTURE,"clock",return_value=NOW), patch.object(FIXTURE,"reserve"), \
                     patch.object(FIXTURE,"phase_observation",side_effect=lambda o,r,p: captured.append(p)), \
                     patch.object(HELPER.os,"open",side_effect=opened), patch.object(HELPER.os,"stat",side_effect=stated), \
                     patch.object(HELPER.os,"lstat",side_effect=lstated), patch.object(HELPER.os,"fstat",side_effect=fstated), \
                     patch.object(HELPER.os,"fstatvfs",return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                    try:
                        def run():
                            FIXTURE.attach(op,role,rows)
                            self.assertIs(op.transport_mount,sentinel)
                            mount = op.app_absence["mount"]
                            self.assertEqual(mount["parent"]["removal_system_path"],"/Volumes")
                            self.assertEqual(mount["parent"]["removal_facts"][0][5],80)
                            if fault == "post-name": own.rename(volumes / "changed")
                            # This lower root/mount test does not invoke the log child.
                            # The separately tested diagnostic slot has no root effect.
                            op.calls.append(call_row("app-absence-log-cursor", entered=True))
                            FIXTURE.root_call(op,"baseline")
                            FIXTURE.detach(op,"app-absence-baseline-detach")
                        if fault:
                            with self.assertRaises((ValueError,HELPER.Refused,RuntimeError,OSError)): run()
                            self.assertFalse(op.app_absence["mount"]["detached"])
                            if fault in ("root-owner","group-write","collision"): self.assertEqual(commands,[])
                            if fault == "native-one": self.assertEqual(op.app_absence["pendingRoot"],"app-absence-baseline")
                        else:
                            run(); self.assertTrue(FIXTURE.finish_ready(op)); self.assertEqual(captured,["baseline"])
                            self.assertFalse(own.exists())
                            self.assertTrue(all(e["closed"] for e in op.entries))
                        self.assertIs(op.transport_mount,sentinel)
                    finally:
                        for entry in reversed(op.entries): op.close(entry)
                    self.assertFalse(op.errors)
                    self.assertTrue(all(e["fd"] is None and e["closed"] for e in op.entries))

    def test_native_fixture_outputs_admit_private_umask_without_relaxing_original_policy(self):
        # Real private files/FDs and actual Operation.original + retained/hash.
        # No pkgbuild/tar/xar/hdiutil execution or native output-mode claim.
        with tempfile.TemporaryDirectory(prefix="mrk-fixture-native-modes-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            op = HELPER.Operation(SimpleNamespace(), root, root, FIXTURE.PREPARE,
                {"GITHUB_SHA":"a"*40, "GITHUB_WORKFLOW_SHA":"a"*40,
                 "GITHUB_WORKFLOW_REF":"inert-source", "GITHUB_RUN_ID":"123",
                 "GITHUB_RUN_ATTEMPT":"1", "MRK_MACOS_PACKAGE_ROLE":"ordinary-image"}, FIXTURE.TARGETS[0])
            op.app_absence, op.app_absence_api = state(), HELPER
            body = b"bounded synthetic package bytes\n"
            modes = (0o600, 0o644, 0o444)
            def create(name, mode=0o600, content=body):
                previous = os.umask(0o077)
                try:
                    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o666)
                finally:
                    os.umask(previous)
                try:
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o600)
                    self.assertEqual(os.write(fd, content), len(content))
                    os.fchmod(fd, mode)
                finally:
                    os.close(fd)
            try:
                fd = os.open(root, HELPER.READ_FLAGS|os.O_DIRECTORY)
                op.work_entry = op.register(fd, "work-root", "directory")
                op.work_entry["identity"] = HELPER.directory_identity(os.fstat(fd))
                with patch.object(FIXTURE, "clock", return_value=NOW):
                    for mode in modes:
                        name = "native-" + str(mode) + ".pkg"
                        create(name, mode)
                        item, sha = FIXTURE.retained(op, op.work_entry, name, len(body), modes)
                        self.assertEqual(op.read(item), body)
                        self.assertEqual(sha, hashlib.sha256(body).hexdigest())
                        self.assertEqual(stat.S_IMODE(item["identity"][2]), mode)
                        self.assertEqual(FIXTURE.original_hash(op, item), sha)
                        op.close(item)
                        self.assertTrue(item["closed"])
                    create("source.py")
                    with self.assertRaisesRegex(HELPER.Refused, "^file-original-shape$"):
                        op.source_original("source.py", "SOURCE-test", len(body))
                    for name, mode, content, limit in (
                            ("executable", 0o700, body, len(body)),
                            ("shared-write", 0o620, body, len(body)),
                            ("empty", 0o600, b"", len(body)),
                            ("oversized", 0o600, body, len(body)-1)):
                        create(name, mode, content)
                        with self.assertRaisesRegex(HELPER.Refused, "^file-original-shape$"):
                            FIXTURE.retained(op, op.work_entry, name, limit, modes)
                    create("linked")
                    os.link(root/"linked", root/"linked-other")
                    with self.assertRaisesRegex(HELPER.Refused, "^file-original-shape$"):
                        FIXTURE.retained(op, op.work_entry, "linked", len(body), modes)
                    os.symlink("source.py", root/"alias")
                    with self.assertRaises(OSError):
                        FIXTURE.retained(op, op.work_entry, "alias", len(body), modes)
                    create("changed")
                    item, _ = FIXTURE.retained(op, op.work_entry, "changed", len(body), modes)
                    os.chmod(root/"changed", 0o644)
                    with self.assertRaisesRegex(ValueError, "^app-absence-original-post$"):
                        FIXTURE.original_hash(op, item)
            finally:
                for item in reversed(op.entries):
                    op.close(item)
            self.assertFalse(op.errors)
            self.assertTrue(all(item["closed"] and item["fd"] is None for item in op.entries))

    def test_actual_shared_cut_builder_selects_fixed_image_script_and_clears_observer_tuple(self):
        # Whole shared prepare_one + genuine Cargo artifact reducer. Compiler,
        # signing/archive, and filesystem effects are inert boundaries here.
        for target in FIXTURE.TARGETS:
            for cut in FIXTURE.CUTS:
                with self.subTest(target=target,cut=cut):
                    op = inert_operation(); op.environment.update(GITHUB_REF=FIXTURE.RECOVERY_REF,
                        GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1', MRK_MACOS_INSTALL_INVENTORY_SHA256='2'*64,
                        MRK_BUNDLED_RUNTIME_MANIFEST_SHA256='3'*64)
                    op.work=Path('/owned/work');op.checkout=Path('/owned/source');op.target=target;op.target_name='compiler'
                    op.target_entry={};op.work_entry={};op.image_source='1'*40;op.image_release='0.1.2'
                    op.app_absence.update(binding={'fixtureSource':op.image_source},future={});op.package_sources=[]
                    identity = [1,2,0o100555,1000,1000,1,16,0,0,0,0]
                    def entry(name): return {'name':name,'identity':identity[:],'closed':False,'fd':55}
                    op.app_absence_api=SimpleNamespace(build_environment=lambda *a,**k:op.environment.copy(),
                        direct_rust_tools=lambda _:('/inert/cargo',),signature=lambda _:identity[:],directory_identity=lambda _:(1,2))
                    original_modes = {}
                    def original(parent, name, role, limit, modes, **kwargs):
                        original_modes[name] = modes
                        return entry(name)
                    op.descend=lambda *a: {};op.original=original
                    op.read=lambda e:b'program';op.close=lambda e:e.update(closed=True)
                    op.package_directory=lambda name:entry(name)
                    digest='4'*64; package_digest='5'*64
                    op.stager=SimpleNamespace(CURRENT_PROTOCOL='6'*64,PACKAGE_ID='fixed.test',macho=lambda *a,**k:None,
                        app_absence_original_command=lambda args:{'originalPackageSha256':package_digest,'packageInfo':b'info'},
                        app_absence_final_command=lambda args,compact:{'packageSha256':package_digest,'packageSize':16})
                    commands=[];written=[];allocations=[]
                    prefix='app-absence-cut-'+cut
                    def call(_op,role,argv,**kwargs):
                        commands.append((role,argv,kwargs))
                        if role.endswith('-build'):
                            self.assertNotIn('MRK_APP_ABSENCE_FIXTURE_SOURCE_COMMIT',kwargs['environment'])
                            self.assertNotIn('MRK_APP_ABSENCE_FIXTURE_RUN_ID',kwargs['environment'])
                            self.assertNotIn('MRK_APP_ABSENCE_FIXTURE_RUN_ATTEMPT',kwargs['environment'])
                            rows=cargo_rows(op.checkout,op.work/op.target_name,target)
                            for row in rows[:2]: row['features']=['macos-installed-installer','macos-installed-restore-'+cut+'-fixture']
                            rows[0]['target']['name']='mrk-macos-install'
                            rows[0]['executable']=str(op.work/op.target_name/target/'release/mrk-macos-install')
                            rows[0]['filenames']=[rows[0]['executable']]
                            return SimpleNamespace(stdout=encoded_rows(rows))
                        return SimpleNamespace(stdout=b'')
                    def copy_file(_op,old,parent,name,*a,**k):
                        e=entry(name);op.app_absence['outputs'].append((e,digest));return e
                    def retained(_op,parent,name,limit,modes=(0o444,0o600)):
                        original_modes[name] = modes
                        e=entry(name);sha=digest if name=='mrk-macos-install' else package_digest
                        op.app_absence['outputs'].append((e,sha));return e,sha
                    def output(_op,parent,name,body,**kwargs): written.append((name,body))
                    def quoted(_op,name=None):
                        if name:
                            allocations.append((name,_op.app_absence['future'][name]));del _op.app_absence['future'][name]
                    with patch.object(FIXTURE,'input_rows',return_value=(entry('inventory'),{'app/Contents/inert':{'size':1}})), \
                         patch.object(FIXTURE,'call',side_effect=call), patch.object(FIXTURE,'script_quote'), \
                         patch.object(FIXTURE,'selected',return_value=SimpleNamespace(package_version='0.1.2')), \
                         patch.object(FIXTURE,'original_hash',side_effect=lambda op,e:digest if e['name']=='mrk-macos-install' else package_digest), \
                         patch.object(FIXTURE,'copy',side_effect=copy_file),patch.object(FIXTURE,'retained',side_effect=retained), \
                         patch.object(FIXTURE,'output',side_effect=output),patch.object(FIXTURE,'mkdir',side_effect=lambda *a:entry('input')), \
                         patch.object(FIXTURE,'copy_input'),patch.object(FIXTURE,'input_post'),patch.object(FIXTURE,'post'), \
                         patch.object(FIXTURE,'reserve',side_effect=quoted),patch.object(FIXTURE,'io',side_effect=lambda op,label,fn,*a:fn(*a)), \
                         patch.object(FIXTURE.os,'fchmod'),patch.object(FIXTURE.os,'fstat',return_value=None):
                        data=FIXTURE.prepare_one(op,cut)
                    self.assertEqual([role for role,_,_ in commands],[prefix+'-'+r for r in ('build','adhoc','verify-code','pkgbuild','tar','xar')])
                    self.assertEqual(commands[0][1][commands[0][1].index('--features')+1],'macos-installed-restore-'+cut+'-fixture')
                    for name in (prefix+'-original.pkg', 'Scripts', 'fixture.pkg'):
                        self.assertEqual(original_modes[name], (0o600,0o644,0o444))
                    self.assertEqual(original_modes['mrk-macos-install'], (0o555,))
                    for index in (1,2): self.assertEqual(commands[index][1][-1],str(op.work/(prefix+'-prepared')/'mrk-macos-install'))
                    self.assertIn(('postinstall',FIXTURE.CUT_POSTINSTALL),written)
                    self.assertIsNone(data['pureDataTests']);self.assertFalse(data['productReady'])
                    self.assertEqual(data['fixtureFeature'],'macos-installed-restore-'+cut+'-fixture')
                    self.assertEqual([n for n,_ in allocations],[prefix+'-'+n for n in ('executable','scripts','original','archive','fixture')])
                    self.assertEqual([size for _,size in allocations],[FIXTURE.OUTPUTS[n] for n in ('executable','scripts','original','archive','fixture')])

    def test_existing_operation_owner_accepts_only_joined_cut_one_and_settled_proof(self):
        # Reuse existing Operation fixture (no new process implementation).
        import sys
        import subprocess
        spec = importlib.util.spec_from_file_location('mrk_restore_chain_existing_fixtures', ROOT/'tests/desktop/test_macos_installed_staging.py')
        fixtures = importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        harness = fixtures.MacAndroidHelperPackagingData()
        for fault in (None, 'zero', 'unknown', 'unproved'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                checkout, work, environment, _, _ = harness.fixture(Path(directory),build_target=FIXTURE.TARGETS[0])
                producer,service,_,_,_=fixtures.packaging_fixture(FIXTURE.TARGETS[0])
                (checkout/HELPER.PROFILE).write_bytes(service);(checkout/HELPER.PRODUCER_PROFILE).write_bytes(producer)
                adapter_path=checkout/'desktop/tools/macos_app_absence_fixture.py';adapter_path.parent.mkdir(parents=True,exist_ok=True)
                adapter_path.write_bytes((ROOT/'desktop/tools/macos_app_absence_fixture.py').read_bytes());adapter_path.chmod(0o644)
                environment.update(GITHUB_REF=HELPER.RESTORE_CHAIN_REF,MRK_MACOS_SAME_PACKAGE_SCOPE='disabled')
                events=[]
                def native(argv,**kwargs):
                    role=operation.calls[-1]['role'];events.append(role)
                    self.assertEqual(argv,['/inert/fixed-data-port',role])
                    if role=='app-absence-cut-app-write' and fault=='unknown': raise RuntimeError('inert original uncertainty')
                    code=1 if role.startswith('app-absence-cut-') else 0
                    if role=='app-absence-cut-app-write' and fault=='zero': code=0
                    return subprocess.CompletedProcess(argv,code,b'',b'')
                operation=HELPER.Operation(SimpleNamespace(run_owned=native),checkout,work,FIXTURE.RESTORE,environment,fixtures.TOOL,target=FIXTURE.TARGETS[0])
                original_load=operation.app_absence_load
                def phase_port(op):
                    adapter=op.app_absence_module;op.app_absence['case']=op.package_directory('app-absence-case')
                    op.app_absence['mount']={'entered':False,'detached':False}
                    for role in adapter.roles(op):
                        op.package_call(role,['/inert/fixed-data-port',role],timeout=30,limit=65536)
                        phase=role.removeprefix('app-absence-')
                        if phase in adapter.RECOVERY_PHASES:
                            _, value=phase_value('verify');index=adapter.RECOVERY_PHASES.index(phase)
                            op.app_absence['nativeBinding']={k:value[k] for k in adapter.BINDING_FIELDS}
                            op.app_absence['baselineSha256']=value['baselineSha256'];value['phase']=phase
                            value['proof']=dict(step=index,initialHistoryPreserved=True,runtimeUnchanged=True,
                                withdrawnAppVerified=True,partialAppConserved=fault!='unproved',recordReadback=True,
                                ordinaryRetryComplete=index==3,originalOuterExitRequired=True)
                            adapter.phase_observation(op,SimpleNamespace(returncode=0,stdout=marker(value),stderr=b''),phase)
                        if role=='app-absence-restore-detach':op.app_absence['mount']['detached']=True
                    op.sha256='a'*64;op.app_absence['complete']=True  # Inert phase port, not a native claim.
                def load():
                    original_load();operation.app_absence_module.restore=phase_port
                try:
                    with patch.dict(sys.modules,{HELPER.__name__:HELPER}),patch.object(operation,'app_absence_load',side_effect=load), \
                         patch.object(os,'fstatvfs',return_value=SimpleNamespace(f_bavail=100*1024*1024,f_frsize=4096)):
                        if fault is None: operation.execute()
                        else:
                            with self.assertRaisesRegex(HELPER.Refused,'^helper-package-incomplete$'):operation.execute()
                    self.assertEqual(operation.credential_calls,[]);self.assertEqual(operation.credential_contexts,[])
                    if fault is None:
                        self.assertTrue(operation.receipt['passed']);self.assertTrue(operation.receipt['originalClosesKnown'])
                        self.assertTrue(operation.receipt['targetRetired'])
                        self.assertEqual(sum(row['returncode']==1 for row in operation.calls),3)
                    else:
                        self.assertFalse(operation.receipt['passed']);self.assertNotIn('app-absence-cut-own-attempt',events)
                        self.assertFalse(operation.receipt['originalClosesKnown'] or operation.receipt['targetRetired'])
                finally:
                    for entry in reversed(operation.entries): operation.close(entry)
