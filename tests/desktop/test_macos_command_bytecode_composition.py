"""#17: complete current ARM Mac composition WITH command bytecode, as DATA.

The actual stager source capture, its loaded preparer, `write_tree`,
`prepare_current(..., macos_command_bytecode=True)`, `current_runtime_files`
and the final normalized `write_tree` all execute unmodified, in the same
order as `current_runtime_command`. Only its signed-supplier/producer entry
(not reproducible without real producer identities) is replaced by the same
explicit DATA it would hand on: a supplier whose stdlib startup sources are
the pinned CPython 3.14.7 compiler's own library bytes, an inert synthetic
Mach-O `tools/gh` provider, and the existing synthetic Store component. No
code is executed from the composition, no signature is created or implied.

A darwin creation context that labels every new file com.apple.provenance
(an attributed, sandboxed launcher) cannot satisfy the unchanged no-xattr
output policy; run these from an ordinary unattributed context, as CI does.
"""
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from test_macos_installed_staging import history_provider_macho_fixture
from test_macos_launcher_staging import TOOL as S
import test_macos_store_staging as store_staging

_SOURCE = Path(__file__).resolve().parents[2]
PINNED = sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 14, 7) and sys.flags.optimize == 0
LIBRARY = Path(os.__file__).parent
STDLIB = "python/lib/python3.14/"


def _pyc_name(source):
    parent, _, leaf = source.rpartition("/")
    return parent + "/__pycache__/" + leaf[:-3] + ".cpython-314.pyc"


@unittest.skipUnless(PINNED, "the closed command bytecode is defined only for the pinned CPython 3.14.7 compiler")
class CommandBytecodeComposition(unittest.TestCase):
    def setUp(self):
        assert os.geteuid() != 0, "Run filesystem cases as a nonroot test user"
        scope = tempfile.TemporaryDirectory(prefix="mrk-command-bytecode-composition-")
        self.addCleanup(scope.cleanup)
        self.root = Path(scope.name).resolve()
        self.checkout = self.root / "checkout"
        # Literal capture of THIS commit's actual selected inputs (core, every
        # fixed bootstrap, CA, preparer, provider profile and Store tooling).
        names = [path.relative_to(_SOURCE).as_posix() for path in sorted((_SOURCE / "src/mobile_release").rglob("*"))
                 if path.is_file() and path.suffix in {".py", ".json", ".pem"} and "__pycache__" not in path.parts]
        names += ["desktop/" + name for name in S.CURRENT_BOOTSTRAPS | {
            "local_store_preflight_bootstrap.py", "local_store_prepare_bootstrap.py", "local_store_execute_bootstrap.py",
            "local_store_reconcile_bootstrap.py", "apple_provisioning_bootstrap.py"}]
        names += [S.CURRENT_CA_SOURCE, S.CURRENT_HELPER_SOURCE, S.HISTORY_PROVIDER_PROFILE]
        preparer = importlib.util.spec_from_file_location("mrk_bytecode_composition_roster", _SOURCE / S.CURRENT_HELPER_SOURCE)
        roster = importlib.util.module_from_spec(preparer)
        preparer.loader.exec_module(roster)
        self.tooling = roster._store_tooling_names((_SOURCE / "src/mobile_release/tooling.py").read_bytes())
        names += list(self.tooling)
        self.inputs = {name: (_SOURCE / name).read_bytes() for name in names}
        for name, body in self.inputs.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        self.component = self.root / "component"
        files = store_staging.StoreStaging().fixture(S.ARM_TARGET)
        files.update({"store/tooling/" + name: (self.inputs[name], 0o444) for name in self.tooling})
        for name, (body, mode) in files.items():
            path = self.component / name.removeprefix("store/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        # Supplier DATA: an inert interpreter entry plus the pinned compiler's
        # own stdlib bytes for the closed roster and one unrelated module.
        self.supplier = {"python/bin/python3": (b"INERT PYTHON, NEVER EXECUTED\n", 0o555),
                         "python/licenses/notice.txt": (b"inert supplier notice\n", 0o444),
                         STDLIB + "this.py": ((LIBRARY / "this.py").read_bytes(), 0o444)}
        for name in S.CURRENT_COMMAND_STDLIB_BYTECODE_FILES:
            self.supplier[STDLIB + name] = ((LIBRARY / name).read_bytes(), 0o444)
        self.provider = history_provider_macho_fixture(target=S.ARM_TARGET)
        self.nomination = {"version": S.HISTORY_PROVIDER_VERSION, "target": S.ARM_TARGET,
                           "sourceManifestSha256": "1" * 64, "sha256": hashlib.sha256(self.provider).hexdigest()}
        patcher = mock.patch.object(S, "DESKTOP", self.checkout / "desktop")
        patcher.start()
        self.addCleanup(patcher.stop)

    def compose(self, label, supplier=None):
        """The current_runtime_command order, from source capture to verification."""
        supplier = self.supplier if supplier is None else supplier
        captured, projection, _ = S.current_source(history_provider=True, store_runtime=True)
        preparer = S.current_preparer(captured)
        preparer._require_core_compiler()
        work = self.root / ("work-" + label)
        work.mkdir()
        source, runtime = work / "source", work / "runtime"
        S.write_tree(source, projection, current_owned=True)
        S.write_tree(runtime, {**supplier, S.HISTORY_PROVIDER_PATH: (self.provider, 0o555)}, root_mode=0o700, current_owned=True)
        store = preparer._store_inputs(self.component, source, runtime)
        rows = preparer._store_output_rows(store)
        old = os.umask(0o077)
        try:
            prepared = preparer.prepare_current(source, runtime, S.ARM_TARGET, history_provider=True,
                                                store_component=self.component, macos_command_bytecode=True)
        finally:
            os.umask(old)
        return preparer, projection, runtime, store, rows, prepared

    def verify(self, runtime, projection, rows, supplier=None):
        return S.current_runtime_files(runtime, projection, self.supplier if supplier is None else supplier,
                                       target=S.ARM_TARGET, history_provider=self.provider, store_rows=rows,
                                       macos_command_bytecode=True)

    def test_complete_composition_ships_exactly_the_independently_rederived_stdlib_rows(self):
        preparer, projection, runtime, store, rows, prepared = self.compose("complete")
        files, manifest = self.verify(runtime, projection, rows)
        preparer._store_recheck(store)
        manifest_body = files["manifest.json"][0]
        self.assertEqual(prepared, {"manifestSha256": hashlib.sha256(manifest_body).hexdigest(),
                                    "protocolSha256": S.CURRENT_PROTOCOL, "qualification": "prepared-not-native-verified"})
        sources = sorted(STDLIB + name for name in S.CURRENT_COMMAND_STDLIB_BYTECODE_FILES)
        expected = {_pyc_name(name): name for name in sources}
        generated = {name for name in files if "__pycache__" in name.split("/") or name.endswith((".pyc", ".pyo"))}
        stdlib = {name for name in generated if name.startswith("python/")}
        # Exactly 64 new stdlib rows, all beside retained, byte-unchanged sources.
        self.assertEqual(len(expected), 64)
        self.assertEqual(stdlib, set(expected))
        self.assertEqual(generated, stdlib)  # Core bytecode lives inside core.zip only.
        for name, value in self.supplier.items():
            self.assertEqual(files[name], value)
        # Manifest/full roster: every file, and only files, with size+digest.
        listed = {row["path"]: row for row in json.loads(manifest_body)["files"]}
        self.assertEqual(set(listed), set(files) - {"manifest.json"})
        for name in expected:
            body = files[name][0]
            self.assertEqual((listed[name]["size"], listed[name]["sha256"]), (len(body), hashlib.sha256(body).hexdigest()))
        # Writer modes: generated private 0600, new cache dirs take 0555 like
        # every other supplier directory; root stays the private 0700 root.
        for name in expected:
            info = (runtime / name).lstat()
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o600, 1))
            self.assertEqual(stat.S_IMODE((runtime / name).parent.lstat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(runtime.lstat().st_mode), 0o700)
        # Bounds: no existing limit raised; generated bytes inside fixed ceiling.
        self.assertLessEqual(sum(len(files[name][0]) for name in expected), preparer.MAX_STDLIB_BYTECODE_BYTES)
        directories = {parent.as_posix() for name in files for parent in Path(name).parents if parent != Path(".")}
        self.assertLessEqual(len(files), preparer.MAC_MAX_FILES)
        self.assertLessEqual(len(files) + len(directories), preparer.MAC_MAX_ENTRIES)
        self.assertLessEqual(len(manifest_body), preparer.MAC_MANIFEST_BYTES)
        self.assertEqual(S.current_stdlib_bytecode({k: v for k, v in self.supplier.items()}),
                         {name: files[name][0] for name in expected})
        # Independent of both tools: each row is checked-hash DATA for its own
        # retained source, with the logical runtime-relative filename.
        for name, source in expected.items():
            body, content = files[name][0], self.supplier[source][0]
            self.assertEqual(body[:4], importlib.util.MAGIC_NUMBER)
            self.assertEqual(body[4:8], (3).to_bytes(4, "little"))
            self.assertEqual(body[8:16], importlib.util.source_hash(content))
            loaded = marshal.loads(body[16:])
            self.assertEqual(loaded, compile(content, source, "exec", dont_inherit=True, optimize=0))
            self.assertEqual(loaded.co_filename, source)
        # Final staging normalizes every generated row to the read-only roles.
        output = self.root / "output-complete"
        normalized = {name: (body, S.current_runtime_mode(name, body, self.nomination, target=S.ARM_TARGET))
                      for name, (body, _) in files.items()}
        S.write_tree(output, normalized, current_owned=True, mac_store_prefix="store")
        staged = S.tree(output, current_root_mode=0o555, mac_store_prefix="store")
        self.assertEqual(staged, normalized)
        self.assertEqual({staged[name][1] for name in expected}, {0o444})

    def test_substituted_missing_or_extra_bytecode_after_preparation_is_refused(self):
        _, projection, runtime, _, rows, _ = self.compose("substitution")
        self.verify(runtime, projection, rows)
        typing, decoder = _pyc_name(STDLIB + "typing.py"), _pyc_name(STDLIB + "json/decoder.py")
        original = {name: (runtime / name).read_bytes() for name in (typing, decoder)}
        def replace(name, body):
            path = runtime / name
            path.parent.chmod(0o700)
            path.unlink()
            path.write_bytes(body)
            path.chmod(0o600)
            path.parent.chmod(0o555)
        cases = {
            "path-substitution": ({typing: original[decoder], decoder: original[typing]},
                                  "current-stdlib-bytecode-correspondence"),
            "untreed-same-code": ({typing: original[typing][:16] + marshal.dumps(marshal.loads(original[typing][16:]))},
                                  "current-stdlib-bytecode-correspondence"),
            "timestamp-header": ({typing: original[typing][:4] + bytes(4) + original[typing][8:]},
                                 "current-stdlib-bytecode-correspondence"),
        }
        for case, (changes, reason) in cases.items():
            with self.subTest(case=case):
                for name, body in changes.items():
                    replace(name, body)
                with self.assertRaisesRegex(S.Refused, reason):
                    self.verify(runtime, projection, rows)
                for name in changes:
                    replace(name, original[name])
                self.verify(runtime, projection, rows)
        extra = runtime / STDLIB / "__pycache__/this.cpython-314.pyc"
        extra.parent.chmod(0o700)
        extra.write_bytes(original[typing])
        extra.chmod(0o600)
        extra.parent.chmod(0o555)
        with self.assertRaisesRegex(S.Refused, "current-stdlib-bytecode-roster"):
            self.verify(runtime, projection, rows)

    def test_incoming_bytecode_or_missing_startup_source_never_reaches_output(self):
        incoming = dict(self.supplier, **{STDLIB + "__pycache__/typing.cpython-314.pyc": (b"cached elsewhere", 0o444)})
        missing = {name: value for name, value in self.supplier.items() if name != STDLIB + "typing.py"}
        for label, supplier in (("incoming", incoming), ("missing", missing)):
            with self.subTest(case=label):
                with self.assertRaises(Exception) as caught:
                    self.compose(label, supplier)
                self.assertIn(type(caught.exception).__name__, {"PreparationError", "Refused"})
                runtime = self.root / ("work-" + label) / "runtime"
                self.assertFalse((runtime / "manifest.json").exists())
                self.assertFalse((runtime / "core.zip").exists())
                self.assertEqual({entry.name for entry in runtime.iterdir()}, {"python", "tools"})


if __name__ == "__main__":
    unittest.main()
