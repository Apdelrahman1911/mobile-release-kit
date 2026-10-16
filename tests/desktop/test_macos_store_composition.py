"""Current packaging integration with inert inputs; never native execution.

The fresh supplier boundary is mocked. The real preparer, source projection,
ZIP creation, Store merge, output checks and final staging all execute.
"""
import contextlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_macos_launcher_staging import TOOL
from test_macos_store_staging import StoreStaging


@contextlib.contextmanager
def fixture():
    assert os.geteuid() != 0, "Run filesystem cases as a nonroot test user"
    helper = (Path(__file__).resolve().parents[2] / "desktop/tools/prepare_runtime.py").read_bytes()
    with tempfile.TemporaryDirectory(prefix="mrk-store-composition-") as directory:
        root = Path(directory)
        checkout = root / "checkout"
        engine = b"# Inert selected core, never executed\n"
        tooling = {"Gemfile": b"# fixed synthetic dependencies\n", "Gemfile.lock": b"fixed lock\n",
                   "fastlane/Fastfile": b"# fixed lane\n", "fastlane/run_lane.rb": b"# current lane runner\n",
                   "fastlane/native_process_spawn.rb": b"# inert source only\n"}
        inputs = {"src/mobile_release/__init__.py": b'__version__ = "0.3.0"\n',
                  "src/mobile_release/_desktop_engine.py": engine,
                  "src/mobile_release/tooling.py": ("REQUIRED_TOOLING_FILES = " + repr(tuple(tooling)) + "\n").encode(),
                  TOOL.CURRENT_CA_SOURCE: b"synthetic CA, not usable TLS material\n",
                  TOOL.CURRENT_HELPER_SOURCE: helper, **tooling}
        inputs.update({"desktop/" + name: b"# inert bootstrap\n" for name in TOOL.CURRENT_BOOTSTRAPS | {"local_store_preflight_bootstrap.py"}})
        for name, body in inputs.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        profile = checkout / TOOL.HISTORY_PROVIDER_PROFILE
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_bytes(TOOL.canonical({"schemaVersion": 1, "version": "2.88.1",
            "sourceManifestSha256": None, "targets": {TOOL.ARM_TARGET: None, TOOL.INTEL_TARGET: None}}))
        component = root / "component"
        component.mkdir()
        component_files = StoreStaging().fixture(TOOL.ARM_TARGET)
        component_files.update({"store/tooling/" + name: (body, 0o444) for name, body in tooling.items()})
        component_files["store/tooling/fastlane/run_lane.rb"] = (b"# obsolete runner\n", 0o444)
        component_files["store/tooling/obsolete.rb"] = (b"# not part of current core\n", 0o444)
        for name, (body, mode) in component_files.items():
            path = component / name.removeprefix("store/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        supplier = {"python/bin/python3": (b"INERT PYTHON, NEVER EXECUTED\n", 0o555),
                    "python/licenses/notice.txt": (b"inert supplier notice\n", 0o444)}
        python_root = root / "python-input"
        python_root.mkdir()
        receipt = root / "supplier.json"
        receipt.write_text("{}")
        fresh = (supplier, {"supplierOrigin": "fresh-public-source"})
        with (mock.patch.object(TOOL, "DESKTOP", checkout / "desktop"),
              mock.patch.object(TOOL, "CURRENT_PROTOCOL", TOOL.digest(engine)),
              mock.patch.object(TOOL, "fresh_supplier", return_value=fresh)):
            yield SimpleNamespace(root=root, checkout=checkout, component=component,
                supplier=supplier, python_root=python_root, receipt=receipt, tooling=tooling)


def args(f, suffix, *, store=True, final=False):
    return SimpleNamespace(command="current-runtime" if final else "describe-current-runtime",
        archive=None, python_root=f.python_root, supplier_receipt=f.receipt,
        expected_supplier="1" * 64, store_component=f.component if store else None,
        work=f.root / ("work-" + suffix), output=f.root / ("output-" + suffix),
        expected_source="0" * 64, expected_manifest="0" * 64)


class StoreComposition(unittest.TestCase):
    def test_current_command_composes_source_tooling_without_rebuilding_dependencies(self):
        with fixture() as f:
            described = TOOL.current_runtime_command(args(f, "description"))
            final = args(f, "final", final=True)
            final.expected_source = described["sourceInputsSha256"]
            final.expected_manifest = described["successorManifestSha256"]
            result = TOOL.current_runtime_command(final)
            output = TOOL.tree(final.output, current_root_mode=0o555)
            self.assertEqual(result["qualification"], "current-source-staged-no-native-execution")
            for name, body in f.tooling.items():
                self.assertEqual(output["store/tooling/" + name], (body, 0o444))
            self.assertEqual(output["local_store_preflight_bootstrap.py"], (b"# inert bootstrap\n", 0o444))
            self.assertNotIn("store/tooling/obsolete.rb", output)
            self.assertEqual((f.component / "tooling/fastlane/run_lane.rb").read_bytes(), b"# obsolete runner\n")
            self.assertEqual(output["python/bin/python3"], f.supplier["python/bin/python3"])
            captured, projection, _ = TOOL.current_source(store_runtime=True)
            self.assertTrue(set(f.tooling) <= set(captured))
            preparer = TOOL.current_preparer(captured)
            observed = preparer._store_inputs(f.component, final.work / "source", final.work / "runtime")
            rows = preparer._store_output_rows(observed)
            runtime = final.work / "runtime"
            TOOL.current_runtime_files(runtime, projection, f.supplier, store_rows=rows)
            changed = runtime / "store/tooling/fastlane/run_lane.rb"
            changed.chmod(0o600)
            changed.write_bytes(b"# substituted runner\n")
            changed.chmod(0o444)
            with self.assertRaisesRegex(TOOL.Refused, "current-store-original-correspondence"):
                TOOL.current_runtime_files(runtime, projection, f.supplier, store_rows=rows)

    def test_omitted_component_preserves_python_only_route_and_store_is_never_implicit(self):
        with fixture() as f:
            selection = args(f, "no-store", store=False)
            TOOL.current_runtime_command(selection)
            files = TOOL.tree(selection.work / "runtime", current_root_mode=0o700)
            self.assertFalse(any(name.startswith("store/") for name in files))
            self.assertNotIn("local_store_preflight_bootstrap.py", files)
            captured, _, _ = TOOL.current_source()
            self.assertTrue(set(f.tooling).isdisjoint(captured))
            rejected = args(f, "historical")
            rejected.archive = f.root / "unread-historical.zip"
            rejected.python_root = None
            rejected.supplier_receipt = None
            rejected.expected_supplier = None
            with self.assertRaisesRegex(TOOL.Refused, "current-store-fresh-supplier-only"):
                TOOL.current_runtime_command(rejected)
            self.assertFalse(rejected.work.exists())

    def test_store_input_overlap_refuses_before_work_or_output_creation(self):
        with fixture() as f:
            selection = args(f, "overlap")
            selection.work = f.component / "would-clobber-input"
            with self.assertRaisesRegex(TOOL.Refused, "current-path-overlap"):
                TOOL.current_runtime_command(selection)
            self.assertFalse(selection.work.exists())
            self.assertFalse(selection.output.exists())
