"""Synthetic CLI packaging DATA only; no compiler, signing, service or native call."""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).absolute().parents[2]
spec = importlib.util.spec_from_file_location("mrk_cli_staging_data", ROOT / "desktop/tools/stage_macos_installed.py")
TOOL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TOOL)
END = {"reason": "build-finished", "success": True}


def named_command(kind, value, prefix):
    data = value + b"\0"
    size = (prefix + len(data) + 7) // 8 * 8
    header = struct.pack("<III", kind, size, prefix)
    return header + bytes(prefix - len(header)) + data + bytes(size - prefix - len(data))


def executable(target=TOOL.ARM_TARGET, *, dependency=b"/usr/lib/libSystem.B.dylib", minimum=26, extra=()):
    cpu, subtype = TOOL.target_machine(target)
    commands = (struct.pack("<6I", 0x32, 24, 1, minimum << 16, minimum << 16, 0),
        named_command(0xC, dependency, 24), named_command(0xE, b"/usr/lib/dyld", 12),
        struct.pack("<IIQQ", 0x80000028, 24, 0, 0), *extra)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, len(commands),
                       sum(map(len, commands)), 0x200084, 0) + b"".join(commands)


def cargo_fixture(*, target=TOOL.ARM_TARGET, version="0.1.2", directory=Path("/synthetic-cli/installed-cli-target")):
    binary = directory / target / "release/mrk"
    root = TOOL.DESKTOP / "src-tauri"
    rows = []
    for source, package, name, kind, source_file, features, package_version in (
        (root, "mobile-release-kit-desktop", "mrk", "bin", "src/installed_cli_main.rs", ["installed-cli"], version),
        (root, "mobile-release-kit-desktop", "mobile_release_desktop", "lib", "src/lib.rs", ["installed-cli"], version),
        (TOOL.DESKTOP / "native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
         "lib", "src/lib.rs", ["default"], "0.1.0"),
    ):
        rows.append({"reason": "compiler-artifact", "package_id": "path+" + source.as_uri() + "#" + package + "@" + package_version,
            "manifest_path": str(source / "Cargo.toml"),
            "target": {"name": name, "kind": [kind], "crate_types": [kind], "src_path": str(source / source_file), "edition": "2021"},
            "profile": {"opt_level": "3", "debug_assertions": False, "test": False}, "features": features, "fresh": False,
            "filenames": [str(binary if kind == "bin" else binary.parent / "deps" / ("lib" + name + ".rlib"))],
            "executable": str(binary) if kind == "bin" else None})
    return directory, binary, rows, executable(target)


def lines(*rows):
    return b"".join(TOOL.canonical(row) + b"\n" for row in rows)


class InstalledCliCargoData(unittest.TestCase):
    def parse(self, rows, *, target=TOOL.ARM_TARGET, version="0.1.2", body=None, binary=None, directory=None):
        folder, path, _, original = cargo_fixture(target=target, version=version)
        return TOOL.installed_cli_cargo_artifact(lines(*rows, END), binary or path, directory or folder,
            original if body is None else body, target=target, package_version=version)

    def test_exact_selected_graph_accepts_both_thin_targets_and_real_boolean_fresh(self):
        for target in TOOL.MAC_TARGETS:
            for fresh in (False, True):
                _, _, rows, body = cargo_fixture(target=target, version="0.1.3")
                for row in rows:
                    row["fresh"] = fresh
                result = self.parse(rows, target=target, version="0.1.3")
                self.assertEqual(result["entrypoint"], "src/installed_cli_main.rs")
                self.assertEqual(result["features"], ["installed-cli"])
                self.assertEqual(result["binarySha256"], TOOL.digest(body))

    def test_wrong_source_binary_manifest_or_artifact_path_is_not_the_cli(self):
        directory, binary, rows, _ = cargo_fixture()
        mutations = (("package_id", "path+file:///foreign#mobile-release-kit-desktop@0.1.2"),
            ("manifest_path", "/foreign/Cargo.toml"), ("executable", str(binary.with_name("mrk-copy"))),
            ("filenames", [str(binary), str(binary.with_name("mrk-copy"))]))
        for key, value in mutations:
            changed = copy.deepcopy(rows); changed[0][key] = value
            with self.subTest(field=key), self.assertRaises(TOOL.Refused):
                self.parse(changed)
        for key, value in (("name", "mobile-release-kit-desktop"), ("kind", ["test"]),
                           ("crate_types", ["cdylib"]), ("src_path", str(TOOL.DESKTOP / "src-tauri/src/main.rs"))):
            changed = copy.deepcopy(rows); changed[0]["target"][key] = value
            with self.subTest(target_field=key), self.assertRaises(TOOL.Refused):
                self.parse(changed)
        for wrong in (binary.with_name("mrk-macos-entry"), directory / TOOL.ARM_TARGET / "debug/mrk", Path("relative/mrk")):
            with self.assertRaises(TOOL.Refused): self.parse(rows, binary=wrong)

    def test_feature_unification_wrong_profile_or_missing_library_refuses(self):
        _, _, rows, _ = cargo_fixture()
        for position, field, value in ((0, "features", ["installed-cli", "desktop-shell"]),
            (1, "features", ["installed-cli", "default"]), (2, "features", ["default", "desktop-image"]),
            (0, "fresh", 1), (1, "fresh", None), (0, "profile", {"opt_level": "0", "debug_assertions": True, "test": False}),
            (1, "profile", {"opt_level": "3", "debug_assertions": False, "test": True})):
            changed = copy.deepcopy(rows); changed[position][field] = value
            with self.subTest(position=position, field=field), self.assertRaises(TOOL.Refused):
                self.parse(changed)
        for changed in (rows[:1], rows[:2], rows + rows[:1]):
            with self.assertRaises(TOOL.Refused): self.parse(changed)
        unrelated = copy.deepcopy(rows[0]); unrelated["target"]["name"] = "other-bin"
        unrelated["filenames"], unrelated["executable"] = ["/other"], "/other"
        with self.assertRaisesRegex(TOOL.Refused, "no-mixed-role"):
            self.parse(rows + [unrelated])

    def test_cargo_requires_complete_success_without_duplicate_terminal_fields(self):
        directory, binary, rows, body = cargo_fixture()
        for data in (lines(*rows), lines(*rows, dict(END, success=False)), lines(*rows, END, rows[0]),
                     lines(*rows, END).rstrip(b"\n"), lines(*rows) + b'{"reason":"build-finished","success":false,"success":true}\n'):
            with self.assertRaises(TOOL.Refused):
                TOOL.installed_cli_cargo_artifact(data, binary, directory, body, package_version="0.1.2")

    def test_macho_architecture_minimum_and_loader_substitutions_refuse(self):
        _, _, rows, body = cargo_fixture()
        bad = [b"\xca\xfe\xba\xbe" + body, body[:31], executable(TOOL.INTEL_TARGET), executable(minimum=25),
               executable(dependency=b"@rpath/private.dylib"), executable(dependency=b"/tmp/private.dylib"),
               executable(extra=(named_command(0x8000001C, b"/tmp", 12),))]
        for offset, value in ((8, 1), (12, 6)):
            changed = bytearray(body); struct.pack_into("<I", changed, offset, value); bad.append(bytes(changed))
        for value in bad:
            with self.assertRaises(TOOL.Refused): self.parse(rows, body=value)
        with mock.patch.object(TOOL, "INSTALLED_CLI_BYTES", len(body) - 1), self.assertRaises(TOOL.Refused):
            self.parse(rows)

    def test_existing_original_reader_refuses_symlink_hardlink_oversize_and_replacement(self):
        with tempfile.TemporaryDirectory(prefix="mrk-cli-input-") as temporary:
            root = Path(temporary).resolve()
            source = root / "mrk"; source.write_bytes(executable())
            self.assertEqual(TOOL.read(source, source.stat().st_size), executable())
            alias = root / "alias"; alias.symlink_to(source)
            with self.assertRaises(TOOL.Refused): TOOL.read(alias)
            alias.unlink(); os.link(source, alias)
            with self.assertRaises(TOOL.Refused): TOOL.read(source)
            alias.unlink()
            with self.assertRaises(TOOL.Refused): TOOL.read(source, source.stat().st_size - 1)
            original_read = os.read
            changed = False
            def replace_after_read(fd, size):
                nonlocal changed
                data = original_read(fd, size)
                if data and not changed:
                    changed = True
                    replacement = root / "replacement"; replacement.write_bytes(data)
                    replacement.replace(source)
                return data
            with mock.patch.object(TOOL.os, "read", side_effect=replace_after_read), self.assertRaisesRegex(TOOL.Refused, "file-read-changed"):
                TOOL.read(source)


class InstalledCliStageData(unittest.TestCase):
    @contextlib.contextmanager
    def inputs(self):
        body = executable()
        app = {TOOL.ENTRY_BINARY: (body, 0o755), TOOL.APP_BINARY: (body, 0o755), TOOL.INSTALLED_CLI: (body, 0o555),
            TOOL.VAULT_HELPER: (body, 0o555), TOOL.REMOVER: (body, 0o555), TOOL.ANDROID_HELPER: (body, 0o555),
            TOOL.RESIDENT_IMAGE: (b"unrelated resident fixture", 0o555), TOOL.ANDROID_SERVICE_PLIST: (b"service fixture", 0o644),
            "Contents/Info.plist": (b"entry info", 0o644), TOOL.PAYLOAD_INFO: (b"payload info", 0o644),
            "Contents/PkgInfo": (b"APPL????", 0o644), TOOL.PAYLOAD_CONTENTS + "PkgInfo": (b"APPL????", 0o644),
            "Contents/Resources/icon.png": (b"icon", 0o644), TOOL.PAYLOAD_CONTENTS + "Resources/icon.png": (b"icon", 0o644),
            "Contents/_CodeSignature/CodeResources": (b"inert seal", 0o644),
            TOOL.PAYLOAD_CONTENTS + "_CodeSignature/CodeResources": (b"inert payload seal", 0o644)}
        manifest = b"inert manifest"
        args = SimpleNamespace(target=TOOL.ARM_TARGET, package_role="installed-shell-observation", current_runtime=True,
            app=Path("/inert/app"), runtime=Path("/inert/runtime"), output=Path("/inert/output"), expected_manifest=TOOL.digest(manifest),
            expected_entry=TOOL.digest(body), expected_app_binary=TOOL.digest(body), expected_vault_helper=TOOL.digest(body),
            expected_remover=TOOL.digest(body), expected_installed_cli=TOOL.digest(body), expected_android_helper=TOOL.digest(body),
            expected_resident_image=TOOL.digest(app[TOOL.RESIDENT_IMAGE][0]))
        # Unrelated runtime/resident/support observations are explicit DATA
        # doubles. The real CLI Mach-O, input roster and inventory paths run.
        with (mock.patch.object(TOOL, "tree", return_value=app),
              mock.patch.object(TOOL, "runtime_tree", return_value={"manifest.json": (manifest, 0o444), "python/bin/python3": (b"python fixture", 0o555)}),
              mock.patch.object(TOOL, "android_support_manifest", return_value=("a" * 64, [])),
              mock.patch.object(TOOL, "android_support_input", return_value="a" * 64),
              mock.patch.object(TOOL, "android_service_input"),
              mock.patch.object(TOOL, "source_entry_info", return_value=b"entry info"),
              mock.patch.object(TOOL, "source_app_info", return_value=b"payload info"),
              mock.patch.object(TOOL, "write_tree") as writer):
            yield args, app, writer

    def test_current_input_retains_exact_cli_bytes_and_executable_inventory_row(self):
        with self.inputs() as (args, _app, writer):
            TOOL.input_with_github_seal(args, {})
            copied = writer.call_args.args[1]
            self.assertEqual(copied["app/" + TOOL.INSTALLED_CLI], (executable(), 0o555))
            inventory = copied["install-inventory.json"][0]
            rows = TOOL.observation_inventory_bytes(inventory, TOOL.digest(inventory), args.expected_manifest)
            self.assertEqual(rows["app/" + TOOL.INSTALLED_CLI]["sha256"], args.expected_installed_cli)
            self.assertIs(rows["app/" + TOOL.INSTALLED_CLI]["executable"], True)

    def test_current_input_refuses_missing_renamed_changed_mode_or_foreign_arch_cli(self):
        for mutation in ("missing", "renamed", "nested", "mode", "hash", "architecture", "unbound"):
            with self.subTest(mutation=mutation), self.inputs() as (args, app, writer):
                if mutation in ("missing", "renamed", "nested"):
                    value = app.pop(TOOL.INSTALLED_CLI)
                    if mutation != "missing":
                        app["Contents/MacOS/mrk-other" if mutation == "renamed" else TOOL.PAYLOAD_CONTENTS + "MacOS/mrk"] = value
                elif mutation == "mode": app[TOOL.INSTALLED_CLI] = (executable(), 0o755)
                elif mutation == "hash": app[TOOL.INSTALLED_CLI] = (executable() + b"changed", 0o555)
                elif mutation == "architecture":
                    app[TOOL.INSTALLED_CLI] = (executable(TOOL.INTEL_TARGET), 0o555)
                    args.expected_installed_cli = TOOL.digest(app[TOOL.INSTALLED_CLI][0])
                else: del args.expected_installed_cli
                with self.assertRaises(TOOL.Refused): TOOL.input_with_github_seal(args, {})
                writer.assert_not_called()

    def test_historical_inventory_without_cli_remains_data_but_lookalike_code_refuses(self):
        with self.inputs() as (args, _app, writer):
            TOOL.input_with_github_seal(args, {})
            current = json.loads(writer.call_args.args[1]["install-inventory.json"][0])
        old = copy.deepcopy(current)
        old["files"] = [row for row in old["files"] if row["path"] != "app/" + TOOL.INSTALLED_CLI]
        def parse(value):
            data = TOOL.canonical(value) + b"\n"
            return TOOL.observation_inventory_bytes(data, TOOL.digest(data), args.expected_manifest)
        self.assertNotIn("app/" + TOOL.INSTALLED_CLI, parse(old))
        for name, code in (("app/Contents/MacOS/mrk-other", True), ("app/" + TOOL.INSTALLED_CLI, False)):
            changed = copy.deepcopy(current)
            row = next(item for item in changed["files"] if item["path"] == "app/" + TOOL.INSTALLED_CLI)
            row["path"], row["executable"] = name, code
            changed["files"].sort(key=lambda item: item["path"])
            with self.assertRaises(TOOL.Refused): parse(changed)


if __name__ == "__main__":
    unittest.main()
