"""Tiny ordinary DATA copies only: no publisher, ELF, shell or package execution.

Fixtures are synthetic bytes, not an admitted runtime, archive, compiler output
or license set. Actual native publisher/package qualification is separate.
"""
from __future__ import annotations

from copy import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("deb_stage", SOURCE / "desktop/tools/stage_ubuntu_deb.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
D = S.D


class DebianStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-deb-data-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        roots = {name: self.root / name for name in ("compiled", "runtime", "kit", "notices", "output-parent")}
        for root in roots.values():
            root.mkdir(mode=0o700)
        self.args = SimpleNamespace(compiled=roots["compiled"], runtime=roots["runtime"],
            prepared_artifact=roots["kit"], desktop_notices=roots["notices"],
            output=roots["output-parent"] / "package", version="0.1.0-1", depends="libc6 (>= 2.39)",
            protocol_sha256="c" * 64)
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x03\x00\x3e\x00"
        for name in S.BINARIES:
            self.put(roots["compiled"] / name, elf + name.encode("ascii"))
        self.inventory("compiler_files", roots["compiled"])
        for name in (*S.P.BOOTSTRAPS, "core.zip", "python/bin/python3", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3"):
            self.put(roots["runtime"] / name, b"inert:" + name.encode("ascii"))
        # Public CA DATA only; needed by the unchanged fixed manifest validator.
        self.put(roots["runtime"] / "github-ca.pem", (SOURCE / "desktop/cpython-source-inputs/github-ca.pem").read_bytes())
        rows = self.records(roots["runtime"])
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "0.3.0", "target": S.TARGET,
            "coreSha256": next(row["sha256"] for row in rows if row["path"] == "core.zip"),
            "protocolSha256": self.args.protocol_sha256,
            "inventorySha256": hashlib.sha256(S.P.canonical(rows)).hexdigest(), "files": rows}
        raw = D.canonical(manifest)
        self.put(roots["runtime"] / "manifest.json", raw)
        self.args.manifest_sha256 = hashlib.sha256(raw).hexdigest()
        for name in (S.KIT_CONTROL | S.PREPARATION_ONLY) - {"notice-inventory.json"}:
            self.put(roots["kit"] / name, b"inert kit:" + name.encode("ascii"))
        self.put(roots["kit"] / "notices/PYTHON-CHANGES.txt", b"Synthetic DATA-only notice\n")
        notice = {"schemaVersion": 1, "profile": D.PROFILE, "pythonChangeSummary": "PYTHON-CHANGES.txt",
                  "files": self.records(roots["kit"] / "notices")}
        self.put(roots["kit"] / "notice-inventory.json", D.canonical(notice))
        self.inventory("prepared_files", roots["kit"])
        self.put(roots["notices"] / "NOTICE.txt", b"Synthetic desktop obligations; not release evidence\n")
        self.inventory("desktop_notice_files", roots["notices"])

    @staticmethod
    def put(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    @staticmethod
    def records(root):
        return [{**D.file_record(path), "path": path.relative_to(root).as_posix()}
                for path in sorted(root.rglob("*")) if path.is_file()]

    def inventory(self, name, root):
        raw = D.canonical(self.records(root))
        path = self.root / (name + ".json")
        path.write_bytes(raw)
        setattr(self.args, name, path)
        setattr(self.args, name + "_sha256", hashlib.sha256(raw).hexdigest())

    def test_exact_layout_modes_and_unchanged_obligation_bytes(self):
        result = S.stage(self.args)
        self.assertFalse(result["installed"])
        self.assertFalse(result["qualified"])
        root = self.args.output
        self.assertFalse((root / "opt").exists())
        prefix = root / "usr/lib/mobile-release-kit/runtime-input" / S.TARGET / self.args.manifest_sha256
        for row in self.records(self.args.runtime):
            copied = prefix / row["path"]
            D.bound(copied, row)
            self.assertNotEqual(copied.stat().st_ino, (self.args.runtime / row["path"]).stat().st_ino)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o555 if row["path"] == "python/bin/python3" else 0o444)
        for row in self.records(self.args.prepared_artifact):
            copied = root / S.DOCS / "runtime" / row["path"]
            if row["path"] in S.PREPARATION_ONLY:
                self.assertFalse(copied.exists())
            else:
                D.bound(copied, row)
        self.assertEqual((root / S.DOCS / "desktop/NOTICE.txt").read_bytes(), (self.args.desktop_notices / "NOTICE.txt").read_bytes())
        for name in ("postinst", "prerm", "postrm"):
            self.assertEqual((root / "DEBIAN" / name).read_bytes(), (S.TEMPLATES / name).read_bytes())
            self.assertEqual(stat.S_IMODE((root / "DEBIAN" / name).stat().st_mode), 0o755)
        self.assertIn(b"Architecture: amd64\n", (root / "DEBIAN/control").read_bytes())
        self.assertEqual(result["files"], len(self.records(root)))

    def test_bad_inventory_manifest_protocol_or_control_refuses_before_output(self):
        for key, value in (("compiler_files_sha256", "0" * 64), ("prepared_files_sha256", "0" * 64),
                           ("desktop_notice_files_sha256", "0" * 64), ("manifest_sha256", "0" * 64),
                           ("protocol_sha256", "0" * 64), ("depends", "libc6\nPre-Depends: bad"),
                           ("version", "0.1\nPackage: bad")):
            args = copy(self.args)
            setattr(args, key, value)
            with self.subTest(field=key), self.assertRaises((ValueError, S.Q.SmokeRefused)):
                S.stage(args)
            self.assertFalse(self.args.output.exists())

    def test_extra_or_aliased_inputs_are_not_silently_packaged(self):
        extra = self.args.runtime / "unexpected"
        extra.write_bytes(b"not in inventory")
        with self.assertRaises(ValueError):
            S.stage(self.args)
        extra.unlink()
        original = self.args.runtime / "core.zip"
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    extra.symlink_to(original)
                else:
                    os.link(original, extra)
                with self.assertRaises(ValueError):
                    S.stage(self.args)
                self.assertTrue(extra.is_symlink() or extra.is_file())
                extra.unlink()
        self.assertFalse(self.args.output.exists())

    def test_unreviewed_kit_member_is_rejected_even_with_updated_list(self):
        self.put(self.args.prepared_artifact / "not-authorized.txt", b"inert extra")
        self.inventory("prepared_files", self.args.prepared_artifact)
        with self.assertRaises(ValueError):
            S.stage(self.args)
        self.assertFalse(self.args.output.exists())

    def test_existing_and_partial_outputs_are_preserved_without_retry(self):
        self.args.output.mkdir(mode=0o700)
        sentinel = self.args.output / "keep"
        sentinel.write_bytes(b"preexisting")
        with self.assertRaises(FileExistsError):
            S.stage(self.args)
        self.assertEqual(sentinel.read_bytes(), b"preexisting")
        # A different fresh task output for the injected copy failure.
        self.args.output = self.args.output.with_name("partial")
        with patch.object(D, "copy", side_effect=OSError("synthetic copy refusal")) as copier, self.assertRaises(OSError):
            S.stage(self.args)
        self.assertEqual(copier.call_count, 1)
        self.assertTrue(self.args.output.is_dir())
        self.assertEqual(sentinel.read_bytes(), b"preexisting")

    def test_privileged_cli_refuses_without_staging(self):
        with patch.object(S.argparse.ArgumentParser, "parse_args", return_value=self.args), \
                patch.object(S.os, "getuid", return_value=0), patch.object(S.os, "geteuid", return_value=0), \
                patch.object(S, "stage") as stage, self.assertRaises(SystemExit) as outcome:
            S.main()
        self.assertEqual(outcome.exception.code, 1)
        stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
