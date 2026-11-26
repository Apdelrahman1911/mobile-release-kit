"""Tiny fresh-supplier transport regressions, for the reviewed nonroot DATA owner.

These deliberately synthetic receipts and non-executable bytes are never native
supplier evidence. No upstream archive, command, network or payload execution.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STAGE = load("_transport_test_stage", "stage_macos_installed.py")
TOOL = load("_transport_test_projector", "macos_python_supplier_transport.py")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fixture(target="aarch64-apple-darwin"):
    files = {"python/bin/python3": (b"not an executable; transport DATA only", 0o555),
             "python/lib/python3.14/fixture.py": (b"# inert selected source\n", 0o444)}
    notices = []
    required = []
    for number in range(6):
        name, body = "python/licenses/notice-" + str(number) + ".txt", ("public fixture " + str(number)).encode()
        files[name] = (body, 0o444)
        notices.append(name)
        required.append({"bytes": len(body), "sha256": digest(body)})
    lock = encoded({"schemaVersion": 1, "target": {"triple": target,
        "minimumMacOS": "26.0", "pythonVersion": "3.14.7", "gil": True}, "requiredPublicNoticeInputs": required})
    rows = [{"path": name, "size": len(body), "sha256": digest(body), "mode": mode}
            for name, (body, mode) in sorted(files.items())]
    receipt = {"schemaVersion": 1, "kind": "mrk-macos-cpython-source-supplier-v1",
        "target": target, "pythonVersion": "3.14.7", "gil": True,
        "sourceLockSha256": digest(lock), "producerSourceSha256": "1" * 64,
        "recipeSha256": "2" * 64, "toolchainSha256": "3" * 64,
        "inventorySha256": digest(encoded(rows)), "files": rows, "notices": sorted(notices),
        "nativeEvidence": {name: "4" * 64 for name in ("build", "relocation", "modules", "loader", "tls", "cancellation", "notices")}}
    return files, lock, receipt


def archive(files, *, reverse=False, header_change=None, extra=False):
    # A normal stdlib USTAR writer independent of the projector implementation.
    parents = sorted({parent.as_posix() for name in files for parent in Path(name).parents if parent.as_posix() != "."})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name in reversed(parents) if reverse else parents:
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o555
            if header_change is not None:
                header_change(item)
            output.addfile(item)
        for name, (body, mode) in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(body), mode
            if header_change is not None:
                header_change(item)
            output.addfile(item, io.BytesIO(body))
        if extra:
            output.addfile(tarfile.TarInfo("unlisted.txt"), io.BytesIO())
    return buffer.getvalue()


@contextmanager
def temporary():
    with tempfile.TemporaryDirectory(prefix="mrk-transport-data-") as value:
        root = Path(value)
        try:
            yield root
        finally:
            # Only this test's original small fixture, never a shared source/cache.
            for directory, children, _ in os.walk(root, followlinks=False):
                os.chmod(directory, 0o700)
                for child in children:
                    path = Path(directory) / child
                    if not path.is_symlink():
                        os.chmod(path, 0o700)


def on_disk(root, files, lock, receipt, tar=None, *, target="aarch64-apple-darwin"):
    source = root / "source"
    path = source / ("desktop/macos-cpython-source-inputs/source-lock.json" if target == "aarch64-apple-darwin" else
                     "desktop/macos-cpython-source-inputs/source-lock-intel.json")
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(lock)
    transport = root / "download"
    transport.mkdir(mode=0o700)
    body = encoded(receipt)
    raw = archive(files) if tar is None else tar
    (transport / "supplier-receipt.json").write_bytes(body)
    (transport / "supplier.tar").write_bytes(raw)
    os.chmod(transport / "supplier-receipt.json", 0o644)
    os.chmod(transport / "supplier.tar", 0o644)
    output = root / "outputs"
    output.mkdir(mode=0o700)
    return SimpleNamespace(target=target, transport_root=transport, expected_supplier=digest(body), expected_tar=digest(raw),
        python_output=output / "supplier", receipt_root=output / "receipt"), source


class MacPythonSupplierTransportTests(unittest.TestCase):
    def test_fixed_ustar_projection_refuses_header_order_kinds_body_and_tail(self):
        files, lock, receipt = fixture()
        receipt_body = encoded(receipt)
        _, rows = STAGE.fresh_supplier_receipt(receipt_body, digest(receipt_body), lock)
        good = archive(files)
        self.assertEqual(TOOL.project_archive(good, rows, STAGE), files)
        changed_body = bytearray(good)
        position = good.index(files["python/bin/python3"][0])
        changed_body[position] ^= 1
        changed_padding = bytearray(good)
        changed_padding[position + len(files["python/bin/python3"][0])] = 1
        bad = [archive(files, reverse=True), archive(files, extra=True), bytes(changed_body), bytes(changed_padding),
               archive(files, header_change=lambda item: setattr(item, "uid", 7)),
               archive(files, header_change=lambda item: setattr(item, "mode", 0o777)),
               archive(files, header_change=lambda item: setattr(item, "type", tarfile.SYMTYPE)),
               good + good, good + b"\0" * tarfile.RECORDSIZE, good[:-512]]
        for value in bad:
            with self.subTest(size=len(value), sha=digest(value)):
                with self.assertRaises(STAGE.Refused):
                    TOOL.project_archive(value, rows, STAGE)

    def test_pins_receipts_extra_inputs_and_overlaps_refuse_before_outputs(self):
        files, lock, receipt = fixture()
        for kind in ("receipt-pin", "tar-pin", "wrong-target", "case-alias", "extra-input", "output-overlap", "source-overlap"):
            with self.subTest(kind=kind), temporary() as root:
                selected = json.loads(encoded(receipt))
                if kind == "wrong-target":
                    selected["target"] = "x86_64-apple-darwin"
                if kind == "case-alias":
                    row = dict(selected["files"][0])
                    row["path"] = row["path"].upper().replace("PYTHON/", "python/")
                    row["mode"] = 0o444
                    selected["files"].append(row)
                    selected["files"].sort(key=lambda item: item["path"])
                    selected["inventorySha256"] = digest(encoded(selected["files"]))
                args, source = on_disk(root, files, lock, selected)
                if kind == "receipt-pin":
                    args.expected_supplier = "0" * 64
                elif kind == "tar-pin":
                    args.expected_tar = "0" * 64
                elif kind == "extra-input":
                    (args.transport_root / "unlisted.txt").write_bytes(b"extra")
                elif kind == "output-overlap":
                    args.receipt_root = args.python_output / "receipt"
                elif kind == "source-overlap":
                    args.python_output = source / "supplier"
                with mock.patch.object(STAGE, "DESKTOP", source / "desktop"), mock.patch.object(STAGE, "write_tree") as writer:
                    with self.assertRaises(STAGE.Refused) as failure:
                        TOOL.project_transport(args, STAGE)
                    if kind == "case-alias":
                        self.assertEqual(str(failure.exception), "path-alias-or-type-collision")
                    writer.assert_not_called()
                self.assertFalse(args.python_output.exists())
                self.assertFalse(args.receipt_root.exists())

        for kind in ("missing-selected-lock", "wrong-selected-lock", "invalid-selector"):
            with self.subTest(kind=kind), temporary() as root:
                if kind == "wrong-selected-lock":
                    intel_files, _, intel_receipt = fixture("x86_64-apple-darwin")
                    intel_receipt["sourceLockSha256"] = digest(lock)
                    args, source = on_disk(root, intel_files, lock, intel_receipt, target="x86_64-apple-darwin")
                else:
                    args, source = on_disk(root, files, lock, receipt)
                    args.target = "x86_64-apple-darwin" if kind == "missing-selected-lock" else "universal"
                with mock.patch.object(STAGE, "DESKTOP", source / "desktop"), mock.patch.object(STAGE, "write_tree") as writer:
                    with self.assertRaises((STAGE.Refused, OSError)): TOOL.project_transport(args, STAGE)
                    writer.assert_not_called()
                self.assertFalse(args.python_output.exists())
                self.assertFalse(args.receipt_root.exists())

    def test_actual_nonroot_projection_preserves_inputs_and_consumer_modes(self):
        self.assertNotEqual(os.getuid(), 0)
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            files, lock, receipt = fixture(target)
            with temporary() as root:
                args, source = on_disk(root, files, lock, receipt, target=target)
                originals = {path.name: (path.read_bytes(), STAGE.signature(path.lstat())) for path in args.transport_root.iterdir()}
                with (mock.patch.object(STAGE, "DESKTOP", source / "desktop"),
                      mock.patch.object(STAGE, "fresh_supplier", wraps=STAGE.fresh_supplier) as consumer):
                    result = TOOL.project_transport(args, STAGE)
                    self.assertEqual([call.args[0].target for call in consumer.call_args_list], [target, target])
                    self.assertEqual(STAGE.tree(args.python_output, current_root_mode=0o555), files)
                    self.assertEqual(STAGE.tree(args.receipt_root, current_root_mode=0o555),
                                     {"supplier-receipt.json": (encoded(receipt), 0o444)})
                self.assertEqual(result["qualification"], "transport-projected-data-only-not-native-approval")
                self.assertEqual(result["files"], len(files))
                self.assertEqual(result["supplierReceiptSha256"], args.expected_supplier)
                self.assertEqual({path.name: (path.read_bytes(), STAGE.signature(path.lstat())) for path in args.transport_root.iterdir()}, originals)

    def test_collisions_post_mutation_and_close_refusal_preserve_partial_outputs(self):
        self.assertNotEqual(os.getuid(), 0)
        files, lock, receipt = fixture()
        for kind in ("collision", "input-post", "source-post", "close"):
            with self.subTest(kind=kind), temporary() as root:
                args, source = on_disk(root, files, lock, receipt)
                if kind == "collision":
                    args.python_output.mkdir(mode=0o700)
                    (args.python_output / "keep.txt").write_bytes(b"unrelated existing bytes")
                original_write, original_close = STAGE.write_tree, STAGE.close_once
                state = {"writing": False, "injected": False}

                def close(fd):
                    regular = stat.S_ISREG(os.fstat(fd).st_mode)
                    original_close(fd)
                    if kind == "close" and state["writing"] and regular and not state["injected"]:
                        state["injected"] = True
                        # The fixture consumes the real original; simulate a
                        # reported uncertain close, never actually leak a FD.
                        raise STAGE.Refused("original-close-unknown")

                def write(output, payload, **kwargs):
                    state["writing"] = True
                    try:
                        original_write(output, payload, **kwargs)
                    finally:
                        state["writing"] = False
                    if not state["injected"]:
                        if kind == "input-post":
                            path = args.transport_root / "supplier-receipt.json"
                            path.write_bytes(path.read_bytes() + b"\n")
                        elif kind == "source-post":
                            path = source / "desktop/macos-cpython-source-inputs/source-lock.json"
                            # Same bytes, replaced original: content alone must
                            # not establish source PRE/POST identity.
                            body = path.read_bytes()
                            temporary_path = path.with_name("replacement.json")
                            temporary_path.write_bytes(body)
                            temporary_path.replace(path)
                        state["injected"] = True

                with mock.patch.object(STAGE, "DESKTOP", source / "desktop"), mock.patch.object(STAGE, "write_tree", side_effect=write), mock.patch.object(STAGE, "close_once", side_effect=close):
                    with self.assertRaises(STAGE.Refused):
                        TOOL.project_transport(args, STAGE)
                self.assertTrue(args.python_output.exists())
                if kind == "collision":
                    self.assertEqual((args.python_output / "keep.txt").read_bytes(), b"unrelated existing bytes")
                    self.assertFalse(args.receipt_root.exists())
                elif kind == "close":
                    self.assertTrue(state["injected"])
                    self.assertFalse(args.receipt_root.exists())
                else:
                    self.assertTrue(args.receipt_root.exists())


if __name__ == "__main__":
    unittest.main()
