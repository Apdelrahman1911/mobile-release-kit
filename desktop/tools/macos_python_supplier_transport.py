#!/usr/bin/env python3
"""Project one independently pinned fresh Python supplier transport as DATA.

The downloaded artifact contains exactly supplier.tar and supplier-receipt.json.
It is not a release, installed/native approval or an archive extraction authority.
Only the fixed producer USTAR representation of the receipt's complete roster is
accepted. Existing stager APIs own receipt policy and exclusive output writing.
No payload execution, network, replacement, input chmod or deletion occurs here.
On failure preserve partial outputs; only a returned success permits the next
separately reviewed current-runtime step.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace

RECEIPT_NAME = "supplier-receipt.json"
TAR_NAME = "supplier.tar"
RECEIPT_LIMIT = 1024 * 1024
TAR_LIMIT = 468 * 1024 * 1024
TRANSPORT_NAMES = {RECEIPT_NAME, TAR_NAME}


def load_stage():
    # Fixed sibling SOURCE, never an argument or downloaded payload module.
    path = Path(__file__).absolute().with_name("stage_macos_installed.py")
    spec = importlib.util.spec_from_file_location("_mrk_fresh_transport_stager", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed-transport-stager-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_lock(stage, *, target):
    with stage.parent(stage.DESKTOP.parent / stage.source_lock_input(target)) as (fd, name):
        body, info = stage.read_at(fd, name, stage.FRESH_SOURCE_LOCK_LIMIT)
    return body, stage.signature(info)


def transport_inputs(path, expected_supplier, expected_tar, stage):
    """Capture only two ordinary caller-owned inputs, with complete originals."""
    stage.need(stage.sha(expected_supplier) and stage.sha(expected_tar), "transport-expected-pins")
    owner = stage.packager_ids()
    captured, identities = {}, {}
    with stage.parent(path) as (outer, name):
        before = os.stat(name, dir_fd=outer, follow_symlinks=False)
        stage.need(stat.S_ISDIR(before.st_mode) and (before.st_uid, before.st_gid) == owner
                   and stat.S_IMODE(before.st_mode) in (0o500, 0o555, 0o700, 0o755),
                   "transport-directory-owner-mode")
        original = None
        try:
            original = os.open(name, stage.READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
            stage.need(stage.signature(os.fstat(original)) == stage.signature(before),
                       "transport-directory-open-changed")
            stage.no_xattrs(original)
            stage.need(set(os.listdir(original)) == TRANSPORT_NAMES, "transport-exact-two-files")
            for leaf, limit, expected in ((RECEIPT_NAME, RECEIPT_LIMIT, expected_supplier),
                                          (TAR_NAME, TAR_LIMIT, expected_tar)):
                body, info = stage.read_at(original, leaf, limit)
                stage.need((info.st_uid, info.st_gid) == owner
                           and stat.S_IMODE(info.st_mode) in (0o400, 0o444, 0o600, 0o644),
                           "transport-file-owner-mode")
                stage.need(stage.digest(body) == expected, "transport-file-pin")
                captured[leaf], identities[leaf] = body, stage.signature(info)
            stage.need(set(os.listdir(original)) == TRANSPORT_NAMES
                       and stage.signature(os.fstat(original)) == stage.signature(before)
                       == stage.signature(os.stat(name, dir_fd=outer, follow_symlinks=False)),
                       "transport-directory-post-changed")
        finally:
            if original is not None:
                stage.close_once(original)
    identities["."] = stage.signature(before)
    return captured[RECEIPT_NAME], captured[TAR_NAME], identities


def member_header(name, mode, size, is_directory, stage):
    # Construct from validated receipt DATA. Never parse an untrusted header or
    # let an archive member decide its destination, size, kind or permissions.
    item = tarfile.TarInfo(name)
    item.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    item.mode, item.size = mode, size
    item.uid = item.gid = item.mtime = 0
    try:
        return item.tobuf(format=tarfile.USTAR_FORMAT)
    except (ValueError, UnicodeError, OverflowError) as error:
        raise stage.Refused("transport-ustar-representation") from error


def project_archive(body, rows, stage):
    """Exact inverse of the fixed producer: dirs, receipt files, zero framing."""
    stage.need(type(body) is bytes and 0 < len(body) <= TAR_LIMIT
               and len(body) % tarfile.RECORDSIZE == 0, "transport-tar-bound-framing")
    directories = sorted(stage.directories(rows))
    position, files = 0, {}

    def header(name, mode, size, is_directory):
        nonlocal position
        expected = member_header(name, mode, size, is_directory, stage)
        stage.need(len(expected) == tarfile.BLOCKSIZE
                   and body[position:position + tarfile.BLOCKSIZE] == expected,
                   "transport-canonical-member-header")
        position += tarfile.BLOCKSIZE

    for name in directories:
        header(name, 0o555, 0, True)
    for name, row in rows.items():
        header(name, row["mode"], row["size"], False)
        end = position + row["size"]
        content = body[position:end]
        stage.need(len(content) == row["size"] and stage.digest(content) == row["sha256"],
                   "transport-member-bytes")
        padding = (-row["size"]) % tarfile.BLOCKSIZE
        stage.need(end + padding <= len(body) and body[end:end + padding] == b"\0" * padding,
                   "transport-member-zero-padding")
        files[name] = (content, row["mode"])
        position = end + padding
    # TarFile.close emits exactly two zero blocks plus record alignment. No
    # second archive, extra zero records, PAX/GNU headers or arbitrary tail.
    zeros = 2 * tarfile.BLOCKSIZE
    zeros += (-(position + zeros)) % tarfile.RECORDSIZE
    stage.need(len(body) == position + zeros and body[position:] == b"\0" * zeros,
               "transport-exact-end-framing")
    return files


def output_paths(args, stage):
    inputs = [args.transport_root, stage.DESKTOP.parent]
    outputs = [args.python_output, args.receipt_root]
    folded = lambda value: tuple(part.casefold() for part in value.parts)
    stage.need(all(isinstance(path, Path) and path.is_absolute() for path in inputs + outputs),
               "transport-absolute-paths")
    for index, output in enumerate(outputs):
        current = folded(output)
        for other in inputs + outputs[:index]:
            comparison = folded(other)
            stage.need(current[:len(comparison)] != comparison
                       and comparison[:len(current)] != current, "transport-path-overlap")
    return {path: stage.current_output_absent(path) for path in outputs}


def project_transport(args, stage):
    target = stage.mac_target(getattr(args, "target", stage.ARM_TARGET))
    parents = output_paths(args, stage)
    lock_body, lock_identity = source_lock(stage, target=target)
    receipt_body, archive_body, originals = transport_inputs(
        args.transport_root, args.expected_supplier, args.expected_tar, stage)
    receipt, rows = stage.fresh_supplier_receipt(receipt_body, args.expected_supplier, lock_body, target=target)
    files = project_archive(archive_body, rows, stage)
    del archive_body  # Do not retain a second complete payload while writing.
    for path, identity in parents.items():
        stage.current_output_absent(path, identity)
    stage.write_tree(args.python_output, files, current_owned=True)
    stage.current_output_absent(args.receipt_root, parents[args.receipt_root])
    stage.write_tree(args.receipt_root, {RECEIPT_NAME: (receipt_body, 0o444)}, current_owned=True)
    # This is the same actual consumer admission, not a lookalike receipt check.
    supplier, provenance, actual_lock, actual_receipt = stage.fresh_supplier(SimpleNamespace(
        python_root=args.python_output, supplier_receipt=args.receipt_root / RECEIPT_NAME,
        expected_supplier=args.expected_supplier, target=target))
    stage.need(supplier == files and actual_lock == lock_body and actual_receipt == receipt_body,
               "transport-consumer-correspondence")
    count, total = len(rows), sum(row["size"] for row in rows.values())
    del files, supplier
    post_receipt, post_tar, post_originals = transport_inputs(
        args.transport_root, args.expected_supplier, args.expected_tar, stage)
    stage.need(post_originals == originals and post_receipt == receipt_body,
               "transport-input-originals-post")
    del post_tar
    post_lock, post_identity = source_lock(stage, target=target)
    stage.need(post_lock == lock_body and post_identity == lock_identity, "transport-source-lock-post")
    # Verify sealed complete output originals once more after input/source POST;
    # no cleanup or publication repair is performed for a changed tree.
    final_supplier, final_provenance, final_lock, final_receipt = stage.fresh_supplier(SimpleNamespace(
        python_root=args.python_output, supplier_receipt=args.receipt_root / RECEIPT_NAME,
        expected_supplier=args.expected_supplier, target=target))
    stage.need(final_provenance == provenance and final_lock == lock_body and final_receipt == receipt_body
               and len(final_supplier) == count, "transport-final-consumer-admission")
    return {"schemaVersion": 1, "supplierOrigin": "fresh-public-source",
            "qualification": "transport-projected-data-only-not-native-approval",
            "supplierReceiptSha256": args.expected_supplier, "supplierTarSha256": args.expected_tar,
            "supplierSourceLockSha256": receipt["sourceLockSha256"],
            "files": count, "bytes": total}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport-root", type=Path, required=True)
    parser.add_argument("--expected-supplier", required=True)
    parser.add_argument("--expected-tar", required=True)
    parser.add_argument("--python-output", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--target", choices=("aarch64-apple-darwin", "x86_64-apple-darwin"),
                        default="aarch64-apple-darwin", help="Caller-selected exact Mac supplier target")
    args = parser.parse_args(argv)
    stage = load_stage()
    try:
        result = project_transport(args, stage)
    except (stage.Refused, OSError, ValueError) as error:
        # No captured input/exception payload is printed; partial files remain.
        code = str(error) if type(error) is stage.Refused else type(error).__name__
        print("Fresh supplier transport refused: " + code)
        return 1
    print(stage.canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
