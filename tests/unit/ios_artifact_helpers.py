"""Independent tiny Mach-O/ZIP fixtures, never Apple-signed release artifacts."""
from __future__ import annotations

import hashlib
import plistlib
import shutil
import struct
import uuid
import zipfile
from pathlib import Path


def native_image(label: str = "main", *, cpu: int = 0x100000C, subtype: int = 0,
                 file_type: int = 2, code: bytes = b"original instructions", signature: bytes | None = b"first",
                 dsym: bool = False, endian: str = "<", wide: bool = True) -> bytes:
    """An explicitly laid-out object independent of the production parser.

    The dSYM has virtual original-image sections, then __LINKEDIT and __DWARF.
    CodeDirectory hash slots are fictional: only cryptographic test seams may
    claim native-signature success; format/content tests use the actual parser.
    """
    header_size = 32 if wide else 28
    section_size, segment_size = (80, 72) if wide else (68, 56)
    pack = lambda fmt, *items: struct.pack(endian + fmt, *items)
    identifier = uuid.UUID(bytes=hashlib.sha256(label.encode()).digest()[:16]).bytes
    content_end = 4128
    sig = b""
    if signature is not None and not dsym:
        name = b"com.example." + signature + b"\0"
        hash_offset = 44 + len(name)
        directory = struct.pack(">9I4BI", 0xFADE0C02, hash_offset + 64, 0x20001, 0, hash_offset,
                                44, 0, 2, content_end, 32, 2, 0, 12, 0) + name + b"\0" * 64
        length = 20 + len(directory)
        sig = struct.pack(">5I", 0xFADE0CC0, length, 1, 0, 20) + directory
        sig += b"\0" * (-len(sig) % 16)

    def segment(name, address, virtual, offset, size, prot, section=None):
        command_size = segment_size + (section_size if section else 0)
        value = pack("II16sQQQQIIII" if wide else "II16s8I", 0x19 if wide else 1,
                     command_size, name.encode(), address, virtual, offset, size, prot, prot, int(bool(section)), 0)
        if section:
            sec_name, sec_address, sec_size, sec_offset = section
            fields = (sec_name.encode(), name.encode(), sec_address, sec_size, sec_offset, 2, 0, 0, 0, 0, 0)
            value += pack("16s16sQQ8I" if wide else "16s16s9I", *fields, *([0] if wide else []))
        return value

    commands = [segment("__TEXT", 0x10000, 4096, 0, 0 if dsym else 4096, 5,
                        ("__text", 0x10400, len(code), 0 if dsym else 1024)),
                segment("__LINKEDIT", 0x11000, (32 + len(sig) + 4095) // 4096 * 4096, 4096, 32 + len(sig), 1),
                pack("II", 0x1B, 24) + identifier,
                pack("6I", 2, 24, 4096, 1, 4112, 16)]
    if dsym:
        commands.append(segment("__DWARF", 0x12000, 4096, 8192, 16, 3,
                                ("__debug_info", 0x12000, 16, 8192)))
    elif sig:
        commands.append(pack("4I", 0x1D, 16, content_end, len(sig)))
    header = pack("8I" if wide else "7I", 0xFEEDFACF if wide else 0xFEEDFACE, cpu, subtype,
                  10 if dsym else file_type, len(commands), sum(map(len, commands)), 0x85, *([0] if wide else []))
    result = bytearray((8208 if dsym else content_end + len(sig)))
    result[:header_size] = header
    result[header_size:header_size + sum(map(len, commands))] = b"".join(commands)
    if not dsym:
        result[1024:1024 + len(code)] = code
    result[4112:4128] = b"\0symbol\0".ljust(16, b"\0")
    if dsym:
        result[8192:] = b"synthetic DWARF!".ljust(16, b"\0")
    else:
        result[content_end:] = sig
    return bytes(result)


def fat_image(slices: list[bytes], *, wide: bool = False, endian: str = ">", reverse: bool = False) -> bytes:
    entries, chunks, cursor = [], [], 4096
    for raw in slices:
        thin_endian = "<" if raw[:4] in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"} else ">"
        cpu, subtype = struct.unpack_from(thin_endian + "2I", raw, 4)
        entries.append(struct.pack(endian + ("IIQQII" if wide else "5I"), cpu, subtype, cursor, len(raw), 12, *([0] if wide else [])))
        chunks.append((cursor, raw))
        cursor = (cursor + len(raw) + 4095) // 4096 * 4096
    output = bytearray(chunks[-1][0] + len(chunks[-1][1]))
    header = struct.pack(endian + "2I", 0xCAFEBABF if wide else 0xCAFEBABE, len(slices))
    declarations = b"".join(reversed(entries) if reverse else entries)
    output[:len(header) + len(declarations)] = header + declarations
    for offset, raw in chunks:
        output[offset:offset + len(raw)] = raw
    return bytes(output)


def table_image(*, sections: int = 1024, records: int = 10000) -> bytes:
    """Small unsigned layout exposing independent section/table work dimensions.

    Each valid table record addresses the final one-byte __TEXT section. This
    reproduces the reviewer's work-amplification input without a large payload.
    """
    command_size = 72 + 80 * sections + 72 + 24 + 16
    code_start = (32 + command_size + 15) // 16 * 16
    code_end = code_start + sections
    link_start = (code_end + 4095) // 4096 * 4096
    table = struct.pack("<IHH", code_end - 1, 1, 1) * records
    commands = [struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * sections, b"__TEXT",
                            0x10000, link_start, 0, link_start, 5, 5, sections, 0)]
    for index in range(sections):
        commands.append(struct.pack("<16s16sQQ8I", f"__s{index}".encode(), b"__TEXT",
                                    0x10000 + code_start + index, 1, code_start + index, 0, 0, 0, 0, 0, 0, 0))
    commands.extend([
        struct.pack("<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", 0x10000 + link_start,
                    (len(table) + 4095) // 4096 * 4096, link_start, len(table), 1, 1, 0, 0),
        struct.pack("<II16s", 0x1B, 24, b"budget-probe-id00"),
        struct.pack("<4I", 0x29, 16, link_start, len(table)),
    ])
    raw = bytearray(link_start + len(table))
    raw[:32] = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 4, command_size, 0x85, 0)
    raw[32:32 + command_size] = b"".join(commands)
    raw[code_start:code_end] = b"\x1f" * sections
    raw[link_start:] = table
    return bytes(raw)


def zip_tree(root: Path, destination: Path, *, prefix: str = "") -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            name = prefix + relative
            if path.is_dir():
                archive.writestr(name + "/", b"")
            else:
                archive.writestr(name, path.read_bytes())


def artifact_set(root: Path, *, nested: bool = True, detached: bool = True) -> dict[str, Path]:
    """Create a correlated main/extension/framework/dylib/helper and symbol set."""
    archive = root / "archive.xcarchive"
    main = archive / "Products/Applications/Reader.app"
    main.mkdir(parents=True)
    info = {"CFBundleIdentifier": "com.example.reader", "CFBundleExecutable": "Reader",
            "CFBundleVersion": "42", "CFBundleShortVersionString": "1.2.3"}
    (main / "Info.plist").write_bytes(plistlib.dumps(info))
    (main / "Reader").write_bytes(native_image())
    (main / "resource.txt").write_text("reviewed resource\n")
    (main / "_CodeSignature").mkdir()
    (main / "_CodeSignature/CodeResources").write_bytes(b"synthetic signature resources")
    (main / "embedded.mobileprovision").write_bytes(b"synthetic profile, never a real credential")
    binaries = {"main": main / "Reader"}
    if nested:
        for name, relative, kind in (("Widget", "PlugIns/Widget.appex", 2),
                                     ("ReaderKit", "Frameworks/ReaderKit.framework", 6)):
            bundle = main / relative
            bundle.mkdir(parents=True)
            (bundle / name).write_bytes(native_image(name, file_type=kind))
            nested_info = dict(info, CFBundleIdentifier=f"com.example.reader.{name.lower()}", CFBundleExecutable=name)
            if kind == 6:
                nested_info.update(CFBundleVersion="7", CFBundleShortVersionString="0.7")
            (bundle / "Info.plist").write_bytes(plistlib.dumps(nested_info))
            binaries[name] = bundle / name
        for name, relative, kind in (("runtime", "Frameworks/libexample.dylib", 6), ("helper", "Helpers/helper", 2)):
            path = main / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(native_image(name, file_type=kind))
            binaries[name] = path
    for label, path in binaries.items():
        dsym = archive / "dSYMs" / (path.name + ".dSYM")
        dwarf = dsym / "Contents/Resources/DWARF" / path.name
        dwarf.parent.mkdir(parents=True)
        dwarf.write_bytes(native_image(label, dsym=True))
        (dsym / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundlePackageType": "dSYM"}))
    exported = root / "export/Payload/Reader.app"
    exported.parent.mkdir(parents=True)
    shutil.copytree(main, exported)
    # Export legitimately re-signs code/resources/profile without changing images.
    (exported / "Reader").write_bytes(native_image(signature=b"second-signature"))
    (exported / "_CodeSignature/CodeResources").write_bytes(b"different synthetic resource signature")
    (exported / "embedded.mobileprovision").write_bytes(b"different synthetic profile")
    ipa = root / "app.ipa"
    zip_tree(root / "export", ipa)
    paths = {"ios-ipa": ipa, "ios-archive": archive}
    if detached:
        paths["ios-dsyms"] = root / "dsyms"
        shutil.copytree(archive / "dSYMs", paths["ios-dsyms"])
    return paths


def packed_artifact_set(root: Path, **options) -> dict[str, Path]:
    paths = artifact_set(root, **options)
    for name, prefix, filename in (("ios-archive", "archive.xcarchive/", "archive.zip"), ("ios-dsyms", "dsyms/", "dsyms.zip")):
        if name in paths:
            destination = root / filename
            zip_tree(paths[name], destination, prefix=prefix)
            paths[name] = destination
    return paths
