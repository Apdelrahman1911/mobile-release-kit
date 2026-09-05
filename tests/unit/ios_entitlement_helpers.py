"""Independent fictional policy fixtures, not real profiles or signatures."""
from __future__ import annotations

import hashlib
import plistlib
import struct
import types
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TEAM = "ABCDE12345"
BUNDLE = "com.example.reader"
CERTIFICATE = b"fictional public signer certificate; never an Apple credential"


def binary_plist(objects: list[bytes], *, root: int = 0, offset_width: int | None = None,
                 reference_width: int = 1, order: list[int] | None = None,
                 padding: bytes = b"", leading: bytes = b"") -> bytes:
    """Independent raw fixtures: callers supply complete original object bytes."""
    result, offsets = bytearray(b"bplist00" + leading), [0] * len(objects)
    for index in (range(len(objects)) if order is None else order):
        offsets[index] = len(result)
        result.extend(objects[index] + padding)
    table = len(result)
    width = offset_width or max(1, (max(offsets).bit_length() + 7) // 8)
    result.extend(b"".join(offset.to_bytes(width, "big") for offset in offsets))
    result.extend(b"\0" * 6 + bytes((width, reference_width)) + struct.pack(">3Q", len(objects), root, table))
    return bytes(result)


def binary_dictionary(value: bytes, **kwargs: Any) -> bytes:
    width = kwargs.get("reference_width", 1)
    return binary_plist([b"\xd1" + (1).to_bytes(width, "big") + (2).to_bytes(width, "big"), b"\x51x", value], **kwargs)


def malformed_binary_cases() -> dict[str, bytes]:
    cases = {"non-dictionary-root": binary_plist([b"\x09"]),
             "indexed-fill": binary_dictionary(b"\x0f"),
             "null-value": binary_dictionary(b"\x00"),
             "nonzero-wide-integer": binary_dictionary(b"\x14" + b"\xff" * 16),
             "overflow-wide-integer": binary_dictionary(b"\x14" + (1 << 64).to_bytes(16, "big")),
             "invalid-ascii": binary_dictionary(b"\x51\xff"),
             "invalid-utf16": binary_dictionary(b"\x61\xd8\x00"),
             "unindexed-content": binary_dictionary(b"\x09", leading=b"private-plist-value-canary"),
             "unused-invalid-object": binary_plist([b"\xd0", b"\x0f"]),
             "invalid-key": binary_plist([b"\xd1\x01\x02", b"\x09", b"\x08"]),
             "duplicate-encoding-keys": binary_plist([b"\xd2\x01\x02\x03\x03", b"\x51x", b"\x61\0x", b"\x09"]),
             "unused-duplicate-keys": binary_plist([b"\xd0", b"\x51x", b"\x61\0x", b"\xd2\x01\x02\x04\x04", b"\x09"]),
             "invalid-reference": binary_dictionary(b"\xa1\xff"),
             "self-cycle": binary_dictionary(b"\xa1\x02"),
             "mutual-cycle": binary_plist([b"\xd1\x01\x02", b"\x51x", b"\xa1\x03", b"\xa1\x02"]),
             "unused-cycle": binary_plist([b"\xd0", b"\xa1\x01"])}
    valid = binary_dictionary(b"\x09")
    for name, start, end, replacement in (
        ("header", 0, 8, b"bplist01"), ("trailer-version", -32, -26, b"\x01" + b"\0" * 5),
        ("zero-offset-width", -26, -25, b"\0"), ("large-offset-width", -26, -25, b"\x09"),
        ("zero-reference-width", -25, -24, b"\0"), ("large-reference-width", -25, -24, b"\x09"),
        ("zero-count", -24, -16, b"\0" * 8), ("huge-count", -24, -16, b"\xff" * 8),
        ("invalid-root", -16, -8, (3).to_bytes(8, "big")),
    ):
        raw = bytearray(valid); raw[start:end] = replacement
        cases[name] = bytes(raw)
    for offset in (0, 8, len(valid), (1 << 64) - 1):
        cases[f"table-{offset}"] = valid[:-8] + offset.to_bytes(8, "big")
    table = int.from_bytes(valid[-8:], "big")
    for name, index, offset in (("before-header", 0, 7), ("in-table", 0, table),
                                ("aliased-offsets", 1, 8), ("overlapping-object", 2, 12)):
        raw = bytearray(valid); raw[table + index] = offset
        cases[name] = bytes(raw)
    cases["offset-table-gap"] = valid[:-32] + b"\0" + valid[-32:]
    for size in (0, 7, 8, 31, 32, 39):
        cases[f"truncated-file-{size}"] = valid[:size]
    for marker in (0x01, 0x07, 0x0e, 0x15, 0x1f, 0x20, 0x21, 0x24, 0x30, 0x32, 0x34, 0x70, 0x80, 0xb0, 0xc0, 0xe0, 0xff):
        cases[f"unsupported-marker-{marker:02x}"] = binary_dictionary(bytes((marker,)) + b"\0" * 32)
    for marker, width in ((0x11, 2), (0x12, 4), (0x13, 8), (0x14, 16), (0x22, 4), (0x23, 8), (0x33, 8), (0x44, 4), (0x54, 4), (0x62, 4)):
        for size in range(width):
            cases[f"truncated-body-{marker:02x}-{size}"] = binary_dictionary(bytes((marker,)) + b"\0" * size)
    for marker in (0x00, 0x04, 0x08, 0x09, 0x14, 0x20, 0x40, 0x50, 0xa0, 0xe0):
        for kind, body in ((0x4f, b"A"), (0x5f, b"A"), (0x6f, b"\0A"), (0xaf, b"\x01"), (0xdf, b"\x01\x01")):
            cases[f"invalid-length-{kind:02x}-{marker:02x}"] = binary_dictionary(bytes((kind, marker, 1)) + body)
    for width in (1, 2, 4, 8):
        marker = 0x10 + width.bit_length() - 1
        for size in range(width):
            cases[f"truncated-length-{width}-{size}"] = binary_dictionary(bytes((0x5f, marker)) + b"\0" * size)
        cases[f"length-out-of-span-{width}"] = binary_dictionary(bytes((0x5f, marker)) + (50).to_bytes(width, "big") + b"A")
    for value in (-0.0, 1e-7, 2e-7, .1234567, float("inf"), float("-inf"), float("nan"), 1e300, -1e300):
        cases[f"unsupported-date-{value!r}"] = binary_dictionary(b"\x33" + struct.pack(">d", value))
    for marker, fmt in ((0x22, ">f"), (0x23, ">d")):
        for value in (float("inf"), float("-inf"), float("nan")):
            cases[f"nonfinite-real-{marker:02x}-{value!r}"] = binary_dictionary(bytes((marker,)) + struct.pack(fmt, value))
    return cases


def malformed_xml_cases() -> dict[str, bytes]:
    """Independent raw corpus shared by both public dictionary-reader tests."""
    def value(tag: str, text: str) -> str:
        return f'<plist><dict><key>private-plist-key-canary</key><{tag}>{text}</{tag}></dict></plist>'

    cases = {
        "multiple-values": '<plist><dict><key>lost</key><true/></dict><dict/></plist>',
        "unknown-element": '<plist><dict><key>x</key><true/><unknown>private-plist-value-canary</unknown></dict></plist>',
        "empty-dangling-key": '<plist><dict><key/></dict></plist>',
        "dangling-key": '<plist><dict><key>missing-value</key></dict></plist>',
        "root-key": '<plist><key>private-plist-key-canary</key></plist>',
        "array-key": '<plist><dict><key>x</key><array><key>misplaced</key></array></dict></plist>',
        "missing-plist": '<dict/>',
        "empty-plist": '<plist/>',
        "trailing-root": '<plist><dict/></plist><plist><dict/></plist>',
        "root-array": '<plist><array/></plist>',
        "container-text": '<plist><dict>private-plist-value-canary</dict></plist>',
        "boolean-text": value("true", "private-plist-value-canary"),
        "boolean-whitespace": value("false", " "),
        "primitive-child": value("string", "before<dict/>after"),
        "unknown-attribute": '<plist><dict unknown="private-plist-value-canary"/></plist>',
        "root-version": '<plist version="2.0"><dict/></plist>',
        "xml-version": '<?xml version="1.1"?><plist><dict/></plist>',
        "date-incomplete": value("date", "2026"),
        "date-calendar": value("date", "2026-02-30T00:00:00Z"),
        "date-leap-second": value("date", "2026-09-05T00:00:60Z"),
        "date-zone": value("date", "2026-09-05T00:00:00+00:00"),
        "date-fraction": value("date", "2026-09-05T00:00:00.0Z"),
        "integer-whitespace": value("integer", " 1 "),
        "integer-underscore": value("integer", "1_0"),
        "integer-overflow": value("integer", "18446744073709551616"),
        "integer-underflow": value("integer", "-9223372036854775809"),
        "integer-huge": value("integer", "9" * 1000),
        "real-whitespace": value("real", " 1.0"),
        "real-underscore": value("real", "1_0"),
        "real-nonfinite": value("real", "1e999"),
        "real-nan": value("real", "nan"),
        "data-garbage": value("data", "%%%%"),
        "data-unpadded": value("data", "YQ"),
        "data-padding-bits": value("data", "YR=="),
        "data-extra-padding": value("data", "YQ==="),
        "internal-dtd": '<!DOCTYPE plist [<!ENTITY private "canary">]><plist><dict/></plist>',
        "wrong-dtd": '<!DOCTYPE plist SYSTEM "https://example.invalid/never-fetch"><plist><dict/></plist>',
        "processing-instruction": '<?unsupported private-plist-value-canary?><plist><dict/></plist>',
        "unknown-encoding": '<?xml version="1.0" encoding="UNKNOWN-CODEC"?><plist><dict/></plist>',
        "unsupported-encoding": '<?xml version="1.0" encoding="utf-7"?><plist><dict/></plist>',
        "entity-spelled-version": '<plist version="&#49;.0"><dict/></plist>',
    }
    for scheme in ("http", "https"):
        dtd = f'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "{scheme}://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        cases[f"{scheme}-skipped-text-entity"] = dtd + value("string", "left&undefined;right")
        cases[f"{scheme}-lost-attribute-entity"] = dtd + '<plist version="1.0&undefined;"><dict/></plist>'
    comments = {"string": "left<!--private-comment-canary-->right", "integer": "1<!---->2",
                "real": "1<!---->.5", "date": "2026-09-05T00:00:<!---->00Z", "data": "Y<!---->Q==",
                "true": "<!---->", "false": "<!---->"}
    for tag, body in comments.items():
        cases[f"{tag}-comment"] = value(tag, body)
    cases["key-comment"] = '<plist><dict><key>left<!---->right</key><true/></dict></plist>'
    for tag, body in (("integer", "1"), ("date", "2026-09-05T00:00:00Z"), ("data", "YQ=="),
                      ("true", ""), ("false", ""), ("dict", ""), ("array", " ")):
        cases[f"{tag}-cdata"] = value(tag, f"<![CDATA[{body}]]>")
        cases[f"{tag}-empty-cdata"] = value(tag, "<![CDATA[]]>")
    cases["plist-cdata"] = '<plist><![CDATA[]]><dict/></plist>'
    for tag, body in (("integer", "1&#50;"), ("date", "2026-09-05T00:00:0&#48;Z"),
                      ("data", "Y&#81;=="), ("data", "Y&#x51;==")):
        cases[f"{tag}-reference-{body}"] = value(tag, body)
    cases["plist-reference"] = '<plist>&#32;<dict/></plist>'
    cases["dict-reference"] = '<plist><dict>&#32;</dict></plist>'
    cases["array-reference"] = value("array", "&#32;")
    cases["explicit-ascii-codec"] = '<?xml version="1.0" encoding="US-ASCII"?><plist><dict/></plist>'
    cases["explicit-latin-codec"] = '<?xml version="1.0" encoding="ISO-8859-1"?><plist><dict/></plist>'
    for spacing in ("", " ", "\n\t"):
        cases[f"self-closing-data-{spacing}"] = f'<plist><dict><key>x</key><data{spacing}/></dict></plist>'
    result = {name: text.encode() for name, text in cases.items()}
    result["invalid-utf8"] = b'<plist><dict><key>x</key><string>\xff</string></dict></plist>'
    for encoding, bom in (("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
        result[f"{encoding}-lost-attribute-entity"] = bom + cases["http-lost-attribute-entity"].encode(encoding)
        for name, source in cases.items():
            if name.startswith("self-closing-data-"):
                result[f"{encoding}-{name}"] = bom + source.encode(encoding)
        for declared in ("", '<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>',
                         f'<?xml version="1.0" encoding="{encoding.replace("16-", "16")}"?>'):
            result[f"{encoding}-no-bom-{declared}"] = (declared + '<plist><dict/></plist>').encode(encoding)
        opposite = "UTF-16BE" if encoding.endswith("le") else "UTF-16LE"
        for declared in ("UTF-8", opposite):
            result[f"{encoding}-contradictory-{declared}"] = bom + (
                f'<?xml version="1.0" encoding="{declared}"?><plist><dict/></plist>').encode(encoding)
    return result


def supported_xml_lexical_cases() -> dict[str, tuple[str, dict[str, Any]]]:
    """Raw spelling and independent typed expectations, also checked by plutil."""
    def value(tag: str, body: str) -> str:
        return f'<plist><dict><key>x</key><{tag}>{body}</{tag}></dict></plist>'

    return {
        "literal-newlines": (value("string", "a\rb\r\nc\nd\te"), {"x": "a\rb\r\nc\nd\te"}),
        "cdata-newlines": (value("string", "<![CDATA[a\rb\r\nc\nd\te]]>"), {"x": "a\rb\r\nc\nd\te"}),
        "reference-newlines": (value("string", "a&#13;b&#13;&#10;c&#10;d&#9;e"), {"x": "a\rb\r\nc\nd\te"}),
        "distinct-keys": ('<plist><dict><key>a\r</key><integer>1</integer><key>a\n</key><integer>2</integer></dict></plist>',
                          {"a\r": 1, "a\n": 2}),
        "key-cdata": ('<plist><dict><key><![CDATA[a\r\n&]]></key><string>value</string></dict></plist>', {"a\r\n&": "value"}),
        "one-pass-refs": (value("string", "&amp;amp;&amp;#13;&lt;string&gt;&quot;&apos;&#65;&#x1F600;"),
                          {"x": '&amp;&#13;<string>"\'A😀'}),
        "literal-cdata": (value("string", "left<![CDATA[&amp;&#13;<tag>]]>right"), {"x": "left&amp;&#13;<tag>right"}),
        "real-cdata": (value("real", "<![CDATA[1.5]]>"), {"x": 1.5}),
        "real-reference": (value("real", "&#49;.5"), {"x": 1.5}),
        "data-whitespace": (value("data", "Y\r\n Q\t=="), {"x": b"a"}),
        "empty-forms": ('<plist><dict><key/><string></string><key>data</key><data></data><key>list</key><array/></dict></plist>',
                        {"": "", "data": b"", "list": []}),
        "container-comments": ('<!--before--><plist><!--root--><dict><!--member--><key>x</key><!--pair--><array>'
                               '<!--first--><true/><!--last--></array></dict><!--end--></plist><!--after-->', {"x": [True]}),
    }


def add_discardable_root_dictionary(xml: bytes) -> bytes:
    return xml.replace(b"<dict>", b"<dict><key>private-plist-key-canary</key><true/></dict><dict>", 1)


def rewrite_zip_members(path: Path, replacements: dict[str, bytes]) -> None:
    """Edit only owned fictional fixtures, never a real retained candidate."""
    with zipfile.ZipFile(path) as archive:
        records = {entry.filename: (entry, archive.read(entry)) for entry in archive.infolist()}
    for name, data in replacements.items():
        records[name] = (records[name][0] if name in records else name, data)
    with zipfile.ZipFile(path, "w") as archive:
        for entry, data in records.values():
            archive.writestr(entry, data)


def tlv(tag: int, body: bytes) -> bytes:
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def der_value(value: Any, *, dictionary_tag: int = 0xB0) -> bytes:
    if type(value) is bool:
        return tlv(1, b"\xff" if value else b"\x00")
    if type(value) is int:
        raw = value.to_bytes(9, "big", signed=True)
        while len(raw) > 1 and ((raw[0] == 0 and raw[1] < 128) or (raw[0] == 255 and raw[1] >= 128)):
            raw = raw[1:]
        return tlv(2, raw)
    if type(value) is str:
        return tlv(12, value.encode())
    if type(value) is bytes:
        return tlv(4, value)
    if type(value) is datetime:
        instant = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        if 1950 <= instant.year <= 2049:
            return tlv(23, instant.strftime("%y%m%d%H%M%SZ").encode())
        return tlv(24, instant.strftime("%Y%m%d%H%M%SZ").encode())
    if type(value) is list:
        return tlv(48, b"".join(der_value(item) for item in value))
    if type(value) is dict:
        pairs = [tlv(48, der_value(key) + der_value(item)) for key, item in sorted(value.items())]
        return tlv(dictionary_tag, b"".join(sorted(pairs) if dictionary_tag == 49 else pairs))
    raise AssertionError(f"unsupported fictional fixture value type: {type(value)}")


def der_entitlements(claims: dict[str, Any]) -> bytes:
    return tlv(0x70, der_value(1) + der_value(claims))


def signed_entitlements(bundle_id: str = BUNDLE) -> dict[str, Any]:
    return {"application-identifier": f"{TEAM}.{bundle_id}",
            "com.apple.developer.team-identifier": TEAM, "get-task-allow": False}


def profile(certificate: bytes = CERTIFICATE, bundle_id: str = BUNDLE) -> dict[str, Any]:
    return {"Entitlements": {**signed_entitlements(bundle_id), "beta-reports-active": True},
            "TeamIdentifier": [TEAM], "UUID": "12345678-1234-1234-1234-1234567890AB",
            "CreationDate": datetime(2020, 1, 1), "ExpirationDate": datetime(2099, 1, 1),
            "DeveloperCertificates": [certificate]}


def modern_profile_bytes(outer: dict[str, Any], *, authoritative: dict[str, Any] | None = None) -> bytes:
    # The explicitly mocked authentication seam returns its input. This wraps real DER in a
    # real plist, but neither layer has a CMS signature; never use as a profile.
    inner = dict(outer if authoritative is None else authoritative)
    inner.pop("DER-Encoded-Profile", None)
    inner["DeveloperCertificates"] = [hashlib.sha256(item).digest() for item in inner["DeveloperCertificates"]]
    pairs = []
    for key, item in inner.items():
        encoded = der_entitlements(item) if key == "Entitlements" else der_value(item)
        pairs.append(tlv(48, der_value(key) + encoded))
    return plistlib.dumps({**outer, "DER-Encoded-Profile": tlv(49, b"".join(sorted(pairs)))})


def modernize_ipa_fixture(path: Path) -> None:
    """Replace fictional app profiles only; preserve every original binary byte."""
    with zipfile.ZipFile(path) as archive:
        members = {entry.filename: archive.read(entry) for entry in archive.infolist()}
    for name, data in list(members.items()):
        if name.endswith("/Info.plist") and Path(name).parent.suffix in {".app", ".appex"}:
            identity = plistlib.loads(data)["CFBundleIdentifier"]
            members[str(Path(name).parent / "embedded.mobileprovision")] = modern_profile_bytes(profile(bundle_id=identity))
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


class NativeProfileSeam:
    """Fake native app signing, preserving actual bytes, parsers and inventory.

    Entitlement-content tests must separately patch authenticate_cms with the
    explicit method below. These fixtures do NOT establish Apple issuer trust.
    """
    def __init__(self):
        self.claims = {}
        self.teams = {}
        self.certificates = {}
        self.missing_certificates = set()
        self.calls = []
        self.extracted = []
        self.failures = set()
        self.cms_calls = []

    def authenticate_cms(self, content, *, deadline):
        deadline.check()
        self.cms_calls.append(content)
        return content

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        path = Path(argv[-1])
        arch = argv[argv.index("--architecture") + 1] if "--architecture" in argv else None
        key = (path.name, arch)
        operation = next((item for item in ("--entitlements", "--extract-certificates", "--verbose=4") if item in argv), argv[0])
        if (operation, *key) in self.failures:
            return types.SimpleNamespace(returncode=1, stdout=b"private-native-canary", stderr=b"private-native-canary")
        if argv[0] == "security":
            raise AssertionError("CMS decoding must not replace authenticated profile authority")
        if "--entitlements" in argv:
            if key in self.claims:
                value = self.claims[key]
            elif path.name in self.claims:
                value = self.claims[path.name]
            elif path.is_dir() and path.suffix in {".app", ".appex"}:
                value = signed_entitlements(plistlib.loads((path / "Info.plist").read_bytes())["CFBundleIdentifier"])
            else:
                value = None
            data = b"" if value is None else (der_entitlements(value) if "--der" in argv else plistlib.dumps(value))
            return types.SimpleNamespace(returncode=0, stdout=data, stderr=b"")
        if "--extract-certificates" in argv:
            prefix = Path(argv[argv.index("--extract-certificates") + 1])
            leaf = Path(str(prefix) + "0")
            self.extracted.append(leaf)
            if key not in self.missing_certificates:
                leaf.write_bytes(self.certificates.get(key, CERTIFICATE))
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if argv[0] == "openssl":
            certificate = Path(argv[argv.index("-in") + 1]).read_bytes()
            return types.SimpleNamespace(returncode=0, stdout=f"sha256 Fingerprint={hashlib.sha256(certificate).hexdigest()}\nnotBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2099 GMT\n", stderr="")
        if "--verbose=4" in argv:
            return types.SimpleNamespace(returncode=0, stdout="", stderr=self.teams.get(key, f"TeamIdentifier={TEAM}\n"))
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
