"""Finite synthetic DATA checks. No compiler, native work, or acceptance receipt.

The separately admitted generation owner additionally compares every frozen
production row. These small tests do not stand in for that full comparison or
for the actual Rust serializer, static-pointer, layout and resource checks.
"""
import hashlib
import importlib.util
import re
import struct
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    path = ROOT / 'desktop/tools' / filename
    if name in sys.modules:
        module = sys.modules[name]
        if Path(module.__file__).resolve() != path:
            raise RuntimeError('unexpected source module collision')
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


T = load('macos_android_catalogue_tables', 'macos_android_catalogue_tables.py')
G = load('mrk_catalogue_typed_generator_tests', 'macos_android_supplier_catalogue.py')
SHA = 'a' * 64
HEADER = 'NativeHeader { prefix: CAT_H0_PREFIX, commands: CAT_H0_COMMANDS }'
HEADERS = {'CAT_H0_PREFIX': (0, 64), 'CAT_H0_COMMANDS': (64, 64)}


def fixture():
    rows = {
        'CAT_A0': ('OfficialMember', [
            'OfficialMember { name: "directory", kind: ArchiveKind::Directory { mode: 0o40755 }, disposition: ArchiveDisposition::WrapperDirectory }',
            'OfficialMember { name: "file", kind: ArchiveKind::File { mode: 0o100644, bytes: 4294967303, sha256: "' + SHA + '" }, disposition: ArchiveDisposition::Picked { source_index: 12 } }',
            'OfficialMember { name: "alias", kind: ArchiveKind::Alias { mode: 0o120777, target: "file" }, disposition: ArchiveDisposition::SealedSupport(SupportAsset::Aapt2OsxJar) }',
        ] * 32),
        'CAT_SOURCES': ('SourceMemberSpec', [
            'SourceMemberSpec { group: SourceGroup::Jdk, relative: "directory", kind: SourceKindSpec::Directory { modes: &[0o755] } }',
            'SourceMemberSpec { group: SourceGroup::Sdk, relative: "file", kind: SourceKindSpec::File { bytes: 4294967303, sha256: "' + SHA + '", modes: &[0o444,0o644] } }',
            'SourceMemberSpec { group: SourceGroup::Gradle, relative: "alias", kind: SourceKindSpec::Alias { target: "file", canonical: "directory/file", modes: &[0o777] } }',
        ]),
        'CAT_BINDINGS': ('SourceBinding', [
            'SourceBinding { provenance: SourceProvenance::Vendor { archive: 5, member: 12 }, disposition: SourceDisposition::Payload(34) }',
            'SourceBinding { provenance: SourceProvenance::ArchiveParent { archive: 0, prefix: "directory" }, disposition: SourceDisposition::Directory }',
            'SourceBinding { provenance: SourceProvenance::Vendor { archive: 3, member: 8 }, disposition: SourceDisposition::Alias(2) }',
        ]),
        'CAT_PAYLOAD': ('PayloadSource', [
            'PayloadSource { installed: CanonicalFile { path: "installed-' + str(i) + '", size: 4294967303, sha256: "' + SHA + '", mode: 0o444 }, origin: ' + origin + ' }'
            for i, origin in enumerate([
                'PayloadOrigin::DirectOriginal(OriginalSource::Picked { group: SourceGroup::FixedSupport, relative: "file" })',
                'PayloadOrigin::DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar))',
                'PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::BuildTools35)',
                'PayloadOrigin::MemberOfSameOriginalArchive { asset: SupportAsset::Aapt2OsxJar, archive: ArchivePin { bytes: 4294967309, sha256: "' + SHA + '" }, member: CAT_PROJECTED }',
            ])
        ]),
        'CAT_CLASSES': ('FileClass', [
            'FileClass::Data', 'FileClass::LicenseText', 'FileClass::GradleShell',
            'FileClass::GradleForeignLauncher', 'FileClass::AndroidTargetElf',
            'FileClass::SdkBash(policy::Sdk35File::D8)',
            'FileClass::SdkLegacyIntel(policy::Sdk35File::CxxAbiIntel, ' + HEADER + ')',
            'FileClass::MachO(' + HEADER + ')',
            'FileClass::JvmArchive { native_members: &[] }',
            'FileClass::JvmArchive { native_members: CAT_N0 }',
        ]),
        'CAT_N0': ('NestedNative', [
            'NestedNative { member: "native-' + str(i) + '", bytes: 4294967311, sha256: "' + SHA + '", mode: 0o100755, kind: NativeResourceKind::' + kind + ', header: ' + ('Some(' + HEADER + ')' if i % 2 else 'None') + ' }'
            for i, kind in enumerate(T.NATIVE)
        ]),
        'CAT_ALIASES': ('CanonicalAlias', ['CanonicalAlias { path: "alias", target: "file", canonical: "directory/file", source_index: 2 }']),
        'CAT_DIRECTORIES': ("&'static str", ['"directory"', '"directory/child"']),
    }
    for i in range(1, 6): rows['CAT_A' + str(i)] = ('OfficialMember', [])
    prelude = ('// Fixed small source region.\n'
               'const CAT_HEADER_BYTES: &[u8] = include_bytes!("unchanged_header.bin");\n'
               'const CAT_H0_PREFIX: &[u8] = CAT_HEADER_BYTES.split_at(0).1.split_at(64).0;\n'
               'const CAT_H0_COMMANDS: &[u8] = CAT_HEADER_BYTES.split_at(64).1.split_at(64).0;\n'
               'const CAT_PROJECTED: ZipMemberSpec = Unchanged;\n')
    body = ''.join('const ' + name + ': &[' + typ + '] = &[\n'
                   + ''.join('    ' + row + ',\n' for row in values) + '];\n'
                   for name, (typ, values) in rows.items())
    return (prelude + body + 'const REFERENCES: &[Reference] = &[Unchanged];\n').encode()


def collect(source, profile='arm64'):
    output, assets = [], {}
    def source_sink(raw):
        assert type(raw) is bytes and 0 < len(raw) <= 65536
        output.append(raw)
    def asset_sink(path, offset, raw):
        assert type(raw) is bytes and 0 < len(raw) <= 65536
        value = assets.setdefault(path, bytearray())
        assert offset == len(value)
        value.extend(raw)
    receipt = T.convert(source, profile, source_sink, asset_sink=asset_sink)
    return b''.join(output), {path: bytes(raw) for path, raw in assets.items()}, receipt


def decoded(assets, receipt):
    pins = {row['kind']: row for row in receipt['assets']}
    strings = T.string_pool(assets[pins['strings']['path']], receipt['profile'])
    sections = T.record_sections(assets[pins['records']['path']], receipt['profile'])
    return {(kind, ordinal): list(T.decoded_rows(kind, raw, strings, receipt['modes'], receipt['nativeTables'], HEADERS))
            for kind, ordinal, count, raw in sections}


class CatalogueTablesTests(unittest.TestCase):
    def test_all_typed_rows_roundtrip_and_profile_packs_are_separate(self):
        source = fixture()
        _, original = T.source_sections(source)
        expected = {(row['kind'], row['index']): row['rows'] for row in original}
        outputs = {}
        for profile in T.PROFILES:
            with self.subTest(profile=profile):
                output, assets, receipt = collect(source, profile)
                self.assertEqual(decoded(assets, receipt), expected)
                self.assertEqual((output, assets, receipt), collect(source, profile))
                self.assertLessEqual(len(output) + sum(map(len, assets.values())) + 128, T.LIMIT)
                self.assertLessEqual(len(output) + sum(map(len, assets.values())), len(source))
                self.assertEqual(receipt['source'], {'bytes': len(output), 'sha256': hashlib.sha256(output).hexdigest()})
                for pin in receipt['assets']:
                    self.assertEqual((len(assets[pin['path']]), hashlib.sha256(assets[pin['path']]).hexdigest()), (pin['bytes'], pin['sha256']))
                for section in receipt['sections']:
                    self.assertEqual(section['tupleSha256'], hashlib.sha256(T.canonical(expected[(section['kind'], section['index'])])).hexdigest())
                self.assertIn(b'const CAT_PROJECTED: ZipMemberSpec = Unchanged;', output)
                self.assertIn(b'const REFERENCES: &[Reference] = &[Unchanged];', output)
                self.assertEqual(output.count(b'include_bytes!'), 3)
                outputs[profile] = set(assets)
        self.assertTrue(outputs['arm64'].isdisjoint(outputs['x86_64']))

    def test_pack_headers_ranges_order_counts_and_profiles_refuse(self):
        _, assets, receipt = collect(fixture())
        for pin in receipt['assets']:
            raw = assets[pin['path']]
            reader = T.string_pool if pin['kind'] == 'strings' else T.record_sections
            for cut in (0, 7, 15, 19, len(raw) - 1):
                with self.subTest(kind=pin['kind'], cut=cut), self.assertRaises(T.Refused): reader(raw[:cut], 'arm64')
            with self.assertRaises(T.Refused): reader(raw, 'x86_64')
            with self.assertRaises(T.Refused): reader(raw + b'\0', 'arm64')
            for offset in ((0, 8, 12, 16, 20, 24, 25, 28, 32, 36, 40) if pin['kind'] == 'records' else (0, 8, 12, 16, 20, 24)):
                bad = bytearray(raw); bad[offset:offset + 4] = b'\xff' * 4
                with self.subTest(kind=pin['kind'], offset=offset), self.assertRaises(T.Refused): reader(bytes(bad), 'arm64')
        # An otherwise closed string pack with invalid UTF8 and repeated values.
        for payload, offsets in ((b'\xff', (0, 0, 1)), (b'aa', (0, 0, 1, 2))):
            raw = b'MRKSTR01' + struct.pack('<II', 1, len(offsets) - 1) + struct.pack('<' + 'I' * len(offsets), *offsets) + payload
            with self.assertRaises(T.Refused): T.string_pool(raw, 'arm64')

    def test_record_tags_reserved_indices_and_header_ranges_refuse(self):
        _, assets, receipt = collect(fixture())
        pins = {row['kind']: row for row in receipt['assets']}
        strings = T.string_pool(assets[pins['strings']['path']], 'arm64')
        sections = T.record_sections(assets[pins['records']['path']], 'arm64')
        offsets = {1: (0, 4, 5, 7), 2: (0, 1, 2, 4, 28), 3: (0, 1, 2, 3),
                   4: (0, 20, 21, 22, 40), 5: (0, 1, 2, 4, 8), 6: (0, 20, 21, 22), 7: (0, 4, 8), 8: (0,)}
        for kind, ordinal, count, raw in sections:
            if not count: continue
            for offset in offsets[kind]:
                bad = bytearray(raw[:T.STRIDES[kind]])
                bad[offset] = 255
                if offset == 0 and kind not in (2, 3, 5): bad[:4] = b'\xff' * 4
                with self.subTest(kind=kind, offset=offset), self.assertRaises(T.Refused):
                    list(T.decoded_rows(kind, bad, strings, receipt['modes'], receipt['nativeTables'], HEADERS))
        for values in ('&[', 'Bad { field: 1, field: 2 }', 'Bad(1) trailing', '"\\u00e9"', '__import__("os").system("x")'):
            with self.subTest(expression=values), self.assertRaises(T.Refused): T.expression(values)

    def test_output_bounds_and_sink_failures_are_not_receipts(self):
        class SinkFailure(Exception): pass
        def reject(*_): raise SinkFailure()
        for source_sink, asset_sink in ((reject, lambda *_: None), (lambda *_: None, reject)):
            with self.assertRaises(SinkFailure): T.convert(fixture(), 'arm64', source_sink, asset_sink=asset_sink)
        emitted = []
        with mock.patch.object(T, 'LIMIT', 8), self.assertRaises(T.Refused):
            T.convert(fixture(), 'arm64', emitted.append, asset_sink=lambda *row: emitted.append(row))
        self.assertEqual(emitted, [])

    def test_default_generator_packing_boundary_is_connected(self):
        source = fixture()
        def literal(_projection, sink, *, asset_sink, profile):
            sink(source)
            asset_sink('unchanged_header.bin', 0, b'h' * 128)
            return {'bytes': len(source), 'sha256': hashlib.sha256(source).hexdigest(),
                    'assets': [{'path': 'unchanged_header.bin', 'bytes': 128, 'sha256': hashlib.sha256(b'h' * 128).hexdigest()}],
                    'headers': []}
        output, assets = [], {}
        def receive(path, offset, raw):
            value = assets.setdefault(path, bytearray()); self.assertEqual(offset, len(value)); value.extend(raw)
        with mock.patch.object(G, '_render_literal', literal):
            receipt = G.render(None, output.append, asset_sink=receive)
        self.assertEqual(len(receipt['assets']), 3)
        self.assertEqual(receipt['typedTables']['profile'], 'arm64')
        self.assertEqual(assets['unchanged_header.bin'], b'h' * 128)
        self.assertIn(b'catalogue_binary::official', b''.join(output))


    def test_generated_const_regions_are_exact_complete_and_closed(self):
        source = fixture(); original, sections = T.source_sections(source, parsed=False)
        outside = []; at = 0
        for section in sections:
            outside.append(original[at:section['start']]); at = section['end']
        outside.append(original[at:]); expected = ''.join(outside).encode()
        for profile in T.PROFILES:
            output, _, receipt = collect(source, profile)
            self.assertEqual(T.unchanged_source_regions(output, receipt), expected)
            self.assertIn(b'const CAT_A1_SECTION: catalogue_binary::Section = CAT_TABLES.section(1, 1, 0);', output)
            self.assertIn(b'assemble_official::<0>(CAT_A1_SECTION, &CAT_A1_CHUNKS)', output)
            self.assertNotRegex(output, rb'(?:const|static) CAT_A1_C0:')
            intermediates = re.findall(rb'^(const|static) (CAT_[A-Z_0-9]+_(?:C[0-9]+|CHUNKS)):', output, re.MULTILINE)
            expected_units = sum((row['count'] + 31) // 32 + 1 for row in receipt['sections'])
            self.assertEqual(len(intermediates), expected_units)
            self.assertTrue(all(kind == b'const' for kind, _ in intermediates))
            for _, name in intermediates:
                self.assertEqual(len(re.findall(rb'\b' + name + rb'\b', output)), 2)
            self.assertEqual(len(re.findall(rb'^static CAT_[A-Z_0-9]+_ROWS:', output, re.MULTILINE)), len(receipt['sections']))
            mutations = [
                output.replace(b'const CAT_A0_C0:', b'static CAT_A0_C0:', 1),
                output.replace(b'[S0,', b'[S0,S0,', 1),
                output.replace(b'&CAT_A0_C0,&CAT_A0_C1,', b'&CAT_A0_C1,&CAT_A0_C0,', 1),
                output.replace(b'CAT_TABLES.section(1, 0, 96)', b'CAT_TABLES.section(1, 0, 95)', 1),
                output.replace(b'include!("android_supplier_macos_catalogue_binary.rs")', b'include!("foreign.rs")', 1),
                output.replace(b'// MRK_CATALOGUE_SECTION_BEGIN CAT_A1', b'// MRK_CATALOGUE_SECTION_BEGIN CAT_A2', 1),
                output + b'// MRK_CATALOGUE_UNKNOWN\n',
            ]
            begin = ('// MRK_CATALOGUE_CODEC_BEGIN ' + profile + '\n').encode()
            mutations.append(output.replace(begin, begin + begin, 1))
            for changed in mutations:
                self.assertNotEqual(changed, output)
                with self.assertRaises(T.Refused): T.unchanged_source_regions(changed, receipt)


if __name__ == '__main__':
    unittest.main()
