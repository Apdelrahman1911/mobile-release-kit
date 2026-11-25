"""Closed SOURCE representation codec; no paths, IO, subprocess or authority.

Only the existing generated catalogue grammar is accepted. The owner binds the
original SOURCE/header assets and owns every tentative output until completion.
Neither a storage digest nor successful decoding replaces supplier validation.
"""
import hashlib
import json
import re
import struct

LIMIT = 32 * 1024 * 1024
CHUNK = 65536
MAX_SECTIONS = 128
MAX_STRINGS = 131072
STRIDES = {1: 32, 2: 32, 3: 16, 4: 48, 5: 24, 6: 40, 7: 16, 8: 4}
PROFILES = {"arm64": 1, "x86_64": 2}
GROUPS = ("Jdk", "Sdk", "Gradle", "FixedSupport")
ASSETS = ("BundletoolJar", "Aapt2OsxJar")
NATIVE = ("Arm64", "JdkInstalledCounterpart", "JdkJpackageTemplate", "OtherPlatformElf",
          "OtherPlatformPe", "GradleIntelPlatform", "GradlePlainJansiIntel", "BundletoolDarwinI386X64",
          "CurrentX64", "OtherPlatformArm64", "OtherPlatformI386")
CLASSES = ("Data", "LicenseText", "GradleShell", "GradleForeignLauncher", "AndroidTargetElf",
           "SdkBash", "SdkLegacyIntel", "MachO", "JvmArchive")
SDK = ("D8", "Apksigner", "LldShell", "LldIntel", "CxxIntel", "CxxAbiIntel")
METADATA = ("Platform35Revision2", "BuildTools35")


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


_TOKEN = re.compile(r'\s*("(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*|0o[0-7]+|[0-9]+|[&\[\]{}(),:])')


def expression(raw):
    """Finite generated-row grammar, never eval or a general Rust parser."""
    need(type(raw) is str and raw.isascii() and len(raw) <= CHUNK, "expression-bound")
    tokens, at = [], 0
    while at < len(raw):
        match = _TOKEN.match(raw, at)
        need(match is not None and len(tokens) < 512, "expression-token")
        tokens.append(match[1]); at = match.end()
    pos = 0

    def take(wanted=None):
        nonlocal pos
        need(pos < len(tokens), "expression-short")
        value = tokens[pos]; pos += 1
        need(wanted is None or value == wanted, "expression-punctuation")
        return value

    def parse(depth=0):
        nonlocal pos
        need(depth <= 8, "expression-depth")
        token = take()
        if token.startswith('"'):
            value = json.loads(token)
            need(type(value) is str and value.isascii() and len(value) <= 2048, "expression-string")
            return value
        if token[0].isdigit():
            value = int(token[2:], 8) if token.startswith("0o") else int(token)
            need(0 <= value < 1 << 64, "expression-integer")
            return value
        if token == "&":
            take("["); values = []
            while tokens[pos] != "]":
                need(len(values) < 128, "expression-array")
                values.append(parse(depth + 1))
                if tokens[pos] != "]": take(",")
            take("]")
            return {"array": values}
        need(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*", token), "expression-name")
        if pos == len(tokens) or tokens[pos] not in ("{", "("):
            return {"name": token}
        opening = take(); close = "}" if opening == "{" else ")"
        values = {} if opening == "{" else []
        while tokens[pos] != close:
            if opening == "{":
                key = take(); take(":")
                need(key not in values, "expression-duplicate-field")
                values[key] = parse(depth + 1)
            else:
                values.append(parse(depth + 1))
            if tokens[pos] != close: take(",")
        take(close)
        return {"name": token, "fields" if opening == "{" else "args": values}

    try:
        value = parse()
    except (IndexError, ValueError, OverflowError) as error:
        raise Refused("expression-malformed") from error
    need(pos == len(tokens), "expression-trailing")
    return value


def fields(value, name, keys):
    need(type(value) is dict and set(value) == {"name", "fields"} and value["name"] == name
         and set(value["fields"]) == set(keys.split()), "record-fields-" + name)
    return value["fields"]


def named(value, prefix, choices):
    need(type(value) is dict and set(value) == {"name"} and value["name"].startswith(prefix), "record-enum")
    name = value["name"][len(prefix):]
    need(name in choices, "record-enum-tag")
    return choices.index(name)


def call(value, name, count):
    need(type(value) is dict and set(value) == {"name", "args"} and value["name"] == name
         and len(value["args"]) == count, "record-call-" + name)
    return value["args"]


def uint(value, bits=32):
    need(type(value) is int and 0 <= value < 1 << bits, "record-integer")
    return value


def section_key(name):
    if re.fullmatch(r"CAT_A[0-5]", name): return 1, int(name[5:])
    if re.fullmatch(r"CAT_N[0-9]+", name): return 6, int(name[5:])
    return {"CAT_SOURCES": (2, 0), "CAT_BINDINGS": (3, 0), "CAT_PAYLOAD": (4, 0),
            "CAT_CLASSES": (5, 0), "CAT_ALIASES": (7, 0), "CAT_DIRECTORIES": (8, 0)}.get(name)


def source_sections(source, *, parsed=True):
    need(type(source) is bytes and len(source) <= LIMIT and source.isascii(), "source-bound")
    text = source.decode("ascii")
    pattern = re.compile(r"^const (CAT_[A-Z0-9]+): &\[[^\n]+\] = &\[\n", re.MULTILINE)
    result = []
    for match in pattern.finditer(text):
        key = section_key(match[1])
        if key is None: continue
        end = text.find("];\n", match.end())
        need(end >= match.end(), "source-section-end")
        rows = []
        for line in text[match.end():end].splitlines():
            need(line.startswith("    ") and line.endswith(",") and len(rows) < 32768, "source-row")
            rows.append(expression(line[4:-1]) if parsed else line[4:-1])
        result.append({"name": match[1], "kind": key[0], "index": key[1], "rows": rows,
                       "start": match.start(), "end": end + 3})
    need(12 <= len(result) <= MAX_SECTIONS and len({(s['kind'], s['index']) for s in result}) == len(result), "source-sections")
    need({s['kind'] for s in result} == set(STRIDES), "source-section-kinds")
    need({s['index'] for s in result if s['kind'] == 1} == set(range(6)), "source-archives")
    return text, result


# The following functions emit/check source text only. They never open a path,
# qualify a supplier, evaluate a Rust proof, or replace the actual const checks.
BLOCK_ROWS = 32
_TYPES = {1: 'OfficialMember', 2: 'SourceMemberSpec', 3: 'SourceBinding', 4: 'PayloadSource',
          5: 'FileClass', 6: 'NestedNative', 7: 'CanonicalAlias', 8: "&'static str"}
_DECODERS = {1: 'official', 2: 'sources', 3: 'bindings', 4: 'payload', 5: 'classes',
             6: 'nested', 7: 'aliases', 8: 'directories'}


def storage_regions(profile, string_count, sections, modes, native_names, names):
    """Closed single-wrapper recipe; actual Rust calls validate every raw row."""
    need(profile in PROFILES and type(string_count) is int and 0 < string_count <= MAX_STRINGS,
         'storage-string-profile-count')
    need(type(sections) is list and 12 <= len(sections) <= MAX_SECTIONS, 'storage-sections')
    need(type(names) is dict and set(names) == {'records', 'strings'}, 'storage-asset-kinds')
    for kind, path in names.items():
        need(type(path) is str and re.fullmatch(
            r'android_supplier_macos_catalogue_assets/' + profile + '_' + kind + r'_[a-f0-9]{64}\.bin', path),
            'storage-asset-path')
    seen = set(); total = 0; archives = set(); kinds = set(); nested = []
    for section in sections:
        need(type(section) is dict, 'storage-section-object')
        name, kind, index, count = (section.get(k) for k in ('name', 'kind', 'index', 'count'))
        need(type(name) is str and type(kind) is int and type(index) is int and type(count) is int
             and section_key(name) == (kind, index) and kind in STRIDES and name not in seen
             and 0 <= count <= (128 if kind == 6 else 32768), 'storage-section-shape')
        need(0 <= index < (32768 if kind == 6 else 6 if kind == 1 else 1), 'storage-section-index')
        seen.add(name); kinds.add(kind); total += count
        if kind == 1: archives.add(index)
        if kind == 6: nested.append((index, name))
    need(total <= 8 * 32768 + 128 * 128 and kinds == set(STRIDES) and archives == set(range(6)),
         'storage-complete-sections')
    need(native_names == [name for _, name in sorted(nested)], 'storage-nested-order')
    need(type(modes) is list and 0 < len(modes) <= 16, 'storage-mode-list')
    for row in modes:
        need(type(row) in (list, tuple) and 0 < len(row) <= 4
             and all(type(v) is int and 0 <= v <= 0o777 for v in row)
             and list(row) == sorted(set(row)), 'storage-mode-row')
    unit_count = (string_count + BLOCK_ROWS - 1) // BLOCK_ROWS
    prefix = (f'// MRK_CATALOGUE_CODEC_BEGIN {profile}\n'
              f'const CAT_RECORD_BYTES: &[u8] = include_bytes!("{names["records"]}");\n'
              f'const CAT_STRING_BYTES: &[u8] = include_bytes!("{names["strings"]}");\n'
              'mod catalogue_binary {\ninclude!("android_supplier_macos_catalogue_binary.rs");\n'
              'mod checked_strings {\nconst RAW: &[u8] = super::super::CAT_STRING_BYTES;\n'
              f'const SHAPE: super::StringShape = super::string_shape(RAW, {PROFILES[profile]});\n')
    prefix += ''.join(f'const S{i}: super::CheckedStringChunk = super::check_string_chunk(SHAPE, {i});\n'
                      for i in range(unit_count))
    prefix += ('pub(super) const STRINGS: super::Strings = super::finish_strings(SHAPE, &['
               + ''.join(f'S{i},' for i in range(unit_count)) + ']);\n}\n'
               'pub(super) const CHECKED_STRINGS: Strings = checked_strings::STRINGS;\n}\n'
               f'const CAT_TABLES: catalogue_binary::Tables = catalogue_binary::Tables::new(CAT_RECORD_BYTES, {PROFILES[profile]});\n'
               'const CAT_STRINGS: catalogue_binary::Strings = catalogue_binary::CHECKED_STRINGS;\n'
               'const CAT_MODES: &[&[u32]] = &[' + ', '.join('&[' + ','.join(oct(v) for v in m) + ']' for m in modes) + '];\n'
               'const CAT_NESTED: &[&[NestedNative]] = &[&[], ' + ', '.join(native_names) + '];\n'
               f'// MRK_CATALOGUE_CODEC_END {profile}\n')
    blocks = {}
    for section in sections:
        name, kind, index, count = (section[k] for k in ('name', 'kind', 'index', 'count'))
        typ, decoder = _TYPES[kind], _DECODERS[kind]
        chunks = (count + BLOCK_ROWS - 1) // BLOCK_ROWS
        args = (', CAT_MODES' if kind == 2 else ', CAT_PROJECTED' if kind == 4 else
                ', CAT_HEADER_BYTES, CAT_NESTED' if kind == 5 else ', CAT_HEADER_BYTES' if kind == 6 else '')
        value = (f'// MRK_CATALOGUE_SECTION_BEGIN {name} {kind} {index} {count}\n'
                 f'const {name}_SECTION: catalogue_binary::Section = CAT_TABLES.section({kind}, {index}, {count});\n')
        value += ''.join(f'const {name}_C{i}: catalogue_binary::DecodedChunk<{typ}> = catalogue_binary::{decoder}_chunk({name}_SECTION, CAT_STRINGS, {i}{args});\n'
                         for i in range(chunks))
        value += (f'const {name}_CHUNKS: [&catalogue_binary::DecodedChunk<{typ}>; {chunks}] = ['
                  + ''.join(f'&{name}_C{i},' for i in range(chunks)) + '];\n'
                  f'static {name}_ROWS: [{typ}; {count}] = catalogue_binary::assemble_{decoder}::<{count}>({name}_SECTION, &{name}_CHUNKS);\n'
                  f'const {name}: &[{typ}] = &{name}_ROWS;\n'
                  f'// MRK_CATALOGUE_SECTION_END {name}\n')
        blocks[name] = value
    need(len(prefix) + sum(map(len, blocks.values())) <= LIMIT, 'storage-regions-bound')
    return prefix, blocks


def unchanged_source_regions(source, receipt):
    """Remove only exact closed generated regions bound to validated metadata.

    Callers must independently verify all actual binary rows/header/source pins;
    this check alone is neither tuple equivalence nor Rust execution evidence.
    """
    need(type(source) is bytes and len(source) <= LIMIT and source.isascii()
         and type(receipt) is dict, 'storage-source-bound')
    assets = receipt.get('assets')
    need(type(assets) is list and len(assets) == 2 and all(type(a) is dict for a in assets)
         and [a.get('kind') for a in assets] == ['records', 'strings'], 'storage-source-assets')
    prefix, blocks = storage_regions(receipt.get('profile'), receipt.get('strings'), receipt.get('sections'),
                                    receipt.get('modes'), receipt.get('nativeTables'),
                                    {a['kind']: a.get('path') for a in assets})
    text = source.decode('ascii'); intervals = []
    expected = [prefix] + [blocks[s['name']] for s in receipt['sections']]
    previous = -1
    for value in expected:
        begin = value.split('\n', 1)[0] + '\n'
        end = value.rsplit('\n', 2)[-2] + '\n'
        need(text.count(begin) == 1 and text.count(end) == 1, 'storage-region-roster')
        start = text.index(begin); stop = text.index(end, start) + len(end)
        need(start > previous and (start == 0 or text[start - 1] == '\n')
             and text[start:stop] == value, 'storage-region-exact')
        intervals.append((start, stop)); previous = stop - 1
    result = []; previous = 0
    for start, stop in intervals:
        result.append(text[previous:start]); previous = stop
    result.append(text[previous:]); cleaned = ''.join(result)
    need('MRK_CATALOGUE_' not in cleaned, 'storage-unknown-region')
    return cleaned.encode('ascii')


def convert(source, profile, sink, *, asset_sink):
    """Generate tentative wrappers/packs from exact owner-bound emitted SOURCE.

    No input asset is opened: headers remain byte-identical references in SOURCE.
    The caller retains their exact originals and combines all output accounting.
    """
    need(profile in PROFILES and callable(sink) and callable(asset_sink), "conversion-arguments")
    # Retain bounded row text, not every nested expression dictionary at once.
    # Each pass decodes one row and discards it before advancing.
    text, sections = source_sections(source, parsed=False)
    header_matches = list(re.finditer(r"^const (CAT_H[0-9]+_(?:PREFIX|COMMANDS)): &\[u8\] = CAT_HEADER_BYTES\.split_at\(([0-9]+)\)\.1\.split_at\(([0-9]+)\)\.0;$", text, re.MULTILINE))
    headers = {m[1]: (int(m[2]), int(m[3])) for m in header_matches}
    need(len(headers) == len(header_matches) and len(headers) <= 256 and len(headers) % 2 == 0, "conversion-headers")
    modes = set()
    strings = {""}

    def collect(value):
        if type(value) is str: strings.add(value)
        elif type(value) is list:
            for item in value: collect(item)
        elif type(value) is dict:
            if set(value) == {"name"}: return
            if "fields" in value:
                for item in value["fields"].values(): collect(item)
            if "args" in value: collect(value["args"])
            if "array" in value: collect(value["array"])

    for section in sections:
        for raw_row in section['rows']: collect(expression(raw_row))
        if section['kind'] == 2:
            for raw_row in section['rows']:
                row = expression(raw_row)
                value = fields(row, "SourceMemberSpec", "group relative kind")["kind"]["fields"]["modes"]
                need(type(value) is dict and set(value) == {"array"}, "source-modes-array")
                mode = tuple(value["array"])
                need(0 < len(mode) <= 4 and all(type(v) is int and 0 <= v <= 0o777 for v in mode)
                     and tuple(sorted(set(mode))) == mode, "source-modes")
                modes.add(mode)
    strings = sorted(strings); modes = sorted(modes)
    need(len(strings) <= MAX_STRINGS and len(modes) <= 16, "conversion-pools")
    string_ids = {s: i for i, s in enumerate(strings)}
    mode_ids = {m: i for i, m in enumerate(modes)}
    native_names = [s['name'] for s in sorted(sections, key=lambda s: (s['kind'], s['index'])) if s['kind'] == 6]

    def string(value):
        need(type(value) is str and value in string_ids, "record-string")
        return string_ids[value]

    def header(value):
        h = fields(value, "NativeHeader", "prefix commands")
        names = []
        for key in ("prefix", "commands"):
            need(type(h[key]) is dict and set(h[key]) == {"name"} and h[key]['name'] in headers, "record-header-name")
            names.append(h[key]['name'])
        need(names[0].endswith('_PREFIX') and names[1] == names[0][:-7] + '_COMMANDS', "record-header-pair")
        return (*headers[names[0]], *headers[names[1]])

    def encode(kind, row):
        if kind == 1:
            r = fields(row, 'OfficialMember', 'name kind disposition'); k = r['kind']; d = r['disposition']
            name = string(r['name']); asset = source = size = sha = target = 0
            if k['name'] == 'ArchiveKind::Directory':
                v = fields(k, k['name'], 'mode'); tag = 0
            elif k['name'] == 'ArchiveKind::File':
                v = fields(k, k['name'], 'mode bytes sha256'); tag = 1; size = uint(v['bytes'], 64); sha = string(v['sha256'])
            else:
                v = fields(k, 'ArchiveKind::Alias', 'mode target'); tag = 2; target = string(v['target'])
            if d['name'] == 'ArchiveDisposition::Picked':
                disposition = 0; source = uint(fields(d, d['name'], 'source_index')['source_index'])
            elif d['name'] == 'ArchiveDisposition::SealedSupport':
                disposition = 1; asset = named(call(d, d['name'], 1)[0], 'SupportAsset::', ASSETS)
            else:
                need(d == {'name': 'ArchiveDisposition::WrapperDirectory'}, 'archive-disposition'); disposition = 2
            return struct.pack('<IBBBBIIQII', name, tag, disposition, asset, 0, uint(v['mode']), source, size, sha, target)
        if kind == 2:
            r = fields(row, 'SourceMemberSpec', 'group relative kind'); k = r['kind']; size = sha = target = canonical_id = 0
            if k['name'] == 'SourceKindSpec::Directory':
                v = fields(k, k['name'], 'modes'); tag = 0
            elif k['name'] == 'SourceKindSpec::File':
                v = fields(k, k['name'], 'bytes sha256 modes'); tag = 1; size = uint(v['bytes'], 64); sha = string(v['sha256'])
            else:
                v = fields(k, 'SourceKindSpec::Alias', 'target canonical modes'); tag = 2
                target = string(v['target']); canonical_id = string(v['canonical'])
            return struct.pack('<BBHIQIIII', named(r['group'], 'SourceGroup::', GROUPS), tag, 0,
                               string(r['relative']), size, sha, target, canonical_id, mode_ids[tuple(v['modes']['array'])])
        if kind == 3:
            r = fields(row, 'SourceBinding', 'provenance disposition'); p = r['provenance']; d = r['disposition']
            member = prefix = ordinal = 0
            if p['name'] == 'SourceProvenance::Vendor':
                v = fields(p, p['name'], 'archive member'); tag = 0; member = uint(v['member'])
            else:
                v = fields(p, 'SourceProvenance::ArchiveParent', 'archive prefix'); tag = 1; prefix = string(v['prefix'])
            if d == {'name': 'SourceDisposition::Directory'}: disposition = 2
            else:
                need(d['name'] in ('SourceDisposition::Payload', 'SourceDisposition::Alias'), 'source-disposition')
                disposition = 0 if d['name'].endswith('Payload') else 1; ordinal = uint(call(d, d['name'], 1)[0])
            return struct.pack('<BBBBIII', tag, uint(v['archive'], 8), disposition, 0, member, ordinal, prefix)
        if kind == 4:
            r = fields(row, 'PayloadSource', 'installed origin'); f = fields(r['installed'], 'CanonicalFile', 'path size sha256 mode')
            origin = r['origin']; group = asset = metadata = relative = archive_sha = archive_bytes = member = 0
            if origin['name'] == 'PayloadOrigin::DirectOriginal':
                direct = call(origin, origin['name'], 1)[0]
                if direct['name'] == 'OriginalSource::Picked':
                    v = fields(direct, direct['name'], 'group relative'); tag = 0
                    group = named(v['group'], 'SourceGroup::', GROUPS); relative = string(v['relative'])
                else:
                    tag = 1; asset = named(call(direct, 'OriginalSource::Support', 1)[0], 'SupportAsset::', ASSETS)
            elif origin['name'] == 'PayloadOrigin::CompiledSdkMetadata':
                tag = 2; metadata = named(call(origin, origin['name'], 1)[0], 'SdkMetadataKind::', METADATA)
            else:
                v = fields(origin, 'PayloadOrigin::MemberOfSameOriginalArchive', 'asset archive member'); tag = 3
                asset = named(v['asset'], 'SupportAsset::', ASSETS)
                a = fields(v['archive'], 'ArchivePin', 'bytes sha256'); archive_bytes = uint(a['bytes'], 64); archive_sha = string(a['sha256'])
                need(v['member'] == {'name': 'CAT_PROJECTED'}, 'payload-projected-member')
            return struct.pack('<IIQIBBBBIIQII', string(f['path']), uint(f['mode']), uint(f['size'], 64), string(f['sha256']),
                               tag, group, asset, metadata, relative, archive_sha, archive_bytes, member, 0)
        if kind == 5:
            name = row['name']; need(name.startswith('FileClass::') and name[11:] in CLASSES, 'file-class')
            tag = CLASSES.index(name[11:]); sdk = nested = 0; h = (0, 0, 0, 0)
            if tag < 5: need(row == {'name': name}, 'plain-file-class')
            elif tag == 5: sdk = named(call(row, name, 1)[0], 'policy::Sdk35File::', SDK)
            elif tag == 6:
                args = call(row, name, 2); sdk = named(args[0], 'policy::Sdk35File::', SDK); h = header(args[1])
            elif tag == 7: h = header(call(row, name, 1)[0])
            else:
                value = fields(row, name, 'native_members')['native_members']
                if value != {'array': []}:
                    need(value.get('name') in native_names and set(value) == {'name'}, 'class-native-slice')
                    nested = native_names.index(value['name']) + 1
            return struct.pack('<BBHI4I', tag, sdk, 0, nested, *h)
        if kind == 6:
            r = fields(row, 'NestedNative', 'member bytes sha256 mode kind header'); present = 0; h = (0, 0, 0, 0)
            if r['header'] != {'name': 'None'}: present = 1; h = header(call(r['header'], 'Some', 1)[0])
            return struct.pack('<IIQIBBH4I', string(r['member']), uint(r['mode']), uint(r['bytes'], 64), string(r['sha256']),
                               named(r['kind'], 'NativeResourceKind::', NATIVE), present, 0, *h)
        if kind == 7:
            r = fields(row, 'CanonicalAlias', 'path target canonical source_index')
            return struct.pack('<4I', string(r['path']), string(r['target']), string(r['canonical']), uint(r['source_index']))
        need(kind == 8, 'record-kind')
        return struct.pack('<I', string(row))

    encoded = []
    for section in sorted(sections, key=lambda s: (s['kind'], s['index'])):
        data = bytearray(); tuple_hash = hashlib.sha256(b'[')
        for index, raw_row in enumerate(section['rows']):
            row = expression(raw_row)
            if index: tuple_hash.update(b',')
            tuple_hash.update(canonical(row))
            raw = encode(section['kind'], row)
            need(len(raw) == STRIDES[section['kind']] and len(data) + len(raw) <= LIMIT, 'record-stride-bound')
            data.extend(raw)
        tuple_hash.update(b']'); section['tupleSha256'] = tuple_hash.hexdigest()
        encoded.append((section, bytes(data)))
    directory_bytes = 24 + 20 * len(encoded); offset = directory_bytes
    records = bytearray(b'MRKTBL01' + struct.pack('<IIII', PROFILES[profile], len(encoded), directory_bytes, 0))
    for section, raw in encoded:
        records.extend(struct.pack('<BBHIIII', section['kind'], 0, section['index'], STRIDES[section['kind']],
                                   len(section['rows']), offset, len(raw)))
        offset += len(raw)
    for _, raw in encoded: records.extend(raw)
    pool = bytearray(); offsets = [0]
    for value in strings:
        pool.extend(value.encode('ascii')); offsets.append(len(pool))
    string_bytes = (b'MRKSTR01' + struct.pack('<II', PROFILES[profile], len(strings))
                    + struct.pack('<' + 'I' * len(offsets), *offsets) + pool)
    need(len(records) + len(string_bytes) <= LIMIT, 'packed-output-bound')
    assets = []
    for kind, raw in (('records', bytes(records)), ('strings', bytes(string_bytes))):
        sha = hashlib.sha256(raw).hexdigest()
        path = f'android_supplier_macos_catalogue_assets/{profile}_{kind}_{sha}.bin'
        assets.append({'kind': kind, 'path': path, 'bytes': len(raw), 'sha256': sha})
    names = {a['kind']: a['path'] for a in assets}
    source_meta = [{'name': s['name'], 'kind': s['kind'], 'index': s['index'], 'count': len(s['rows'])}
                   for s in sections]
    prefix, regions = storage_regions(profile, len(strings), source_meta, modes, native_names, names)
    output = []; previous = 0
    for section in sections:
        output.append(text[previous:section['start']])
        if previous == 0: output.append(prefix)
        output.append(regions[section['name']])
        previous = section['end']
    output.append(text[previous:]); output = ''.join(output).encode('ascii')
    header_extent = max((a + b for a, b in headers.values()), default=0)
    need(len(output) + len(records) + len(string_bytes) + header_extent <= LIMIT
         and len(output) + len(records) + len(string_bytes) <= len(source), 'combined-output-bound')
    for asset, raw in zip(assets, (bytes(records), bytes(string_bytes))):
        for at in range(0, len(raw), CHUNK): asset_sink(asset['path'], at, raw[at:at + CHUNK])
    for at in range(0, len(output), CHUNK): sink(output[at:at + CHUNK])
    return {'schemaVersion': 1, 'profile': profile, 'source': {'bytes': len(output), 'sha256': hashlib.sha256(output).hexdigest()},
            'before': {'bytes': len(source), 'sha256': hashlib.sha256(source).hexdigest()}, 'assets': assets,
            'sections': [{'name': s['name'], 'kind': s['kind'], 'index': s['index'], 'count': len(s['rows']),
                          'stride': STRIDES[s['kind']], 'tupleSha256': s['tupleSha256']} for s in sections],
            'strings': len(strings), 'modes': [list(m) for m in modes], 'nativeTables': native_names,
            'nativeExecuted': False, 'supplierAuthority': False}


def string_pool(raw, profile):
    """Closed independent DATA reader for the exact string-section format."""
    need(type(raw) is bytes and 20 <= len(raw) <= LIMIT and raw[:8] == b'MRKSTR01'
         and profile in PROFILES, 'strings-header')
    tag, count = struct.unpack_from('<II', raw, 8)
    need(tag == PROFILES[profile] and 0 < count <= MAX_STRINGS, 'strings-profile-count')
    base = 16 + (count + 1) * 4
    need(base <= len(raw), 'strings-directory')
    offsets = struct.unpack_from('<' + 'I' * (count + 1), raw, 16)
    need(offsets[0] == offsets[1] == 0 and offsets[-1] == len(raw) - base, 'strings-extent')
    result = []
    for index in range(count):
        start, end = offsets[index:index + 2]
        need(start <= end <= len(raw) - base and end - start <= 2048, 'string-range')
        try: value = raw[base + start:base + end].decode('utf-8', 'strict')
        except UnicodeError as error: raise Refused('string-utf8') from error
        need(not result or result[-1].encode('utf-8') < value.encode('utf-8'), 'string-order')
        result.append(value)
    return result


def record_sections(raw, profile):
    """Closed rows are borrowed as memoryviews; no unbounded row graph."""
    need(type(raw) is bytes and 24 <= len(raw) <= LIMIT and raw[:8] == b'MRKTBL01'
         and profile in PROFILES, 'records-header')
    tag, count, next_offset, reserved = struct.unpack_from('<IIII', raw, 8)
    need(tag == PROFILES[profile] and 12 <= count <= MAX_SECTIONS and reserved == 0
         and next_offset == 24 + 20 * count and next_offset <= len(raw), 'records-directory')
    result = []; previous = (0, 0); total_rows = 0
    for index in range(count):
        kind, reserved, ordinal, stride, rows, offset, size = struct.unpack_from('<BBHIIII', raw, 24 + 20 * index)
        need(reserved == 0 and kind in STRIDES and (kind, ordinal) > previous
             and stride == STRIDES[kind] and rows <= 32768 and (kind != 6 or rows <= 128)
             and (ordinal < 6 if kind == 1 else ordinal < 32768 if kind == 6 else ordinal == 0), 'record-section')
        need(offset == next_offset and size == rows * stride and size <= len(raw) - offset, 'record-section-extent')
        total_rows += rows
        need(total_rows <= 8 * 32768 + 128 * 128, 'record-total-rows')
        result.append((kind, ordinal, rows, memoryview(raw)[offset:offset + size]))
        next_offset += size; previous = kind, ordinal
    need(next_offset == len(raw) and {s[0] for s in result} == set(STRIDES)
         and {s[1] for s in result if s[0] == 1} == set(range(6)), 'records-complete')
    return result


def decoded_rows(kind, data, strings, modes, native_names, headers):
    """Bounded iterator returns the same closed expression tuples as SOURCE.

    Tests compare every tuple. The live preparation reader consumes only its
    selected source-member tuples and retains its existing roster allocation.
    """
    need(kind in STRIDES and len(data) % STRIDES[kind] == 0, 'decode-stride')

    def name(value): return {'name': value}
    def obj(value, **items): return {'name': value, 'fields': items}
    def invoke(value, *items): return {'name': value, 'args': list(items)}
    def enum(prefix, choices, tag):
        need(0 <= tag < len(choices), 'decode-tag'); return name(prefix + choices[tag])
    def text(index):
        need(0 <= index < len(strings), 'decode-string'); return strings[index]
    def empty(*values): need(not any(values), 'decode-reserved')
    reverse_headers = {}
    for key, extent in headers.items(): reverse_headers.setdefault(tuple(extent), []).append(key)

    def snapshot(values):
        prefix, plen, command, clen = values
        need(0 < plen <= 4096 and 32 <= clen <= 16416, 'decode-header-range')
        candidates = reverse_headers.get((prefix, plen), [])
        pairs = [(n, n[:-7] + '_COMMANDS') for n in candidates if n.endswith('_PREFIX')
                 and headers.get(n[:-7] + '_COMMANDS') == (command, clen)]
        need(len(pairs) == 1, 'decode-header-pair')
        return obj('NativeHeader', prefix=name(pairs[0][0]), commands=name(pairs[0][1]))

    for at in range(0, len(data), STRIDES[kind]):
        row = data[at:at + STRIDES[kind]]
        if kind == 1:
            n, tag, disposition, asset, reserved, mode, source, size, sha, target = struct.unpack('<IBBBBIIQII', row)
            empty(reserved)
            if tag == 0: empty(size, sha, target); k = obj('ArchiveKind::Directory', mode=mode)
            elif tag == 1: empty(target); k = obj('ArchiveKind::File', mode=mode, bytes=size, sha256=text(sha))
            else:
                need(tag == 2, 'decode-archive-kind'); empty(size, sha); k = obj('ArchiveKind::Alias', mode=mode, target=text(target))
            if disposition == 0: empty(asset); d = obj('ArchiveDisposition::Picked', source_index=source)
            elif disposition == 1: empty(source); d = invoke('ArchiveDisposition::SealedSupport', enum('SupportAsset::', ASSETS, asset))
            else:
                need(disposition == 2, 'decode-archive-disposition'); empty(asset, source); d = name('ArchiveDisposition::WrapperDirectory')
            yield obj('OfficialMember', name=text(n), kind=k, disposition=d)
        elif kind == 2:
            group, tag, reserved, relative, size, sha, target, canonical_id, mode = struct.unpack('<BBHIQIIII', row)
            empty(reserved); need(mode < len(modes), 'decode-mode-index'); values = modes[mode]
            need(0 < len(values) <= 4 and list(values) == sorted(set(values)) and all(type(v) is int and 0 <= v <= 0o777 for v in values), 'decode-modes')
            mode_array = {'array': list(values)}
            if tag == 0: empty(size, sha, target, canonical_id); k = obj('SourceKindSpec::Directory', modes=mode_array)
            elif tag == 1: empty(target, canonical_id); k = obj('SourceKindSpec::File', bytes=size, sha256=text(sha), modes=mode_array)
            else:
                need(tag == 2, 'decode-source-kind'); empty(size, sha)
                k = obj('SourceKindSpec::Alias', target=text(target), canonical=text(canonical_id), modes=mode_array)
            yield obj('SourceMemberSpec', group=enum('SourceGroup::', GROUPS, group), relative=text(relative), kind=k)
        elif kind == 3:
            tag, archive, disposition, reserved, member, ordinal, prefix = struct.unpack('<BBBBIII', row)
            empty(reserved); need(archive < 6, 'decode-binding-archive')
            if tag == 0: empty(prefix); p = obj('SourceProvenance::Vendor', archive=archive, member=member)
            else:
                need(tag == 1, 'decode-provenance'); empty(member); p = obj('SourceProvenance::ArchiveParent', archive=archive, prefix=text(prefix))
            if disposition < 2: d = invoke('SourceDisposition::' + ('Payload', 'Alias')[disposition], ordinal)
            else:
                need(disposition == 2, 'decode-source-disposition'); empty(ordinal); d = name('SourceDisposition::Directory')
            yield obj('SourceBinding', provenance=p, disposition=d)
        elif kind == 4:
            path, mode, size, sha, tag, group, asset, metadata, relative, archive_sha, archive_size, member, reserved = struct.unpack('<IIQIBBBBIIQII', row)
            empty(member, reserved)
            if tag == 0:
                empty(asset, metadata, archive_sha, archive_size)
                origin = invoke('PayloadOrigin::DirectOriginal', obj('OriginalSource::Picked', group=enum('SourceGroup::', GROUPS, group), relative=text(relative)))
            elif tag == 1:
                empty(group, metadata, relative, archive_sha, archive_size)
                origin = invoke('PayloadOrigin::DirectOriginal', invoke('OriginalSource::Support', enum('SupportAsset::', ASSETS, asset)))
            elif tag == 2:
                empty(group, asset, relative, archive_sha, archive_size)
                origin = invoke('PayloadOrigin::CompiledSdkMetadata', enum('SdkMetadataKind::', METADATA, metadata))
            else:
                need(tag == 3, 'decode-payload-origin'); empty(group, metadata, relative)
                origin = obj('PayloadOrigin::MemberOfSameOriginalArchive', asset=enum('SupportAsset::', ASSETS, asset),
                             archive=obj('ArchivePin', bytes=archive_size, sha256=text(archive_sha)), member=name('CAT_PROJECTED'))
            yield obj('PayloadSource', installed=obj('CanonicalFile', path=text(path), size=size, sha256=text(sha), mode=mode), origin=origin)
        elif kind == 5:
            tag, sdk, reserved, native, *h = struct.unpack('<BBHI4I', row); empty(reserved)
            need(tag < len(CLASSES), 'decode-file-class'); n = 'FileClass::' + CLASSES[tag]
            if tag < 5: empty(sdk, native, *h); value = name(n)
            elif tag == 5: empty(native, *h); value = invoke(n, enum('policy::Sdk35File::', SDK, sdk))
            elif tag == 6: empty(native); value = invoke(n, enum('policy::Sdk35File::', SDK, sdk), snapshot(h))
            elif tag == 7: empty(sdk, native); value = invoke(n, snapshot(h))
            else:
                empty(sdk, *h); need(native <= len(native_names), 'decode-nested-index')
                value = obj(n, native_members=name(native_names[native - 1]) if native else {'array': []})
            yield value
        elif kind == 6:
            member, mode, size, sha, tag, present, reserved, *h = struct.unpack('<IIQIBBH4I', row); empty(reserved)
            need(present in (0, 1), 'decode-optional-header')
            if not present: empty(*h)
            yield obj('NestedNative', member=text(member), bytes=size, sha256=text(sha), mode=mode,
                      kind=enum('NativeResourceKind::', NATIVE, tag), header=invoke('Some', snapshot(h)) if present else name('None'))
        elif kind == 7:
            path, target, canonical_id, source = struct.unpack('<4I', row)
            yield obj('CanonicalAlias', path=text(path), target=text(target), canonical=text(canonical_id), source_index=source)
        else:
            yield text(struct.unpack('<I', row)[0])

# Fixed pure source-pin replacements. The external output owner supplies held
# originals and the real convert() results, owns every sink/close, and separately
# checks all raw assets. No caller JSON is a generation or installer admission.
_PIN_INPUTS = {
    'desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift': '034bf85757363d4e9ca9fb7e961846fe10b1d7e7c508b4e702081766e1b4d3ab',
    'desktop/tools/macos_normal_ui_runner.py': '200a5fd6298fbbc0e0d26e89e0ce91fb0084dd998972ad13134e0adb638ace75',
    'desktop/tools/macos_android_dependency_preparation.py': 'f7923f3006dfc5a5941055d2373bc14cfcc0065f3c3aff99183986d31171e160',
    'docs/desktop-macos-android-catalogue-storage.json': '010413e90c30f0144c713b5c1a18b7981662e9f620c78eb36a345521eee80dec',
    'tests/desktop/test_macos_android_dependency_preparation_source.py': '8ea0495efb828a090c49f8065d3f2830df345d4e3e39f40b0182a2f7070b701b',
}
_OLD_WRAPPERS = {
    'arm64': (722777, '694c605669a185d44feb53c09946eaac5ba4753554ce7d27c500554b922704d9'),
    'x86_64': (723059, '0d07a164c24d28661038482649e4ee3c453158088c7db5b35a3274c1487cfc12'),
}


def emit_updated_source_pins(originals, wrappers, receipts, sink):
    """Tentative exact five-consumer replacements after real wrapper emission."""
    need(type(originals) is dict and set(originals) == set(_PIN_INPUTS)
         and type(wrappers) is dict and set(wrappers) == set(PROFILES)
         and type(receipts) is dict and set(receipts) == set(PROFILES) and callable(sink), 'source-pin-inputs')
    for path, expected in _PIN_INPUTS.items():
        raw = originals[path]
        need(type(raw) is bytes and len(raw) <= 1 << 20 and hashlib.sha256(raw).hexdigest() == expected,
             'source-pin-original')
    document_path = 'docs/desktop-macos-android-catalogue-storage.json'
    document = json.loads(originals[document_path])
    need(document.get('schemaVersion') == 2 and len(document['catalogues']) == 2, 'source-pin-manifest')
    new = {}
    for profile in PROFILES:
        raw, receipt = wrappers[profile], receipts[profile]
        need(type(raw) is bytes and len(raw) <= LIMIT and type(receipt) is dict and receipt.get('profile') == profile,
             'source-pin-wrapper')
        pin = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        need(receipt.get('source') == pin, 'source-pin-real-output')
        entries = [row for row in document['catalogues'] if row['profile'] == profile]
        need(len(entries) == 1, 'source-pin-profile')
        entry = entries[0]; old = entry['output']['typedTables']
        need({k: v for k, v in receipt.items() if k != 'source'} == {k: v for k, v in old.items() if k != 'source'},
             'source-pin-preserved-tuples-and-assets')
        need(hashlib.sha256(unchanged_source_regions(raw, receipt)).hexdigest() == entry['unchangedSourceRegionsSha256'],
             'source-pin-unchanged-regions')
        entry['output']['bytes'] = pin['bytes']; entry['output']['sha256'] = pin['sha256']
        entry['output']['typedTables'] = receipt
        new[profile] = pin
    outputs = {}
    for path, raw in originals.items():
        if path == document_path:
            outputs[path] = (json.dumps(document, indent=2, sort_keys=True) + '\n').encode(); continue
        value = raw
        for profile, (old_size, old_hash) in _OLD_WRAPPERS.items():
            pin = new[profile]; old = old_hash.encode(); replacement = pin['sha256'].encode()
            need(value.count(old) == 1, 'source-pin-hash-site')
            if path == 'desktop/tools/macos_android_dependency_preparation.py':
                before = f"[{old_size}, '{old_hash}']".encode()
                after = f"[{pin['bytes']}, '{pin['sha256']}']".encode()
                need(value.count(before) == 1, 'source-pin-size-site'); value = value.replace(before, after)
            elif path == 'tests/desktop/test_macos_android_dependency_preparation_source.py':
                label = "('aarch64-apple-darwin','arm64','ARM64'," if profile == 'arm64' else "('x86_64-apple-darwin','x86_64','X64',"
                before = (label + str(old_size) + ',').encode(); after = (label + str(pin['bytes']) + ',').encode()
                need(value.count(before) == 1, 'source-pin-test-size-site'); value = value.replace(before, after).replace(old, replacement)
            else:
                value = value.replace(old, replacement)
        outputs[path] = value
    need(sum(map(len, outputs.values())) <= sum(map(len, originals.values())) + 32768, 'source-pin-output-bound')
    for path in sorted(outputs):
        raw = outputs[path]
        for at in range(0, len(raw), CHUNK): sink(path, at, raw[at:at + CHUNK])
    return [{'path': path, 'bytes': len(outputs[path]), 'sha256': hashlib.sha256(outputs[path]).hexdigest()}
            for path in sorted(outputs)]
