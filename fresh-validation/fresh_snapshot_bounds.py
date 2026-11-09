"""Pure DATA quote for the fixed first-frame torn control, not native admission.

Caller must bind a separately authenticated final inventory/package/producer.
This module neither opens a protected path nor executes product code.
"""
import hashlib
import json

ENTRY_FRAME_MAX = 2048 + 4
CONTROL_FILE_MAX = 16 * 1024
PATH_MAX = 1024 + len('.install-' + 'f' * 32 + '/')
GATE_BYTES = (b'MRK-MACOS-REGISTRATION-RESERVATION-v1\n',
              b'MRK-MACOS-MAINTENANCE-GATE-v1\n')


def quote_for_depth(directory_count, metadata_source_bytes):
    if type(directory_count) is not int or not 2 <= directory_count <= 16:
        raise ValueError('first-app-directory-depth')
    if type(metadata_source_bytes) is not int or not 0 < metadata_source_bytes <= 128 * 1024:
        raise ValueError('metadata-source-size')
    # root, versions, stage; D payload directories; seven files including the
    # empty first payload. Runtime/release/launcher publication has not begun.
    nodes = directory_count + 10
    journal = (directory_count + 1) * ENTRY_FRAME_MAX + 1
    gates = sum(map(len, GATE_BYTES))
    # Gate contents are read once for locks and once by the full tree walk.
    logical = 2 * gates + 3 * CONTROL_FILE_MAX + journal
    # At most nine private leaf reads including duplicate gates, plus the one
    # empty public request export. EOF probes and metadata source are charged.
    requested = 2 * logical + metadata_source_bytes + 1 + 10
    # Five OS ancestor originals, duplicate gate readers and one bound export.
    originals = nodes + 5 + 2 + 1
    # Conservative JSON upper bound: each row's scalar/native structure <=1KiB;
    # path and child-name Unicode escape growth <=6/UTF8 byte. Every private
    # edge is charged once in a parent's names. Final envelope/binding <=4KiB.
    row_max = 1024 + 6 * PATH_MAX + 6 * 255 + 4
    output = nodes * row_max + 2048 + 4096
    if output > 256 * 1024 or originals + 4 > 64:
        raise ValueError('existing-snapshot-envelope')
    return {
        'maxNodes': nodes,
        'maxDepth': directory_count + 1,
        'maxLogicalBytes': logical,
        'maxFileBytes': max(CONTROL_FILE_MAX, journal),
        'maxRequestedReadBytes': requested,
        'maxLiveOriginals': originals,
        'maxOutputBytes': output,
    }


def derive_inventory(raw, metadata_source_bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= 12 * 1024 * 1024:
        raise ValueError('inventory-byte-bound')
    data = json.loads(raw)
    rows = data.get('files')
    if type(rows) is not list or not rows or len(rows) > 16384 - 3:
        raise ValueError('inventory-row-bound')
    paths = []
    for row in rows:
        path = row.get('path')
        if (type(path) is not str or not path.isascii() or len(path) > 1024
                or not path.startswith(('app/Contents/', 'runtime/')) or '\0' in path
                or any(not part or part in ('.', '..') for part in path.split('/'))):
            raise ValueError('inventory-path')
        if path.startswith('app/') and len(path.split('/')) > 17:
            raise ValueError('app-depth')
        if path.startswith('runtime/') and len(path.split('/')) > 18:
            raise ValueError('runtime-depth')
        paths.append(path)
    if paths != sorted(set(paths)) or 'app/Contents/Info.plist' not in paths:
        raise ValueError('inventory-order-or-required-file')
    files = set(paths)
    directories = {'app', 'runtime'}
    children = {}
    for path in paths:
        parts = path.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            child = parts[i]
            directories.add(parent)
            children.setdefault(parent, set()).add(child)
    if files & directories:
        raise ValueError('file-directory-collision')
    visited = []

    def first_file(path):
        visited.append(path)
        for leaf in sorted(children[path]):
            child = path + '/' + leaf
            if child in files:
                return child
            found = first_file(child)
            if found:
                return found
        raise ValueError('empty-derived-app-directory')

    first = first_file('app')
    if visited != ['/'.join(first.split('/')[:i]) for i in range(1, len(first.split('/')))]:
        raise ValueError('unexpected-prior-empty-directory')
    return {
        'inventorySha256': hashlib.sha256(raw).hexdigest(),
        'inventoryBytes': len(raw),
        'inventoryFiles': len(paths),
        'firstPayloadPath': first,
        'visitedAppDirectories': visited,
        'directoryCount': len(visited),
        'firstPayloadBytesAtTornBoundary': 0,
        'privateDirectories': 3 + len(visited),
        'privateFiles': 7,
        'publicRequestExports': 1,
        'publicRequestExportBytes': 0,
        'bounds': quote_for_depth(len(visited), metadata_source_bytes),
        'nativeAuthority': False,
    }
