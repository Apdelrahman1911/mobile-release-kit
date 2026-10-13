import errno, json, os, re, stat

# Only fixed public OS DATA is provisioned on this disposable runner.
# Never runtime admission or arbitrary filesystem repair.
PREPARE_DIRS = (
    '/usr/share', '/etc/gtk-3.0', '/etc/fonts', '/etc/fonts/conf.d',
    '/usr/share/fontconfig', '/usr/share/fontconfig/conf.avail', '/usr/share/fonts',
    '/usr/local/share/fonts', '/var/cache/fontconfig',
    '/usr/share/glib-2.0', '/usr/share/glib-2.0/schemas',
    '/usr/share/glvnd', '/usr/share/glvnd/egl_vendor.d', '/etc/glvnd', '/etc/glvnd/egl_vendor.d',
    '/usr/share/drirc.d', '/usr/share/X11', '/usr/share/X11/xkb', '/usr/share/X11/locale',
    '/usr/share/icons', '/usr/share/icons/Adwaita', '/usr/share/icons/hicolor',
    '/usr/share/themes', '/usr/share/themes/Adwaita', '/usr/share/mime',
    '/usr/share/hunspell', '/usr/share/hyphen',
    '/usr/share/byobu', '/usr/share/byobu/pixmaps',
)
DATA_ROOTS = (
    ('/etc/gtk-3.0', 'directory'), ('/etc/fonts', 'directory'),
    ('/usr/share/fontconfig', 'directory'), ('/usr/share/fonts', 'directory'),
    ('/usr/local/share/fonts', 'directory'), ('/var/cache/fontconfig', 'directory'),
    ('/usr/share/glib-2.0/schemas', 'directory'),
    ('/usr/share/glvnd/egl_vendor.d', 'directory'), ('/etc/glvnd/egl_vendor.d', 'directory'),
    ('/usr/share/drirc.d', 'directory'), ('/etc/drirc', 'file'),
    ('/usr/share/X11/xkb', 'directory'), ('/usr/share/X11/locale', 'directory'),
    ('/usr/share/icons/Adwaita', 'directory'), ('/usr/share/icons/hicolor', 'directory'),
    ('/usr/share/themes/Adwaita', 'directory'), ('/usr/share/mime/mime.cache', 'file'),
    ('/usr/share/hunspell', 'directory'), ('/usr/share/hyphen', 'directory'),
    ('/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache', 'file'),
    ('/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache', 'file'),
    ('/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache', 'file'),
    ('/usr/share/byobu/pixmaps/byobu.svg', 'file'),
)
SCOPE = 'fixed-shell-data-directory-preparation'
ACL_REMOVAL = {kind: {'attempted': False, 'established': False, 'attemptedCount': 0, 'establishedCount': 0}
               for kind in ('access', 'default')}
ACL_ORIGINALS = {kind: set() for kind in ACL_REMOVAL}
_first_removal_refusal = None

def removal_receipt(all_states=False):
    return {kind + 'AclRemoval': dict(state) for kind, state in ACL_REMOVAL.items()
            if all_states or state['attempted']}


def need(ok, check, observed=None):
    global _first_removal_refusal
    if not ok:
        payload = {'scope': SCOPE, 'failedCheck': check, 'observed': observed}
        effects = removal_receipt()
        if effects:
            # Retain the first refusal if a later sole-close attempt also fails.
            if _first_removal_refusal is None:
                _first_removal_refusal = payload
            if check.endswith('close'):
                _first_removal_refusal['cleanupUnknown'] = True
            payload = {**_first_removal_refusal, **effects}
        diagnostic = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        if (len(diagnostic.encode('ascii')) > 2048 and isinstance(payload['observed'], dict)
                and any(key in payload['observed'] for key in ('defaultAclShape', 'accessAclShape'))):
            # An optional structure summary must never displace the first refusal.
            payload = {**payload, 'observed': {key: value for key, value in payload['observed'].items()
                                              if key not in ('defaultAclShape', 'accessAclShape')}}
            diagnostic = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        if len(diagnostic.encode('ascii')) > 2048 and effects:
            diagnostic = json.dumps({**payload, 'observed': None, 'truncated': True},
                                    sort_keys=True, separators=(',', ':'))
        print(diagnostic if len(diagnostic.encode('ascii')) <= 2048
              else 'Fixed directory preparation refused; diagnostic bound exceeded.', flush=True)
        raise SystemExit(70)

def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def record(s):
    return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid,
            'mode': format(s.st_mode, '06o'), 'nlink': s.st_nlink, 'size': s.st_size}

class XattrFailure(Exception):
    def __init__(self, path, item, phase, *, attribute='system.posix_acl_access',
                 result='binding-unproven', number=None, probe_performed=False,
                 binding_unknown=True, truncated=False):
        super().__init__('guarded-xattr')
        self.observed = {'path': path[:512], 'pathTruncated': len(path) > 512,
            'kind': 'directory' if stat.S_ISDIR(item.st_mode) else 'regular',
            'attribute': attribute, 'result': result,
            'errno': number if type(number) is int and 0 <= number <= 4095 else None,
            'original': list(identity(item)), 'phase': phase, 'complete': False,
            'truncated': truncated or len(path) > 512, 'cleanupUnknown': False,
            'bindingUnknown': binding_unknown, 'probePerformed': probe_performed}


def public_acl_scope(path, item):
    kind = 'directory' if stat.S_ISDIR(item.st_mode) else 'file' if stat.S_ISREG(item.st_mode) else None
    return kind is not None and (kind == 'directory' and path in PREPARE_DIRS or any(
        path == root and kind == root_kind or root_kind == 'directory' and path.startswith(root + '/')
        for root, root_kind in DATA_ROOTS))


def public_acl_eligible(path, item):
    mode = stat.S_IMODE(item.st_mode)
    return (item.st_dev == MOUNT_DEVICE and item.st_uid == item.st_gid == 0
            and item.st_mode == stat.S_IFMT(item.st_mode) | mode and public_acl_scope(path, item)
            and (stat.S_ISDIR(item.st_mode) and mode in (0o755, 0o775, 0o777)
                 or stat.S_ISREG(item.st_mode) and item.st_nlink == 1
                 and mode in (0o444, 0o644, 0o664, 0o666, 0o555, 0o755, 0o775, 0o777)))


def supported_access_acl(value, item):
    # Canonical v2, at most32 entries. Every masked non-owner class equals G,
    # and O must be a subset of G: removing named entries cannot add access.
    if (type(value) is not bytes or not 28 <= len(value) <= 260 or (len(value) - 4) % 8
            or value[:4] != b'\x02\0\0\0'):
        return False
    rows = [tuple(int.from_bytes(value[i + a:i + b], 'little') for a, b in ((0, 2), (2, 4), (4, 8)))
            for i in range(4, len(value), 8)]
    u, g, o = (item.st_mode >> shift & 7 for shift in (6, 3, 0))
    undefined, index, group, named = 0xffffffff, 1, None, False
    if rows[0] != (1, u, undefined) or o & ~g or any(row[1] > 7 for row in rows):
        return False
    for tag in (2, 4, 8):
        previous = -1
        while index < len(rows) and rows[index][0] == tag:
            _, permissions, principal = rows[index]
            if permissions & g != g:
                return False
            index += 1
            if tag == 4:
                if principal != undefined:
                    return False
                group = permissions
                break
            if principal == undefined or principal <= previous:
                return False
            previous, named = principal, True
        if tag == 4 and group is None:
            return False
    if index < len(rows) and rows[index][0] == 16:
        if rows[index] != (16, g, undefined):
            return False
        index += 1
    elif named or group != g:
        return False
    return index == len(rows) - 1 and rows[index] == (32, o, undefined)


def supported_public_acl(path, item, attribute, value):
    return public_acl_eligible(path, item) and (supported_access_acl(value, item)
        if attribute == 'system.posix_acl_access' else stat.S_ISDIR(item.st_mode)
        and attribute == 'system.posix_acl_default' and supported_default_acl(value))


def supported_default_acl(value):
    # Fixed disposable-host provisioning, not a general or monotonic ACL policy.
    return type(value) is bytes and (value in (
        bytes.fromhex('02000000 01000700ffffffff 04000700ffffffff 20000700ffffffff'),
        bytes.fromhex('02000000 01000700ffffffff 04000700ffffffff 10000700ffffffff 20000700ffffffff'),
    ) or len(value) == 44
        and value[:16] == bytes.fromhex('02000000 01000700ffffffff 02000700')
        and value[16:20] != b'\xff\xff\xff\xff'
        and value[20:] == bytes.fromhex('04000700ffffffff 10000700ffffffff 20000700ffffffff'))


def acl_shape(value):
    # Structural decoding only; no semantic ACL validity or removal authority.
    shape = {'byteLength': None, 'version2': None, 'aligned': False,
             'entryCount': None, 'entries': [], 'complete': False, 'reason': None}
    if type(value) is not bytes:
        shape['reason'] = 'not-bytes'
        return shape
    length = len(value)
    if length > 65536:
        shape['reason'] = 'byte-bound'
        return shape
    shape['byteLength'] = length
    if length < 4:
        shape['reason'] = 'header-short'
        return shape
    shape['version2'] = int.from_bytes(value[:4], 'little') == 2
    shape['aligned'] = (length - 4) % 8 == 0
    if shape['aligned']:
        shape['entryCount'] = (length - 4) // 8
    if not shape['aligned']:
        shape['reason'] = 'entry-alignment'
        return shape
    if not shape['version2']:
        shape['reason'] = 'version'
        return shape
    labels = {1: 'user-object', 2: 'user', 4: 'group-object',
              8: 'group', 16: 'mask', 32: 'other'}
    for offset in range(4, 4 + min(shape['entryCount'], 16) * 8, 8):
        tag = int.from_bytes(value[offset:offset + 2], 'little')
        permissions = int.from_bytes(value[offset + 2:offset + 4], 'little')
        undefined = int.from_bytes(value[offset + 4:offset + 8], 'little') == 0xffffffff
        shape['entries'].append([labels.get(tag, 'unknown'),
                                 permissions if permissions <= 7 else 'invalid',
                                 'undefined' if undefined else 'defined'])
    shape['complete'] = shape['entryCount'] <= 16
    shape['reason'] = None if shape['complete'] else 'entry-bound'
    return shape


def guarded_xattrs(fd, parent, name, path, item, phase, held=None, *, classify_acls=False):
    # fgetxattr requires an ordinary FD, not O_PATH. Query only the two
    # guarded names; successful empty bytes are still forbidden presence.
    def binding():
        try:
            same = (identity(os.fstat(fd)) == identity(item)
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            if held is not None:
                same = same and identity(os.fstat(held)) == identity(item)
            return same, None
        except OSError as error:
            return False, error.errno

    needed = [False, False]
    for index, attribute in enumerate(('system.posix_acl_access', 'system.posix_acl_default'
                                      if stat.S_ISDIR(item.st_mode) else 'security.capability')):
        kind = attribute.rsplit('_', 1)[-1]
        bound, number = binding()
        result, truncated, probe_performed, shape = None, False, False, None
        binding_unknown = not bound
        if not bound:
            result = 'binding-unproven'
        else:
            probe_performed = True
            try:
                value = os.getxattr(fd, attribute)
            except OSError as error:
                if error.errno != errno.ENODATA:
                    result, number = 'errno', error.errno
            else:
                # Only the no-effect DATA census may classify supported presence;
                # this is normalization-needed, never absence or runtime admission.
                if classify_acls and supported_public_acl(path, item, attribute, value):
                    needed[index] = True
                else:
                    result = 'present'
                    truncated = type(value) is not bytes or len(value) > 65536
                    if classify_acls and kind in ACL_REMOVAL and public_acl_scope(path, item):
                        shape = acl_shape(value)
                del value  # Never retain raw attribute bytes or principal IDs.
            bound, after_errno = binding()
            if not bound:
                binding_unknown = True
                if result is None:
                    result, number = 'binding-unproven', after_errno
        if result is not None:
            error = XattrFailure(path, item, phase, attribute=attribute, result=result, number=number,
                                 probe_performed=probe_performed, binding_unknown=binding_unknown,
                                 truncated=truncated)
            if shape is not None:
                error.observed[kind + 'AclShape'] = shape
            raise error
    return tuple(needed)


def changed_only(before, after, mode, gid):
    # chmod/chown may change ctime, never identity, link count, size or mtime.
    expected = list(identity(before))
    expected[2], expected[4], expected[-1] = stat.S_IFMT(before.st_mode) | mode, gid, after.st_ctime_ns
    return identity(after) == tuple(expected)

def mount_table():
    # The only content read in this preparer is fixed kernel mount metadata.
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read((1 << 20) + 1)
    need(0 < len(raw) <= 1 << 20 and raw.endswith(b'\n') and b'\0' not in raw,
         'mount-metadata-bound')
    return raw

def mount_scope(raw, device):
    roots, ids, points = [], set(), set()
    for line in raw.decode('ascii').splitlines():
        fields = line.split(' ')
        need(len(ids) < 4096 and all(fields) and fields.count('-') == 1, 'mount-grammar-bound')
        at = fields.index('-')
        need(at >= 6 and len(fields) == at + 4 and re.fullmatch(r'[1-9][0-9]{0,9}', fields[0])
             and fields[0] not in ids and re.fullmatch(r'[1-9][0-9]{0,9}', fields[1])
             and re.fullmatch(r'[0-9]{1,10}:[0-9]{1,10}', fields[2])
             and fields[5].split(',')[0] in {'ro', 'rw'}, 'mount-identity-options')
        ids.add(fields[0])
        decoded = []
        for path in fields[3:5]:
            need(path.startswith('/') and re.fullmatch(r'(?:[^\\\x00-\x20]|\\(?:040|011|012|134))+', path),
                 'mount-path-escape')
            decoded.append(re.sub(r'\\(040|011|012|134)', lambda found: chr(int(found[1], 8)), path))
        points.add(decoded[1])
        tags = set()
        for option in fields[6:at]:
            tag, separator, number = option.partition(':')
            need(tag not in tags and ((tag == 'unbindable' and not separator)
                 or (tag in {'shared', 'master', 'propagate_from'} and re.fullmatch(r'[1-9][0-9]{0,9}', number))),
                 'mount-propagation-or-idmap')
            tags.add(tag)
        if decoded[1] == '/':
            need(decoded[0] == '/' and fields[at + 1] in {'ext4', 'xfs'}
                 and tuple(int(part) for part in fields[2].split(':')) == (os.major(device), os.minor(device)),
                 'mount-root-device-filesystem')
            roots.append(int(fields[0]))
    need(len(roots) == 1, 'mount-root-ambiguous')
    # No mount may intercept a fixed target or a traversable DATA descendant.
    for target, subtree in [*((path, False) for path in PREPARE_DIRS),
                            *((path, kind == 'directory') for path, kind in DATA_ROOTS)]:
        need(not any(point != '/' and (target == point or target.startswith(point + '/')
                     or subtree and point.startswith(target + '/')) for point in points),
             'mounted-data-target', {'path': target})
    return points

def mount_unchanged():
    need(mount_table() == MOUNT_RAW, 'mount-table-changed')

def protected(s, path):
    need(stat.S_ISDIR(s.st_mode) and s.st_dev == MOUNT_DEVICE
         and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o7022,
         'protected-ancestor', {'path': path, **record(s)})

def prepare_public_acls(fd, parent, name, path, before, ancestors, prefix):
    # Original no-follow object; exact rooted custody, not a path-prefix grant.
    # Ancestors remain protected/ACL-free even when this target may change.
    parts = path.split('/')[1:]
    need(public_acl_scope(path, before) and path.startswith('/') and parts
         and all(part not in {'', '.', '..'} for part in parts)
         and [entry[3] for entry in ancestors] == [('/' + '/'.join(parts[:index]) if index else '/')
                                                   for index in range(len(parts))]
         and ancestors[0][1:3] == (None, '/') and name == parts[-1]
         and all(entry[1] == ancestors[index - 1][0] and entry[2] == parts[index - 1]
                 for index, entry in enumerate(ancestors) if index)
         and ancestors[-1][0] == parent and fd not in {entry[0] for entry in ancestors},
         'fixed-public-acl-target')
    for _, _, _, ancestor_path, expected in ancestors:
        protected(expected, ancestor_path)
    attributes = ('system.posix_acl_access', 'system.posix_acl_default'
                  if stat.S_ISDIR(before.st_mode) else 'security.capability')

    def failure(attribute, phase, *, result='binding-unproven', number=None,
                probe=False, unknown=True, truncated=False):
        return XattrFailure(path, before, phase, attribute=attribute,
                            result=result, number=number, probe_performed=probe,
                            binding_unknown=unknown, truncated=truncated)

    def binding(item, phase):
        try:
            for original, original_parent, original_name, ancestor_path, expected in ancestors:
                guarded_xattrs(original, original_parent, original_name, ancestor_path, expected, phase)
                if (identity(os.fstat(original)) != identity(expected)
                        or identity(os.stat(original_name, dir_fd=original_parent,
                                            follow_symlinks=False)) != identity(expected)):
                    return False, None, None
            bound = (identity(os.fstat(fd)) == identity(item)
                     == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            # Same fixed bounded kernel read and immutable mount baseline.
            with open('/proc/self/mountinfo', 'rb') as stream:
                bound = stream.read((1 << 20) + 1) == MOUNT_RAW and bound
            return bound, None, None
        except XattrFailure as error:
            return False, None, error
        except OSError as error:
            return False, error.errno, None

    def require_binding(item, phase, attribute):
        bound, number, first = binding(item, phase)
        if not bound:
            raise first or failure(attribute, phase, number=number)

    def query(item, attribute, phase, *, permit_supported=False, expected=None):
        require_binding(item, phase, attribute)
        value, error = None, None
        kind = attribute.rsplit('_', 1)[-1]
        try:
            value = os.getxattr(fd, attribute)
        except OSError as cause:
            if cause.errno != errno.ENODATA:
                error = failure(attribute, phase, result='errno', number=cause.errno, probe=True, unknown=False)
            elif expected is not None:
                error = failure(attribute, phase, result='errno', number=cause.errno, probe=True, unknown=False)
        else:
            allowed = (supported_public_acl(path, before, attribute, value) if permit_supported
                       else expected is not None and type(value) is bytes and value == expected)
            if not allowed:
                error = failure(attribute, phase, result='present', probe=True, unknown=False,
                                truncated=type(value) is not bytes or len(value) > 65536)
                if permit_supported and kind in ACL_REMOVAL:
                    error.observed[kind + 'AclShape'] = acl_shape(value)
                value = None  # Retain only qualified bounded buffers for exact peer checks.
        bound, number, first = binding(item, phase)
        if error is not None:
            error.observed['bindingUnknown'] = not bound
            raise error  # First query refusal survives later binding failure.
        if not bound:
            raise first or failure(attribute, phase, number=number, probe=True)
        return value

    phase = 'share-default-before' if path == '/usr/share' else prefix + '-before'
    # Qualify BOTH original attributes before any effect (capability must be absent).
    expected = {attribute: query(before, attribute, phase, permit_supported=True) for attribute in attributes}
    item, result = before, {}
    for kind in ('access', 'default') if stat.S_ISDIR(before.st_mode) else ('access',):
        attribute = 'system.posix_acl_' + kind
        result[kind + 'Acl'] = 'absent'
        if expected[attribute] is None:
            continue
        effect_prefix = ('share' if path == '/usr/share' else prefix) + '-' + kind
        phase = effect_prefix + '-remove'
        require_binding(item, phase, attribute)
        original_key, custody, state = (before.st_dev, before.st_ino), ACL_ORIGINALS[kind], ACL_REMOVAL[kind]
        need(original_key not in custody, kind + '-acl-removal-already-attempted')
        need(len(custody) < 32768, kind + '-acl-removal-attempt-bound')
        custody.add(original_key)  # Register per-attribute custody before its sole syscall.
        state['attempted'], state['established'] = True, False
        state['attemptedCount'] += 1
        try:
            os.removexattr(fd, attribute)  # Only the two fixed ACL names; never ENODATA-as-success.
        except OSError as error:
            raise failure(attribute, phase, result='errno', number=error.errno, probe=True) from None
        phase = effect_prefix + '-after'
        try:
            provisional = os.fstat(fd)
        except OSError as error:
            raise failure(attribute, phase, number=error.errno) from None
        if identity(provisional)[:-1] != identity(item)[:-1]:
            raise failure(attribute, phase)
        expected[attribute] = None
        # Provisional ctime only; removed attribute absent, peer buffer/absence unchanged.
        for other in (attribute, *(name for name in attributes if name != attribute)):
            query(provisional, other, phase, expected=expected[other])
        require_binding(provisional, phase, attribute)
        state['establishedCount'] += 1
        state['established'] = state['establishedCount'] == state['attemptedCount']
        item, result[kind + 'Acl'] = provisional, 'removed'
    return item, result


def prepare_directory(path):
    need(path in PREPARE_DIRS, 'fixed-target')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fds, originals, authority_failure = [], [], None

    def recheck(phase=None):
        for fd, parent, name, path, expected in originals:
            if phase is not None:
                guarded_xattrs(fd, parent, name, path, expected, phase)
            need(identity(os.fstat(fd)) == identity(expected)
                 == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'original-directory-changed')

    try:
        root = os.open('/', flags)
        fds.append(root)
        before = os.fstat(root)
        protected(before, '/')
        originals.append((root, None, '/', '/', before))
        recheck('prepare-before')
        parent, parts, current = root, path.split('/')[1:], ''
        for index, name in enumerate(parts):
            current += '/' + name
            try:
                fd = os.open(name, flags, dir_fd=parent)
            except FileNotFoundError:
                need(path != '/usr/share', 'required-share-directory')
                recheck()
                return {'path': path, 'absentAt': current}
            fds.append(fd)
            before = os.fstat(fd)
            need(identity(before) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'directory-name', {'path': current, **record(before)})
            if index + 1 == len(parts):
                # Ubuntu's fixed local font directory is root:staff 02775.
                # Only this exact original may have its group normalized;
                # all descendants/files and other groups remain excluded.
                local_fonts = (path == '/usr/local/share/fonts' and stat.S_ISDIR(before.st_mode)
                               and before.st_uid == 0 and before.st_gid == 50
                               and stat.S_IMODE(before.st_mode) == 0o2775)
                need(before.st_dev == MOUNT_DEVICE and (local_fonts or (stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                     and stat.S_IMODE(before.st_mode) in (0o755, 0o775, 0o777))),
                     'target-policy', {'path': current, **record(before)})
                expected, acl_status = prepare_public_acls(fd, parent, name, path, before, originals, 'prepare')
                originals.append((fd, parent, name, current, expected))
                recheck('prepare-before')
                mount_unchanged()
                if local_fonts:
                    os.fchown(fd, -1, 0)
                    grouped = os.fstat(fd)
                    need(changed_only(before, grouped, stat.S_IMODE(before.st_mode), 0),
                         'same-object-group-change')
                    originals[-1] = (fd, parent, name, current, grouped)
                    recheck('prepare-after-group')
                    mount_unchanged()
                if stat.S_IMODE(before.st_mode) != 0o755:
                    recheck('prepare-before')
                    mount_unchanged()
                    os.fchmod(fd, 0o755)
                after = os.fstat(fd)
                need(changed_only(before, after, 0o755, 0),
                     'same-object-mode-change')
                originals[-1] = (fd, parent, name, current, after)
                recheck('prepare-after-mode')
                mount_unchanged()
                return {'path': path, 'before': record(before), 'after': record(after),
                        **acl_status}
            protected(before, current)
            originals.append((fd, parent, name, current, before))
            guarded_xattrs(fd, parent, name, current, before, 'prepare-before')
            parent = fd
        need(False, 'missing-directory-target')
    except XattrFailure as error:
        authority_failure = error
        raise
    except OSError as error:
        if removal_receipt():
            need(False, 'preparation-os-error', {'path': path,
                 'errno': error.errno if type(error.errno) is int and 0 <= error.errno <= 4095 else None})
        raise
    finally:
        failed_close = False
        while fds:
            fd = fds.pop()
            try:
                os.close(fd)
            except OSError:
                failed_close = True
        if failed_close and authority_failure is not None:
            authority_failure.observed['cleanupUnknown'] = True
        else:
            need(not failed_close, 'original-directory-close')

def metadata_preflight(*, normalize=False):
    # Two finite passes: first diagnose unsupported objects without descendant
    # effects; only a fully supported scope may enter the normalization pass.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    count, unsafe_count, unsupported_count, changed_count, default_acl_count, access_acl_count = 0, 0, 0, 0, 0, 0
    unsafe, changed, fds, originals = [], [], [], []
    selected_links = []

    def bound(fd, parent, name, item):
        need(identity(os.fstat(fd)) == identity(item)
             == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
             'metadata-original-changed')

    def recheck(phase=None):
        for fd, parent, name, path, item in originals:
            if phase is not None:
                guarded_xattrs(fd, parent, name, path, item, phase)
            bound(fd, parent, name, item)

    def tighten(fd, parent, name, path, item, mode):
        nonlocal changed_count
        for ancestor, _, _, ancestor_path, before in originals[:-1]:
            protected(before, ancestor_path)
            protected(os.fstat(ancestor), ancestor_path)
        recheck('metadata-before')
        need(mode & ~stat.S_IMODE(item.st_mode) == 0, 'data-permission-addition')
        mount_unchanged()
        os.fchmod(fd, mode)
        after = os.fstat(fd)
        need(changed_only(item, after, mode, 0), 'same-data-object-mode-change')
        originals[-1] = (fd, parent, name, path, after)
        recheck('metadata-after')
        mount_unchanged()
        changed_count += 1
        if len(changed) < 64:
            changed.append({'path': path[:512], 'pathTruncated': len(path) > 512,
                            'before': record(item), 'after': record(after)})
        return after

    def visit(parent, name, path, depth, root_kind):
        nonlocal count, unsafe_count, unsupported_count, default_acl_count, access_acl_count
        count += 1
        need(count <= 32768 and depth <= 16, 'metadata-entry-depth-bound')
        try:
            item = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            need(depth == 0, 'metadata-member-disappeared')
            return
        link, directory, regular = stat.S_ISLNK(item.st_mode), stat.S_ISDIR(item.st_mode), stat.S_ISREG(item.st_mode)
        need(item.st_dev == MOUNT_DEVICE, 'metadata-device', {'path': path[:512], **record(item)})
        if depth == 0:
            need(directory if root_kind == 'directory' else regular or link,
                 'data-root-kind', {'path': path, **record(item)})
        if link:
            need(len(selected_links) < 4096, 'metadata-link-count-bound')
            selected_links.append((path, identity(item)))
        owned = item.st_uid == item.st_gid == 0
        single = directory or item.st_nlink == 1
        safe = (owned and single and (directory or regular or link)
                and (link or not item.st_mode & 0o7022)
                and (directory or link or not item.st_mode & 0o111))
        mode = stat.S_IMODE(item.st_mode)
        repairable = owned and single and (directory and mode in (0o775, 0o777)
            or regular and mode in (0o644, 0o664, 0o666, 0o555, 0o755, 0o775, 0o777))
        if normalize:
            need(safe or repairable, 'unsupported-data-before-effect', {'path': path[:512], **record(item)})
        fd, authority_failure = None, None
        try:
            if directory or regular:
                try:
                    fd = os.open(name, flags if directory else file_flags, dir_fd=parent)
                except OSError as error:
                    raise XattrFailure(path, item, 'metadata-before' if normalize else 'metadata-census',
                                       number=error.errno) from None
                fds.append(fd)
                originals.append((fd, parent, name, path, item))
                if normalize:
                    item, _ = prepare_public_acls(fd, parent, name, path, item, originals[:-1], 'metadata')
                    originals[-1] = (fd, parent, name, path, item)
                access_needed, default_needed = guarded_xattrs(fd, parent, name, path, item,
                    'metadata-before' if normalize else 'metadata-census', classify_acls=not normalize)
                bound(fd, parent, name, item)
                access_acl_count += int(access_needed)
                default_acl_count += int(default_needed)
                if normalize and not safe:
                    item = tighten(fd, parent, name, path, item, 0o755 if directory else mode & ~0o133)
                    safe = True  # Exact same-object postcondition above, not an inferred repair.
            if not safe:
                unsafe_count += 1
                unsupported_count += int(not repairable)
                if len(unsafe) < 64:
                    unsafe.append({'path': path[:512], 'pathTruncated': len(path) > 512, **record(item)})
            if not directory:
                need(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(item),
                     'metadata-entry-changed')
                return
            children = sorted(os.listdir(fd))
            need(len(children) <= 8192 and all(child not in {'.', '..'} and re.fullmatch(r'[A-Za-z0-9_.+@\-]+', child) for child in children),
                 'metadata-membership-bound-grammar')
            for child in children:
                visit(fd, child, path + '/' + child, depth + 1, root_kind)
            bound(fd, parent, name, item)
            need(sorted(os.listdir(fd)) == children, 'metadata-membership-changed')
            recheck()
        except XattrFailure as error:
            authority_failure = error
            raise
        finally:
            if fd is not None:
                originals.pop()
                fds.pop()  # Retire this original before its sole close attempt.
                try:
                    os.close(fd)
                except OSError:
                    if authority_failure is not None:
                        authority_failure.observed['cleanupUnknown'] = True
                    else:
                        need(False, 'metadata-original-close')

    for root, root_kind in DATA_ROOTS:
        originals, authority_failure = [], None
        try:
            parent = os.open('/', flags)
            fds.append(parent)
            before = os.fstat(parent)
            protected(before, '/')
            originals.append((parent, None, '/', '/', before))
            guarded_xattrs(parent, None, '/', '/', before,
                           'metadata-before' if normalize else 'metadata-census')
            bound(parent, None, '/', before)
            parts, current = root.split('/')[1:], ''
            for name in parts[:-1]:
                current += '/' + name
                try:
                    fd = os.open(name, flags, dir_fd=parent)
                except FileNotFoundError:
                    count += 1
                    need(count <= 32768, 'metadata-entry-depth-bound')
                    break
                fds.append(fd)
                before = os.fstat(fd)
                protected(before, current)
                originals.append((fd, parent, name, current, before))
                guarded_xattrs(fd, parent, name, current, before,
                               'metadata-before' if normalize else 'metadata-census')
                bound(fd, parent, name, before)
                parent = fd
            else:
                visit(parent, parts[-1], root, 0, root_kind)
            recheck()
        except XattrFailure as error:
            authority_failure = error
            raise
        finally:
            failed_close = False
            while fds:
                fd = fds.pop()
                try:
                    os.close(fd)
                except OSError:
                    failed_close = True
            if failed_close and authority_failure is not None:
                authority_failure.observed['cleanupUnknown'] = True
            else:
                need(not failed_close, 'metadata-original-close')
    return {'_selectedLinks': selected_links, 'entries': count, 'unsafeCount': unsafe_count, 'unsafe': unsafe,
            'unsafeListTruncated': unsafe_count > len(unsafe), 'unsupportedCount': unsupported_count,
            'defaultAclNormalizationCount': default_acl_count, 'accessAclNormalizationCount': access_acl_count,
            'changedCount': changed_count, 'changed': changed, 'changedListTruncated': changed_count > len(changed)}

def link_closure_metadata(selections):
    """Point-in-time public link metadata; never contents, effects or admission."""
    meta_flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    public = ('/usr/share', '/usr/local/share', '/usr/lib', '/etc/alternatives', '/opt')
    covered_ancestors, public_ancestors = {'/'}, {'/'}
    for roots, ancestors in ((tuple(path for path, _ in DATA_ROOTS), covered_ancestors),
                             (public, public_ancestors)):
        for path in roots:
            while path != '/':
                path = path.rpartition('/')[0] or '/'
                ancestors.add(path)

    def covered(path):
        return path in covered_ancestors or any(path == root or kind == 'directory'
            and path.startswith(root + '/') for root, kind in DATA_ROOTS)

    def permitted(path):
        return covered(path) or path in public_ancestors or any(
            path == root or path.startswith(root + '/') for root in public)

    def inspect(selected, expected):
        row = {'selectedPath': selected, 'terminalPath': None, 'links': [],
               'externalPaths': [], 'unsafePaths': [], 'error': None, 'cleanupUnknown': False,
               'authorityFailure': None}
        fds, originals, link_originals, observations, raw_links = [], {}, [], {}, []
        external, unsafe = set(), set()

        def check(ok, code):
            if not ok:
                raise ValueError(code)

        def recheck():
            check(mount_table() == MOUNT_RAW, 'mount-changed')
            for fd, parent, name, before in originals.values():
                check(identity(os.fstat(fd)) == identity(before)
                      == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'original-changed')
            for fd, target in link_originals:
                check(os.readlink('', dir_fd=fd) == target, 'original-link-changed')

        def acquire(path, parent, name):
            check(permitted(path), 'private-target-scope')
            check(not any(point != '/' and (path == point or path.startswith(point + '/'))
                          for point in MOUNT_POINTS), 'mounted-target')
            if path not in originals:
                check(len(fds) < 24, 'fd-bound')
                fd = os.open(name, meta_flags, dir_fd=parent)
                fds.append(fd)  # Register before fstat or any later fallible observation.
                before = os.fstat(fd)
                originals[path] = (fd, parent, name, before)
            fd, original_parent, original_name, before = originals[path]
            check(identity(os.fstat(fd)) == identity(before)
                  == identity(os.stat(original_name, dir_fd=original_parent, follow_symlinks=False)),
                  'original-changed')
            check(before.st_dev == MOUNT_DEVICE, 'wrong-device')
            observations[path] = record(before)
            if not covered(path):
                external.add(path)
            link = stat.S_ISLNK(before.st_mode)
            ordinary = link or stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)
            if (not ordinary or before.st_uid != 0 or before.st_gid != 0
                    or not link and before.st_mode & 0o7022
                    or (link or stat.S_ISREG(before.st_mode)) and before.st_nlink != 1):
                unsafe.add(path)
            if stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode):
                recheck()
                check(len(fds) < 24, 'fd-bound')
                try:
                    ordinary_fd = os.open(original_name, directory_flags if stat.S_ISDIR(before.st_mode)
                                          else file_flags, dir_fd=original_parent)
                except OSError as error:
                    raise XattrFailure(path, before, 'link-closure', number=error.errno) from None
                fds.append(ordinary_fd)  # Also register this extra original before fstat/query.
                authority_failure = None
                try:
                    guarded_xattrs(ordinary_fd, original_parent, original_name, path, before,
                                   'link-closure', held=fd)
                except XattrFailure as error:
                    authority_failure = error
                    raise
                finally:
                    fds.pop()  # Retire before the sole close, including a failed first fstat.
                    try:
                        os.close(ordinary_fd)
                    except OSError:
                        row['cleanupUnknown'] = True
                        if authority_failure is None:
                            raise ValueError('original-close-unknown') from None
                recheck()
            return fd, before

        try:
            check(type(selected) is str and selected.startswith('/') and len(selected) <= 4096
                  and covered(selected), 'selection-scope')
            root_fd, root = acquire('/', None, '/')
            check(stat.S_ISDIR(root.st_mode), 'non-directory-root')
            recheck()
            current, parent, pending, steps, hops, found = '/', root_fd, selected.split('/')[1:], 0, 0, False
            while pending:
                steps += 1
                check(steps <= 256 and len(pending) <= 256, 'component-bound')
                name = pending.pop(0)
                if name in {'', '.'}:
                    continue
                if name == '..':
                    current = current.rpartition('/')[0] or '/'
                    check(current in originals and stat.S_ISDIR(originals[current][3].st_mode), 'parent-unavailable')
                    parent = originals[current][0]
                    continue
                check(re.fullmatch(r'[A-Za-z0-9_.+@\-]+', name) is not None, 'component-grammar')
                candidate = current.rstrip('/') + '/' + name
                fd, item = acquire(candidate, parent, name)
                if candidate == selected:
                    check(stat.S_ISLNK(item.st_mode) and identity(item) == tuple(expected), 'selected-link-changed')
                    found = True
                if stat.S_ISLNK(item.st_mode):
                    hops += 1
                    check(hops <= 40, 'link-bound')
                    target = os.readlink('', dir_fd=fd)
                    check(type(target) is str and 0 < len(target) <= 4096
                          and re.fullmatch(r'[A-Za-z0-9_./+\-]+', target) is not None, 'link-grammar')
                    link_originals.append((fd, target))
                    raw_links.append([candidate, target])
                    if target.startswith('/'):
                        current, parent, parts = '/', root_fd, target.split('/')[1:]
                    else:
                        parts = target.split('/')
                    pending = parts + pending
                elif pending:
                    check(stat.S_ISDIR(item.st_mode), 'non-directory-component')
                    current, parent = candidate, fd
                else:
                    row['terminalPath'] = candidate
                    check(stat.S_ISREG(item.st_mode), 'nonregular-terminal')
                    if item.st_mode & 0o111:
                        unsafe.add(candidate)
            check(found and row['terminalPath'] is not None, 'unresolved-terminal')
            recheck()
        except XattrFailure as error:
            row['error'], row['authorityFailure'] = 'guarded-xattr', error.observed
        except ValueError as error:
            # All ValueErrors above carry fixed codes, never target/error text.
            code = str(error)
            row['error'] = code if re.fullmatch(r'[a-z][a-z-]{0,47}', code) else 'metadata-error'
        except OSError as error:
            row['error'] = 'unresolved-entry' if error.errno == 2 else 'metadata-os-error'
        finally:
            while fds:
                fd = fds.pop()  # One original close attempt; never retry this numeric FD.
                try:
                    os.close(fd)
                except OSError:
                    row['cleanupUnknown'] = True
            if row['authorityFailure'] is not None:
                row['authorityFailure']['cleanupUnknown'] = row['cleanupUnknown']
            if row['cleanupUnknown'] and row['error'] is None:
                row['error'] = 'original-close-unknown'
        # A refused private/invalid target is not public diagnostic text.
        row['links'] = ([[path, '<redacted>'] for path, _ in raw_links]
                        if row['error'] is not None or row['cleanupUnknown'] else raw_links)
        row['externalPaths'], row['unsafePaths'] = sorted(external), sorted(unsafe)
        keep = set(row['externalPaths']) | set(row['unsafePaths']) | {selected, row['terminalPath']}
        keep.update(path for path, _ in raw_links)
        return row, {path: value for path, value in observations.items() if path in keep}

    report = {'scope': 'fixed-shell-data-link-closure', 'runtimeAdmission': False,
              'selectedCount': len(selections), 'examinedCount': 0, 'externalCount': 0,
              'unsafeCount': 0, 'complete': True, 'safe': True, 'truncated': False,
              'records': [], 'nodes': {}, 'globalError': None, '_authorityFailure': None}
    unsafe_paths = set()
    if len(selections) > 4096:
        report.update(complete=False, safe=False, truncated=True, globalError='selection-bound')
        return report
    for selected, expected in selections:
        row, observations = inspect(selected, expected)
        report['examinedCount'] += 1
        if row['authorityFailure'] is not None:
            report['_authorityFailure'] = row['authorityFailure']
        unsafe_paths.update(row['unsafePaths'])
        report['unsafeCount'] = len(unsafe_paths)
        report['externalCount'] += bool(row['externalPaths'])
        if row['error'] is not None or row['cleanupUnknown']:
            report['complete'] = False
        report['safe'] = report['complete'] and not unsafe_paths
        if row['externalPaths'] or row['unsafePaths'] or row['error'] is not None:
            previous = report['nodes']
            nodes = dict(previous)
            for path, metadata in observations.items():
                if path in nodes and nodes[path] != metadata:
                    report.update(complete=False, safe=False, globalError='between-selection-drift')
                else:
                    nodes[path] = metadata  # Never replace the first differing observation.
            report['nodes'] = nodes
            report['records'].append(row)
            if len(json.dumps(report, sort_keys=True, separators=(',', ':')).encode('ascii')) > 65024:
                report['records'].pop()
                report['nodes'] = previous
                report.update(complete=False, safe=False, truncated=True, globalError='diagnostic-byte-bound')
                break
        if (row['cleanupUnknown'] or row['authorityFailure'] is not None or row['error'] in {'mount-changed', 'mounted-target', 'wrong-device',
                'original-changed', 'original-link-changed', 'selected-link-changed'} or report['globalError']):
            break
    if report['examinedCount'] != report['selectedCount']:
        report['complete'] = report['safe'] = False
    return report


try:
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'root-credentials')
    MOUNT_RAW = mount_table()
    MOUNT_DEVICE = os.stat('/', follow_symlinks=False).st_dev
    MOUNT_POINTS = mount_scope(MOUNT_RAW, MOUNT_DEVICE)
    prepared = [prepare_directory(path) for path in sorted(PREPARE_DIRS, key=lambda path: (path.count('/'), path))]
    metadata = metadata_preflight()
    if metadata['unsupportedCount'] == 0 and (metadata['unsafeCount']
            or metadata['defaultAclNormalizationCount'] or metadata['accessAclNormalizationCount']):
        metadata = metadata_preflight(normalize=True)
    mount_unchanged()
    selected_links = metadata.pop('_selectedLinks')
    metadata['selectedLinkCount'] = len(selected_links)
    receipt = json.dumps({'scope': SCOPE, 'prepared': prepared, 'metadata': metadata,
                          **removal_receipt(all_states=True),
                          'runtimeAdmission': False}, sort_keys=True, separators=(',', ':'))
    need(len(receipt.encode('ascii')) <= 65536, 'receipt-bound')
    print(receipt, flush=True)
    need(metadata['unsafeCount'] == metadata['defaultAclNormalizationCount'] == metadata['accessAclNormalizationCount'] == 0,
         'unhandled-unsafe-data-metadata')

    closure = link_closure_metadata(selected_links)
    authority_failure = closure.pop('_authorityFailure')
    closure_receipt = json.dumps(closure, sort_keys=True, separators=(',', ':'))
    need(len(closure_receipt.encode('ascii')) <= 65536, 'link-closure-receipt-bound')
    print(closure_receipt, flush=True)
    need(closure['complete'] and closure['safe'], 'unhandled-data-link-closure', authority_failure)
except XattrFailure as error:
    need(False, 'guarded-xattr', error.observed)
except OSError as error:
    if removal_receipt():
        need(False, 'preparation-os-error',
             {'errno': error.errno if type(error.errno) is int and 0 <= error.errno <= 4095 else None})
    raise
