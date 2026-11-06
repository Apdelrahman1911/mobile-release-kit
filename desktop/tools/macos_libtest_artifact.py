"""Exact current DATA parser reused for one application libtest artifact."""
import hashlib
import json
import math
from pathlib import Path
import re
CAPTURE=4*1024*1024
TARGET='aarch64-apple-darwin'
def need(value, reason):
    if not value: raise ValueError(reason)

def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def finite_float(value):
    parsed = float(value)
    need(math.isfinite(parsed), 'nonfinite-json')
    return parsed


def document(raw):
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs, parse_float=finite_float,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite-json')))


def remaining_artifact_data(raw, checkout, work, role):
    """Bind each actual compiler artifact to its distinct manifest, role and profile."""
    need(type(raw) is bytes and 0 < len(raw) <= CAPTURE and raw.endswith(b'\n'), 'cargo-output-bound')
    lines = raw.splitlines()
    need(0 < len(lines) <= 16384 and all(0 < len(line) <= 1024 * 1024 for line in lines), 'cargo-line-bound')
    rows = [document(line) for line in lines]
    need(all(type(row) is dict and row.get('reason') in ('compiler-artifact', 'compiler-message',
             'build-script-executed', 'build-finished') for row in rows), 'cargo-document')
    need([row for row in rows if row['reason'] == 'build-finished'] == [{'reason': 'build-finished', 'success': True}]
         and rows[-1] == {'reason': 'build-finished', 'success': True}, 'cargo-finished')
    table = {
        'resident-image-build': ('desktop/helpers/macos-android-register', 'mrk_resident_image', 'cdylib', False, '3', [], 'src/lib.rs'),
        'shipping-image-build': ('desktop/helpers/macos-desktop-image', 'mrk_desktop_image', 'cdylib', False, '3', [], 'src/lib.rs'),
        'vault-helper-build': ('desktop/helpers/macos-vault-helper', 'mrk-vault-keychain', 'bin', False, '3', [], 'src/main.rs'),
        'installed-cli-build': ('desktop/src-tauri', 'mrk', 'bin', False, '3', ['installed-cli'], 'src/installed_cli_main.rs'),
        'observer-build': ('desktop/src-tauri', 'installed-shell-observation', 'test', True, '0',
                           ['custom-protocol', 'desktop-shell', 'macos-installed-observation'], 'tests/installed_shell_observation.rs'),
        'application-libtest-build': ('desktop/src-tauri', 'mobile_release_desktop', 'lib', True, '1', [], 'src/lib.rs'),
    }
    need(role in table, 'compile-artifact-role')
    relative, name, kind, test, opt, features, entry = table[role]
    manifest = checkout / relative / 'Cargo.toml'
    selected = [row for row in rows if row['reason'] == 'compiler-artifact'
                and row.get('manifest_path') == str(manifest) and row.get('target', {}).get('name') == name
                and row.get('profile', {}).get('test') is test]
    need(len(selected) == 1, 'cargo-facade-count')
    row = selected[0]; target = row.get('target', {}); profile = row.get('profile', {})
    need(target.get('kind') == [kind] and target.get('crate_types') == [kind if kind in ('lib', 'cdylib') else 'bin']
         and target.get('src_path') == str(checkout / relative / entry)
         and row.get('features') == features and profile.get('opt_level') == opt
         and profile.get('debug_assertions') is (role == 'observer-build') and row.get('fresh') is False,
         'cargo-real-facade')
    files = row.get('filenames'); executable = row.get('executable')
    need(type(files) is list and len(files) == 1 and type(files[0]) is str, 'cargo-target-shape')
    output = Path(files[0]); directory = work / 'cargo-target' / TARGET / ('debug' if role == 'observer-build' else 'release')
    if test:
        need(executable == str(output) and output.parent == directory / 'deps'
             and re.fullmatch(re.escape(name.replace('-', '_')) + r'-[0-9a-f]{16}', output.name), 'cargo-real-facade')
    else:
        leaf = 'lib' + name + '.dylib' if kind == 'cdylib' else name
        need(output == directory / leaf and executable == (None if kind == 'cdylib' else str(output)), 'cargo-real-facade')
    if role in ('resident-image-build', 'shipping-image-build'):
        app = [r for r in rows if r['reason'] == 'compiler-artifact'
               and r.get('manifest_path') == str(checkout / 'desktop/src-tauri/Cargo.toml')
               and r.get('target', {}).get('name') == 'mobile_release_desktop']
        app_features = (['macos-android-registration-helper', 'macos-installed-resident-image']
                        if role == 'resident-image-build' else ['custom-protocol', 'desktop-shell', 'macos-installed-desktop-image'])
        need(len(app) == 1 and app[0].get('features') == app_features and app[0].get('profile', {}).get('test') is False
             and app[0].get('profile', {}).get('opt_level') == ('1' if role == 'resident-image-build' else '3'), 'cargo-shipping-feature')
    return output, dict(role=role, manifest=relative + '/Cargo.toml', target=name, kind=kind, test=test,
                         optLevel=opt, features=features, cargoStdoutSha256=hashlib.sha256(raw).hexdigest())


