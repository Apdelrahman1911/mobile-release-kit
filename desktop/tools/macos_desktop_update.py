"""Focused ordinary Desktop update composition DATA; no native authority."""
import argparse
import hashlib
import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('desktop_update_stager', Path(__file__).with_name('stage_macos_installed.py'))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

MAINTENANCE_GENERATION_LIMIT = 9
MAINTENANCE_STORAGE_BYTES = MAINTENANCE_GENERATION_LIMIT * S.MAX_BYTES + S.MAINTENANCE_METADATA_BYTES


def maintenance_payload_floor_data(generations):
    """Authenticated inventory input comparison, never full native admission.

    The caller must authenticate each inventory against its signed release.
    Metadata, archives and physical launcher copies are omitted from this floor
    and still need the original complete native storage/resource observation.
    """
    S.need(type(generations) in (list, tuple) and 0 < len(generations) <= MAINTENANCE_GENERATION_LIMIT,
           'desktop-update-generation-bound')
    total = 0
    for inventory in generations:
        S.need(type(inventory) is dict and type(inventory.get('files')) is list
               and 0 < len(inventory['files']) <= S.MAX_FILES, 'desktop-update-payload-floor-shape')
        sizes = []
        for row in inventory['files']:
            S.need(type(row) is dict and type(row.get('size')) is int
                   and 0 <= row['size'] <= S.MAX_BYTES, 'desktop-update-payload-floor-size')
            sizes.append(row['size'])
        cost = sum(sizes)
        S.need(cost <= S.MAX_BYTES, 'desktop-update-generation-payload-bound')
        total += cost
    S.need(total <= MAINTENANCE_STORAGE_BYTES, 'desktop-update-maintenance-storage-bound')
    return dict(payloadBytesLowerBound=total, maintenanceStorageCapBytes=MAINTENANCE_STORAGE_BYTES,
                metadataAndLauncherCopiesIncluded=False, fullNativeBudgetAdmitted=False)


def contents_data(inventory, package_role):
    S.need(package_role == 'ordinary-image' and type(inventory) is dict
           and type(inventory.get('files')) is list, 'desktop-update-ordinary-role')
    rows = inventory['files']
    S.need(0 < len(rows) <= S.MAX_FILES and all(type(row) is dict for row in rows),
           'desktop-update-inventory')
    names = [row.get('path') for row in rows]
    S.need(all(type(name) is str for name in names) and len(set(names)) == len(names),
           'desktop-update-inventory')
    launcher = 'app/' + S.LAUNCHER_BUNDLE + '/'
    required = {launcher + name for name in S.LAUNCHER_LIMITS} | {'app/' + S.LAUNCHER_TICKET}
    actual = {name for name in names if name.startswith(launcher)}
    S.need(actual == required, 'desktop-update-five-launcher-components')
    executable = 'app/' + S.LAUNCHER_EXECUTABLE
    for row in rows:
        if row['path'] in required:
            S.need(set(row) == {'path', 'sha256', 'size', 'executable'}
                   and type(row['size']) is int and row['size'] > 0
                   and type(row['executable']) is bool and row['executable'] == (row['path'] == executable)
                   and S.maintenance_hex(row['sha256'], 64), 'desktop-update-launcher-leaf')
    # Real ordinary Desktop cdylib + facade, resident service and installed CLI.
    # Observer bootstrap peers do not replace these production components.
    functional = {'app/' + leaf for leaf in (S.ENTRY_BINARY, S.APP_BINARY, S.DESKTOP_IMAGE,
                                           S.RESIDENT_IMAGE, 'Contents/MacOS/mrk', S.VAULT_HELPER,
                                           S.REMOVER, S.ANDROID_HELPER, S.ANDROID_SERVICE_PLIST)}
    S.need(functional <= set(names), 'desktop-update-functional-components')
    return dict(packageRole=package_role, launcherComponents=5, ordinaryDesktopImagePresent=True,
                residentImagePresent=True, installedCliPresent=True, installed=False, productReady=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--expected-inventory', required=True)
    parser.add_argument('--package-role', choices=['ordinary-image'], required=True)
    args = parser.parse_args()
    body = S.read(args.inventory, 12 * 1024 * 1024)
    S.need(hashlib.sha256(body).hexdigest() == args.expected_inventory, 'desktop-update-inventory-binding')
    value = contents_data(json.loads(body), args.package_role)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    main()
