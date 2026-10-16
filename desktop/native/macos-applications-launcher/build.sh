#!/bin/bash
# Developer-only staged-component build; does not install, sign or distribute.
# Integrated /Applications publication and its collision/removal lifecycle need
# separate review. Never copy the protected application's actual entry instead.
set -euo pipefail
umask 022
if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: build.sh ABSENT_OUTPUT.app arm64|x86_64' >&2
    exit 64
fi
case "$2" in arm64|x86_64) architecture="$2" ;; *) exit 64 ;; esac
case "$1" in /*.app) output="$1" ;; *) printf '%s\n' 'Use an absolute, new .app output path.' >&2; exit 64 ;; esac
if [ "$(/usr/bin/uname -s)" != Darwin ]; then
    printf '%s\n' 'Build this component with the macOS SDK on a Mac.' >&2
    exit 69
fi
if [ "$(/usr/bin/id -u)" = 0 ]; then
    printf '%s\n' 'Build as your ordinary user, not root.' >&2
    exit 77
fi
if [ -e "$output" ] || [ -L "$output" ]; then
    printf '%s\n' 'Output already exists; nothing was overwritten.' >&2
    exit 73
fi
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
desktop="$(cd -- "$here/../.." && pwd -P)"
version="$(/usr/bin/plutil -extract version raw -o - "$desktop/src-tauri/tauri.conf.json")"
for key in CFBundleShortVersionString CFBundleVersion; do
    [ "$(/usr/bin/plutil -extract "$key" raw -o - "$here/Info.plist")" = "$version" ] || {
        printf '%s\n' 'Launcher and application versions differ.' >&2; exit 65;
    }
done
/usr/bin/plutil -lint "$here/Info.plist" >/dev/null
scratch="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/mrk-launcher-build.XXXXXX")"
trap '/bin/rm -rf -- "$scratch"' EXIT
sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
swiftc="$(/usr/bin/xcrun --sdk macosx --find swiftc)"
"$swiftc" -swift-version 6 -O -whole-module-optimization \
    -target "$architecture-apple-macosx26.0" -sdk "$sdk" \
    -module-cache-path "$scratch/module-cache" \
    -framework AppKit -framework Security "$here/main.swift" \
    -o "$scratch/mrk-macos-launcher"
# Exclusive destination creation refuses races as well as earlier collisions.
# A partial output remains identifiable after publication failure; it is never
# mistaken for a signed or ready distribution, and unrelated files are retained.
/bin/mkdir "$output"
/bin/mkdir "$output/Contents" "$output/Contents/MacOS" "$output/Contents/Resources"
/usr/bin/install -m 0755 "$scratch/mrk-macos-launcher" "$output/Contents/MacOS/mrk-macos-launcher"
/usr/bin/install -m 0644 "$here/Info.plist" "$output/Contents/Info.plist"
/usr/bin/install -m 0644 "$desktop/src-tauri/icons/icon.png" "$output/Contents/Resources/icon.png"
printf '%s\n' 'Unsigned launcher component built; installation, signing, notarization and native verification remain required.'
