#!/bin/sh
# Mobile Release Kit: delete the app's OWN per-user data (#83, OD-05c).
#
# Runs as the signed-in user, never as root, and only after Remove.pkg has
# confirmed removal (the managed app is absent). It deletes nothing else:
# only the exact, fixed locations below, each only if it is a real (non-link)
# entry owned by this user. Projects, documents, ~/.config/gh and any other
# file are never touched. Every outcome is printed; exit 0 means everything
# that existed was deleted, 1 means something was kept (listed), 64/65 mean
# the request itself was refused and nothing was deleted.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

INSTALLED='/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app'
uid=$(id -u) || exit 64
[ "$uid" -ne 0 ] || { echo "refused: run as the signed-in user, not root"; exit 64; }
if [ -e "$INSTALLED" ] || [ -L "$INSTALLED" ]; then
    echo "refused: Mobile Release Kit is still installed; no data was deleted"
    exit 65
fi
home=${HOME:-}
lib="$home/Library"
case "$home" in /*) ;; *) echo "refused: no home folder"; exit 64 ;; esac
if [ -L "$home" ] || [ ! -d "$home" ] || [ -L "$lib" ] || [ ! -d "$lib" ] \
    || [ "$(stat -f %u "$home")" != "$uid" ] || [ "$(stat -f %u "$lib")" != "$uid" ]; then
    echo "refused: the home Library folder is not a folder owned by this user"
    exit 64
fi
home=$(cd -P "$home" && pwd -P) || exit 64
lib="$home/Library"
library_device=$(stat -f %d "$lib") || exit 64

status=0
remove() {
    target="./$1"
    display="$directory/$1"
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        return 0
    fi
    if [ -L "$target" ]; then
        echo "kept (link, not followed): $display"; status=1; return 0
    fi
    if [ "$(stat -f '%u:%d' "$target")" != "$uid:$device" ]; then
        echo "kept (different owner or volume): $display"; status=1; return 0
    fi
    if [ "$#" -eq 2 ] && [ -f "$target" ]; then
        defaults delete "$2" >/dev/null 2>&1 || true
    fi
    if rm -r -f -x -- "$target" && [ ! -e "$target" ]; then
        echo "deleted: $display"
    else
        echo "could not delete: $display"; status=1
    fi
}

remove_directory_data() (
    directory="$lib/$1"
    if [ -L "$directory" ]; then
        echo "kept (link, not followed): $directory"
        exit 1
    fi
    [ -e "$directory" ] || exit 0
    if ! cd -P "$directory" || [ "$(pwd -P)" != "$directory" ] || [ "$(stat -f %u .)" != "$uid" ]; then
        echo "kept (unverified Library directory): $directory"
        exit 1
    fi
    device=$(stat -f %d .) || exit 1
    if [ "$device" != "$library_device" ]; then
        echo "kept (different volume): $directory"
        exit 1
    fi
    # The working directory pins the verified parent. Remove only its fixed
    # leaves. The device check and rm -x constrain traversal below that parent.
    status=0
    for id in dev.mobile-release-kit.desktop dev.mobile-release-kit.desktop.entry dev.mobile-release-kit.desktop.launcher; do
        case "$1" in
            Preferences) remove "$id.plist" "$id" ;;
            "Saved Application State") remove "$id.savedState" ;;
            HTTPStorages) remove "$id"; remove "$id.binarycookies" ;;
            *) remove "$id" ;;
        esac
    done
    exit "$status"
)

for directory in "Application Support" Caches WebKit HTTPStorages "Saved Application State" Logs Preferences; do
    remove_directory_data "$directory" || status=1
done

# The app's own login-keychain items, matched by their exact fixed service.
for service in 'dev.mobile-release-kit.desktop/vault/wrapping-key/v1' \
    'dev.mobile-release-kit.desktop/local-release/key/v1' \
    'dev.mobile-release-kit.desktop/local-release/checkpoint/v1'; do
    count=0
    while [ "$count" -lt 16 ] && security find-generic-password -s "$service" >/dev/null 2>&1; do
        if security delete-generic-password -s "$service" >/dev/null 2>&1; then
            echo "deleted keychain item: $service"
        else
            echo "kept keychain item (not allowed or failed): $service"; status=1; break
        fi
        count=$((count + 1))
    done
done
exit "$status"
