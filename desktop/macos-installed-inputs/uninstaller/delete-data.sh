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

status=0
remove() {
    target=$1
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        return 0
    fi
    if [ -L "$target" ]; then
        echo "kept (link, not followed): $target"; status=1; return 0
    fi
    if [ "$(stat -f %u "$target")" != "$uid" ]; then
        echo "kept (not owned by you): $target"; status=1; return 0
    fi
    # -x: never cross into another mounted volume. rm never follows links.
    if rm -r -f -x -- "$target" && [ ! -e "$target" ]; then
        echo "deleted: $target"
    else
        echo "could not delete: $target"; status=1
    fi
}

for id in dev.mobile-release-kit.desktop dev.mobile-release-kit.desktop.entry dev.mobile-release-kit.desktop.launcher; do
    remove "$lib/Application Support/$id"
    remove "$lib/Caches/$id"
    remove "$lib/WebKit/$id"
    remove "$lib/HTTPStorages/$id"
    remove "$lib/HTTPStorages/$id.binarycookies"
    remove "$lib/Saved Application State/$id.savedState"
    remove "$lib/Logs/$id"
    if [ -f "$lib/Preferences/$id.plist" ] && [ ! -L "$lib/Preferences/$id.plist" ]; then
        defaults delete "$id" >/dev/null 2>&1 || true
    fi
    remove "$lib/Preferences/$id.plist"
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
