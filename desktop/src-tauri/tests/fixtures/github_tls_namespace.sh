#!/usr/bin/bash
# SOURCE only until the dedicated TLS command/runner admission is accepted.
# Fixed Ubuntu24 GitHub-hosted T1--T3 entry, not a general privileged launcher.
# The original CI observer owns sudo/unshare and its wait. This entry cannot
# certify that outer wait, retire another task's resources or authorize cleanup.
set -euo pipefail

refuse() {
    printf 'github-tls-namespace: %s\n' "$1" >&2
    exit 71
}

[[ $# == 12 && $UID == 0 && $EUID == 0 && ${LANG-} == C && ${LC_ALL-} == C ]] || refuse admission
source=$1
root=$2
artifact=$3
python=$4
original_uid=$5
original_gid=$6
parent_netns=$7
parent_mntns=$8
inputs_sha=$9
artifact_sha=${10}
artifact_bytes=${11}
source_sha=${12}
[[ $original_uid =~ ^[1-9][0-9]{0,9}$ && $original_gid =~ ^[1-9][0-9]{0,9}$ ]] || refuse identity
(( original_uid < 4294967295 && original_gid < 4294967295 )) || refuse identity
[[ $inputs_sha =~ ^[0-9a-f]{64}$ && $artifact_sha =~ ^[0-9a-f]{64}$
    && $source_sha =~ ^[0-9a-f]{40}$ && $source_sha != 0000000000000000000000000000000000000000
    && $artifact_bytes =~ ^[1-9][0-9]{0,8}$ ]] || refuse binding
(( artifact_bytes <= 536870912 )) || refuse binding
net_pattern='^net:\[[1-9][0-9]{0,19}\]$'
mnt_pattern='^mnt:\[[1-9][0-9]{0,19}\]$'
[[ $parent_netns =~ $net_pattern && $parent_mntns =~ $mnt_pattern ]] || refuse namespace

# Observe the followed kernel namespace labels, NOT the proc symlink inodes.
# This is before any mount, interface or sysctl change. There is no fallback to
# host isolation, a caller-selected destination, a PID namespace or an endpoint.
netns=$(/usr/bin/readlink -- /proc/self/ns/net 2>/dev/null) || refuse namespace
mntns=$(/usr/bin/readlink -- /proc/self/ns/mnt 2>/dev/null) || refuse namespace
[[ $netns =~ $net_pattern && $mntns =~ $mnt_pattern
    && $netns != "$parent_netns" && $mntns != "$parent_mntns" ]] || refuse namespace
umask 077

canonical() {
    local value=$1 actual
    [[ ${#value} -le 4096 && $value =~ ^/[A-Za-z0-9_./-]+$ && $value != /
        && $value != */ && $value != *//* && $value != */./* && $value != */../*
        && $value != */. && $value != */.. ]] || refuse path
    actual=$(/usr/bin/readlink -e -- "$value" 2>/dev/null) || refuse path
    [[ $actual == "$value" ]] || refuse path
}

stamp() {
    /usr/bin/stat --format='%d:%i:%f:%h:%u:%g:%s:%y:%z' -- "$1" 2>/dev/null || refuse metadata
}

ordinary() {
    local pathname=$1 owner=$2 maximum=$3 metadata mode links uid gid size
    canonical "$pathname"
    [[ -f $pathname && ! -L $pathname ]] || refuse file
    metadata=$(/usr/bin/stat --format='%f %h %u %g %s' -- "$pathname" 2>/dev/null) || refuse metadata
    [[ $metadata =~ ^[0-9a-f]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || refuse metadata
    IFS=' ' read -r mode links uid gid size <<< "$metadata"
    (( (16#$mode & 0170000) == 0100000 && (16#$mode & 07022) == 0
        && links == 1 && uid == owner && size > 0 && size <= maximum )) || refuse file
}

directory() {
    local pathname=$1 metadata mode uid
    canonical "$pathname"
    [[ -d $pathname && ! -L $pathname ]] || refuse directory
    metadata=$(/usr/bin/stat --format='%f %u' -- "$pathname" 2>/dev/null) || refuse metadata
    [[ $metadata =~ ^[0-9a-f]+\ [0-9]+$ ]] || refuse metadata
    IFS=' ' read -r mode uid <<< "$metadata"
    (( (16#$mode & 0170000) == 0040000 && (16#$mode & 0022) == 0
        && uid == original_uid )) || refuse directory
}

hash_is() {
    local pathname=$1 expected=$2 result
    result=$(/usr/bin/sha256sum -- "$pathname" 2>/dev/null) || refuse hash
    [[ $result == "$expected  $pathname" ]] || refuse hash
}

exact_config() {
    local pathname=$1 expected=$2 value= before
    ordinary "$pathname" "$original_uid" 1024
    before=$(stamp "$pathname")
    # Delimiter NUL: success means a NUL or the hard character limit was hit.
    # EOF preserves the final newline for the exact byte comparison below.
    if IFS= read -r -d '' -n 1025 value < "$pathname"; then
        refuse configuration
    fi
    [[ $value == "$expected" && $(stamp "$pathname") == "$before" ]] || refuse configuration
}

for pathname in "$source" "$root" "$artifact" "$python"; do
    canonical "$pathname"
done
[[ $source != "$root" && $source != "$root/"* && $root != "$source/"* ]] || refuse layout
root_name=${root##*/}
[[ $root_name =~ ^mrk-desktop-foundation-github-tls-([1-9][0-9]{0,19})-([1-9][0-9]{0,19})$ ]] || refuse layout
run_id=${BASH_REMATCH[1]}
attempt=${BASH_REMATCH[2]}
artifact_name=${artifact##*/}
[[ ${artifact%/*} == "$root/target/x86_64-unknown-linux-gnu/debug/deps"
    && $artifact_name =~ ^mobile_release_desktop-[0-9a-f]{16}$ ]] || refuse artifact
entry=$source/desktop/src-tauri/tests/fixtures/github_tls_namespace.sh
[[ $0 == "$entry" && -x $python ]] || refuse entry
ordinary "$entry" "$original_uid" 65536
for pathname in "$source" "$source/src" "$root" "$root/github-tls" "$root/github-tls-namespace" \
    "$root/target" "$root/target/x86_64-unknown-linux-gnu" \
    "$root/target/x86_64-unknown-linux-gnu/debug" "$root/target/x86_64-unknown-linux-gnu/debug/deps"; do
    directory "$pathname"
done

manifest=$root/github-tls-inputs.json
ordinary "$manifest" "$original_uid" 1048576
manifest_stamp=$(stamp "$manifest")
hash_is "$manifest" "$inputs_sha"
[[ $(stamp "$manifest") == "$manifest_stamp" ]] || refuse binding
ordinary "$artifact" "$original_uid" 536870912
[[ -x $artifact && $(/usr/bin/stat --format='%s' -- "$artifact" 2>/dev/null) == "$artifact_bytes" ]] || refuse artifact
artifact_stamp=$(stamp "$artifact")
hash_is "$artifact" "$artifact_sha"
[[ $(stamp "$artifact") == "$artifact_stamp" ]] || refuse artifact

hosts=$'127.0.0.1 api.github.com localhost\n::1 localhost\n'
resolver=$'# Synthetic namespace: DNS is disabled by hosts: files.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n'
nsswitch=$'passwd: files\ngroup: files\nhosts: files\n'
config_root=$root/github-tls-namespace
exact_config "$config_root/hosts" "$hosts"
exact_config "$config_root/resolv.conf" "$resolver"
exact_config "$config_root/nsswitch.conf" "$nsswitch"

# Ubuntu's resolver is sometimes a systemd-owned symlink. Only these literal
# canonical target spellings are admitted; never remove/replace that link or
# write through it. hosts/nsswitch do not receive a generic alias exception.
resolver_target=$(/usr/bin/readlink -e -- /etc/resolv.conf 2>/dev/null) || refuse resolver
case "$resolver_target" in
    /etc/resolv.conf|/run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/resolv.conf) ;;
    *) refuse resolver ;;
esac
for pathname in /etc/hosts "$resolver_target" /etc/nsswitch.conf; do
    ordinary "$pathname" 0 65536
done

# These fixed, synchronous system tools start no service and leave no detached
# worker. --no-mtab/--internal-only prevent userspace mount-file updates or a
# filesystem helper. Every target is a private-namespace read-only bind mount.
/usr/bin/mount --no-mtab --internal-only --make-rprivate / 2>/dev/null || refuse propagation
propagation=$(/usr/bin/findmnt --noheadings --raw --mountpoint / --output PROPAGATION 2>/dev/null) || refuse propagation
[[ $propagation == private ]] || refuse propagation

bind_readonly() {
    local input=$1 target=$2 options
    /usr/bin/mount --no-mtab --internal-only --bind -- "$input" "$target" 2>/dev/null || refuse mount
    /usr/bin/mount --no-mtab --internal-only --options remount,bind,ro,nosuid,nodev,noexec -- \
        "$input" "$target" 2>/dev/null || refuse readonly
    options=$(/usr/bin/findmnt --noheadings --raw --mountpoint "$target" --output VFS-OPTIONS 2>/dev/null) || refuse readonly
    [[ $options != *$'\n'* && ,$options, == *,ro,* && ,$options, != *,rw,*
        && ,$options, == *,nosuid,* && ,$options, == *,nodev,* && ,$options, == *,noexec,* ]] || refuse readonly
}
bind_readonly "$config_root/hosts" /etc/hosts
bind_readonly "$config_root/resolv.conf" "$resolver_target"
bind_readonly "$config_root/nsswitch.conf" /etc/nsswitch.conf
[[ $(/usr/bin/readlink -e -- /etc/resolv.conf 2>/dev/null) == "$resolver_target" ]] || refuse resolver
exact_config /etc/hosts "$hosts"
exact_config "$resolver_target" "$resolver"
exact_config /etc/nsswitch.conf "$nsswitch"

/usr/bin/ip link set dev lo up 2>/dev/null || refuse loopback
interfaces=$(/usr/bin/ip -o link show 2>/dev/null) || refuse loopback
[[ $interfaces == '1: lo: '* && $interfaces != *$'\n'* ]] || refuse loopback
flags=${interfaces#*<}
flags=${flags%%>*}
[[ ,$flags, == *,LOOPBACK,* && ,$flags, == *,UP,* ]] || refuse loopback
for family in -4 -6; do
    routes=$(/usr/bin/ip "$family" route show table all 2>/dev/null) || refuse route
    while IFS= read -r route; do
        [[ -z $route ]] && continue
        [[ $route != *default* && $route != *' via '* && " $route " == *' dev lo '* ]] || refuse route
    done <<< "$routes"
done
/usr/sbin/sysctl --quiet --write net.ipv4.ip_unprivileged_port_start=0 2>/dev/null || refuse port
[[ $(/usr/sbin/sysctl --values net.ipv4.ip_unprivileged_port_start 2>/dev/null) == 0 ]] || refuse port

# Recheck retained source/artifact identities before exec. The compile-anchored
# Rust manifest checks the complete Python/SSL/source/CA/tool closure after drop;
# no privileged JSON parser/import or caller-supplied executable selection here.
[[ $(/usr/bin/readlink -- /proc/self/ns/net 2>/dev/null) == "$netns"
    && $(/usr/bin/readlink -- /proc/self/ns/mnt 2>/dev/null) == "$mntns" ]] || refuse namespace
ordinary "$artifact" "$original_uid" 536870912
ordinary "$manifest" "$original_uid" 1048576
[[ $(stamp "$artifact") == "$artifact_stamp" && $(stamp "$manifest") == "$manifest_stamp" ]] || refuse changed
hash_is "$artifact" "$artifact_sha"
hash_is "$manifest" "$inputs_sha"
[[ $(stamp "$artifact") == "$artifact_stamp" && $(stamp "$manifest") == "$manifest_stamp" ]] || refuse changed
cd -- "$root"

# Both privilege drop and the exact artifact are mandatory. No PATH, HOME,
# loader, proxy, TLS-default, Python or account environment is inherited. The
# ordinary libtest owner independently retains/settles its product and peer.
exec /usr/bin/setpriv --reuid="$original_uid" --regid="$original_gid" --clear-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
    /usr/bin/env -i LANG=C LC_ALL=C \
    MRK_DESKTOP_HOSTED_CHECKS=github-readonly-tls-v1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_REF=refs/heads/verify/desktop-github-connection-tls GITHUB_SHA="$source_sha" \
    GITHUB_RUN_ID="$run_id" GITHUB_RUN_ATTEMPT="$attempt" \
    MRK_DESKTOP_TEST_ROOT="$root/github-tls" MRK_DESKTOP_TEST_CORE_ZIP="$root/core.zip" \
    MRK_DESKTOP_DEV_CORE="$source/src" MRK_DESKTOP_DEV_PYTHON="$python" \
    MRK_GITHUB_TLS_INPUTS="$manifest" MRK_GITHUB_TLS_ARTIFACT="$artifact" \
    MRK_GITHUB_TLS_ARTIFACT_SHA256="$artifact_sha" MRK_GITHUB_TLS_ARTIFACT_BYTES="$artifact_bytes" \
    MRK_TLS_ORIGINAL_UID="$original_uid" MRK_TLS_ORIGINAL_GID="$original_gid" \
    MRK_TLS_PARENT_NETNS="$parent_netns" MRK_TLS_PARENT_MNTNS="$parent_mntns" \
    MRK_TLS_NETNS="$netns" MRK_TLS_MNTNS="$mntns" \
    "$artifact" --ignored --exact supervisor::hosted_tests::github_tls_hosted_contract --nocapture --test-threads=1
