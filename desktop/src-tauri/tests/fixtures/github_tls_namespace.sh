#!/usr/bin/bash
# SOURCE only until the dedicated TLS command/runner admission is accepted.
# Fixed Ubuntu24 GitHub-hosted T1--T6 entry, not a general privileged launcher.
# The original CI observer owns sudo/unshare and its wait. This entry cannot
# certify that outer wait, retire another task's resources or authorize cleanup.
set -euo pipefail
diagnostic_stage=admission

refuse() {
    # Both fields are literal source labels, never pathname/identity/input data.
    printf 'github-tls-namespace: %s/%s\n' "$diagnostic_stage" "$1" >&2
    exit 71
}

[[ ( $# == 12 || $# == 13 ) && $UID == 0 && $EUID == 0 && ${LANG-} == C && ${LC_ALL-} == C ]] || refuse admission
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
# The old twelve-argument entry retains its original single test/configuration.
# Only these two literal follow-on profiles add entries, never a caller-supplied
# libtest filter, resolver setting, endpoint, command or destination.
profile=original
if [[ $# == 13 ]]; then
    case ${13} in
        hosts|dns-withhold) profile=${13} ;;
        *) refuse profile ;;
    esac
fi
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
diagnostic_stage=initial-namespace
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
    (( (16#$mode & 0170000) == 0100000 )) || refuse file-type
    (( (16#$mode & 07022) == 0 )) || refuse file-permissions
    (( links == 1 )) || refuse file-links
    (( uid == owner )) || refuse file-owner
    (( size > 0 && size <= maximum )) || refuse file-size
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

# BEGIN PURE RESOLVER OWNERSHIP POLICY
# These two functions inspect supplied strings only. Inert contract tests run
# these exact definitions, never this privileged namespace entry.
resolver_service_uid() {
    [[ $# == 2 ]] || return 1
    local rows=$1 runner_uid=$2 line separators name password uid gid gecos home shell
    local found=0 result=
    [[ ${#rows} -gt 0 && ${#rows} -le 65536 && $rows == *$'\n'
        && $runner_uid =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    (( runner_uid < 4294967295 )) || return 1
    while IFS= read -r line; do
        [[ ${line%%:*} == systemd-resolve ]] || continue
        (( found += 1 ))
        (( found == 1 )) || return 1
        separators=${line//[^:]/}
        [[ ${#separators} == 6 ]] || return 1
        IFS=: read -r name password uid gid gecos home shell <<< "$line"
        [[ $name == systemd-resolve && $uid =~ ^[1-9][0-9]{0,9}$
            && $gid =~ ^(0|[1-9][0-9]{0,9})$ ]] || return 1
        (( uid < 4294967295 && gid < 4294967295 && uid != runner_uid )) || return 1
        result=$uid
    done <<< "$rows"
    (( found == 1 )) || return 1
    printf '%s\n' "$result"
}

resolver_exact_owner() {
    [[ $# == 4 ]] || return 1
    local pathname=$1 observed_uid=$2 service_uid=$3 runner_uid=$4
    [[ $observed_uid =~ ^(0|[1-9][0-9]{0,9})$
        && $service_uid =~ ^(0|[1-9][0-9]{0,9})$
        && $runner_uid =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    (( observed_uid < 4294967295 && service_uid < 4294967295
        && runner_uid < 4294967295 )) || return 1
    case "$pathname" in
        /etc/resolv.conf) (( observed_uid == 0 )) || return 1 ;;
        /run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/resolv.conf)
            (( observed_uid == 0 || (service_uid > 0 && observed_uid == service_uid
                && service_uid != runner_uid) )) || return 1 ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$observed_uid"
}
# END PURE RESOLVER OWNERSHIP POLICY

protected_host_directory() {
    local pathname=$1 service_uid=$2 metadata mode uid
    # canonical() intentionally rejects '/', so only this literal root gets
    # the narrow exception. No caller-selected or intermediate alias is allowed.
    [[ $pathname == / ]] || canonical "$pathname"
    [[ -d $pathname && ! -L $pathname ]] || refuse directory
    metadata=$(/usr/bin/stat --format='%f %u' -- "$pathname" 2>/dev/null) || refuse metadata
    [[ $metadata =~ ^[0-9a-f]+\ [0-9]+$ ]] || refuse metadata
    IFS=' ' read -r mode uid <<< "$metadata"
    (( (16#$mode & 0170000) == 0040000 && (16#$mode & 07022) == 0
        && (uid == 0 || (service_uid > 0 && uid == service_uid)) )) || refuse directory
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

diagnostic_stage=source-paths
for pathname in "$source" "$root" "$artifact" "$python"; do
    canonical "$pathname"
done
diagnostic_stage=layout
[[ $source != "$root" && $source != "$root/"* && $root != "$source/"* ]] || refuse layout
root_name=${root##*/}
[[ $root_name =~ ^mrk-desktop-foundation-github-tls-([1-9][0-9]{0,19})-([1-9][0-9]{0,19})$ ]] || refuse layout
run_id=${BASH_REMATCH[1]}
attempt=${BASH_REMATCH[2]}
artifact_name=${artifact##*/}
[[ ${artifact%/*} == "$root/target/x86_64-unknown-linux-gnu/debug/deps"
    && $artifact_name =~ ^mobile_release_desktop-[0-9a-f]{16}$ ]] || refuse artifact
diagnostic_stage=source-inputs
entry=$source/desktop/src-tauri/tests/fixtures/github_tls_namespace.sh
[[ $0 == "$entry" && -x $python ]] || refuse entry
ordinary "$entry" "$original_uid" 65536
test_root=$root/github-tls
config_root=$root/github-tls-namespace
manifest=$root/github-tls-inputs.json
check_mode=github-readonly-tls-v1
test_name=supervisor::hosted_tests::github_tls_hosted_contract
extra_env=()
case "$profile" in
    hosts|dns-withhold)
        test_root=$root/github-tls-deadline
        config_root=$root/github-tls-deadline-namespace-$profile
        manifest=$root/github-tls-deadline-inputs.json
        check_mode=github-readonly-tls-deadline-v1
        extra_env+=("MRK_GITHUB_TLS_PROFILE=$profile")
        if [[ $profile == hosts ]]; then
            test_name=supervisor::hosted_tests::github_tls_deadline_hosts_hosted_contract
        else
            test_name=supervisor::hosted_tests::github_tls_deadline_dns_hosted_contract
        fi
        ;;
esac
for pathname in "$source" "$source/src" "$root" "$test_root" "$config_root" \
    "$root/target" "$root/target/x86_64-unknown-linux-gnu" \
    "$root/target/x86_64-unknown-linux-gnu/debug" "$root/target/x86_64-unknown-linux-gnu/debug/deps"; do
    directory "$pathname"
done

diagnostic_stage=manifest
ordinary "$manifest" "$original_uid" 1048576
manifest_stamp=$(stamp "$manifest")
hash_is "$manifest" "$inputs_sha"
[[ $(stamp "$manifest") == "$manifest_stamp" ]] || refuse binding
diagnostic_stage=artifact
ordinary "$artifact" "$original_uid" 536870912
[[ -x $artifact && $(/usr/bin/stat --format='%s' -- "$artifact" 2>/dev/null) == "$artifact_bytes" ]] || refuse artifact
artifact_stamp=$(stamp "$artifact")
hash_is "$artifact" "$artifact_sha"
[[ $(stamp "$artifact") == "$artifact_stamp" ]] || refuse artifact

diagnostic_stage=resolver-inputs
hosts=$'127.0.0.1 api.github.com localhost\n::1 localhost\n'
resolver=$'# Synthetic namespace: DNS is disabled by hosts: files.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n'
nsswitch=$'passwd: files\ngroup: files\nhosts: files\n'
if [[ $profile == dns-withhold ]]; then
    hosts=$'127.0.0.1 localhost\n::1 localhost\n'
    resolver=$'nameserver 127.0.0.1\noptions timeout:15 attempts:1 ndots:1\n'
    nsswitch=$'passwd: files\ngroup: files\nhosts: dns\n'
    # The admitted libc/NSS closure must separately prove its applicable cache
    # path. These fixed Linux nscd paths must be absent, including dangling links;
    # do not stop a host service, remove its socket or claim a hosts/cache hit
    # qualifies genuine resolver timeout. The only resolver is owned UDP:53.
    for pathname in /run/nscd/socket /var/run/nscd/socket /run/.nscd_socket /var/run/.nscd_socket; do
        [[ ! -e $pathname && ! -L $pathname ]] || refuse resolver-cache
    done
fi
exact_config "$config_root/hosts" "$hosts"
exact_config "$config_root/resolv.conf" "$resolver"
exact_config "$config_root/nsswitch.conf" "$nsswitch"

# Ubuntu's resolver can be a root-owned alias to a systemd-resolve-owned runtime
# file. Admit that exact named service, not any nonroot owner or the runner.
# Never change ownership, remove the alias, or write through it.
diagnostic_stage=host-resolver-path
resolver_alias_stamp=$(stamp /etc/resolv.conf)
resolver_target=$(/usr/bin/readlink -e -- /etc/resolv.conf 2>/dev/null) || refuse resolver
case "$resolver_target" in
    /etc/resolv.conf|/run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/resolv.conf) ;;
    *) refuse resolver ;;
esac
host_directories=(/ /etc)
service_uid=0
diagnostic_stage=host-resolver
for pathname in "${host_directories[@]}"; do protected_host_directory "$pathname" 0; done
if [[ $resolver_target != /etc/resolv.conf ]]; then
    [[ -L /etc/resolv.conf ]] || refuse resolver
    alias_metadata=$(/usr/bin/stat --format='%f %h %u' -- /etc/resolv.conf 2>/dev/null) || refuse metadata
    [[ $alias_metadata =~ ^[0-9a-f]+\ [0-9]+\ [0-9]+$ ]] || refuse metadata
    IFS=' ' read -r alias_mode alias_links alias_uid <<< "$alias_metadata"
    (( (16#$alias_mode & 0170000) == 0120000 && alias_links == 1 && alias_uid == 0 )) || refuse resolver
    alias_target=$(/usr/bin/readlink -- /etc/resolv.conf 2>/dev/null) || refuse resolver
    [[ $alias_target == "$resolver_target" || $alias_target == "../${resolver_target#/}" ]] || refuse resolver
    for pathname in /run /run/systemd; do protected_host_directory "$pathname" 0; done
    canonical /run/systemd/resolve
    canonical "$resolver_target"
    target_uid=$(/usr/bin/stat --format='%u' -- "$resolver_target" 2>/dev/null) || refuse metadata
    parent_uid=$(/usr/bin/stat --format='%u' -- /run/systemd/resolve 2>/dev/null) || refuse metadata
    if [[ $target_uid != 0 || $parent_uid != 0 ]]; then
        ordinary /etc/passwd 0 65536
        passwd_stamp=$(stamp /etc/passwd)
        passwd_rows=
        # NUL, overflow and unterminated records cannot select an account. No
        # NSS/getent/id lookup, service operation or numeric UID guess is used.
        if IFS= read -r -d '' -n 65537 passwd_rows < /etc/passwd; then refuse identity; fi
        [[ $(stamp /etc/passwd) == "$passwd_stamp" ]] || refuse changed
        service_uid=$(resolver_service_uid "$passwd_rows" "$original_uid") || refuse identity
        unset passwd_rows
    fi
    protected_host_directory /run/systemd/resolve "$service_uid"
    host_directories+=(/run /run/systemd /run/systemd/resolve)
fi
observed_uid=$(/usr/bin/stat --format='%u' -- "$resolver_target" 2>/dev/null) || refuse metadata
resolver_owner=$(resolver_exact_owner "$resolver_target" "$observed_uid" "$service_uid" "$original_uid") || refuse file-owner
ordinary "$resolver_target" "$resolver_owner" 65536
resolver_target_stamp=$(stamp "$resolver_target")
host_directory_stamps=()
for pathname in "${host_directories[@]}"; do host_directory_stamps+=("$(stamp "$pathname")"); done
for pathname in /etc/hosts /etc/nsswitch.conf; do
    case "$pathname" in
        /etc/hosts) diagnostic_stage=host-hosts ;;
        /etc/nsswitch.conf) diagnostic_stage=host-nsswitch ;;
    esac
    ordinary "$pathname" 0 65536
done
diagnostic_stage=host-resolver
[[ $(stamp /etc/resolv.conf) == "$resolver_alias_stamp"
    && $(/usr/bin/readlink -e -- /etc/resolv.conf 2>/dev/null) == "$resolver_target"
    && $(stamp "$resolver_target") == "$resolver_target_stamp" ]] || refuse changed
for index in "${!host_directories[@]}"; do
    [[ $(stamp "${host_directories[index]}") == "${host_directory_stamps[index]}" ]] || refuse changed
done

# These fixed, synchronous system tools start no service and leave no detached
# worker. --no-mtab/--internal-only prevent userspace mount-file updates or a
# filesystem helper. Every target is a private-namespace read-only bind mount.
diagnostic_stage=mount-propagation
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
diagnostic_stage=mount-hosts
bind_readonly "$config_root/hosts" /etc/hosts
diagnostic_stage=mount-resolver
bind_readonly "$config_root/resolv.conf" "$resolver_target"
diagnostic_stage=mount-nsswitch
bind_readonly "$config_root/nsswitch.conf" /etc/nsswitch.conf
diagnostic_stage=mounted-configuration
[[ $(/usr/bin/readlink -e -- /etc/resolv.conf 2>/dev/null) == "$resolver_target" ]] || refuse resolver
exact_config /etc/hosts "$hosts"
exact_config "$resolver_target" "$resolver"
exact_config /etc/nsswitch.conf "$nsswitch"

diagnostic_stage=loopback
/usr/bin/ip link set dev lo up 2>/dev/null || refuse loopback
interfaces=$(/usr/bin/ip -o link show 2>/dev/null) || refuse loopback
[[ $interfaces == '1: lo: '* && $interfaces != *$'\n'* ]] || refuse loopback
flags=${interfaces#*<}
flags=${flags%%>*}
[[ ,$flags, == *,LOOPBACK,* && ,$flags, == *,UP,* ]] || refuse loopback
diagnostic_stage=routes
for family in -4 -6; do
    routes=$(/usr/bin/ip "$family" route show table all 2>/dev/null) || refuse route
    while IFS= read -r route; do
        [[ -z $route ]] && continue
        [[ $route != *default* && $route != *' via '* && " $route " == *' dev lo '* ]] || refuse route
    done <<< "$routes"
done
diagnostic_stage=port-policy
/usr/sbin/sysctl --quiet --write net.ipv4.ip_unprivileged_port_start=0 2>/dev/null || refuse port
[[ $(/usr/sbin/sysctl --values net.ipv4.ip_unprivileged_port_start 2>/dev/null) == 0 ]] || refuse port

# Recheck retained source/artifact identities before exec. The compile-anchored
# Rust manifest checks the complete Python/SSL/source/CA/tool closure after drop;
# no privileged JSON parser/import or caller-supplied executable selection here.
diagnostic_stage=final-bindings
[[ $(/usr/bin/readlink -- /proc/self/ns/net 2>/dev/null) == "$netns"
    && $(/usr/bin/readlink -- /proc/self/ns/mnt 2>/dev/null) == "$mntns" ]] || refuse namespace
ordinary "$artifact" "$original_uid" 536870912
ordinary "$manifest" "$original_uid" 1048576
[[ $(stamp "$artifact") == "$artifact_stamp" && $(stamp "$manifest") == "$manifest_stamp" ]] || refuse changed
hash_is "$artifact" "$artifact_sha"
hash_is "$manifest" "$inputs_sha"
[[ $(stamp "$artifact") == "$artifact_stamp" && $(stamp "$manifest") == "$manifest_stamp" ]] || refuse changed
if [[ $profile == hosts ]]; then
    # Fixed synthetic settings exist BEFORE libtest threads start. Product
    # spawning remains env_clear; only the literal direct probes explicitly
    # construct their own opposing CA set. No live credential or proxy exists.
    ambient=$root/github-tls-deadline-ambient
    directory "$ambient"
    directory "$ambient/empty-ca-dir"
    shopt -s nullglob dotglob
    empty_ca_entries=("$ambient/empty-ca-dir"/*)
    shopt -u nullglob dotglob
    (( ${#empty_ca_entries[@]} == 0 )) || refuse ambient
    [[ ! -e $ambient/owner-clear.keylog && ! -L $ambient/owner-clear.keylog ]] || refuse ambient
    other_ca=$source/desktop/src-tauri/tests/fixtures/github_tls/other-root-ca.pem
    ordinary "$other_ca" "$original_uid" 16384
    extra_env+=("HTTP_PROXY=http://127.0.0.1:18888" "http_proxy=http://127.0.0.1:18888"
        "HTTPS_PROXY=http://127.0.0.1:18888" "https_proxy=http://127.0.0.1:18888"
        "ALL_PROXY=http://127.0.0.1:18888" "all_proxy=http://127.0.0.1:18888"
        "NO_PROXY=" "no_proxy=" "SSL_CERT_FILE=$other_ca"
        "SSL_CERT_DIR=$ambient/empty-ca-dir" "SSLKEYLOGFILE=$ambient/owner-clear.keylog")
fi
cd -- "$root"

# Both privilege drop and the exact artifact are mandatory. No PATH, HOME,
# loader, proxy, TLS-default, Python or account environment is inherited. Only
# the new hosts profile CONSTRUCTS the above literal inert settings; no ambient
# value is forwarded. The ordinary libtest owner retains/settles product/probe,
# peer and the S+EOF writer separately. Rust verifies every new bound input.
exec /usr/bin/setpriv --reuid="$original_uid" --regid="$original_gid" --clear-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
    /usr/bin/env -i LANG=C LC_ALL=C \
    MRK_DESKTOP_HOSTED_CHECKS="$check_mode" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_REF=refs/heads/verify/desktop-github-connection-tls GITHUB_SHA="$source_sha" \
    GITHUB_RUN_ID="$run_id" GITHUB_RUN_ATTEMPT="$attempt" \
    MRK_DESKTOP_TEST_ROOT="$test_root" MRK_DESKTOP_TEST_CORE_ZIP="$root/core.zip" \
    MRK_DESKTOP_DEV_CORE="$source/src" MRK_DESKTOP_DEV_PYTHON="$python" \
    MRK_GITHUB_TLS_INPUTS="$manifest" MRK_GITHUB_TLS_ARTIFACT="$artifact" \
    MRK_GITHUB_TLS_ARTIFACT_SHA256="$artifact_sha" MRK_GITHUB_TLS_ARTIFACT_BYTES="$artifact_bytes" \
    MRK_TLS_ORIGINAL_UID="$original_uid" MRK_TLS_ORIGINAL_GID="$original_gid" \
    MRK_TLS_PARENT_NETNS="$parent_netns" MRK_TLS_PARENT_MNTNS="$parent_mntns" \
    MRK_TLS_NETNS="$netns" MRK_TLS_MNTNS="$mntns" \
    "${extra_env[@]}" \
    "$artifact" --ignored --exact "$test_name" --nocapture --test-threads=1
