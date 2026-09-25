# Fixed61000 native identity gate. NOT EXECUTED. Distinct COMMAND review + root GO required.
# The reviewed launcher reads these exact bytes as bash -c source (not a sourced startup file).
set -euo pipefail
umask 077
refuse() {
    # Finite diagnostic labels only; never print observed credentials, paths,
    # descriptor targets, environment or an arbitrary caller value.
    local label
    case "${1-}" in
        argument-count|shell-uid|status-duplicate|status-uid-values|status-gid-values|status-groups|status-cap-inh|status-cap-prm|status-cap-eff|status-cap-bnd|status-cap-amb|status-no-new-privileges|status-fields|mapping-row|mapping-count|fixture-cd|fixture-pwd|network-row-size|network-header|network-columns|network-row-shape|network-interface|network-roster|fd-inheritance) label=$1 ;;
        *) label=invalid-label ;;
    esac
    printf 'MRK_GNOME_NATIVE_ENTRY refused=true site=%s\n' "$label" >&2
    exit 90
}
# Failure-only DATA from the existing Bash-visible row, never a new gate.
# Explicit ASCII whitespace: SP09(HT)0A(LF)0B(VT)0C(FF)0D(CR), with SP=20.
# Bash strings cannot retain NUL; this classification makes no raw-byte claim.
network_interface_diagnostic() {
    local ordinal prefix_class synthetic raw_prefix sample
    local loopback_pattern=$'^[ \t\n\v\f\r]*lo[ \t\n\v\f\r]*$'
    local ascii_pattern=$'^[\001-\177]*$'
    case "$network_rows" in
        2) ordinal=first ;;
        3) ordinal=second ;;
        *) ordinal=later ;;
    esac
    raw_prefix=${network_row%%:*}
    if [[ $raw_prefix =~ $loopback_pattern ]]; then
        prefix_class=canonical-loopback
    elif [[ -z $raw_prefix ]]; then
        prefix_class=empty
    elif [[ $raw_prefix =~ $ascii_pattern ]]; then
        prefix_class=other-ascii
    else
        prefix_class=other-bytes
    fi
    sample=$' \t\n\v\f\rlo \t\n\v\f\r'
    sample=${sample//[[:space:]]/}
    if [[ $sample == lo ]]; then synthetic=pass; else synthetic=fail; fi
    printf 'MRK_GNOME_NATIVE_NETWORK_DIAGNOSTIC ordinal=%s prefix=%s synthetic=%s\n' \
        "$ordinal" "$prefix_class" "$synthetic" >&2
}
[[ $# == 0 ]] || refuse argument-count
expected_uid=61000
expected_gid=61000
[[ $UID == "$expected_uid" && $EUID == "$expected_uid" ]] || refuse shell-uid
seen=0
one() { (( (seen & $1) == 0 )) || refuse status-duplicate; seen=$((seen | $1)); }
while read -r key a b c d extra; do
    case "$key" in
        Uid:)
            one 1
            [[ $a == "$expected_uid" && $b == "$expected_uid" && $c == "$expected_uid" && $d == "$expected_uid" && -z $extra ]] || refuse status-uid-values
            ;;
        Gid:)
            one 2
            [[ $a == "$expected_gid" && $b == "$expected_gid" && $c == "$expected_gid" && $d == "$expected_gid" && -z $extra ]] || refuse status-gid-values
            ;;
        Groups:)
            one 4
            [[ -z $a && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-groups
            ;;
        CapInh:) one 8; [[ $a == 0000000000000000 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-cap-inh ;;
        CapPrm:) one 16; [[ $a == 0000000000000000 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-cap-prm ;;
        CapEff:) one 32; [[ $a == 0000000000000000 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-cap-eff ;;
        CapBnd:) one 64; [[ $a == 0000000000000000 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-cap-bnd ;;
        CapAmb:) one 128; [[ $a == 0000000000000000 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-cap-amb ;;
        NoNewPrivs:) one 256; [[ $a == 1 && -z $b && -z $c && -z $d && -z $extra ]] || refuse status-no-new-privileges ;;
    esac
done < /proc/self/status
[[ $seen == 511 ]] || refuse status-fields
for mapping in /proc/self/uid_map /proc/self/gid_map; do
    count=0
    while read -r inner outer length extra; do
        count=$((count + 1))
        [[ $inner == 0 && $outer == 0 && $length == 4294967295 && -z $extra ]] || refuse mapping-row
    done < "$mapping"
    [[ $count == 1 ]] || refuse mapping-count
done
# bwrap reaches a public readonly cwd before dropping to the fixture owner.
# Only the verified61000 identity enters its private0700 directory; do not
# grant the root launcher additional filesystem permissions or capabilities.
cd -P -- /mrk-gnome-fixture || refuse fixture-cd
[[ $PWD == /mrk-gnome-fixture ]] || refuse fixture-pwd
# Both entry-only smoke and real native entry inherit the outer isolated
# network. Permit only its loopback interface; this is not the isolation authority.
network_rows=0
loopbacks=0
while IFS= read -r network_row; do
    [[ ${#network_row} -lt 4096 ]] || refuse network-row-size
    case "$network_rows" in
        0) [[ $network_row == *"Inter-"*"Receive"*"Transmit"* ]] || refuse network-header ;;
        1) [[ $network_row == *"face"*"bytes"*"packets"* ]] || refuse network-columns ;;
        *)
            [[ $network_row == *:* ]] || refuse network-row-shape
            interface=${network_row%%:*}
            interface=${interface//[[:space:]]/}
            if [[ $interface != lo ]]; then
                network_interface_diagnostic || :
            fi
            [[ $interface == lo ]] || refuse network-interface
            loopbacks=$((loopbacks + 1))
            ;;
    esac
    network_rows=$((network_rows + 1))
done < /proc/net/dev
[[ $network_rows == 3 && $loopbacks == 1 ]] || refuse network-roster
# No still-live inherited descriptor beyond stdio. Transient glob directory FDs
# may have disappeared before the loop and cannot be inherited by exec.
for descriptor in /proc/self/fd/[0-9]*; do
    case "${descriptor##*/}" in
        0|1|2) ;;
        *) [[ ! -e $descriptor && ! -L $descriptor ]] || refuse fd-inheritance ;;
    esac
done
printf '%s\n' 'MRK_GNOME_NATIVE_ENTRY identity=nonroot-exact groups=empty capabilities=empty no_new_privileges=true user_mapping=initial-exact fd_inheritance=stdio-only'
exec -c /mrk-libtest --ignored --exact --test-threads=1 --color=never --nocapture asset_session::gnome_transport_fixture::real_gnome_session_transport_originals
