# Fixed trusted diagnostic bootstrap. No xtrace, caller command or tool probe.
set +x
set -euo pipefail
set +o posix
umask 077
unset CDPATH ENV BASH_ENV POSIXLY_CORRECT
export PATH=/usr/bin:/bin
fail() { printf 'MRK-H1 ERROR BOOTSTRAP\n'; exit 70; }
[[ ${GITHUB_EVENT_NAME-} == push && ${GITHUB_REF-} == refs/heads/verify/desktop-packaged-host-tools ]] || fail
[[ ${GITHUB_REPOSITORY-} == Apdelrahman1911/mobile-release-kit && ${RUNNER_ENVIRONMENT-} == github-hosted ]] || fail
[[ ${GITHUB_RUN_ID-} =~ ^[1-9][0-9]{0,19}$ && ${GITHUB_RUN_ATTEMPT-} == 1 ]] || fail
[[ ${GITHUB_SHA-} =~ ^[0-9a-f]{40}$ && ${GITHUB_SHA-} != 0000000000000000000000000000000000000000 ]] || fail
[[ ${GITHUB_WORKSPACE-} == /home/runner/work/mobile-release-kit/mobile-release-kit && ${RUNNER_TEMP-} == /home/runner/work/_temp ]] || fail
[[ ${GITHUB_EVENT_PATH-} == /home/runner/work/_temp/_github_workflow/event.json ]] || fail
[[ ${ImageOS-} =~ ^[A-Za-z0-9_.-]{1,32}$ && ${ImageVersion-} =~ ^[0-9]{8}\.[0-9]{1,6}\.[0-9]{1,6}$ ]] || fail
uuid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
[[ ${GITHUB_ENV-} =~ ^/home/runner/work/_temp/_runner_file_commands/set_env_${uuid}$ ]] || fail
[[ ${GITHUB_OUTPUT-} =~ ^/home/runner/work/_temp/_runner_file_commands/set_output_${uuid}$ ]] || fail
[[ ${GITHUB_PATH-} =~ ^/home/runner/work/_temp/_runner_file_commands/add_path_${uuid}$ ]] || fail
[[ ${GITHUB_STEP_SUMMARY-} =~ ^/home/runner/work/_temp/_runner_file_commands/step_summary_${uuid}$ ]] || fail
[[ $UID == "$EUID" && $EUID -gt 0 && -d /tmp && ! -L /tmp ]] || fail
[[ ${MRK_H1_PROGRAM+x} == x ]] || fail
readonly MRK_H1_PROGRAM
[[ ${MRK_H1_POLICY_B85+x} == x ]] || fail
readonly MRK_H1_POLICY_B85
[[ ${#MRK_H1_POLICY_B85} -eq 27665 ]] || fail
[[ ${#MRK_H1_PROGRAM} -eq 31171 ]] || fail
S="/tmp/mrk-packaged-host-tools-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
readonly S
[[ ! -e $S && ! -L $S ]] || fail
# Bash's non-POSIX ulimit -f units are 1024 bytes. Python reapplies exact bytes.
{ ulimit -v 524288 && ulimit -t 60 && ulimit -n 128 && ulimit -f 8192 && ulimit -c 0; } 2>/dev/null || fail
/usr/bin/mkdir -m 700 -- "$S" 2>/dev/null || fail
/usr/bin/mkdir -m 700 -- "$S/home" "$S/tmp" "$S/neutral" 2>/dev/null || fail
export HOME="$S/home" TMPDIR="$S/tmp" TMP="$S/tmp" TEMP="$S/tmp"
cd -- "$S/neutral" 2>/dev/null || fail
set -C
printf 'MRK-H1 SCRATCH %s\n' "$S"
start=$EPOCHREALTIME
set +e
{
  /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    HOME="$S/home" \
    TMPDIR="$S/tmp" \
    TMP="$S/tmp" \
    TEMP="$S/tmp" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    ImageOS="$ImageOS" \
    ImageVersion="$ImageVersion" \
    GITHUB_WORKSPACE=/home/runner/work/mobile-release-kit/mobile-release-kit \
    RUNNER_TEMP=/home/runner/work/_temp \
    GITHUB_ENV="$GITHUB_ENV" \
    GITHUB_OUTPUT="$GITHUB_OUTPUT" \
    GITHUB_PATH="$GITHUB_PATH" \
    GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
    GITHUB_EVENT_PATH=/home/runner/work/_temp/_github_workflow/event.json \
    GITHUB_SHA="$GITHUB_SHA" \
    GITHUB_REPOSITORY=Apdelrahman1911/mobile-release-kit \
    GITHUB_RUN_ID="$GITHUB_RUN_ID" \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_EVENT_NAME=push \
    RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_REF=refs/heads/verify/desktop-packaged-host-tools \
    MRK_H1_POLICY_B85="$MRK_H1_POLICY_B85" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 180s \
    /usr/bin/python3.12 -I -S -B - <<MRK_H1_PY
${MRK_H1_PROGRAM}
MRK_H1_PY
} >"$S/stdout.bin" 2>"$S/stderr.bin"
rc=$?
end=$EPOCHREALTIME
set -e
# This is the actual foreground timeout wait, not a later process-name search.
[[ $start =~ ^[0-9]{10,12}\.[0-9]{6}$ && $end =~ ^[0-9]{10,12}\.[0-9]{6}$ ]] || fail
{ printf '{"endUnix":"%s","schema":"mrk-h1-shell-wait-1","startUnix":"%s","status":%s}\n' "$end" "$start" "$rc" >"$S/wait.json"; } 2>/dev/null || fail
printf 'MRK-H1 OBSERVER-WAIT %s\n' "$rc"
if [[ $rc -ne 0 ]]; then
  # Closed failure labels only; original nonzero result is retained.
  case "$rc" in
    79) printf 'MRK-H1 OBSERVER-FAILURE CLEANUP_UNKNOWN\n' ;;
    80) printf 'MRK-H1 OBSERVER-FAILURE BOOTSTRAP_CONTEXT REFUSED\n' ;;
    81) printf 'MRK-H1 OBSERVER-FAILURE BOOTSTRAP_CONTEXT IO\n' ;;
    82) printf 'MRK-H1 OBSERVER-FAILURE BOOTSTRAP_CONTEXT DATA_OR_INTERNAL\n' ;;
    83) printf 'MRK-H1 OBSERVER-FAILURE EVENT REFUSED\n' ;;
    84) printf 'MRK-H1 OBSERVER-FAILURE EVENT IO\n' ;;
    85) printf 'MRK-H1 OBSERVER-FAILURE EVENT DATA_OR_INTERNAL\n' ;;
    86) printf 'MRK-H1 OBSERVER-FAILURE OWNED_SCRATCH REFUSED\n' ;;
    87) printf 'MRK-H1 OBSERVER-FAILURE OWNED_SCRATCH IO\n' ;;
    88) printf 'MRK-H1 OBSERVER-FAILURE OWNED_SCRATCH DATA_OR_INTERNAL\n' ;;
    89) printf 'MRK-H1 OBSERVER-FAILURE CANDIDATES REFUSED\n' ;;
    90) printf 'MRK-H1 OBSERVER-FAILURE CANDIDATES IO\n' ;;
    91) printf 'MRK-H1 OBSERVER-FAILURE CANDIDATES DATA_OR_INTERNAL\n' ;;
    92) printf 'MRK-H1 OBSERVER-FAILURE ENCODE REFUSED\n' ;;
    93) printf 'MRK-H1 OBSERVER-FAILURE ENCODE IO\n' ;;
    94) printf 'MRK-H1 OBSERVER-FAILURE ENCODE DATA_OR_INTERNAL\n' ;;
    95) printf 'MRK-H1 OBSERVER-FAILURE WRITE REFUSED\n' ;;
    96) printf 'MRK-H1 OBSERVER-FAILURE WRITE IO\n' ;;
    97) printf 'MRK-H1 OBSERVER-FAILURE WRITE DATA_OR_INTERNAL\n' ;;
    *) : ;;
  esac
  printf 'MRK-H1 ERROR OBSERVER_RETAINED\n'
  exit "$rc"
fi
# No body is sent here. The next fixed step must independently verify the
# original wait, identities, closed DTOs and empty capture EOF before framing.
