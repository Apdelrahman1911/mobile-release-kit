#!/bin/bash
# Fixed direct invocation and two original FIFO recorders; GitHub owns deadlines.
set -euo pipefail
[[ "$#" == 3 ]] || exit 2
role=$1
control_work=$2
control_python=$3
case "$role" in npm-ci|frontend-build|locked-dependency-fetch|application-libtest-build) ;; *) exit 2 ;; esac
"$control_python" -I -S -B "$control_work/macos_libtest_control.py" begin "$control_work" "$role"
builtin source "$control_work/$role-command.sh"
cd "$command_cwd"
# Each exact child is retained in its original Bash child table until one wait.
"$control_python" -I -S -B "$control_work/macos_libtest_control.py" record "$control_work" "$role" stdout &
stdout_original=$!
"$control_python" -I -S -B "$control_work/macos_libtest_control.py" record "$control_work" "$role" stderr &
stderr_original=$!
set +e
command_started_seconds=$SECONDS
/usr/bin/env -i "${command_environment[@]}" "${command[@]}" \
  > "$control_work/$role-stdout.fifo" 2> "$control_work/$role-stderr.fifo"
original_status=$?
command_elapsed_seconds=$((SECONDS - command_started_seconds))
"$control_python" -I -S -B "$control_work/macos_libtest_control.py" returned "$control_work" "$role" "$original_status" "$command_elapsed_seconds"
original_saved=$?
# Always settle both original recorders, independently of result-writer failure.
wait "$stdout_original"
stdout_return=$?
wait "$stderr_original"
stderr_return=$?
"$control_python" -I -S -B "$control_work/macos_libtest_control.py" end "$control_work" "$role" "$stdout_return" "$stderr_return"
completion_status=$?
[[ "$original_saved" == 0 ]] || exit 125
exit "$completion_status"
