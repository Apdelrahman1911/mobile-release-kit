#!/bin/bash
# Diagnostic direct calls only. GitHub's existing step supervises the pipeline.
set -euo pipefail
[[ "$#" == 3 ]] || exit 2
role=$1
control_work=$2
control_python=$3
case "$role" in npm-ci|frontend-build|resident-image-build|shipping-image-build) ;; *) exit 2 ;; esac
"$control_python" -I -S -B "$control_work/macos_cargo_control.py" begin "$control_work" "$role"
builtin source "$control_work/$role-command.sh"
cd "$command_cwd"
set +e
(
  set +e
  command_started_seconds=$SECONDS
  /usr/bin/env -i "${command_environment[@]}" "${command[@]}"
  original_status=$?
  command_elapsed_seconds=$((SECONDS - command_started_seconds))
  # Save the direct command status before any pipeline/sink status is examined.
  "$control_python" -I -S -B "$control_work/macos_cargo_control.py" returned "$control_work" "$role" "$original_status" "$command_elapsed_seconds"
  original_saved=$?
  if [[ "$original_saved" != 0 ]]; then exit 125; fi
  exit "$original_status"
) 2>&1 | "$control_python" -I -S -B "$control_work/macos_cargo_control.py" record "$control_work" "$role"
pipeline_status=("${PIPESTATUS[@]}")
# This array must be saved in one assignment immediately after the pipeline.
# Component0 is the shell group; the separately saved original is Cargo/npm.
"$control_python" -I -S -B "$control_work/macos_cargo_control.py" end "$control_work" "$role" "${pipeline_status[@]}"
completion_status=$?
exit "$completion_status"
