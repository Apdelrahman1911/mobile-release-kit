# One ordinary installed CLI / Desktop local-check journey

This is nonshipping observation source, **not a native pass or an availability
change**. Plan `8a046d77` was independently reviewed by Credentials. The lane
base is `274312883152ee91f8c2a006d1fd71a77f0c99d1`; the seven-parent integration
patch is based on Root `1bb859381ce7473020f92c3775904b864c623639` and preserves
the subsequent Git Upstream route and extracted workflow scripts.

## Fixed route and genuine operation

Called scope/case: `installed-cli-local-check`. Only the existing ARM
`installed-shell-observation` / `tool-setup` image admits it. The ordinary app,
ordinary CLI, Git image, service protocol, production grants and quotas are
unchanged. No new image, bootstrap, transport, process runner or public command
is introduced.

The existing native project picker and original snapshot select the existing
five-file `local-saved-offline` fixture. Its saved Android config explicitly
sets all three `projectChecks` arrays empty; services and iOS are disabled.
There is no Git repository, wrapper, project executable, artifact or credential.
The actual local-check engine must finish with its typed
`saved-local-android-project-checks` report. MISSING Gradle wrapper is an
expected finding, not an admission refusal or a release-readiness pass.

The same observer relay calls the genuine Document read Allow and named local
check Allow, through the existing Host and current saved observation. It does
not assign a grant, original, terminal, service instance or native receipt.
Seven ordinary installed `Contents/MacOS/mrk` processes run sequentially:

1. `observe PROJECT --json` reads the actual allowed observation.
2. `local-check PROJECT REVISION --json` is the **one** execution submission.
3. After the native original reaches terminal complete,
   `local-check-status PROJECT INSTANCE REQUEST --json` recovers it.
4. `local-check-cancel PROJECT INSTANCE REQUEST --json` makes a late STOP of
   that already-settled original; its full result must remain unchanged.
5. After genuine named and read revocation, `observe PROJECT --json` must
   return ordinary AccessDenied / exit 4.
6. After genuine READ-only re-Allow,
   `local-check-status PROJECT INSTANCE REQUEST --json` recovers the same
   result. Re-Allow takes its own fresh snapshot; status does not refresh it
   or authorize another execution.
7. `requests PROJECT --json` identifies the one retained local-check request.

Local-check sends Info then Submit, so this means **eight actual IPC
connections**, not seven. The final native comparison consumes the actual
existing Host shutdown report once and requires all eight workers joined with
no close failure. Normal original Quit, app return, thread return and fixture
readback must all complete. This does not test live interruption or an app
restart; both report fields are explicitly false.

## Same original files, callers and time limits

The fixture exclusively creates a short `.c-<12hex>` child of the actual
nonroot native home. The actual ordinary CLI HOME convention and actual Host
use that same held application-data directory; the runner socket path is 101
bytes, below the unchanged 104-byte limit. No endpoint, connection capability
or private state is copied, guessed or passed as a new CLI option.

The installed ordinary `mrk` and its parents are held and compared against the
same installed inventory/M/source originals, before every call and after the
sequence. Two held, no-follow, append-only 4 KiB files carry only public
comparison phases/IDs/digests. Each has one writer and at most four lines.
Each native-read phase line is additionally capped at 512 bytes **before** the
general JSON parser; native serialization uses the same smaller bound. The
4 KiB whole-file allowance does not authorize an arbitrary JSON allocation.
File DATA never replaces native permission, operation or shutdown evidence.

The existing `Fixtures/run_cases/run_owned` still owns the app. One retained
non-daemon fixture thread calls that same `run_owned` for the CLI sequence;
each call uses its own thread-local `cancellation=None` guard, never the main
thread's signal guard. A short lock records each numbered call before launch
and linearizes closing future admission; it is never held over a process or
thread join. Main error closes admission and attempts that original thread
join once. A preclaimed call may return under its existing timeout but cannot
permit a successor after failure. Unknown call/close/join leaves
`Fixtures.inflight` latched and prevents normal outer cleanup.

Unchanged limits: 120-second success endpoint, 135-second app call, existing
3-second cleanup and 138-second enclosing endpoint, established before the
thread starts. Each CLI call is at most 30 seconds and is clamped to the same
remaining success/hard endpoints, reserving cleanup plus one-second join
margin. Seven 128 KiB bounded captures are retained; each fixture side admits
at most 16 extra held FDs. There is no renewed deadline, retry, thread kill or
new cancellation source.

The seventh hook adds a conservative **256 KiB** observer DATA reservation to
the existing Document census, only in the compiled ARM tool image. The full
reservation persists for the image; absent/retired records earn no credit.
The existing service's 2 MiB `DOCUMENT_BACKING` is still charged separately.
The additional 64-bit native backing allowance is:

| Retained or simultaneously live data | KiB |
|---|---:|
| One typed original projection (at most 128 enum-only findings), access and origin copies | 32 |
| Typed report conversion plus one JSON value of at most 32 fixture findings | 64 |
| One at-most-512-byte phase JSON parse, including duplicate-key and map backing | 96 |
| Both 4 KiB phase prefixes, bounded read/serialization buffers and hash inputs | 32 |
| Sixteen FD/parent/name cells, paths, Record and fixed metadata/allocation rounding | 24 |
| Unused fixed headroom | 8 |
| **Total** | **256** |

The fixture report is capped at 8 KiB/32 findings before conversion to JSON;
the service's 64 KiB public report ABI is unchanged. The projection is typed,
not an arbitrary retained JSON tree. This accounts for collection/string
backing, not just `size_of`, and is not an RSS claim. Parent-process captures
and original process resources retain their existing separate limits.

## Seven Root hooks

`docs/installed-cli-observation-hooks-20261021.patch` contains only:

- Existing Mac observer: closed case/module/Record, same picker/snapshot,
  report comparison and fixed reservation accessor.
- Existing `tick_original` relay: dispatch the fixed CLI phase before the
  unchanged other phase arms; no new task.
- Existing shell exit: observe the once-returned actual Host shutdown report.
- Existing Aqua fixture driver: fixed case/files, held installed CLI and
  sequential-original/thread accounting.
- Existing current-runtime driver: tool-only scope and one-case completion.
- Existing `tool_service` workflow step: after the original service case
  returns successfully, call the one CLI case from the **same installed image**.
- Existing Document census: charge the fixed observer reserve without IO or
  taking an observer lock under Doc.

The future workflow command is:

```sh
"$MRK_PYTHON" -I -S -B desktop/tools/macos_identity_current_runtime.py \
  --target "$MRK_MACOS_TARGET" --scope installed-cli-local-check
```

The tool step remains 13 minutes. Its aggregate cap is tighter than the sum of
the individual worst-case bounds; this is not a promise that every worst case
fits. No new job, timeout or candidate scope activation is included. Current
Git13 work is unaffected. Root alone applies shared hooks, builds and dispatches.

## Verification and remaining work

All Python execution here is an explicit inert source projection: UID/GID
65534, private 0700 HOME/TMPDIR, empty environment, no capabilities, core dumps
off. Popen and socket construction are forbidden. Real small phase files and
the actual fixture thread are exercised; CLI/service/native replies are fake
DATA, never native evidence.

- Initial 16-test run: 14 methods passed; two subcases failed because an
  original append could fall between held/named full-stat samples. Failure
  logs and its small projection are retained. Identity checks stay strict;
  the reader now separately waits for a stable content sample. A deterministic
  append-between-stat regression was added.
- Corrected **17 tests passed in 0.746 s**, exit 0, no skips. Actual caller and
  all fixture threads returned. The successful projection was removed.
- Current Root union: only the three affected scope/current-driver tests were
  rerun, **3 passed in 0.094 s**, exit 0. The other 14 were not repeated. The
  successful 727,432-byte projection was removed after joined return.
- Four Python AST parses, six Rust syntax parses, YAML syntax and current
  Root patch apply/whitespace checks passed. These are not Rust typechecks.

Six native-module DATA tests are authored but **unrun**, under
`shell::installed_observation::cli::tests::`:

1. `only_the_fixed_tool_image_accepts_the_cli_fixture`
2. `phase_data_cannot_replace_origin_or_actual_complete_report`
3. `only_same_terminal_projection_and_saved_config_match_the_fixture`
4. `late_stop_comparison_keeps_full_original_report_not_just_pass_count`
5. `canonical_report_comparison_is_independent_of_map_insertion_order`
6. `actual_host_return_needs_all_eight_ipc_workers_and_no_close_failure`

Actual source review identified the need for the smaller pre-parse phase
bound. The second DATA test now checks all eight actual fixed phase shapes,
the valid 512-byte boundary, and overbound/empty rejection before parsing.
The whole-file/case/census limits and the tested Python source are unchanged.

They need the existing Mac debug lib-test feature graph (`desktop-shell`,
`custom-protocol`, `macos-installed-observation`, no development/publisher/
installer feature); they do not execute native APIs. The actual installed
journey still requires Root's combined compile, current signed/installed
tool-setup image and real seven callers/eight IPC joins. No build, native
journey, user repository, real account, remote operation or provider call was
performed by this lane.
