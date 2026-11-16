# macOS CLI status and read access (#50)

`mrk status` is an authenticated query to the running Desktop service. Read
access is deliberately off until explicitly allowed. `mrk version` and
`mrk capabilities` are offline compiled-interface queries, so their success
does not establish a running service or a read grant.

## Enable the intended read session

1. Keep Desktop open and select a saved project you intend the local tool to read.
2. Open **Project settings → Advanced · CLI / AI access**.
3. Choose **Check access**, then **Allow selected project for 1 hour**.
4. Run `mrk status --json`. Successful live status returns zero and describes a
   read session; `mrk projects --json` lists only the explicitly allowed projects.
5. **Turn off access**, expiration or closing Desktop ends that read session.
   No grant is restored automatically after reopening.

Read permission does not authorize builds, edits, Git mutations, uploads or
release actions. Those retain separate native permissions and one-use reviews.

For an explicit foreground cached read service, `mrk serve-history` is the
separate existing alternative. Its observations stay stale; it is not fresh
access, an action service or restored Desktop authorization.

## Error and source trace

An unavailable endpoint/service produces exit 3. The message now gives the exact
UI steps above and the cached-read alternative. A denied or expired authenticated
grant produces exit 4. Neither error calls for modifying state files, tokens,
permissions or configuration by hand. A path/ABI/transport refusal can also make
the endpoint unavailable; if explicit Allow does not resolve it, preserve the
failure and inspect it rather than recreating the service state.

`installed_cli.rs` parses `status` as `RequestBody::Info`; the installed Rust
client uses `installed_cli_ipc::request`, not the Python project CLI. The service
checks the original client/instance and live grant before producing `ServiceInfo`.
The status renderer is shared with the compiled data-only regression tests.
It distinguishes live Desktop status from foreground cached-history status and
keeps the separate-execution-permission caveat.

The retained old acceptance JSON confirms original return 3 but does not retain
an error payload. The issue's prose reason is therefore not treated as an exact
literal from the current source. Current source policy establishes the intended
gate; no default read access or automatic Allow was introduced.

## Verification and remaining installed gate

Three real shared Rust formatter/guidance tests pass. Fifty-eight frontend
read-access and Git-permission tests pass, including explicit Allow, enabled
status, revoke/late reply handling, expiry and project/session mismatches.
The final source check includes the current protocol module; an installed-cli
feature check is an additional final compilation gate.

The final integrated, signed CLI still needs an owner/authorized test-host
observation of default refusal → explicit Check/Allow → successful status →
revoke/expiry refusal. This task does not launch or modify the installed app,
create a real user grant, or build/distribute a release.
