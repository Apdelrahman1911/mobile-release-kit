# Git remote credential channel — supporting slice

## Status and scope

This slice adds one **private original-owned descriptor route**, not Fetch,
Push, a credential provider, or a generic subprocess endpoint. Full Fetch is
still unavailable pending an enforceable aggregate staging bound and admission
of the exact Git HTTPS/helper/TLS closure. Push has a separate, unimplemented
pre-push guard/send-ACK requirement. No existing GitRead/GitLocal availability,
network policy, runtime profile, command, or UI changes here.

Root approved this limited extension; Credentials independently accepted its
plan. Actual source review and native qualification are separate. Neither a
version string nor the following passive tests authorizes a new native route.

Owned files:

- `src/mobile_release/_git_remote_command_channel.py`
- `tests/unit/test_git_remote_command_channel.py`
- this document and `git-remote-command-channel-hooks-20261020.patch`

The patch changes only `_native_process.py` and `_command_process.py` on the
Root integration branch. It is not applied to the agent's old parent files.
Ordinary `run_command` keeps its signature and behavior; the existing engine
body is shared, not copied. Ordinary three/eight-slot maps, account FD5,
creator/group/wait custody, error recording, and deadlines are unchanged.

## Exact original-map extension

1. `OriginalChannel` retains the original input's existing `FDLease`, cancellation
   owner, process/thread and single-command latch. **There is no production
   initial issuer in this slice.** The future separately reviewed
   `_desktop_git_remote_control.GitRemoteInput` must obtain the actual native
   socketpair endpoint from its original input map; it cannot construct a
   channel from a path, descriptor number, account DTO, or socket metadata.
2. Only private `_run_git_remote_command` consumes that exact input and its
   closed operation recipe. It freezes argv/environment before checking,
   admits one captured command with no signing/cleanup/callback modes, and
   consumes the attempt before owner callbacks. No public `pass_fds` exists.
3. The same original acquisition borrows/duplicates the endpoint atomically
   CLOEXEC at FD >=9. A returned duplicate is published into that acquisition's
   existing inventory. Lost return retains its root/borrow/UNKNOWN; it is not
   permission to close the source or try another duplicate.
4. The same original `CommandMapPermit` carries a sealed `SocketBinding` and
   exact source lease through O→C→A→W. Only map-v2 has nine slots; slot8 is the
   one O_RDWR socket. The original eight directions/kinds remain unchanged;
   map-v2 refuses an account-hold source at FD5. Equal-looking map or identity
   DATA cannot replace the retained objects.
5. The fixed loader carries canonical comparison metadata and map version;
   HELLO must match the parent's actual retained permit. Each helper adopts
   FD8 once through a **separate** closed socket path, not a widened `adopt_fd`.
   Socket fstat/access/identity are rechecked before and after CLOEXEC setup.
   UID/device/inode are only comparisons, including platforms returning zero
   inode/device for sockets; they are not peer authentication or original
   open-file-description proof.
6. C/A close their endpoint copies in their existing post-spawn close rosters.
   W alone makes its same mapped endpoint inheritable during its existing
   irreversible pre-exec effects, for stock Git's fixed admitted helper chain.
   Ordinary W has no ninth descriptor or inheritance effect.
7. O closes its exported duplicate through the original roster. The initial
   input endpoint remains with its input owner. **CommandCallEvidence does not
   prove credential-channel closure.** The future native operation must join
   its private IO, every inherited-copy EOF, original input close, and unchanged
   C/A/W management/runtime/source tails before retiring the token. Partial
   close or late failure remains UNKNOWN under those same owners.

This does not lengthen any clock. The future GitRemote operation uses its one
45/55-second original work/cleanup envelope; each nested command still has the
existing tighter three-second C/A/W cleanup grace. No new epoch or timer reset
is introduced by map selection, adoption, or forwarding. The added fixed lease
slots fit the existing 64-lease per-acquisition bound; no inventory cap is raised.

The native peer, shipped credential helper, once-only bounded get/store/erase
protocol, account/repository/consent rechecks, token zeroizing IO, and initial
GitRemote map issuer remain **unimplemented here**. They must be reviewed before
any route is usable. No secret is sent, read, stored or logged by these tests.

## Source findings that keep full Fetch unavailable

Only bounded public source was retrieved; none was installed or executed.
References are the official [Apple Git-155 tree][apple] and upstream
[Git 2.50.1 tree][upstream]. Apple `Git.plist` records upstream commit
`d82adb61ba2fd11d8f2587fca1b6bd7925ce4044`; twelve selected file blobs match
exactly, with Apple's `http.c` additionally guarding SSL-backend selection by
the macOS deployment target. This is **not a match to an installed CLT binary**.
The current GitRead CLT version range is not a remote-tool nomination.

- `remote-curl.c::fetch` falls back to the dumb HTTP walker when discovery is
  not smart. `GIT_SMART_HTTP=1` requests smart discovery; it does not require it.
  The fallback can write many loose objects, so a one-pack assumption is false.
- `fetch-pack.c` accepts an unsolicited `packfile-uris` section and launches
  `http-fetch` for its entries. Empty `fetch.uriProtocols` prevents advertising
  the feature but does not turn that response into a mandatory rejection.
  `protocol.version=0` is not an enforceable response-version firewall.
- In the ordinary single-smart-pack path, `index-pack` owns temporary pack/index
  files and optional reverse index/keep files. Disabling maintenance, tags,
  recursion, bundle/URI requests and reverse indexes removes normal extra work,
  **not the above server-controlled fallbacks**. A per-file RLIMIT, reservation,
  postscan, or short deadline cannot by itself enforce an aggregate disk cap.
  No direct-original-ODB download fallback is allowed.
- `credential.c` launches even an absolute helper with `use_shell`; its command
  includes the operation argument. The protected helper **and shell** belong
  in the admitted closure. The initial credential protocol can include known
  `capability[]` and `wwwauth[]` fields; a real helper's closed grammar must
  account for them within its original <=8KiB/8-field bounds.
- `http.c` uses `CURL_NETRC_OPTIONAL`. Actual private empty HOME/netrc custody,
  explicit empty proxy, no redirects, TLS verification, no ambient tracing or
  credential helpers, and exact credential-useHttpPath/HTTPS URL binding must
  be enforced. Existing native GitHub API TLS ownership does not qualify the
  separate protected `git-remote-https`/libcurl/CA closure.

The retained source-only manifest lists 874093 bytes over 26 unauthenticated,
bounded reads and each immutable URL/SHA256. It contains no user repository or
credentials. No source finding above authorizes Fetch or a new execution guard.

[apple]: https://github.com/apple-oss-distributions/Git/tree/6b2f9bfe72d6d4b5c9bcc1c2d0236c026d321cba
[upstream]: https://github.com/git/git/tree/d82adb61ba2fd11d8f2587fca1b6bd7925ce4044

## Verification

Author ran only the new passive suite against the exact two patched parent
projections: **21 tests passed in 0.040s**, caller exit0. Native creation, thread
start and actual FD/process effects are forbidden by this fixture. It exercises
the real map/adoption/lease/HELLO code against finite fake returned effects;
the fake future input exists only inside tests, never as production admission.

Covered: old map unchanged; foreign lease/equal DATA/wrong nonce/acquisition;
v1 upgrade and account mixing refusal; exact FD8 adoption/once-only close;
wrong fstat; setup/close/dup interruption and original exception preservation;
map-v2 duplication floor/destinations; HELLO downgrade; owner callback reentry;
pre/post-dup revocation; retained unknown borrow; absent issuer/no retry.

The initial run failed in a test-only global stat stub used by Path.resolve and
traceback. The fixture now delegates ordinary source metadata stat while faking
only `/dev/null`; production checks were not relaxed. Historical failure log is
retained. Four Python files also parsed. No real socket, child, Git, native ABI,
account, secret, remote, or network operation was tested. Actual Git/helper
inheritance, all-copy EOF, native resource joins and full Fetch remain pending.
