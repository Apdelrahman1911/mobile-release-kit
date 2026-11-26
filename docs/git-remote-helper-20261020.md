# Fetch: fixed helper body and same-owner HTTP (supporting source slice)

This implements the protocol/HTTP portion of the accepted Fetch plan
`22efc84c92543d23092bb50f6ed1e8909250707dcee1e73c18ecbb09cc478544`.
It **does not enable Fetch** or install a native credential/helper entry. No
remote operation or installed CLT applicability was tested by this slice.
Push, pull and remote mutation remain outside this increment.

## Implemented, finite behavior

* `git_remote_wire.py`: bounded protocol-v2 advertisement, selected full-head
  ls-refs/want comparison and incremental packet framing. Ref-in-want and
  sideband-all follow the offered bytes. No haves, shallow/filter/URI request,
  unsolicited shallow/URI section, alternate service, protocol fallback or
  retry. Pack objects stay opaque; stock Git must validate them separately.
* `_desktop_git_remote_helper.py`: the actual fixed helper **body**, supplied
  with original private IO by the future admitted entry. It accepts only
  `capabilities` then `stateless-connect git-upload-pack`, advertises only
  `stateless-connect`, and relays one ls-refs and one reviewed fetch. It adds
  `0002` only after the same HTTP exchange returned through its close path;
  the final marker also waits for post-account/repository checks. Extra input
  after the final round is an error, not another request. Missing input, partial
  writes, STOP, late callbacks and unknown closes cannot retry the transcript.
* `git_remote_transport.py`: exact seven-request Apply schedule: API account,
  repository, Git advertisement, ls-refs, fetch, API account, repository.
  Selected login and immutable account/repository IDs are compared before and
  after, including the exact canonical HTTPS clone URL. This is not account
  discovery and never switches accounts. Metadata without a reviewed OID cannot
  authorize the transfer. A separate native Prepare entry is still required.

`Target` and `Transcript` are comparison DATA only. Neither supplies consent,
runtime/tool admission, a token, an original clock, native IO custody, process
settlement, repository publication or Store authority. Private callback seams
are for the eventual original input owner and inert tests, not public endpoints.
No fake native issuer or availability flag was added.

## Exact shared owner hook

`git-remote-helper-hooks-20261020.patch` changes only
`src/mobile_release/_github_connection_transport.py` (base file SHA
`5a55e8ed22fea67ae6f989090540c5e9a7bfb8c069c0b53f6ec3fa1bd29e2b50`).
Root alone applies it. It adds the private `GIT_REMOTE` profile and five fixed
roles; ordinary profiles, their role/path rules and budgets are unchanged.

The role chooses `api.github.com` or `github.com`, never a caller URL. The
existing SSLContext, held fixed CA, hostname/CERT_REQUIRED/TLS>=1.2/ALPN policy,
strict framing, cooldown/error handling, FixedConnection/FixedResponse and
one-attempt close/failure path remain the only HTTP owner. No curl, urllib,
redirect, proxy, netrc, cookie, default-CA loading or auth retry is introduced.
API requests retain private bearer auth; Git requests use private Basic auth
with the already selected login. Tokens/headers never enter result objects,
argv, environment, credential files, logs or public frames. Python copies and
the existing native String are **not** claimed end-to-end zeroized.

Git response media and request type are exact, with `Git-Protocol: version=2`
and identity encoding. Metadata bodies are at most256KiB, requests64KiB,
fetch body32MiB including framing/progress, seven requests/34MiB combined bodies.
Existing header/chunk/trailer bounds remain. A framed binary response also
observes the same original's clean TLS EOF before its finally close returns.

**There is no third32MiB spool.** Fetch uses only one <=65520-byte packet decoder
and <=4096-byte writes to the same helper-to-Git pipe, inside the exchange.
Metadata is separately bounded. A progress frame is private Git pipe content;
the later fixed Git command must discard/private-capture its stderr and never
publish remote progress or raw errors. Neither parsed packet completion nor
the helper's input EOF is a C/A/W/all-copy-EOF receipt.

The factory requires an existing same-instance budget, one-use factory claim,
original currentness callback and already bridged work endpoint no later than
original T+45. A tighter endpoint is preserved; none is rebuilt at helper
launch/get/POST. The future original input must derive that bridge from its
actual retained native45/55 clock and first-failure endpoint. Supplying numeric
timestamps or callbacks does not establish that authority. The original native
deadline/STOP and management joins still own blocking IO and cleanup.

## Remaining before an available native Fetch

1. Actual GitRemote input/FD8 native issuer with once-only bounded get and
   store/erase discard; exact ConnectionState/Doc/repository/consent binding,
   original peer IO and EOF from **all** inherited copies. The accepted map-v2
   supporting channel is not that issuer. No token source was added here.
2. Same admitted CLT/shell/Python/helper exec roster and bootstrap; its actual
   source nomination must match the examined stock Git path. Existing general
   CLT version/data lookup is not evidence of that match.
3. The approved original W-only FSIZE32MiB/CORE0 effect, exact source-derived
   two-content-inode/80MiB isolated output reservation and retained directory
   inventory. Wire/per-file caps alone are not an aggregate disk or RSS proof.
4. Fixed private stock Git fetch with `fetch.fsckObjects=true`, real connectivity
   and selected-layout validation; same-row Preparing/candidate ACK before any
   original ODB write. Same-filesystem publication keeps the original owned
   `.keep` durably fsynced **before** the first no-clobber pack/index link and
   retains it through exact tracking-ref CAS and all consumer joins.
5. Original source POST, runtime/management/FD closure, exact positive successor,
   final journal CAS and NativeUse retirement; pending/Unknown never retry or
   adopt arbitrary matching object filenames. Then genuine Prepare/review/Apply
   UI and native/installed qualification. No activation shortcut is implied.

## Focused evidence

Only inert byte/IO return tests are used: wire packets/caps/refs/sections,
actual helper-body round/marker ordering, original shared response delegates and
factory with forbidden real socket/TLS/file entry, fixed headers/host/CA options,
clamped clock, same private stream, identity drift, cooldown, partial write,
BaseException, duplicate entry and unknown-close refusal. Opaque synthetic PACK
bytes are deliberately not Git objects. No Git, network, process, native, real
credential, repository or provider operation was executed.

Run the three named modules with the exact one-parent patch applied to a public
source projection (or after Root integration): `test_git_remote_wire`,
`test_git_remote_transport`, `test_git_remote_helper`. The projection only
overrides that parent on `mobile_release.__path__`; original production files
remain unchanged. Root retains Cargo/native/installed test ownership.
