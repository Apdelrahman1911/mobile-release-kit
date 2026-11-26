# #46 — original first-connection investigation

Status on 2026-11-17: **unresolved; original failure not reproduced**. The failing
native predicate and a first-install race have not been identified. No readiness
wait, retry, timeout increase or inspection-policy relaxation was implemented.

## Actual installed application

The original signed `ac506bb3aa663b1389f21d2cc2ff4b9b21ad96e3` application was
restored after #45. All five restored code/signature hashes and the strict deep
signature were verified before these tests. Desktop was 0.1.4; Core was 0.3.0.

| Entry | User-state condition | Starts | First runtime | Reloads |
|---|---|---:|---|---:|
| Normal Applications / LaunchServices | Existing state | 1 | Available | 0 |
| Protected installed entry | Existing state | 3 | Available | 0 |
| Normal Applications / LaunchServices | Fresh WebKit directory | 1 | Available | 0 |
| Protected installed entry | Fresh WebKit directory for every start | 3 | Available | 0 |

The two normal-launch results were inspected in the actual application window.
The six direct-entry results were captured from the original process's first
capabilities result and catalogue completion. Each owned idle test process was
retired before the next case. No reload was invoked.

The original 22 WebKit files were moved recoverably before the fresh-state
experiment, then restored with their contents, ownership and modes verified.
Generated test state was preserved separately. Native app data, projects,
Keychain contents, helper registration and installation records were not reset.
Fresh WebKit state is **not** a fresh native installation or a fresh macOS user.

These eight passes are negative reproduction evidence. They do not demonstrate
that the original first-install failure has been fixed. The earlier native ACL,
account and bundle-metadata observations also returned successfully after the
historical incident; they contain no original failing syscall.

## Measurement limits

The first direct-entry driver overwrote its catalogue timestamp while polling.
Those three catalogue durations were withdrawn and are excluded from performance
results. The first-capabilities observations remain valid. The corrected fresh
WebKit driver recorded first capabilities in 3.219, 1.649 and 1.661 seconds, and
catalogue completion in 4.252, 2.784 and 2.896 seconds. These are individual warm
machine observations, not a startup baseline.

A read-only filesystem trace did not accompany a failing startup. Its bracketed
number parser was not validated against the formatter's descriptor fields;
purported errno counts are excluded from failure evidence.

## Fresh-install route examined

The original prepared artifact from [run 42930321870](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/42930321870)
was downloaded and checked against GitHub's service digest:

- Artifact 13821079751: 254,100,139 bytes; SHA-256
  `412c467c0c67da282d57981d46984b46c8c77423ff16e70eef54ad5acb0a9530`.
- The original finalized application package is bound to SHA-256
  `ed44a41a0b286ce831fe18c36e5178afbab492ce12e77aff294ce3dfaa0a4f15`.
- The archive contains two application packages, their finalization receipt,
  status and prepared-input manifest. It contains no completed removal package,
  removal producer descriptor/signature or removal disk image.
- Matching signed-remover intermediate artifact 13816754872 also verified:
  SHA-256 `bb7bf2ca6525f643e56c0e71abd95389da4318cfc8fbe7b28bd5e87be6d98312`.
  Its nested archive contains the signed binary and signing receipt. It is
  explicitly intermediate data, not a completed removal carrier or authority.

The original coordinator is explicitly disabled for further entry and its
consumed commands were not replayed. A bare remover binary is not substituted
for its authenticated completed-package input. The application's documented
removal route requires the matching completed package and preserves user data;
force-deleting the managed installation would bypass that route.

The current verification head examined was
`9440987cb28c52c37576d928ccd8b9ea4a491019`. Of its 32 changed files relative to
`ac506bb3`, 31 are outside the prepared-input consumer's harness allowlist,
including native/product inputs. Its strict compatibility guard therefore does
not admit this old prepared cohort. The guard and workflows were not edited,
and no fake producer facts, duplicate runs or published refs were created.

The earlier restriction on Mac installation/testing is no longer a blocker:
the owner explicitly authorized those operations. The remaining fresh-install
gap is an eligible authenticated test cohort/environment, followed by an actual
failing predicate. The eight installed starts do not replace that evidence.
Issue #46 remains open; no root-cause fix or passing regression for the original
incident is claimed.
