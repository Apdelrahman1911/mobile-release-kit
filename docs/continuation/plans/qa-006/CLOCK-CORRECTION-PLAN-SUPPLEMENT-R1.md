# Clock-correction R1: complete inherited pure-fixture inventory

This supplement is **plan-only** and must be reviewed together with
`SANDBOX-INHERITANCE-CLOCK-CORRECTION-PLAN-R1.md` (SHA256
`8f0d16050f95f13704d3aeb05a92a756a6f6a8b2ea1653b3db310130c0d77f96`).
It does not alter the clock design, verification proposals, limits or permissions.
No implementation or execution has started for this correction.

The initial package list must additionally include these **unchanged original
test fixtures**, not merely the nine runtime files and two test drivers:

| Relative file in the original/new package | Bytes | SHA256 |
| --- | ---: | --- |
| `legacy-r3-r3-snippets.txt` | 24172 | `34c721ab2720e74d89ade3a3ec06136d46d131e1e10b4f010406b546428fa4c6` |
| `selector-control-snapshots/SNAPSHOT.json` | 25573 | `abb6503fe36d442b229ed294a423e6fdabd507a49d4c2628d399c2544fa2226a` |
| `selector-control-snapshots/BASELINE.json` | 32910 | `9afd73ab899717857ecb8ccbac3be16d00fab3ef15836c965a686a473b69d691` |

Root's bounded static caller trace `190266`, actual exit0, found the real reads
at original `test_pure.py:1571–1572,2516,2810`; the source is178278 bytes with
SHA256 `81c2c0df5dd8cd17c4b81f602461e30acf8d91ff6f645bccedfa9c7d4d1404af`.
These files are already bound by the original `CODE-BINDINGS.json.semanticFiles`.
Copy only these exact regular-file bytes and their existing relative locations
after verifying those bindings. Do not regenerate, rewrite paths inside their
payloads, reinterpret the snapshots as a new source baseline or omit their tests.

Include their before/after bindings in the new complete implementation package.
Review the unchanged fixture consumers together with all actual BASE/path/grant
expectation changes. They supply fictional pure-test evidence only. Real native
source selection must continue using the independently bound original R6 controls,
not these copied fixtures. No source/index/cache payload is added to the pure
driver's allowed filesystem scope, and no native/pure quota is renewed.
