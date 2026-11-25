# macOS source performance baseline (#66)

This is an isolated source/test-runtime baseline on macOS arm64, Node
24.12.0. It is not an installed-app acceptance result. React renders without
running effects; no native service, helper, user project or credential is opened.
The source loader retains TypeScript/compiler code, so its RSS is not comparable
to the packaged WebView's footprint. No release/installer was built or installed.

## Reproduce

With the existing desktop dependencies installed, run from the repository root:

```sh
node --expose-gc desktop/tools/macos_performance_baseline.mjs
```

The tool emits only numeric metrics, fixed scope labels and runtime versions.
It compares the old and current path algorithms in one process (100 warmups,
25 samples of 100 comparisons), parses the real 512-change protocol, performs
10 batches of 1,000 controller construction/edit/subscription-retirement cycles,
and runs the actual workspace through a fresh source SSR process. Explicit GC
is used only for the test memory samples. There is no timing assertion in unit
tests and no claim of a universal device budget.

## Observations

| Measurement | Observed | Meaning |
|---|---:|---|
| 512 paths, repeated scans, median / p95 | 1.511 / 1.670 ms | Pre-change algorithm retained as the comparison fixture |
| 512 paths, membership set, median / p95 | 0.012 / 0.013 ms | Current linear lookup; no persistent cache |
| Real 512-change parser, median / p95 | 1.564 / 1.737 ms | Complete bounded validation and immutable projection |
| Source SSR import, two runs | 829–1,785 ms | Includes TypeScript source loading; host cache/JIT sensitive |
| First static workspace render, two runs | 29.3–36.5 ms | No DOM, layout, native connection or effects |
| Source renderer post-GC heap / RSS | 57.5 / 367.3 MiB | Includes the test source compiler and loaded modules |
| Source renderer idle CPU, 2-second interval | 4.47 ms CPU | A short Node idle observation, not app idle CPU |
| Post-GC heap across 10,000 controller cycles | 8.142–8.152 MiB | No growing retained controller heap in this bounded fixture |

The initial independent pre-change process measured 1.488 ms median for the same
512-path comparison. The optimized result is therefore consistent with the
same-process comparison, rather than an inferred startup improvement. Bounds
remain unchanged: 512 changes are admitted and 513 are refused by the real
parser. Larger real repositories still require native scan/working-set tests;
this fixture does not claim to measure disk traversal.

Full safe numeric receipt: [macos-essential-performance.json](macos-essential-performance.json).

## Remaining physical-Mac / installed gates

- Measure first paint, first capabilities response and helper-approval return on
  the final integrated candidate, cold and warm, with exact source and OS build.
- Sum the app, WebView and helper working sets/CPU after settling at idle and
  while opening a large synthetic project. Do not use this Node RSS as a budget.
- Run a real one-hour session with repeated project switches, reads, reviews,
  cancellations and recovery, checking that descriptors, tasks and memory settle.
- Profile the existing 3.79 MB frontend chunk in the actual WebView before
  selecting a loading/splitting change. Compilation warns about its size but
  does not establish a startup bottleneck by itself.
- Agree device-specific budgets with the owner after measurements. No arbitrary
  release gate or threshold is introduced by this branch.

These gates need an authorized installed/test candidate containing the combined
fixes, including the independent #47–#49 work. This task does not build, install,
modify, sign or publish that application, and does not perform that integration.

## Reopened macOS WebView lifecycle check

A disposable test-only Cocoa/WKWebView host loaded the actual current React App
and styles, with controlled finite native DATA. After the complete helper
approval/settings/focus-return sequence, it performed 100 App mount → Project
settings → Home → unmount cycles. Every cycle retired all native-event
subscriptions and left zero root DOM elements; no fatal boundary fired. The
original host returned 0 after 14.716 seconds. This checks real WebKit DOM and
effects, rather than SSR, but does not run the product's native workers/helper.
The output SHA-256 is
`29badf90425fd89894c46b6fe137c45f52f4db23efd3ebc34df689e7d2069de5`.

This short repeated-lifecycle observation is not a one-hour leak check or a
whole-app memory measurement. WebKit XPC processes are reparented outside the
host process group; the supervisor's host RSS omits them and is deliberately
not reported as application memory. No MRK process was running when checked,
and the installed app was not started, restarted or altered for this experiment.
The existing source path-comparison fix remains the only measured bottleneck
eliminated here. Original #66 installed-candidate and agreed-budget acceptance
is still incomplete.
