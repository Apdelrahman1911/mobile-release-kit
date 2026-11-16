# Production release — issue classification and agent assignments

Generated 2026-11-16 for Epic #18 (the single source of truth). This file is a snapshot: live status is in the issues' `status:*` labels and the Epic.
Difficulty labels `difficulty:1`–`difficulty:5`, and exactly one primary `category:*` label, are applied to every Epic issue. Each issue also carries an *Agent assignment* section in its description.

## How to use this

- Pick work for your role from the matrix; start only when the issue has no open blockers and you have announced it in the issue (`status:in-progress`).
- Never start two agents on overlapping files. Shared-file rules are in each issue and in the execution plan below.
- Difficulty ≥ 4 needs an independent agent review before merge; difficulty 5 and security work also need the Security Agent's review.
- Owner decisions are in Epic #18 §2; do not ask them again.

## Difficulty scale

1 Trivial · 2 Easy · 3 Moderate · 4 Hard · 5 Expert/Critical. Based on implementation complexity measured in the code, not priority. Code facts used: Rust under `desktop/src-tauri/src` is 987 files. Files named for macOS hold ~130k lines, against ~5k for Windows (mostly closed stubs) and ~4.6k for Linux. Android ~63k lines, Store ~28k, GitHub ~50k, vault ~13k; `App.tsx` 2,739 lines; `runtime.rs` 3,721 lines; Windows native crate ~24.8k lines.

### Status summary

| Total | Done | Ready | Blocked | In progress | Review |
|---|---|---|---|---|---|
| 72 | 5 | 6 | 61 | 0 | 0 |

### Difficulty distribution

| Level | Meaning | Issues | Count |
|---|---|---|---|
| 1 | Trivial | #19, #20, #21, #23, #24, #54, #70, #85, #86 | 9 |
| 2 | Easy | #22, #27, #28, #35, #44, #50, #52, #55, #56, #67, #74, #87 | 12 |
| 3 | Moderate | #29, #32, #33, #40, #41, #42, #58, #59, #60, #61, #66, #69, #73, #76, #77, #80, #83, #84 | 18 |
| 4 | Hard | #17, #25, #26, #31, #34, #38, #45, #46, #51, #53, #57, #62, #63, #64, #65, #68, #71, #72, #75, #78, #82, #90 | 22 |
| 5 | Expert/Critical | #30, #36, #37, #39, #43, #47, #48, #49, #79, #81, #89 | 11 |

### Issues by primary category

| Category | Label | Issues | Count |
|---|---|---|---|
| Windows Native & Packaging | `category:windows` | #31, #32, #33, #34, #35, #36, #38 | 7 |
| macOS Native & Packaging | `category:macos` | #17, #45, #46, #47, #48, #49, #50, #51, #72, #73 | 10 |
| Linux Native & Packaging | `category:linux` | #40, #41, #42, #44, #75, #76, #77 | 7 |
| Cross-Platform Architecture | `category:cross-platform` | #27, #71, #80, #82, #83, #90 | 6 |
| Android / iOS Tooling | `category:mobile-tooling` | #39, #78, #79 | 3 |
| Security & Cryptography | `category:security` | #30, #37, #43, #52, #81, #89 | 6 |
| CI/CD & Release Infrastructure | `category:ci-cd` | #25, #26, #53, #54, #55, #57, #68, #69, #87 | 9 |
| Testing & Quality Assurance | `category:testing` | #58, #59, #60, #61, #62, #63, #64, #65, #66, #84 | 10 |
| UI/UX | `category:ui-ux` | #28 | 1 |
| Documentation & Maintenance | `category:documentation` | #29, #56, #67, #86 | 4 |
| Research & Investigation | `category:research` | #74 | 1 |
| Owner Decisions & External Dependencies | `category:owner-decision` | #19, #20, #21, #22, #23, #24, #70, #85 | 8 |

### Agent roles, assignments and workload

| Agent | Issues | Open issues | Remaining implementation (agent-days) | Scope |
|---|---|---|---|---|
| CI/CD Agent | #25, #26, #53, #54, #55, #87 | 5 | 13 | Workflows, runner admission, release pipelines, attestations, branch hygiene. |
| Windows Agent | #33, #35, #36, #37, #38, #39, #81 | 7 | 60 | Windows app/native runtime: `desktop/src-tauri/src/*windows*`, `desktop/native/windows-installed-native/src` (non-packaging), Win32 security/token, DPAPI, WebView2. |
| Windows Packaging Agent | #31, #32, #34, #80 | 4 | 20 | MSI/WiX, custom-action DLL, Authenticode, Windows CLI install: `desktop/packaging/windows/**`, `transaction.cpp`. |
| macOS Agent | #17, #45, #46, #47, #50 | 5 | 28 | macOS installed runtime, helper/XPC, maintenance, frontend defect diagnosis: `desktop/src-tauri/src/*macos*`, `desktop/native/macos-installed-native`, `desktop/src` fixes. |
| macOS Packaging Agent | #48, #49, #51, #72, #73 | 5 | 34 | macOS build/sign/notarize, deployment targets, Intel builds, installer/remover, updates: `desktop/tools/macos_*`, `desktop/macos-installed-inputs`, `desktop/native/macos-installed-entry`, macOS workflows. |
| Linux Agent | #40, #42, #43, #78, #89 | 5 | 36 | Linux installed runtime, kernel/filesystem admission, Secret Service vault, Linux features: `desktop/src-tauri/src/*linux*`, `installed_runtime_data.rs`, Linux `cfg` blocks in `runtime.rs`, `desktop/native/linux-mount-observation`. |
| Linux Packaging Agent | #41, #44, #74, #75, #76, #77 | 6 | 29 | deb/rpm/Arch packages, maintainer scripts, distribution CI matrix: `desktop/packaging/debian/**`, `desktop/packaging/linux/**`, new rpm/arch packaging. |
| Cross-Platform Agent | #82, #83, #90 | 3 | 23 | Shared architecture: capability registry, user restrictions, data-removal action, version single source: shared Rust modules, `desktop/src` state/model, CLI command boundary. |
| GitHub Integration Agent | #71 | 1 | 10 | GitHub App device flow, PAT, GitHub API client across platforms: GitHub modules in `desktop/src-tauri/src`, vault adapters. |
| Store Agent | #79 | 1 | 20 | Google Play / App Store Connect operations: `local_store_*_owner.rs`, Store runtime, Python/fastlane bridge. |
| Security Agent | #30, #52 | 2 | 11 | Threat models, security reviews, signing-environment hardening; mandatory reviewer for difficulty-5 and security-category work. |
| Testing Agent | #58, #59, #60, #61, #62, #63, #64, #65, #66, #84 | 10 | 39 | Installed-app acceptance, recovery, performance, real-device journeys (with the owner). |
| UI/UX Agent | #28 | 1 | 3 | Production UI wording and presentation in `desktop/src` (after functional work lands). |
| Release Agent | #27, #29, #56, #57, #67, #68, #69, #86 | 7 | 20 | Versioning, notices, docs, release candidate, main merge and publication preparation. |
| Owner | #19, #20, #21, #22, #23, #24, #70, #85 | 5 | 2 | Decisions, external accounts/certificates, approvals, real-machine presence. |

_Effort = implementation agent-days only. CI time, external waiting (certificates, accounts) and real-device acceptance are listed separately per issue and are **not** included._

### Every issue

| # | Title | Status | Diff. | Primary category | Agent | Effort | Open blockers | Review req. | Owner |
|---|---|---|---|---|---|---|---|---|---|
| #17 | Diagnose GitCli(Checked) deadline locally before further CI verification | `blocked` | 4 | macOS Native & Packaging | macOS Agent | 6 agent-days (low confidence) | #26 | Yes | — |
| #19 | Decision: production feature scope and per-platform capability matrix | `done` | 1 | Owner Decisions & External Dependencies | Owner | — | none open | — | Yes |
| #20 | Decision: Desktop version, tag namespace, installers and channel (tag and release label PENDING) | `ready` | 1 | Owner Decisions & External Dependencies | Owner | 0.5 agent-days (high confidence) | none open | — | Yes |
| #21 | Decision: upgrade-support and user-data preservation policy | `done` | 1 | Owner Decisions & External Dependencies | Owner | — | none open | — | Yes |
| #22 | External: obtain a Windows Authenticode code-signing identity usable from CI | `blocked` | 2 | Owner Decisions & External Dependencies | Owner | 0.5 agent-days (high confidence) | none open | — | Yes |
| #23 | Decision: integrity and signing method for release checksums and the Linux package | `done` | 1 | Owner Decisions & External Dependencies | Owner | — | none open | — | Yes |
| #24 | External: confirm acceptance devices, test projects and accounts | `ready` | 1 | Owner Decisions & External Dependencies | Owner | 0.5 agent-days (high confidence) | none open | — | Yes |
| #25 | Integrate the Windows, Linux and macOS desktop branches into one release branch | `done` | 4 | CI/CD & Release Infrastructure | CI/CD Agent | — | none open | Yes | — |
| #26 | Run all platform pipelines on the release branch and establish a green baseline | `ready` | 4 | CI/CD & Release Infrastructure | CI/CD Agent | 3 agent-days (medium confidence) | none open | Yes | — |
| #27 | Single source of truth for the Desktop version across all packages | `blocked` | 2 | Cross-Platform Architecture | Release Agent | 3 agent-days (medium confidence) | #20, #26 | — | — |
| #28 | Replace pre-release wording in the app UI with production status text | `blocked` | 2 | UI/UX | UI/UX Agent | 3 agent-days (medium confidence) | #27, #36, #37, #38, #39, #42, #43, #45, #90 | — | — |
| #29 | Include complete third-party licence notices in the Windows and macOS packages | `blocked` | 3 | Documentation & Maintenance | Release Agent | 4 agent-days (medium confidence) | #26 | Yes | — |
| #30 | Security and dependency review of the release configuration | `blocked` | 5 | Security & Cryptography | Security Agent | 10 agent-days (low confidence) | #26, #81, #89 | Yes | Yes |
| #31 | Windows: convert the NONSHIPPING MSI into an installable production MSI | `blocked` | 4 | Windows Native & Packaging | Windows Packaging Agent | 6 agent-days (medium confidence) | #20, #26 | Yes | — |
| #32 | Windows: Authenticode-sign the executables, custom-action DLL and MSI in CI | `blocked` | 3 | Windows Native & Packaging | Windows Packaging Agent | 3 agent-days (medium confidence) | #22, #31, #52 | Yes | Yes |
| #33 | Windows: verify project selection and engine connection in the installed app | `blocked` | 3 | Windows Native & Packaging | Windows Agent | 5 agent-days (medium confidence) | #31 | — | — |
| #34 | Windows: test MSI upgrade, repair and uninstall with user-data preservation | `blocked` | 4 | Windows Native & Packaging | Windows Packaging Agent | 6 agent-days (medium confidence) | #33, #35, #83 | Yes | — |
| #35 | Windows: show startup refusals in a visible dialog (and point to the elevated mode) | `blocked` | 2 | Windows Native & Packaging | Windows Agent | 2 agent-days (high confidence) | #33 | — | — |
| #36 | Windows: enable configuration, release-version and metadata saving in the installed app | `blocked` | 5 | Windows Native & Packaging | Windows Agent | 15 agent-days (low confidence) | #26, #35 | Yes | — |
| #37 | Windows: implement an OS-backed credential vault | `blocked` | 5 | Security & Cryptography | Windows Agent | 10 agent-days (low confidence) | #36 | Yes | — |
| #38 | Windows: enable GitHub connection and workflow features in the installed app | `blocked` | 4 | Windows Native & Packaging | Windows Agent | 8 agent-days (medium confidence) | #36, #71 | Yes | — |
| #39 | Windows: enable environment diagnostics and Android build/sign operations | `blocked` | 5 | Android / iOS Tooling | Windows Agent | 12 agent-days (low confidence) | #36, #37 | Yes | — |
| #40 | Linux: remove the exact-kernel pin from the installed feature profiles | `blocked` | 3 | Linux Native & Packaging | Linux Agent | 4 agent-days (medium confidence) | #26 | Yes | — |
| #41 | Linux: test package upgrade, removal and purge with user-data preservation | `blocked` | 3 | Linux Native & Packaging | Linux Packaging Agent | 5 agent-days (medium confidence) | #44, #83 | Yes | — |
| #42 | Linux: run the installed workflow-apply, metadata-save and configuration-save cases | `blocked` | 3 | Linux Native & Packaging | Linux Agent | 4 agent-days (medium confidence) | #40, #71 | — | — |
| #43 | Linux: implement an OS-backed credential vault (Secret Service) | `blocked` | 5 | Security & Cryptography | Linux Agent | 8 agent-days (low confidence) | #40, #89 | Yes | — |
| #44 | Linux: production Debian package metadata and naming | `blocked` | 2 | Linux Native & Packaging | Linux Packaging Agent | 2 agent-days (high confidence) | #20, #26, #74 | — | — |
| #45 | macOS: diagnose and fix the frontend workspace error in the installed app | `blocked` | 4 | macOS Native & Packaging | macOS Agent | 5 agent-days (low confidence) | #26 | Yes | — |
| #46 | macOS: fix the installed runtime showing "unavailable" on first connection | `blocked` | 4 | macOS Native & Packaging | macOS Agent | 5 agent-days (low confidence) | #26 | Yes | — |
| #47 | macOS: fix the failed "Prepare and quit" maintenance shutdown | `blocked` | 5 | macOS Native & Packaging | macOS Agent | 10 agent-days (low confidence) | #26 | Yes | — |
| #48 | macOS: pass the hosted clean-install test (fix `original-correspondence` failure) | `blocked` | 5 | macOS Native & Packaging | macOS Packaging Agent | 8 agent-days (low confidence) | #26 | Yes | — |
| #49 | macOS: verify in-place update with data preservation | `blocked` | 5 | macOS Native & Packaging | macOS Packaging Agent | 10 agent-days (low confidence) | #48, #83 | Yes | — |
| #50 | macOS: installed CLI `status` returns 3 "Desktop read access not enabled" | `blocked` | 2 | macOS Native & Packaging | macOS Agent | 2 agent-days (high confidence) | #26 | — | — |
| #51 | macOS: produce a distributable signed and notarized package for GitHub Releases | `blocked` | 4 | macOS Native & Packaging | macOS Packaging Agent | 5 agent-days (medium confidence) | #20, #26, #72, #73 | Yes | — |
| #52 | Release infra: protect the signing environments (DEFERRED until before release — open security risk) | `blocked` | 2 | Security & Cryptography | Security Agent | 1 agent-days (high confidence) | none open | Yes | Yes |
| #53 | Release infra: workflow that assembles a draft GitHub Release from verified platform runs | `blocked` | 4 | CI/CD & Release Infrastructure | CI/CD Agent | 6 agent-days (medium confidence) | #20, #26 | Yes | — |
| #54 | Release infra: publish SHA256SUMS with verification instructions | `blocked` | 1 | CI/CD & Release Infrastructure | CI/CD Agent | 1 agent-days (high confidence) | #53 | — | — |
| #55 | Release infra: build-provenance attestations for every platform artifact | `blocked` | 2 | CI/CD & Release Infrastructure | CI/CD Agent | 2 agent-days (high confidence) | #31, #44, #51, #53 | — | — |
| #56 | Docs: install, upgrade and uninstall guides plus release-notes template | `blocked` | 2 | Documentation & Maintenance | Release Agent | 4 agent-days (medium confidence) | #20, #83 | — | — |
| #57 | Build the unified release candidate into a draft GitHub Release | `blocked` | 4 | CI/CD & Release Infrastructure | Release Agent | 3 agent-days (medium confidence) | #17, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36, #37, #38, #39, #40, #41, #42, #43, #44, #45, #46, #47, #48, #49, #50, #51, #52, #53, #54, #55, #56, #71, #72, #73, #75, #77, #78, #79, #80, #81, #82, #83, #89, #90 | Yes | — |
| #58 | Acceptance: Windows 11 x64 real-machine install and use | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 3 agent-days (medium confidence) | #24, #57, #80, #81 | — | Yes |
| #59 | Acceptance: Linux distribution matrix install and use | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 5 agent-days (medium confidence) | #24, #57, #74, #75, #76, #77, #80, #89 | — | Yes |
| #60 | Acceptance: macOS Apple Silicon owner install and use | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 2 agent-days (medium confidence) | #24, #57 | — | Yes |
| #61 | Acceptance: macOS Intel install and use | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 2 agent-days (medium confidence) | #24, #57, #72, #73 | — | Yes |
| #62 | Acceptance: Android project journeys on each supported platform | `blocked` | 4 | Testing & Quality Assurance | Testing Agent | 6 agent-days (medium confidence) | #24, #57, #78 | — | Yes |
| #63 | Acceptance: iOS project journeys on macOS | `blocked` | 4 | Testing & Quality Assurance | Testing Agent | 4 agent-days (medium confidence) | #24, #57, #90 | — | Yes |
| #64 | Acceptance: GitHub and Store journeys with real accounts (non-publishing) | `blocked` | 4 | Testing & Quality Assurance | Testing Agent | 5 agent-days (medium confidence) | #24, #57, #70, #71, #79 | Yes | Yes |
| #65 | Acceptance: crash, interruption and data-integrity recovery on installed builds | `blocked` | 4 | Testing & Quality Assurance | Testing Agent | 6 agent-days (medium confidence) | #57 | Yes | — |
| #66 | Acceptance: performance and resource baseline of installed builds | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 4 agent-days (medium confidence) | #57 | — | — |
| #67 | Final documentation and status update for the release | `blocked` | 2 | Documentation & Maintenance | Release Agent | 3 agent-days (medium confidence) | #56, #58, #59, #60, #61, #62, #63, #64, #65, #66, #84 | — | Yes |
| #68 | Merge the release branch into main and validate the merged commit | `blocked` | 4 | CI/CD & Release Infrastructure | Release Agent | 2 agent-days (medium confidence) | #67, #84 | Yes | Yes |
| #69 | Tag and publish the production GitHub Release | `blocked` | 3 | CI/CD & Release Infrastructure | Release Agent | 1 agent-days (high confidence) | #68 | Yes | Yes |
| #70 | External: register the GitHub App for desktop sign-in (device flow) | `ready` | 1 | Owner Decisions & External Dependencies | Owner | 0.5 agent-days (high confidence) | none open | — | Yes |
| #71 | GitHub sign-in on all platforms: App device flow plus optional personal access token | `blocked` | 4 | Cross-Platform Architecture | GitHub Integration Agent | 10 agent-days (medium confidence) | #26, #70 | Yes | — |
| #72 | macOS: support macOS 15 and newer (deployment target, APIs, packaging) | `ready` | 4 | macOS Native & Packaging | macOS Packaging Agent | 6 agent-days (medium confidence) | none open | Yes | — |
| #73 | macOS: production Intel (x86_64) build in the distributable package | `blocked` | 3 | macOS Native & Packaging | macOS Packaging Agent | 5 agent-days (medium confidence) | #26 | Yes | — |
| #74 | Linux: multi-distribution packaging strategy and evidence-based support matrix | `ready` | 2 | Research & Investigation | Linux Packaging Agent | 1 agent-days (high confidence) | none open | — | — |
| #75 | Linux: RPM package for the Fedora / RHEL family | `blocked` | 4 | Linux Native & Packaging | Linux Packaging Agent | 10 agent-days (low confidence) | #40, #74, #89 | Yes | — |
| #76 | Linux: package for distributions outside the Debian and Fedora families (format chosen by research) | `blocked` | 3 | Linux Native & Packaging | Linux Packaging Agent | 5 agent-days (low confidence) | #74 | — | — |
| #77 | Linux: widen Debian-family support (Ubuntu and Debian versions) | `blocked` | 3 | Linux Native & Packaging | Linux Packaging Agent | 6 agent-days (medium confidence) | #40, #74, #89 | — | — |
| #78 | Linux: enable local Android build and signing in the installed app | `blocked` | 4 | Android / iOS Tooling | Linux Agent | 8 agent-days (medium confidence) | #26, #40, #43 | Yes | — |
| #79 | Direct Google Play and App Store Connect operations from the desktop app on every capable platform | `blocked` | 5 | Android / iOS Tooling | Store Agent | 20 agent-days (low confidence) | #26, #37, #43, #90 | Yes | — |
| #80 | Windows and Linux: ship and verify the installed `mrk` CLI | `blocked` | 3 | Cross-Platform Architecture | Windows Packaging Agent | 5 agent-days (medium confidence) | #26, #31, #44 | — | — |
| #81 | Windows: user-controlled elevated (administrator) mode | `blocked` | 5 | Security & Cryptography | Windows Agent | 8 agent-days (low confidence) | #26, #35 | Yes | — |
| #82 | App permission configuration: user-configurable capability restrictions | `blocked` | 4 | Cross-Platform Architecture | Cross-Platform Agent | 8 agent-days (medium confidence) | #26 | Yes | — |
| #83 | All platforms: safe, explicit removal of retained user data | `blocked` | 3 | Cross-Platform Architecture | Cross-Platform Agent | 5 agent-days (medium confidence) | #26 | Yes | — |
| #84 | Acceptance: macOS 15 (oldest supported version) install and use | `blocked` | 3 | Testing & Quality Assurance | Testing Agent | 2 agent-days (medium confidence) | #57, #72 | — | Yes |
| #85 | Decision (deferred to the end): optional diagnostics, telemetry and crash reporting | `blocked` | 1 | Owner Decisions & External Dependencies | Owner | — | none open | — | Yes |
| #86 | Repository: SECURITY.md, support guidance, issue templates and private vulnerability reporting | `done` | 1 | Documentation & Maintenance | Release Agent | — | none open | — | — |
| #87 | Clean up obsolete development branches after their history is preserved | `blocked` | 2 | CI/CD & Release Infrastructure | CI/CD Agent | 1 agent-days (high confidence) | #26 | — | — |
| #89 | Linux: Btrfs root, oo7/new keyring services and portable kernel detection (security-reviewed) | `blocked` | 5 | Security & Cryptography | Linux Agent | 12 agent-days (low confidence) | #26 | Yes | — |
| #90 | All platforms: automatic capability detection — show only supported operations, enforce in the backend | `blocked` | 4 | Cross-Platform Architecture | Cross-Platform Agent | 10 agent-days (medium confidence) | #26 | Yes | — |

### Dependency-aware execution plan

1. **Ready now (implementation/research):** #26, #72, #74.
2. **Blocked directly by #26:** #17, #27, #29, #30, #31, #36, #40, #44, #45, #46, #47, #48, #50, #51, #53, #71, #73, #78, #79, #80, #81, #82, #83, #87, #89, #90.
3. **Can run simultaneously:** the agent streams in the batches below. They own separate files; shared files (`runtime.rs`, `App.tsx`, workflows) follow each issue's ownership rules: Windows edits stay in Windows `cfg` blocks, Linux in Linux blocks, workflow edits are serialized per file, and `App.tsx` edits are sequenced #90 → #82 → #28.
4. **Strictly sequential:** #26 → everything in Phase 2; #31 → #33 → #35 → #36 → #37 → #38/#39; #40 + #89 → #43 → #42/#78; #74 → #75/#76/#77; #48 → #49 → #51; #90 → #79 and #82; all Phase 2 → #28 → #57 → Phase 4 → #67 → #68 → #69.
5. **Critical path:** #26 → #31 → #33 → #35 → #36 → #37 → #38/#39 (+ #71, #79) → #28 → #30 → #57 → Phase 4 → #67 → #68 → #69. External gates before publication: #22 (Windows signing, deferred) and #52 (signing environment, deferred).
6. **High-risk, independent review mandatory (difficulty ≥ 4):** #17, #26, #30, #31, #34, #36, #37, #38, #39, #43, #45, #46, #47, #48, #49, #51, #53, #57, #64, #65, #68, #71, #72, #75, #78, #79, #81, #82, #89, #90. Difficulty-5 and security-category work also needs the Security Agent's review.
7. **Owner-only:** #20, #22, #24, #70, #85; plus approvals in #68, #69 and real-device sessions in #58–#64, #84.
8. **Execution batches (max five concurrent implementation agents):**

**Batch 1 — now (no #26 needed for this part)**
- CI/CD Agent: #26 green baseline (already assigned to the agent that did #25)
- macOS Agent: #45/#46/#47 diagnostic instrumentation on topic branches (code + unit tests; CI after #26)
- Security Agent: Threat-model designs for #89, #81, and vault identity for #37/#43 (design docs only)
- Cross-Platform Agent: #90 capability-registry design, then #82/#83 designs (no code until #26)
- Release Agent: #27 version inventory and #29 licence inventory (read-only); GitHub Integration Agent posts #70 permission list (small)

**Batch 2 — immediately after #26 is green**
- Windows Packaging Agent: #31 production MSI
- Windows Agent: #33 → #35
- Linux Agent: #40 → #89
- macOS Packaging Agent: #72 macOS 15 (workflow lines after #26) → #73
- macOS Agent: #45, #46, #47 with hosted reproduction

**Batch 3**
- Windows Agent: #36 Windows saving (critical path)
- Windows Packaging Agent: #34 → #80 (Windows part)
- Linux Packaging Agent: #44 → #77 → #41
- Cross-Platform Agent: #90 → #82
- macOS Packaging Agent: #48 → #49

**Batch 4**
- Windows Agent: #37 → #38 → #39
- Linux Agent: #43 → #42 → #78
- GitHub Integration Agent: #71
- Store Agent: #79 (after #90 and vaults)
- macOS Packaging Agent: #51; macOS Agent #17, #50 when free

**Batch 5**
- Windows Agent: #81 elevated mode
- Linux Packaging Agent: #75 RPM → #76 Arch; #80 Linux part
- Cross-Platform Agent: #83; Release Agent #27, #29, #56
- CI/CD Agent: #53 → #54, #55
- UI/UX Agent: #28 (last before RC); Security Agent #30 final review in parallel

**Then (sequential)**
- Release Agent: #57 release candidate (publication blocked until #22 and #52)
- Testing Agent + Owner: #58, #59, #60, #61, #84, #62, #63, #64, #65, #66
- Release Agent: #67 → #68 (owner approval) → #69 (owner approval); CI/CD Agent #87

### Per-issue details

#### #17 — Diagnose GitCli(Checked) deadline locally before further CI verification

- Status: `blocked` · Difficulty 4 · macOS Native & Packaging (secondary: Testing & Quality Assurance, CI/CD & Release Infrastructure)
- Agent: **macOS Agent** · Effort: 6 agent-days (low confidence) · Waiting: Hosted macOS runs ~90 min each; held Git CI groups
- Skills: Rust async/process supervision, macOS installed runtime, Git CLI driver
- Risks: Root cause unknown; retained log cannot separate slow call from earlier worker failure; flaky reproduction
- Files/modules: Git CLI driver modules (`git*` under `desktop/src-tauri/src`), `.github/workflows/desktop-macos-installed.yml` Git groups
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Installed `git-index-cli` and the 11 held Git groups pass with original call returns captured
- Independent review mandatory: yes · Owner involvement: no

#### #19 — Decision: production feature scope and per-platform capability matrix

- Status: `done` · Difficulty 1 · Owner Decisions & External Dependencies
- Agent: **Owner** · Effort: — · Waiting: —
- Skills: —
- Risks: —
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: —
- Validation: Decision recorded (closed)
- Independent review mandatory: no · Owner involvement: yes

#### #20 — Decision: Desktop version, tag namespace, installers and channel (tag and release label PENDING)

- Status: `ready` · Difficulty 1 · Owner Decisions & External Dependencies (secondary: CI/CD & Release Infrastructure)
- Agent: **Owner** · Effort: 0.5 agent-days (high confidence) · Waiting: Owner answer for OD-04b/OD-04e
- Skills: Release naming
- Risks: Tag clash with CLI `v0.1.x` tags
- Files/modules: Docs/workflows referencing the tag (after decision)
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Owner confirms tag and release label
- Independent review mandatory: no · Owner involvement: yes

#### #21 — Decision: upgrade-support and user-data preservation policy

- Status: `done` · Difficulty 1 · Owner Decisions & External Dependencies
- Agent: **Owner** · Effort: — · Waiting: —
- Skills: —
- Risks: —
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: —
- Validation: Decision recorded (closed)
- Independent review mandatory: no · Owner involvement: yes

#### #22 — External: obtain a Windows Authenticode code-signing identity usable from CI

- Status: `blocked` · Difficulty 2 · Owner Decisions & External Dependencies (secondary: Windows Native & Packaging, Security & Cryptography)
- Agent: **Owner** · Effort: 0.5 agent-days (high confidence) · Waiting: DEFERRED by owner; identity validation days–weeks once chosen
- Skills: Code-signing procurement
- Risks: Release blocker for Windows; eligibility limits; SmartScreen reputation
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Signing identity usable from CI recorded (non-secret IDs only)
- Independent review mandatory: no · Owner involvement: yes

#### #23 — Decision: integrity and signing method for release checksums and the Linux package

- Status: `done` · Difficulty 1 · Owner Decisions & External Dependencies
- Agent: **Owner** · Effort: — · Waiting: —
- Skills: —
- Risks: —
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: —
- Validation: Decision recorded (closed)
- Independent review mandatory: no · Owner involvement: yes

#### #24 — External: confirm acceptance devices, test projects and accounts

- Status: `ready` · Difficulty 1 · Owner Decisions & External Dependencies (secondary: Testing & Quality Assurance)
- Agent: **Owner** · Effort: 0.5 agent-days (high confidence) · Waiting: Owner arranges devices and Store/GitHub test accounts
- Skills: —
- Risks: Phase 4 cannot start without devices and accounts
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Device/account list confirmed
- Independent review mandatory: no · Owner involvement: yes

#### #25 — Integrate the Windows, Linux and macOS desktop branches into one release branch

- Status: `done` · Difficulty 4 · CI/CD & Release Infrastructure (secondary: Cross-Platform Architecture)
- Agent: **CI/CD Agent** · Effort: — · Waiting: —
- Skills: Git merge, multi-platform Rust/TS
- Risks: —
- Files/modules: Whole tree
- Blockers (all): none; open: none open · Parallel: —
- Validation: Done: integration reviewed (closed)
- Independent review mandatory: yes · Owner involvement: no

#### #26 — Run all platform pipelines on the release branch and establish a green baseline

- Status: `ready` · Difficulty 4 · CI/CD & Release Infrastructure (secondary: Testing & Quality Assurance)
- Agent: **CI/CD Agent** · Effort: 3 agent-days (medium confidence) · Waiting: CI: Windows ~25 min, Linux ~25 min, macOS ~90 min per run; reruns likely
- Skills: GitHub Actions, runner admission scripts, macOS commit tags
- Risks: Hard-coded branch names in admission checks; macOS 60-min observer timeouts; API rate limit
- Files/modules: All `.github/workflows/*desktop*`, `windows-installer-native-transaction.yml`, helper scripts with branch names
- Blockers (all): #25; open: none open · Parallel: No — critical path, sequential
- Validation: One SHA green on Windows, Linux, macOS and desktop-ci; recorded in Epic
- Independent review mandatory: yes · Owner involvement: no

#### #27 — Single source of truth for the Desktop version across all packages

- Status: `blocked` · Difficulty 2 · Cross-Platform Architecture (secondary: CI/CD & Release Infrastructure)
- Agent: **Release Agent** · Effort: 3 agent-days (medium confidence) · Waiting: —
- Skills: Cargo/npm/Tauri/WiX/Debian/Info.plist versioning
- Risks: Version strings scattered (Cargo, package.json, tauri conf, MSI, plists, Debian, release IDs `macos26`)
- Files/modules: `Cargo.toml`, `package.json`, `tauri*.conf.json`, packaging version fields, a check script
- Blockers (all): #20, #26; open: #20, #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: One source → 0.2.0 everywhere; CI check fails on drift
- Independent review mandatory: no · Owner involvement: no

#### #28 — Replace pre-release wording in the app UI with production status text

- Status: `blocked` · Difficulty 2 · UI/UX (secondary: Documentation & Maintenance)
- Agent: **UI/UX Agent** · Effort: 3 agent-days (medium confidence) · Waiting: —
- Skills: React/TypeScript, UX writing
- Risks: Must land last; wording must match real installed capability
- Files/modules: `desktop/src/App.tsx` (2,739 lines), footer/status components, tests
- Blockers (all): #19, #27, #36, #37, #38, #39, #42, #43, #45, #90; open: #27, #36, #37, #38, #39, #42, #43, #45, #90 · Parallel: No — critical path, sequential
- Validation: No pre-release/read-only wording on installed builds; snapshot tests
- Independent review mandatory: no · Owner involvement: no

#### #29 — Include complete third-party licence notices in the Windows and macOS packages

- Status: `blocked` · Difficulty 3 · Documentation & Maintenance (secondary: CI/CD & Release Infrastructure, Security & Cryptography)
- Agent: **Release Agent** · Effort: 4 agent-days (medium confidence) · Waiting: —
- Skills: Licence compliance, cargo-about/npm licence tooling, packaging
- Risks: Copyleft licence found in shipped binary needs owner escalation
- Files/modules: Notices generation scripts, Windows/macOS package inputs
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Complete notices in every package; licence inventory reviewed
- Independent review mandatory: yes · Owner involvement: no

#### #30 — Security and dependency review of the release configuration

- Status: `blocked` · Difficulty 5 · Security & Cryptography (secondary: Testing & Quality Assurance)
- Agent: **Security Agent** · Effort: 10 agent-days (low confidence) · Waiting: Waits for most implementation to land
- Skills: AppSec, Rust/Win32/macOS security, supply chain, threat modelling
- Risks: Large surface (987 Rust files); open #52 risk; critical/high must be fixed or owner-accepted
- Files/modules: Review only (+ `cargo audit`/`npm audit` config)
- Blockers (all): #26, #81, #89; open: #26, #81, #89 · Parallel: No — critical path, sequential
- Validation: Findings filed; critical/high fixed or owner risk-accepted; report linked from Epic
- Independent review mandatory: yes · Owner involvement: yes

#### #31 — Windows: convert the NONSHIPPING MSI into an installable production MSI

- Status: `blocked` · Difficulty 4 · Windows Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **Windows Packaging Agent** · Effort: 6 agent-days (medium confidence) · Waiting: Windows CI ~25 min/run
- Skills: WiX/MSI, custom actions (C++), WebView2 bootstrap, PATH
- Risks: Removing LaunchCondition 0/test MST without breaking SYSTEM guard; prerequisite handling
- Files/modules: `desktop/packaging/windows/**`, `desktop/native/windows-installed-native/src/transaction.cpp`, Windows workflow
- Blockers (all): #20, #26; open: #20, #26 · Parallel: No — critical path, sequential
- Validation: Double-click install on clean Windows 11 runner; installed-app job green
- Independent review mandatory: yes · Owner involvement: no

#### #32 — Windows: Authenticode-sign the executables, custom-action DLL and MSI in CI

- Status: `blocked` · Difficulty 3 · Windows Native & Packaging (secondary: Security & Cryptography, CI/CD & Release Infrastructure)
- Agent: **Windows Packaging Agent** · Effort: 3 agent-days (medium confidence) · Waiting: Blocked by deferred OD-06 (#22); provider onboarding
- Skills: Authenticode, signtool/provider CLI, OIDC
- Risks: Provider unknown; key never exposed
- Files/modules: Windows workflow signing step
- Blockers (all): #22, #31, #52; open: #22, #31, #52 · Parallel: Yes — within its agent stream once blockers close
- Validation: Signed EXE/DLL/MSI verify with `signtool verify /pa`
- Independent review mandatory: yes · Owner involvement: yes

#### #33 — Windows: verify project selection and engine connection in the installed app

- Status: `blocked` · Difficulty 3 · Windows Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **Windows Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Windows CI
- Skills: Rust/Tauri on Windows, Win32 file APIs
- Risks: Engine never exercised beyond window; project selection path untested
- Files/modules: Windows runtime modules, installed smoke script
- Blockers (all): #31; open: #31 · Parallel: No — critical path, sequential
- Validation: Installed app selects a fixture project and reads saved version in CI
- Independent review mandatory: no · Owner involvement: no

#### #34 — Windows: test MSI upgrade, repair and uninstall with user-data preservation

- Status: `blocked` · Difficulty 4 · Windows Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **Windows Packaging Agent** · Effort: 6 agent-days (medium confidence) · Waiting: Windows CI ~25 min/run
- Skills: MSI MajorUpgrade/repair semantics, data preservation
- Risks: Upgrade can drop per-user data or ACLs; downgrade refusal must be enforced
- Files/modules: `desktop/packaging/windows/**`, lifecycle tests
- Blockers (all): #21, #33, #35, #83; open: #33, #35, #83 · Parallel: Yes — within its agent stream once blockers close
- Validation: Upgrade 0.2.0→next keeps data; repair; uninstall keeps data; downgrade refused
- Independent review mandatory: yes · Owner involvement: no

#### #35 — Windows: show startup refusals in a visible dialog (and point to the elevated mode)

- Status: `blocked` · Difficulty 2 · Windows Native & Packaging (secondary: UI/UX)
- Agent: **Windows Agent** · Effort: 2 agent-days (high confidence) · Waiting: Windows CI
- Skills: Win32 dialogs, startup path
- Risks: Must coordinate with elevated mode (#81)
- Files/modules: Windows startup/admission (`security.rs` call site), message text
- Blockers (all): #33; open: #33 · Parallel: No — critical path, sequential
- Validation: Refused launches show a dialog; CI captures it
- Independent review mandatory: no · Owner involvement: no

#### #36 — Windows: enable configuration, release-version and metadata saving in the installed app

- Status: `blocked` · Difficulty 5 · Windows Native & Packaging (secondary: Cross-Platform Architecture)
- Agent: **Windows Agent** · Effort: 15 agent-days (low confidence) · Waiting: Windows CI
- Skills: Transactional file ownership on NTFS, Rust FFI, shared edit owner contracts
- Risks: Windows modules are closed stubs (~5k lines vs ~130k macOS); shared contracts must not regress macOS/Linux
- Files/modules: `desktop/src-tauri/src/*windows_closed*` → real implementations, `runtime.rs` Windows cfg blocks
- Blockers (all): #19, #26, #35; open: #26, #35 · Parallel: No — critical path, sequential
- Validation: Installed Windows saves configuration, release version and metadata with crash-safe writes
- Independent review mandatory: yes · Owner involvement: no

#### #37 — Windows: implement an OS-backed credential vault

- Status: `blocked` · Difficulty 5 · Security & Cryptography (secondary: Windows Native & Packaging)
- Agent: **Windows Agent** · Effort: 10 agent-days (low confidence) · Waiting: Windows CI
- Skills: DPAPI/Credential Manager, Rust Win32 FFI, vault format
- Risks: Credential confidentiality; per-user scope incl. elevated mode; vault format shared contract
- Files/modules: `asset_session_vault_windows_closed.rs` → implementation, vault adapters
- Blockers (all): #19, #36; open: #36 · Parallel: No — critical path, sequential
- Validation: Store/read/delete secrets; elevated session sees only the same user's vault; security review
- Independent review mandatory: yes · Owner involvement: no

#### #38 — Windows: enable GitHub connection and workflow features in the installed app

- Status: `blocked` · Difficulty 4 · Windows Native & Packaging (secondary: Cross-Platform Architecture)
- Agent: **Windows Agent** · Effort: 8 agent-days (medium confidence) · Waiting: Windows CI
- Skills: GitHub features on Windows, path/process handling
- Risks: Depends on #71 sign-in contract
- Files/modules: Windows GitHub feature gates in `runtime.rs`, GitHub modules' Windows paths
- Blockers (all): #19, #36, #71; open: #36, #71 · Parallel: No — critical path, sequential
- Validation: Installed Windows workflow-apply/setup journeys with mock GitHub
- Independent review mandatory: yes · Owner involvement: no

#### #39 — Windows: enable environment diagnostics and Android build/sign operations

- Status: `blocked` · Difficulty 5 · Android / iOS Tooling (secondary: Windows Native & Packaging)
- Agent: **Windows Agent** · Effort: 12 agent-days (low confidence) · Waiting: Windows CI; Android SDK download
- Skills: Android SDK/Gradle/JDK on Windows, process ownership, signing
- Risks: Android modules ~63k lines assume POSIX; keystore handling
- Files/modules: Android build owner Windows paths, environment diagnostics Windows impl
- Blockers (all): #19, #36, #37; open: #36, #37 · Parallel: No — critical path, sequential
- Validation: Installed Windows builds and signs a fixture Android project; cancel/recovery
- Independent review mandatory: yes · Owner involvement: no

#### #40 — Linux: remove the exact-kernel pin from the installed feature profiles

- Status: `blocked` · Difficulty 3 · Linux Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **Linux Agent** · Effort: 4 agent-days (medium confidence) · Waiting: Linux CI ~25 min/run
- Skills: Rust, kernel compatibility parsing
- Risks: 46 exact-kernel comparisons; parser rejects non-Ubuntu kernels
- Files/modules: `runtime.rs` Linux profiles, `installed_runtime_data.rs:179`
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Profiles enable on several kernels; parser tests per distro
- Independent review mandatory: yes · Owner involvement: no

#### #41 — Linux: test package upgrade, removal and purge with user-data preservation

- Status: `blocked` · Difficulty 3 · Linux Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **Linux Packaging Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Linux CI
- Skills: dpkg/rpm maintainer scripts
- Risks: No preinst; downgrade only warns
- Files/modules: `desktop/packaging/debian/**` maintainer scripts (+rpm later)
- Blockers (all): #21, #44, #83; open: #44, #83 · Parallel: Yes — within its agent stream once blockers close
- Validation: Upgrade keeps data; remove keeps data; purge documented; downgrade refused
- Independent review mandatory: yes · Owner involvement: no

#### #42 — Linux: run the installed workflow-apply, metadata-save and configuration-save cases

- Status: `blocked` · Difficulty 3 · Linux Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **Linux Agent** · Effort: 4 agent-days (medium confidence) · Waiting: Linux CI
- Skills: Installed Linux runtime cases
- Risks: Depends on kernel fix and sign-in
- Files/modules: Linux installed case scripts, Linux workflow
- Blockers (all): #19, #40, #71; open: #40, #71 · Parallel: Yes — within its agent stream once blockers close
- Validation: Installed workflow-apply, metadata-save, config-save pass
- Independent review mandatory: no · Owner involvement: no

#### #43 — Linux: implement an OS-backed credential vault (Secret Service)

- Status: `blocked` · Difficulty 5 · Security & Cryptography (secondary: Linux Native & Packaging)
- Agent: **Linux Agent** · Effort: 8 agent-days (low confidence) · Waiting: Linux CI
- Skills: Secret Service/D-Bus, provider identity, Rust
- Risks: Current admission pins one gnome-keyring hash; must support oo7/KWallet without weakening
- Files/modules: Linux vault modules, `secret*` modules, vendored secret-service/zbus
- Blockers (all): #19, #40, #89; open: #40, #89 · Parallel: Yes — within its agent stream once blockers close
- Validation: Vault works on GNOME Keyring/oo7/KWallet; survives provider updates; security review
- Independent review mandatory: yes · Owner involvement: no

#### #44 — Linux: production Debian package metadata and naming

- Status: `blocked` · Difficulty 2 · Linux Native & Packaging (secondary: Documentation & Maintenance)
- Agent: **Linux Packaging Agent** · Effort: 2 agent-days (high confidence) · Waiting: —
- Skills: Debian packaging metadata
- Risks: Provisional maintainer (OD-11) must be flagged
- Files/modules: `desktop/packaging/debian/control` and docs
- Blockers (all): #20, #26, #74; open: #20, #26, #74 · Parallel: Yes — within its agent stream once blockers close
- Validation: lintian clean; production description and naming
- Independent review mandatory: no · Owner involvement: no

#### #45 — macOS: diagnose and fix the frontend workspace error in the installed app

- Status: `blocked` · Difficulty 4 · macOS Native & Packaging (secondary: UI/UX, Testing & Quality Assurance)
- Agent: **macOS Agent** · Effort: 5 agent-days (low confidence) · Waiting: Hosted macOS runs ~90 min
- Skills: React error boundaries, Tauri events, macOS helper state
- Risks: Cause unknown; only reproduced once after helper approval
- Files/modules: `desktop/src/main.tsx`, App state handling of helper status, local error record
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Error record + state-transition tests; reproduction attempt on hosted runner
- Independent review mandatory: yes · Owner involvement: no

#### #46 — macOS: fix the installed runtime showing "unavailable" on first connection

- Status: `blocked` · Difficulty 4 · macOS Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **macOS Agent** · Effort: 5 agent-days (low confidence) · Waiting: Hosted macOS runs
- Skills: macOS installed runtime inspection
- Risks: Fixed category hides failing step
- Files/modules: `installed_runtime_macos.rs` (AdmissionFailure::Native step codes)
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: First-launch connection evidence on hosted clean install
- Independent review mandatory: yes · Owner involvement: no

#### #47 — macOS: fix the failed "Prepare and quit" maintenance shutdown

- Status: `blocked` · Difficulty 5 · macOS Native & Packaging (secondary: Security & Cryptography, Testing & Quality Assurance)
- Agent: **macOS Agent** · Effort: 10 agent-days (low confidence) · Waiting: Hosted macOS runs; five prior diagnostic runs failed
- Skills: XPC/NSXPC, ServiceManagement, root helper lifecycle
- Risks: Root cause unknown; custody/finality checks must not weaken
- Files/modules: `android_maintenance_client.rs`, helper sources, `macos-installed-native`
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Prepare-and-quit passes on hosted reproduction and later on owner Mac (#60)
- Independent review mandatory: yes · Owner involvement: no

#### #48 — macOS: pass the hosted clean-install test (fix `original-correspondence` failure)

- Status: `blocked` · Difficulty 5 · macOS Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **macOS Packaging Agent** · Effort: 8 agent-days (low confidence) · Waiting: Hosted macOS runs ~90 min
- Skills: macOS installer correspondence checks, pkg scripts
- Risks: `original-correspondence` object unknown; Xcode-ownership host setup issue
- Files/modules: macOS installer/entry, `desktop/tools/macos_*`, workflow
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Hosted clean install passes on release branch
- Independent review mandatory: yes · Owner involvement: no

#### #49 — macOS: verify in-place update with data preservation

- Status: `blocked` · Difficulty 5 · macOS Native & Packaging (secondary: Testing & Quality Assurance)
- Agent: **macOS Packaging Agent** · Effort: 10 agent-days (low confidence) · Waiting: Hosted macOS runs
- Skills: macOS update/migration, storage budgets
- Risks: Update failed twice historically; data preservation
- Files/modules: macOS installer update paths, archive conservation
- Blockers (all): #21, #48, #83; open: #48, #83 · Parallel: Yes — within its agent stream once blockers close
- Validation: In-place update 0.2.0→next keeps all data; downgrade refused
- Independent review mandatory: yes · Owner involvement: no

#### #50 — macOS: installed CLI `status` returns 3 "Desktop read access not enabled"

- Status: `blocked` · Difficulty 2 · macOS Native & Packaging (secondary: UI/UX)
- Agent: **macOS Agent** · Effort: 2 agent-days (high confidence) · Waiting: —
- Skills: CLI/service protocol
- Risks: Designed refusal, mostly guidance + verifying enabled path
- Files/modules: `service_protocol.rs` message, CLI docs
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Enabled read-access path verified; clear message
- Independent review mandatory: no · Owner involvement: no

#### #51 — macOS: produce a distributable signed and notarized package for GitHub Releases

- Status: `blocked` · Difficulty 4 · macOS Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **macOS Packaging Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Signing + notarization ~90 min
- Skills: pkgbuild/productbuild, notarization, naming
- Risks: Remove engineering/diagnostic variants without breaking verifiers
- Files/modules: `desktop/tools/macos_*`, macOS workflows
- Blockers (all): #20, #26, #72, #73; open: #20, #26, #72, #73 · Parallel: Yes — within its agent stream once blockers close
- Validation: Production pkg (arm64+x86_64, macOS 15+) notarized and stapled
- Independent review mandatory: yes · Owner involvement: no

#### #52 — Release infra: protect the signing environments (DEFERRED until before release — open security risk)

- Status: `blocked` · Difficulty 2 · Security & Cryptography (secondary: CI/CD & Release Infrastructure, Owner Decisions & External Dependencies)
- Agent: **Security Agent** · Effort: 1 agent-days (high confidence) · Waiting: DEFERRED by owner until before release
- Skills: GitHub environments, deployment rules
- Risks: Open exposure of Apple signing secrets
- Files/modules: Repository settings (owner applies)
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Branch rules/reviewers set; workflows still sign
- Independent review mandatory: yes · Owner involvement: yes

#### #53 — Release infra: workflow that assembles a draft GitHub Release from verified platform runs

- Status: `blocked` · Difficulty 4 · CI/CD & Release Infrastructure (secondary: CI/CD & Release Infrastructure)
- Agent: **CI/CD Agent** · Effort: 6 agent-days (medium confidence) · Waiting: Full pipeline runs
- Skills: GitHub Actions, artifact provenance, release API
- Risks: Must consume only verified run artifacts; no publication
- Files/modules: New release workflow
- Blockers (all): #20, #26; open: #20, #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Draft release assembled from verified runs on a test tag
- Independent review mandatory: yes · Owner involvement: no

#### #54 — Release infra: publish SHA256SUMS with verification instructions

- Status: `blocked` · Difficulty 1 · CI/CD & Release Infrastructure
- Agent: **CI/CD Agent** · Effort: 1 agent-days (high confidence) · Waiting: —
- Skills: Checksums
- Risks: —
- Files/modules: Release workflow step, docs
- Blockers (all): #23, #53; open: #53 · Parallel: Yes — within its agent stream once blockers close
- Validation: `sha256sum -c` passes on downloaded assets
- Independent review mandatory: no · Owner involvement: no

#### #55 — Release infra: build-provenance attestations for every platform artifact

- Status: `blocked` · Difficulty 2 · CI/CD & Release Infrastructure (secondary: Security & Cryptography)
- Agent: **CI/CD Agent** · Effort: 2 agent-days (high confidence) · Waiting: —
- Skills: actions/attest-build-provenance
- Risks: Must cover every asset
- Files/modules: Platform workflows
- Blockers (all): #31, #44, #51, #53; open: #31, #44, #51, #53 · Parallel: Yes — within its agent stream once blockers close
- Validation: `gh attestation verify` passes for each asset
- Independent review mandatory: no · Owner involvement: no

#### #56 — Docs: install, upgrade and uninstall guides plus release-notes template

- Status: `blocked` · Difficulty 2 · Documentation & Maintenance
- Agent: **Release Agent** · Effort: 4 agent-days (medium confidence) · Waiting: —
- Skills: Technical writing
- Risks: Must match verified behaviour per platform
- Files/modules: `docs/`, `desktop/packaging/*/README.md`
- Blockers (all): #19, #20, #21, #83, #86; open: #20, #83 · Parallel: Yes — within its agent stream once blockers close
- Validation: Guides reviewed against installed behaviour
- Independent review mandatory: no · Owner involvement: no

#### #57 — Build the unified release candidate into a draft GitHub Release

- Status: `blocked` · Difficulty 4 · CI/CD & Release Infrastructure (secondary: Testing & Quality Assurance)
- Agent: **Release Agent** · Effort: 3 agent-days (medium confidence) · Waiting: All pipelines ~2–3 h; blocked by #22/#52 for publication
- Skills: Release orchestration
- Risks: Integrating many streams; any red pipeline blocks
- Files/modules: Release workflow inputs, Epic
- Blockers (all): #17, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36, #37, #38, #39, #40, #41, #42, #43, #44, #45, #46, #47, #48, #49, #50, #51, #52, #53, #54, #55, #56, #71, #72, #73, #75, #77, #78, #79, #80, #81, #82, #83, #89, #90; open: #17, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36, #37, #38, #39, #40, #41, #42, #43, #44, #45, #46, #47, #48, #49, #50, #51, #52, #53, #54, #55, #56, #71, #72, #73, #75, #77, #78, #79, #80, #81, #82, #83, #89, #90 · Parallel: No — critical path, sequential
- Validation: Draft release with all assets, checksums, attestations
- Independent review mandatory: yes · Owner involvement: no

#### #58 — Acceptance: Windows 11 x64 real-machine install and use

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance (secondary: Windows Native & Packaging)
- Agent: **Testing Agent** · Effort: 3 agent-days (medium confidence) · Waiting: Real Windows 11 x64 device (owner)
- Skills: Windows acceptance
- Risks: Device availability; UAC/elevated flows
- Files/modules: Acceptance checklist
- Blockers (all): #24, #57, #80, #81; open: #24, #57, #80, #81 · Parallel: Yes — within its agent stream once blockers close
- Validation: Checklist evidence on real Windows 11
- Independent review mandatory: no · Owner involvement: yes

#### #59 — Acceptance: Linux distribution matrix install and use

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance (secondary: Linux Native & Packaging)
- Agent: **Testing Agent** · Effort: 5 agent-days (medium confidence) · Waiting: VMs for every matrix distribution
- Skills: Linux desktop acceptance
- Risks: Many distros; Wayland/X11
- Files/modules: Acceptance checklist
- Blockers (all): #24, #57, #74, #75, #76, #77, #80, #89; open: #24, #57, #74, #75, #76, #77, #80, #89 · Parallel: Yes — within its agent stream once blockers close
- Validation: Evidence per distribution claimed
- Independent review mandatory: no · Owner involvement: yes

#### #60 — Acceptance: macOS Apple Silicon owner install and use

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance (secondary: macOS Native & Packaging)
- Agent: **Testing Agent** · Effort: 2 agent-days (medium confidence) · Waiting: Owner Mac session; guided ac506 removal only on instruction
- Skills: macOS acceptance
- Risks: Owner presence for password/approvals
- Files/modules: Acceptance checklist
- Blockers (all): #24, #57; open: #24, #57 · Parallel: Yes — within its agent stream once blockers close
- Validation: Owner-machine checklist passes
- Independent review mandatory: no · Owner involvement: yes

#### #61 — Acceptance: macOS Intel install and use

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance (secondary: macOS Native & Packaging)
- Agent: **Testing Agent** · Effort: 2 agent-days (medium confidence) · Waiting: Intel Mac availability
- Skills: macOS Intel acceptance
- Risks: Hardware availability
- Files/modules: Acceptance checklist
- Blockers (all): #24, #57, #72, #73; open: #24, #57, #72, #73 · Parallel: Yes — within its agent stream once blockers close
- Validation: Intel checklist evidence
- Independent review mandatory: no · Owner involvement: yes

#### #62 — Acceptance: Android project journeys on each supported platform

- Status: `blocked` · Difficulty 4 · Testing & Quality Assurance (secondary: Android / iOS Tooling)
- Agent: **Testing Agent** · Effort: 6 agent-days (medium confidence) · Waiting: Real Android projects/SDKs on 3 OSes
- Skills: Android Gradle builds/signing
- Risks: SDK/JDK variance
- Files/modules: Fixture projects
- Blockers (all): #19, #24, #57, #78; open: #24, #57, #78 · Parallel: Yes — within its agent stream once blockers close
- Validation: Android journeys pass per platform
- Independent review mandatory: no · Owner involvement: yes

#### #63 — Acceptance: iOS project journeys on macOS

- Status: `blocked` · Difficulty 4 · Testing & Quality Assurance (secondary: Android / iOS Tooling)
- Agent: **Testing Agent** · Effort: 4 agent-days (medium confidence) · Waiting: Owner signing material on Mac
- Skills: Xcode archive/export, ASC
- Risks: Signing material availability
- Files/modules: Fixture iOS project
- Blockers (all): #24, #57, #90; open: #24, #57, #90 · Parallel: Yes — within its agent stream once blockers close
- Validation: iOS journeys on macOS; hidden on Win/Linux
- Independent review mandatory: no · Owner involvement: yes

#### #64 — Acceptance: GitHub and Store journeys with real accounts (non-publishing)

- Status: `blocked` · Difficulty 4 · Testing & Quality Assurance (secondary: Android / iOS Tooling, Security & Cryptography)
- Agent: **Testing Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Real Play/ASC/GitHub test accounts
- Skills: Store/GitHub journeys
- Risks: Must never publish to production
- Files/modules: Test accounts (owner)
- Blockers (all): #19, #24, #57, #70, #71, #79; open: #24, #57, #70, #71, #79 · Parallel: Yes — within its agent stream once blockers close
- Validation: Non-publishing Store and GitHub journeys pass incl. cross-platform upload proof
- Independent review mandatory: yes · Owner involvement: yes

#### #65 — Acceptance: crash, interruption and data-integrity recovery on installed builds

- Status: `blocked` · Difficulty 4 · Testing & Quality Assurance (secondary: Cross-Platform Architecture)
- Agent: **Testing Agent** · Effort: 6 agent-days (medium confidence) · Waiting: CI per platform
- Skills: Fault injection, crash recovery
- Risks: Hard-to-reproduce interrupts
- Files/modules: Test harnesses
- Blockers (all): #57; open: #57 · Parallel: Yes — within its agent stream once blockers close
- Validation: Kill/interrupt during operations never corrupts project files
- Independent review mandatory: yes · Owner involvement: no

#### #66 — Acceptance: performance and resource baseline of installed builds

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance
- Agent: **Testing Agent** · Effort: 4 agent-days (medium confidence) · Waiting: Real devices
- Skills: Profiling
- Risks: Budgets defined by agents (OD-16)
- Files/modules: Measurement scripts
- Blockers (all): #57; open: #57 · Parallel: Yes — within its agent stream once blockers close
- Validation: Budgets documented and met
- Independent review mandatory: no · Owner involvement: no

#### #67 — Final documentation and status update for the release

- Status: `blocked` · Difficulty 2 · Documentation & Maintenance
- Agent: **Release Agent** · Effort: 3 agent-days (medium confidence) · Waiting: —
- Skills: Docs, release notes
- Risks: Must state exactly what was verified
- Files/modules: `docs/`, `README.md`, release notes
- Blockers (all): #56, #58, #59, #60, #61, #62, #63, #64, #65, #66, #84, #86; open: #56, #58, #59, #60, #61, #62, #63, #64, #65, #66, #84 · Parallel: No — critical path, sequential
- Validation: Docs match evidence
- Independent review mandatory: no · Owner involvement: yes

#### #68 — Merge the release branch into main and validate the merged commit

- Status: `blocked` · Difficulty 4 · CI/CD & Release Infrastructure (secondary: Testing & Quality Assurance)
- Agent: **Release Agent** · Effort: 2 agent-days (medium confidence) · Waiting: Full pipelines on main ~2–3 h; owner approval
- Skills: Git, branch protection, verification
- Risks: Linear history; tested commit must equal released commit
- Files/modules: PR to main, history tag
- Blockers (all): #67, #84; open: #67, #84 · Parallel: No — critical path, sequential
- Validation: All pipelines green on the main squash commit
- Independent review mandatory: yes · Owner involvement: yes

#### #69 — Tag and publish the production GitHub Release

- Status: `blocked` · Difficulty 3 · CI/CD & Release Infrastructure
- Agent: **Release Agent** · Effort: 1 agent-days (high confidence) · Waiting: Owner final approval
- Skills: GitHub Releases
- Risks: Accidental publication
- Files/modules: Release
- Blockers (all): #68; open: #68 · Parallel: No — critical path, sequential
- Validation: Published assets verify from clean download
- Independent review mandatory: yes · Owner involvement: yes

#### #70 — External: register the GitHub App for desktop sign-in (device flow)

- Status: `ready` · Difficulty 1 · Owner Decisions & External Dependencies (secondary: Cross-Platform Architecture)
- Agent: **Owner** · Effort: 0.5 agent-days (high confidence) · Waiting: Owner registers App after permission list
- Skills: GitHub App settings
- Risks: Over-broad permissions
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Client ID recorded
- Independent review mandatory: no · Owner involvement: yes

#### #71 — GitHub sign-in on all platforms: App device flow plus optional personal access token

- Status: `blocked` · Difficulty 4 · Cross-Platform Architecture (secondary: Security & Cryptography)
- Agent: **GitHub Integration Agent** · Effort: 10 agent-days (medium confidence) · Waiting: CI per platform; needs #70 for end-to-end
- Skills: OAuth device flow, GitHub API, vault adapters
- Risks: Token handling; scope validation; 3 vault backends
- Files/modules: GitHub auth modules, vault adapters, UI sign-in screens
- Blockers (all): #26, #70; open: #26, #70 · Parallel: No — critical path, sequential
- Validation: Device flow + PAT on all 3 installed builds; tokens only in vault
- Independent review mandatory: yes · Owner involvement: no

#### #72 — macOS: support macOS 15 and newer (deployment target, APIs, packaging)

- Status: `ready` · Difficulty 4 · macOS Native & Packaging (secondary: Research & Investigation)
- Agent: **macOS Packaging Agent** · Effort: 6 agent-days (medium confidence) · Waiting: Hosted macOS 15 + 26 runs
- Skills: Deployment targets, ObjC/Swift availability, verifiers
- Risks: native.m runtime gate; RENAME_RESOLVE_BENEATH; ~60 workflow lines; verifier pins; Xcode minimum for iOS
- Files/modules: plists, `tauri.macos.conf.json`, three `build.rs`, `native.m`, `Distribution.xml`, verifiers, workflows
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Installed checks pass on macOS 15 and 26 runners
- Independent review mandatory: yes · Owner involvement: no

#### #73 — macOS: production Intel (x86_64) build in the distributable package

- Status: `blocked` · Difficulty 3 · macOS Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **macOS Packaging Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Hosted Intel runner
- Skills: Universal/x86_64 builds, lipo
- Risks: Helper packaging builds arm64 only
- Files/modules: macOS build scripts/workflows
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: `lipo -info` evidence; installed checks on Intel runner
- Independent review mandatory: yes · Owner involvement: no

#### #74 — Linux: multi-distribution packaging strategy and evidence-based support matrix

- Status: `ready` · Difficulty 2 · Research & Investigation (secondary: Linux Native & Packaging)
- Agent: **Linux Packaging Agent** · Effort: 1 agent-days (high confidence) · Waiting: —
- Skills: Linux distro research
- Risks: Research done; follow-ups updated
- Files/modules: Docs only
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Matrix posted and linked (done 2026-11-16; close after review)
- Independent review mandatory: no · Owner involvement: no

#### #75 — Linux: RPM package for the Fedora / RHEL family

- Status: `blocked` · Difficulty 4 · Linux Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **Linux Packaging Agent** · Effort: 10 agent-days (low confidence) · Waiting: VM CI for Fedora/openSUSE/RHEL 10
- Skills: RPM spec, SELinux
- Risks: SELinux policy for root helper; depends on #89
- Files/modules: New `desktop/packaging/rpm/**`, workflow
- Blockers (all): #40, #74, #89; open: #40, #74, #89 · Parallel: Yes — within its agent stream once blockers close
- Validation: RPM install/upgrade/remove on each target
- Independent review mandatory: yes · Owner involvement: no

#### #76 — Linux: package for distributions outside the Debian and Fedora families (format chosen by research)

- Status: `blocked` · Difficulty 3 · Linux Native & Packaging
- Agent: **Linux Packaging Agent** · Effort: 5 agent-days (low confidence) · Waiting: Arch container/VM CI
- Skills: PKGBUILD/pacman
- Risks: Arch rolling updates
- Files/modules: New `desktop/packaging/arch/**`
- Blockers (all): #74; open: #74 · Parallel: Yes — within its agent stream once blockers close
- Validation: pacman install/upgrade/remove; installed checks
- Independent review mandatory: no · Owner involvement: no

#### #77 — Linux: widen Debian-family support (Ubuntu and Debian versions)

- Status: `blocked` · Difficulty 3 · Linux Native & Packaging (secondary: CI/CD & Release Infrastructure)
- Agent: **Linux Packaging Agent** · Effort: 6 agent-days (medium confidence) · Waiting: VM CI per Ubuntu/Debian version
- Skills: Debian packaging, glibc floors
- Risks: One deb per distro; 22.04 HWE kernel
- Files/modules: `desktop/packaging/debian/**`, workflow matrix
- Blockers (all): #40, #74, #89; open: #40, #74, #89 · Parallel: Yes — within its agent stream once blockers close
- Validation: Installed checks on 22.04/24.04/26.04/Debian 13
- Independent review mandatory: no · Owner involvement: no

#### #78 — Linux: enable local Android build and signing in the installed app

- Status: `blocked` · Difficulty 4 · Android / iOS Tooling (secondary: Linux Native & Packaging)
- Agent: **Linux Agent** · Effort: 8 agent-days (medium confidence) · Waiting: Linux CI; SDK download
- Skills: Android SDK/Gradle on Linux
- Risks: Signing via Linux vault (#43)
- Files/modules: Android owner Linux cfg paths
- Blockers (all): #26, #40, #43; open: #26, #40, #43 · Parallel: Yes — within its agent stream once blockers close
- Validation: Installed Linux builds and signs fixture project
- Independent review mandatory: yes · Owner involvement: no

#### #79 — Direct Google Play and App Store Connect operations from the desktop app on every capable platform

- Status: `blocked` · Difficulty 5 · Android / iOS Tooling (secondary: Cross-Platform Architecture, Security & Cryptography)
- Agent: **Store Agent** · Effort: 20 agent-days (low confidence) · Waiting: Real accounts in #64
- Skills: Play Developer API, ASC API/JWT, fastlane, Rust/Python
- Risks: New Build Uploads API; Ruby bundling; production-publish safety
- Files/modules: `local_store_*_owner.rs`, Store runtime, Python core
- Blockers (all): #26, #37, #43, #90; open: #26, #37, #43, #90 · Parallel: No — critical path, sequential
- Validation: Play upload on 3 OS; ASC ops; confirmation gates; no production publish without explicit confirm
- Independent review mandatory: yes · Owner involvement: no

#### #80 — Windows and Linux: ship and verify the installed `mrk` CLI

- Status: `blocked` · Difficulty 3 · Cross-Platform Architecture (secondary: Windows Native & Packaging, Linux Native & Packaging)
- Agent: **Windows Packaging Agent** · Effort: 5 agent-days (medium confidence) · Waiting: Windows + Linux CI
- Skills: Packaging, PATH integration
- Risks: Touches both Windows and Linux packaging: Linux part handed to Linux Packaging Agent
- Files/modules: `desktop/packaging/windows/**` (+ debian/rpm by Linux Packaging Agent)
- Blockers (all): #26, #31, #44; open: #26, #31, #44 · Parallel: Yes — within its agent stream once blockers close
- Validation: `mrk` on PATH after install; removed on uninstall; CLI checks in CI
- Independent review mandatory: no · Owner involvement: no

#### #81 — Windows: user-controlled elevated (administrator) mode

- Status: `blocked` · Difficulty 5 · Security & Cryptography (secondary: Windows Native & Packaging)
- Agent: **Windows Agent** · Effort: 8 agent-days (low confidence) · Waiting: Windows CI
- Skills: Windows tokens/UAC/integrity levels, threat modelling
- Risks: Weakening privilege boundaries; ACLs created elevated; RID 500 handling
- Files/modules: `desktop/native/windows-installed-native/src/security.rs` (token_facts), startup
- Blockers (all): #26, #35; open: #26, #35 · Parallel: Yes — within its agent stream once blockers close
- Validation: Threat model reviewed by Security Agent; both modes in CI
- Independent review mandatory: yes · Owner involvement: no

#### #82 — App permission configuration: user-configurable capability restrictions

- Status: `blocked` · Difficulty 4 · Cross-Platform Architecture (secondary: Security & Cryptography)
- Agent: **Cross-Platform Agent** · Effort: 8 agent-days (medium confidence) · Waiting: CI per platform
- Skills: Capability model, command-boundary enforcement
- Risks: Bypass via CLI/native commands
- Files/modules: Shared command boundary, settings UI, CLI
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Restrictions enforced in UI, native and CLI on all platforms
- Independent review mandatory: yes · Owner involvement: no

#### #83 — All platforms: safe, explicit removal of retained user data

- Status: `blocked` · Difficulty 3 · Cross-Platform Architecture (secondary: Documentation & Maintenance)
- Agent: **Cross-Platform Agent** · Effort: 5 agent-days (medium confidence) · Waiting: CI per platform
- Skills: Per-OS data locations, vault deletion
- Risks: Deleting the wrong data
- Files/modules: Data-removal action, docs
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Removes only app data on 3 OSes; project folders untouched
- Independent review mandatory: yes · Owner involvement: no

#### #84 — Acceptance: macOS 15 (oldest supported version) install and use

- Status: `blocked` · Difficulty 3 · Testing & Quality Assurance (secondary: macOS Native & Packaging)
- Agent: **Testing Agent** · Effort: 2 agent-days (medium confidence) · Waiting: macOS 15 machine/VM
- Skills: macOS acceptance
- Risks: Hardware/VM availability
- Files/modules: Acceptance checklist
- Blockers (all): #57, #72; open: #57, #72 · Parallel: Yes — within its agent stream once blockers close
- Validation: #60 checklist on macOS 15
- Independent review mandatory: no · Owner involvement: yes

#### #85 — Decision (deferred to the end): optional diagnostics, telemetry and crash reporting

- Status: `blocked` · Difficulty 1 · Owner Decisions & External Dependencies
- Agent: **Owner** · Effort: — · Waiting: Deferred to end of project
- Skills: —
- Risks: —
- Files/modules: —
- Blockers (all): none; open: none open · Parallel: Yes — within its agent stream once blockers close
- Validation: Owner decides at the end
- Independent review mandatory: no · Owner involvement: yes

#### #86 — Repository: SECURITY.md, support guidance, issue templates and private vulnerability reporting

- Status: `done` · Difficulty 1 · Documentation & Maintenance
- Agent: **Release Agent** · Effort: — · Waiting: —
- Skills: Docs
- Risks: —
- Files/modules: SECURITY.md, SUPPORT.md, issue forms
- Blockers (all): none; open: none open · Parallel: —
- Validation: Done (PR #88, closed)
- Independent review mandatory: no · Owner involvement: no

#### #87 — Clean up obsolete development branches after their history is preserved

- Status: `blocked` · Difficulty 2 · CI/CD & Release Infrastructure
- Agent: **CI/CD Agent** · Effort: 1 agent-days (high confidence) · Waiting: After #26 (and #68 for the release branch)
- Skills: Git hygiene
- Risks: Deleting unique work
- Files/modules: Remote branches only
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Inventory table; only contained branches deleted
- Independent review mandatory: no · Owner involvement: no

#### #89 — Linux: Btrfs root, oo7/new keyring services and portable kernel detection (security-reviewed)

- Status: `blocked` · Difficulty 5 · Security & Cryptography (secondary: Linux Native & Packaging)
- Agent: **Linux Agent** · Effort: 12 agent-days (low confidence) · Waiting: VM CI on each distro default image
- Skills: Linux filesystems (Btrfs), mount/identity security, D-Bus Secret Service
- Risks: Must keep every security property (OD-21); adversarial tests
- Files/modules: `runtime.rs` Linux admission, `installed_runtime_data.rs`, `linux-mount-observation`, vault identity
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: Design reviewed; adversarial tests; installed checks on all distro defaults; Security Agent review
- Independent review mandatory: yes · Owner involvement: no

#### #90 — All platforms: automatic capability detection — show only supported operations, enforce in the backend

- Status: `blocked` · Difficulty 4 · Cross-Platform Architecture (secondary: UI/UX, Android / iOS Tooling)
- Agent: **Cross-Platform Agent** · Effort: 10 agent-days (medium confidence) · Waiting: CI per platform
- Skills: Capability registry, React, Tauri commands, Xcode detection
- Risks: Touches App.tsx broadly; must not hide required features wrongly
- Files/modules: Shared capability module, `desktop/src` navigation/controls, CLI
- Blockers (all): #26; open: #26 · Parallel: Yes — within its agent stream once blockers close
- Validation: No iOS build/sign controls on Win/Linux; backend/CLI refuse; macOS guidance tests
- Independent review mandatory: yes · Owner involvement: no

