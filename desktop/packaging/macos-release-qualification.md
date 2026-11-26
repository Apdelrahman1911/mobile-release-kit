# Apple Silicon macOS release qualification

## Release custody

1. Integrate through protected main. Record the exact commit and tree.
   Run the unsigned preflight against that commit and retain the original
   invocation. The signed build requires the successful preflight run.
2. Bind the ordinary ARM64 carrier to the original successful build and
   attempt. Freeze exactly two DMGs, RELEASE-MANIFEST.json and SHA256SUMS.
   Verify signing, notarization, Gatekeeper and the embedded producer pair.
   GitHub attests the four assets.
3. Run hosted lifecycle qualification and the dedicated UI workflow against
   the frozen artifact. Record the source and evidence artifact IDs.
   Record physical results separately for the identical DMGs and packages.
4. Prepare a private prerelease draft with Latest disabled and target the
   verified source. Use desktop-v0.2.13 for this candidate. Verify the asset
   roster, redownload all four assets and repeat checksum, source and
   attestation verification. Final publication requires owner approval.

Use the macOS release media verifier's `verify` command with the original
frozen directory, source/tree, build run, carrier run and `--draft-id` for
the numeric GitHub draft release ID. This checks private prerelease status,
an exact target commit, and the signed asset roster. It downloads every
asset by ID to a temporary directory and compares its bytes and build
attestation. A tag that already exists must resolve to the same commit.
Keep the draft's original target SHA for eventual tag creation.

The owner deferred [#52]. The current macos-developer-id environment
configuration and signing, secret-handling and verification gates still
apply. Additional environment protections remain open. Public build
attestations identify digests and provenance. The release draft and
signed downloads remain private until publication.

## Draft release notes

Mobile Release Kit 0.2.13 targets Apple Silicon on macOS 26.0 or later. It
brings the qualified macOS installer and uninstaller lineage to protected main.
The matching Install and Remove images include separate signed packages,
checksum and build provenance records. See the
[install, upgrade and removal guide](macos-install-update-remove.md)
for enrolled upgrades, first launch, Keep My Data and safe reinstall.

The integrated changes improve bundled-runtime startup diagnostics, installed
workspace initialization, Prepare and Quit, scoped CLI access, and recovery
after interrupted maintenance. Removal compares durable APFS volume identity
across reboot and audits retained originals before it changes the installation.

Before using this text in a draft, add the exact main revision, evidence and
verified asset links. Record any known limitations that remain on the exact
candidate. Use prerelease with Latest disabled for this Apple Silicon release.

## Feature evidence to collect

Record Passed, Failed, Blocked or Not Tested for each scenario against
the exact signed package. Keep observed UI outcomes, simulated provider
behavior and real external account operations distinct.

| Surface | Required result | Intended evidence |
| --- | --- | --- |
| Launch and navigation | Bundled runtime on first request, working Overview, Build & release, Store listing, Signing & accounts, Project settings, Build tools, GitHub, Build files, Recover work and Automation | Signed UI and hosted fresh launch |
| Projects | Open, import and create with correct identity. Cancel and refuse invalid folders. Quit and reopen with persisted state | Synthetic fixtures. Picker and saved-project read wired |
| Settings and version | Invalid value refused, cancel preserves originals, consent writes only the reviewed file, and values persist after relaunch | Signed UI checks cancel/save/reopen for the saved version. Version recovery wired. Settings edit and invalid-value journeys outstanding |
| CLI and Automation | Default refusal, scoped grant and readback, revoke, second-project denial, review/apply and appropriate recovery | Signed UI and workspace XCTest. Command apply journeys outstanding |
| Store listing and metadata | Read and edit text/images with validation, consent, conflict and persistence checks | Separate local fixture journeys outstanding |
| Build tools and Build files | Correct bundled/tool cards, absent tool guidance, real AAB/IPA metadata and rejection of invalid input | Synthetic fixtures and test artifacts. Dedicated journeys outstanding |
| Android and iOS | Platform tool checks, real build/archive, correct local signing/input preservation and negative cases | Disposable JDK, SDK or Xcode. Device or account paths separate |
| Git and GitHub | Local repository/ref, index, branch switching, dirty refusal, workflow edit/recovery. Hosted authorization uses a dedicated repository | Local fixtures first. Service workflow outstanding |
| Signing and release operations | Correct readiness, consent, exact artifact identities and duplicate or interrupted operation recovery | Synthetic fixtures first. Real Store operations outstanding |
| Install and upgrade | Signed fresh, no-op, downgrade refusal and exact predecessor update with preserved files and credentials | Hosted qualification and exact-package physical upgrade |
| Prepare and Quit | Native confirmation and original settlement, no helper remains registered; refusal and retry preserve state | Hosted prepare after reinstall and physical signed-helper registration/reboot |
| Remove and reinstall | Completion receipt, preserved app files, credentials and archive identity, matching reinstall and working runtime | Hosted qualification and identical packages on physical Mac |
| Uninstaller cancellation and deletion | Cancel both paths, quit Installer without changes, refuse when app remains. Delete only app-owned fixture paths and credentials | Disposable hosted Mac |
| Interrupted recovery and performance | Original saved-version/core receipts, recovery without losing source data, durable resource samples | Hosted recovery and performance jobs. Real reboot separate |
| Window dimensions and prolonged use | Record usability at each tested size, elapsed duration and outcomes | Signed UI selects two window sizes and checks navigation after resize. Qualification collects the prolonged resource samples |

Loopback UI automation uses a bearer generated within each disposable
runner and needs no Actions secret or public tunnel. The pinned action
exposes semantic macOS controls only when native Accessibility permits it.
The workflow records missing authorization as a blocked scenario.
The existing XCTest suite supplies independent native evidence.

External provider journeys have no credential inputs wired into these jobs.
They need an isolated Apple developer/test team and App Store Connect
app-scoped role, a Google Play test app and restricted service account,
or a GitHub test repository and least-privilege GitHub App or fine-grained
credential. Document the exact secret and environment names with each
implemented external workflow. Offline UI, lifecycle and provenance jobs
can proceed without them.

[#52]: https://github.com/Apdelrahman1911/mobile-release-kit/issues/52
