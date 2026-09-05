# iOS signed entitlements and profile grants

## Validation boundary

Fresh signed preflight, candidate preparation and every new IPA upload compare
**every** signed entitlement with the embedded profile's grants. Each primary
or nested `.app`/`.appex` uses its own profile; a parent cannot authorize a child.
Unclaimed profile capabilities are allowed. A missing grant, incompatible type,
unsupported expression or unavailable native inspection fails closed.

Both profile CMS layers also require independent signature verification and the
Apple production iOS provisioning-profile issuer policy under pinned public roots.
`security cms -D` is not used as authority. Content comparison, app signatures and
workflow attestations remain distinct from that check; see
[profile authority, isolation and external requirements](ios-profile-authority.md).

## Supported profile and entitlement formats

Modern profiles must contain `DER-Encoded-Profile`. The toolkit authenticates its CMS
payload and uses that DER dictionary as the authoritative **content**. Complete
entitlements, TeamIdentifier, UUID, creation/expiry dates and device-distribution
fields must agree with the outer plist. Actual outer certificate bytes must hash
to the full inner developer-certificate digest list. Missing modern DER or
conflicting representations fail; there is no legacy-only fallback.

Each native architecture is selected explicitly for `codesign` inspection. V0
SET dictionaries and V1 versioned DER entitlement dictionaries are supported.
The decoded `--der` and `--xml` views must agree with exact types. `--xml` can
render DER: this is cross-decoder consistency, not proof about a legacy XML
signature slot. All slices must have the same entitlement set, leaf signer and
TeamIdentifier. Native signature/designated-requirement checks remain separate.

Plist and DER parsing rejects duplicate keys, malformed/trailing/unsupported
encodings, cyclic values and excessive complexity. Bounds are 4 MiB, 100,000
nodes and depth 64, within the artifact inspection's shared cooperative deadline.
Binary plist objects and reference cells (including keys) are bounded before
stdlib allocation; expanded shared-graph cost and depth are also checked. These
are parser bounds, not a hard memory limit on captured native subprocess output.

The same strict dictionary decoder is used for IPA/archive bundle **and resource**
Info.plists, including dSYM metadata; another plist value cannot silently replace
the first one. XML supports one plist/dictionary root, complete key/value pairs,
known value elements and no ignored container/Boolean text. The optional root
version must be literal `1.0`; every opening tag is bounded to 8192 bytes. Both
standard Apple/Apple Computer public DTD labels and HTTP/HTTPS Apple DTD URLs
are recognized without fetching them. Internal declarations and undeclared or
skipped entities fail. Strings, keys and real-number text support predefined/numeric
references (one to eight original digits, decoded once) and CDATA; literal CR/CRLF text is preserved, not silently
normalized. Comments are allowed between values, never inside primitives/keys.
Integer/date/data/Boolean bodies must be literal, without references or markup;
container whitespace must also be literal. Other attributes/extensions fail.
Integers are signed/unsigned 64-bit, reals are finite and preserve signed zero,
XML dates are exact UTC seconds,
and data uses canonical padded base64. Empty data needs an explicit closing tag
(`<data></data>`, not `<data/>`). UTF-8 BOM is optional; UTF-16 requires a
matching BOM, and any encoding declaration must agree. Only UTF-8/UTF-16
declarations are supported; ASCII without a declaration is a UTF-8 subset. This
is an explicit supported subset, not equivalence to every permissive `plutil`
conversion. Native XML, UTF-8/UTF-16 and bounded binary plist inputs are tested.

Binary plists require `bplist00`, a supported zero-version trailer, valid widths
(1–8 bytes), an exact offset table and unique, nonoverlapping object spans. Every
indexed object is checked, including disconnected components; references, duplicate
decoded keys, cycles and unsupported markers cannot disappear through conversion.
Only unindexed `00`/`0f` padding is allowed; null or fill **values** are unsupported.
Supported values are Booleans, ASCII/UTF-16 strings, data, arrays, dictionaries,
finite 32-/64-bit reals, dates and bounded integers. Extended lengths require
actual 1-/2-/4-/8-byte integer markers; valid nonminimal widths are allowed.
Sixteen-byte integer encodings must be zero-extended unsigned 64-bit values.
Binary dates must round-trip through Python's datetime with their original double
bits intact. Exact microseconds/seconds are supported; negative-zero dates,
out-of-range dates and precision that would be rounded away fail, rather than
falsely equating different native values. These restrictions do not authorize
rewriting a retained artifact to make it pass.

## Grant comparison rules

| Signed capability | Required profile grant |
| --- | --- |
| Application/team identity | Exact configured Team/Bundle ID and exact grant; wildcard App IDs and distinct legacy App ID prefixes remain unsupported |
| `get-task-allow` | Exactly Boolean `false` in both claim and grant |
| APNs environment | Exact `production` |
| iCloud container environment | `Production`, either the exact scalar grant or a member of a profile string-array grant |
| Keychain, iCloud/ubiquity container identifiers | Concrete string-array claims; exact grants or one terminal `.*` prefix grant |
| Ubiquity key/value store identifier | Concrete scalar claim; exact or terminal `.*` prefix grant |
| App groups and merchant identifiers | Exact string-array membership; no inferred Team prefix or wildcard expansion |
| Associated domains | String-array membership, or the profile's scalar/array `*`; a signed `applinks:*.example.test` is a literal domain expression, not a shell glob |
| iCloud services | Nonempty array of `CloudKit`/`CloudDocuments`, authorized by array membership or the documented profile scalar/array `*` |
| Other keys | Type-sensitive scalar/compound equality, or typed array membership; unknown dictionaries do not acquire recursive subset semantics |

Known identifier/capability arrays must be nonempty and correctly typed. Boolean
`true` is not integer `1`. No key is silently dropped, and no generic wildcard,
coercion or profile-bypass flag exists. Site associations, service registration
and Apple's runtime/Store policy still require external validation.

## Nested code and signing

The inventory includes every Mach-O, not just filenames ending in `.dylib`:
frameworks, extensions, nested apps, helpers and signed resource bundles are
inspected. Only an app's exact declared executable is already covered by its
bundle's profile check. A nearby helper cannot inherit those grants.

Profileless frameworks, libraries, helpers, XPC and other unsupported executable
bundles must have **no** signed entitlement claims. Apps/extensions require their
own complete profile checks. The shared signing setup still installs only the
primary profile: additional profile installation/export mappings require bounded
project-owned preparation in a build job, never in a Store job.

Every native slice extracts its certificate to a fresh private path. Missing
output cannot reuse a preceding slice's certificate. All leaf/profile validity
intervals must include the current time. Inspection children receive the existing
credential-free environment, and temporary profile/certificate files are removed.
Errors do not print profile contents, entitlement names/values or raw native output.

## Failure, recovery and verification

Correct capability/profile settings before creating a new candidate. Do not
edit, re-sign, rebuild or replace an already accepted candidate to repair evidence.
Incomplete recovery retains the original authenticated validation and exact bytes;
it does not claim a historical candidate passed a newer policy. Every actual new
upload uses the pinned executor's current-time checks. Upgrade all tooling pins
before starting a new candidate under this contract. See [recovery](recovery.md)
and [IPA/archive correspondence](ios-artifacts.md).

`tests/unit/test_ios_entitlements.py` exercises typed grants, encodings, bounds,
own-profile isolation, profileless claims, every slice and failure cleanup through
real ZIP/plist/native inventories with simulated cryptographic seams.
`test_ios_plist_binary.py` covers original spans/markers, graph and allocation
bounds, numeric precision, shared deadlines and malformed raw inputs at both
readers. Complete resource-pair tests reject numeric and encoding substitutions. CLI and
current-upload regressions prove invalid claims stop before a Store request.
`test_macho_native.py` independently generates ad-hoc multi-architecture DER using
native tools; it is not Apple Distribution signing. A protected, non-public
valid-profile archive/export rehearsal on the pinned Xcode remains an external
consumer gate, not a repository CI result. Actual Apple issuer-policy and native CMS
regressions are documented separately in [profile authority](ios-profile-authority.md).
