# macOS Android catalogue: source provenance

**Status: generated comparison source, not native qualification or Desktop readiness.**

This catalogue covers the existing macOS ARM64 tuple: Temurin17.0.20.1,
Gradle8.14.5, AGP8.9.2, Android platform35 revision2, build-tools35.0.0,
Aapt2 8.9.2-12782657-osx and Bundletool1.18.3. It adds no supported platform
or tool version.

The Gradle wrapper-selection URL is the canonical
`https://services.gradle.org/distributions/gradle-8.14.5-bin.zip`. It is
separate from the authenticated archive acquisition URL; the selected archive
bytes, digest and original acquisition provenance are unchanged.

## Exact source and observation bindings

The complete [public observation-pin inventory](desktop-macos-android-catalogue-observation-pins.json)
contains all **217** logical observation identifiers, byte counts and SHA256
hashes for this generation (**7,338,029 bytes** total). Logical identifiers
are comparison names, not local paths or instructions to open evidence files.
Raw observation bodies, private host locations, accounts and supplier payloads
are intentionally not published here.

| Binding | SHA256 |
|---|---|
| [Generator](../desktop/tools/macos_android_supplier_catalogue.py),139,288 bytes | `87d7264e384182e8495bfd46899fb8896e6f47d2c0be0523242dee4a1d19d97a` |
| [Generated include](../desktop/src-tauri/src/android_supplier_macos_catalogue.rs),20,409,741 bytes | `1d1c1f0f49836180853285d49e114b12c44c9d72c41250b103c5dd34fa792203` |
| Complete217-input commitment | `58a9f1ba78b19be5788717812c47070c2444d93bf0092966eda77fe2fe4fd931` |
| Public observation-pin inventory,36,730 bytes | `6d7d641ef39d0ac5cc83ea0f065c46da47c1b4592eccea25c2bc6f8c9f1bb563` |

The recorded generation evidence reports original exit0, unchanged input and
source pins before/after execution, and two byte-identical complete outputs.
These are source-generation results only. They do not establish that an
installed toolchain, picker selection, native provider or Store operation is
valid. The inventory binds the current generation, not earlier observation
attempts or an inferred successful run.

## How the application uses it

The supplier includes the table privately in its existing module. There is no
runtime JSON catalogue loader, mutable registration API or fixture fallback.
The existing Rust `reference_digest` remains the sole canonical reference
commitment; the generator does not replace it. Existing structural,
source/inventory, native-class, support, provenance and whole-owner checks
remain mandatory.

## Evidence still required at this source checkpoint

- Independent complete observation-to-table correspondence and actual consumer
  review; a matching output hash alone is insufficient.
- Applicable integrated Rust contracts and all three real64MiB whole-owner
  budget gates: fresh Inspect, retained-Review Inspect and Register.
- Genuine reviewed macOS installed-support, source-picker, consent,
  registration/readback and relevant Android build/signing verification.

No compilation, native macOS success, supplier authority or production-readiness
claim is conferred by this document or its pin inventory. Record later reviewed
verification separately rather than changing the meaning of these source pins.
