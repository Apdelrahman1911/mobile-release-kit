# Public Apple profile-authority regression certificates

These four **public certificates only** come from Apple's open-source Security
regression corpus at commit `db15acbe6a7f257a859ad9a3bb86097bfe0679d9`.
`certificates.json` records each HTTPS source, original DER size/SHA-256, and
base64-encoded DER. No Apple source code, private key, consumer profile, account,
or signing asset is copied. These are test inputs, **not trust anchors**.

The production iOS profile-signing leaf/CA proves the real native purpose policy
accepts the expected Apple authority; the TEST and macOS leaves must reject.
The old certificates' dates are intentional: Apple's provisioning-signature
policy omits signer-chain wall-clock expiry. Current authenticated profile dates
and the actual application's distribution-certificate validity are separate gates.

Runtime trust uses only the separately pinned Apple roots in
`src/mobile_release/data/apple-profile-roots.pem`. They are public authority
certificates downloaded from Apple's certificateauthority/appleca HTTPS endpoints,
not consumer-provided anchors. See `docs/ios-profile-authority.md` for pins.

Native CMS tests generate disposable fictional RSA keys and signatures locally,
then remove them. They never inspect the user's keychains, contact a Store, or
sign an application. A synthetic signature is not Apple issuance; the complete
signed-profile positive explicitly mocks only the Apple issuer-policy seam,
while the real default policy rejects that same synthetic input. This and the
public native policy positive are not a current protected Distribution export.
