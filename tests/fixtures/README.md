# Sanitized fixtures

Except for the explicitly documented public Apple authority certificates in
`apple-profile-authority/`, every identifier, repository, workflow run, Store build,
certificate digest, profile UUID, timestamp and artifact digest here is synthetic.
Consumer fixtures must use `example` identities and repeated/fixed hexadecimal
values; never derive them from a consuming repository, CI log, private release
folder or Store response. Public CA fixtures are not private credentials or
runtime trust anchors; their sources/hashes and exact purpose are documented.

Fixtures intentionally contain no signed binary, credential, tester identity, reviewer contact,
private URL, or real product metadata. Tests needing binary structure must generate bounded
temporary files or use separately reviewed synthetic artifacts.

`apple-store-contract.json` is deterministic output from the actual pinned Ruby lanes against a
synthetic HTTP Store. It covers original operations, ambiguous-create grants, partial recovery,
pending versus available TestFlight observations, and production submission. The Python workflow
suite regenerates it twice and validates the resulting intent/raw/receipt chains and schemas.

To inspect a proposed fixture update without overwriting the committed reference:

```bash
bundle exec ruby tests/workflow/export_apple_contract_fixtures.rb /tmp/new-apple-contract.json
diff -u tests/fixtures/apple-store-contract.json /tmp/new-apple-contract.json
```

The output path must not already exist. Review any difference against the implementation before
updating a reference; a changed fixture is not evidence that a changed Store behavior is correct.
