# Sanitized fixtures

Every identifier, repository, workflow run, Store build, certificate digest, profile UUID, timestamp, and artifact digest in this directory is synthetic test data. Fixtures must use `example` identities and repeated/fixed hexadecimal values; never derive them from a consuming repository, CI log, private release folder, or Store response.

Fixtures intentionally contain no signed binary, credential, tester identity, reviewer contact, private URL, or product metadata. Tests needing binary structure must generate bounded temporary files or use separately reviewed synthetic artifacts.
