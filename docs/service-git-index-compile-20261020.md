# Git-index v59 compile correction

Root v59 at `0658afd4830d9e6a25c9536b90e3637f624eba47` stopped before
tests: `DesktopApi` omitted the implemented permission port and the Document
adapter accessed private `FileAction` fields. The original logs are preserved.

Apply `service-git-index-compile-hooks-20261020.patch` to Root's two shared
files alongside these two updated owned Rust leaves. It adds the optional
TypeScript port and one closed, fallible `Action::index` constructor. The
constructor accepts only Stage/Unstage, fixes both private draft fields to
`None`, and uses the original `Action::valid` contract. No visibility expands.

The Document matcher uses that same validator, which already rejects message
or identity on Stage/Unstage, plus the unchanged exact kind/revision/path
comparisons. Construction errors propagate before original Prepare admission.
All owner, consent, publisher, deadline and retirement code is unchanged.

One new DATA regression exercises the real constructor/matcher with both
actions, mismatched selection, private draft fields, unsupported action kinds
and invalid revision/path inputs. Filter:
`asset_session::agent_git_index::tests::native_index_action_preserves_private_field_and_exact_selection_checks`

Author evidence: Rust source parsing and Root patch apply-check passed. No
Cargo, TypeScript graph, Rust test or native execution here; Root must rerun
the real graph and now 27 Git-index Rust cases. The unchanged nine Node cases
retain their prior passing evidence, not a new run.
