"""One fixed predecessor for before-image recognition, never output authority.

Only the immediately previous bundled candidate caller is retained. The same
literal renderer/coordinate/SHA grammar is used as for the current caller. No
YAML merge, file discovery, normalization, remote lookup or dispatch admission
lives here. Every caller still owns its original bytes/revision and separately
requires a CURRENT-template after-image.
"""
from __future__ import annotations

from .workflow_payloads import GITHUB_WORKFLOWS, canonical_workflow_reference

# Exact pre-migration github-setup-v1.json candidate, selected from 420db551.
# This is public shipped text, not an assertion about a user's file or owner.
_PREVIOUS_CANDIDATE = b"""name: Mobile internal candidate
run-name: ${{ inputs.desktop_request != '' && format('MRK Desktop candidate [{0}]', inputs.desktop_request) || 'Mobile internal candidate' }}
on:
  workflow_dispatch:
    inputs:
      platform:
        description: Platform to build once and upload to internal testing
        required: true
        type: choice
        options:
        - android
        - ios
        - both
      confirmation:
        description: candidate:<platform>:<version>:<build>
        required: true
        type: string
      recovery_run_id:
        description: Run holding the original intent or selected complete final; never replaces authorization.
        required: false
        default: ''
        type: string
      recovery_confirmation:
        description: Exact additional iOS recovery confirmation, only when requested by reconciliation.
        required: false
        default: ''
        type: string
      desktop_request:
        description: Optional exact Desktop request marker; use with reviewed source and full ref.
        required: false
        default: ''
        type: string
      desktop_source_sha:
        description: Optional Desktop-reviewed current dispatch commit; not a replacement for original recovery source.
        required: false
        default: ''
        type: string
      desktop_expected_ref:
        description: Optional Desktop-reviewed full branch ref; all three Desktop inputs must be supplied together.
        required: false
        default: ''
        type: string
permissions: {}
jobs:
  candidate:
    permissions:
      actions: read
      artifact-metadata: write
      attestations: write
      contents: read
      id-token: write
    uses: __MOBILE_RELEASE_KIT_REPOSITORY__/.github/workflows/reusable-candidate.yml@__MOBILE_RELEASE_KIT_SHA__
    with:
      tooling_sha: __MOBILE_RELEASE_KIT_SHA__
      source_sha: ${{ github.sha }}
      platform: ${{ inputs.platform }}
      confirmation: ${{ inputs.confirmation }}
      recovery_run_id: ${{ inputs.recovery_run_id }}
      recovery_confirmation: ${{ inputs.recovery_confirmation }}
      desktop_request: ${{ inputs.desktop_request }}
      desktop_source_sha: ${{ inputs.desktop_source_sha }}
      desktop_expected_ref: ${{ inputs.desktop_expected_ref }}
"""


def before_workflow_reference(identity: str, current_template: bytes,
                              content: bytes) -> tuple[str, str] | None:
    """Recognize exact current text, or ONE candidate-only predecessor."""
    if identity not in {name for name, _ in GITHUB_WORKFLOWS}:
        return None
    current = canonical_workflow_reference(current_template, content)
    if current is not None or identity != "candidate":
        return current
    return canonical_workflow_reference(_PREVIOUS_CANDIDATE, content)
