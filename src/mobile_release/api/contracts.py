"""Version-one passive service data. Protocol framing belongs to the engine.

All assurance flags describe what these services did, never release authority.
The UI must not turn a format-valid configuration into native/Store verification.
"""
from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict


class ApiError(Exception):
    """An expected service refusal, safe to put in the bounded error envelope."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class Issue(TypedDict):
    code: str
    status: Literal["INVALID", "SKIP"]
    message: str
    remediation: str


class Assurance(TypedDict):
    basis: Literal["static-text", "schema-policy"]
    projectCodeExecuted: Literal[False]
    toolsProbed: Literal[False]
    credentialsRead: Literal[False]
    gitObserved: Literal[False]
    storeContacted: Literal[False]
    writesPerformed: Literal[False]
    releaseReadiness: Literal["unknown"]


class FieldHelp(TypedDict):
    path: str
    label: str
    section: str
    requiredness: Literal["required", "optional", "conditional"]
    requiredWhen: str
    what: str
    why: str
    where: str
    format: str
    failure: str
    input: Literal["text", "boolean", "number", "enum", "string-list", "argv", "commands"]
    options: NotRequired[list[str]]
    example: NotRequired[Any]


class RequirementDescriptor(TypedDict):
    name: str
    kind: str
    stage: str
    platform: str
    environment: str
    alternatives: list[str]
    reason: str
    state: Literal["unknown"]


class CredentialHelp(TypedDict):
    name: str
    kind: str
    platform: str
    stages: list[str]
    alternatives: list[str]
    requiredness: Literal["conditional"]
    requiredWhen: str
    what: str
    why: str
    where: str
    format: str
    failure: str


GitHubGuidanceId = Literal["source-authority", "protected-environments", "runner-policy",
                           "credentials", "preflight-and-releases", "scope"]


class GitHubSetupInputHelp(TypedDict):
    id: Literal["toolingRepository", "toolingSha", "suppliedSnapshot"]
    label: str
    requiredness: Literal["required", "optional"]
    what: str
    why: str
    where: str
    format: str
    failure: str


class GitHubSetupGuidance(TypedDict):
    id: GitHubGuidanceId
    label: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class GitHubSetupHelp(TypedDict):
    schemaVersion: Literal[1]
    inputs: list[GitHubSetupInputHelp]
    guidance: list[GitHubSetupGuidance]


class MethodCapability(TypedDict):
    method: str
    available: bool
    reason: str


class ActionCapability(TypedDict):
    id: str
    available: Literal[False]
    reason: str


class CapabilitiesResult(TypedDict):
    coreVersion: str
    apiVersion: Literal[1]
    hostPlatform: Literal["linux", "macos", "windows", "other"]
    mode: Literal["read-only-foundation"]
    methods: list[MethodCapability]
    actions: list[ActionCapability]
    limitations: list[str]


class CatalogResult(TypedDict):
    schemaVersion: Literal[1]
    schema: dict[str, Any]
    fields: list[FieldHelp]
    credentials: list[CredentialHelp]
    metadata: dict[str, Any]
    githubSetup: GitHubSetupHelp
    assurance: Assurance


class ValidateResult(TypedDict):
    valid: bool
    state: Literal["invalid", "format-valid"]
    issues: list[Issue]
    requirements: list[RequirementDescriptor]
    assurance: Assurance


class SuggestionHints(TypedDict, total=False):
    platforms: list[Literal["android", "ios"]]
    androidApplicationId: str
    iosBundleId: str
    versionSource: str
    versionNameKey: str
    versionBuildKey: str


class SuggestionProvenance(TypedDict):
    path: str
    source: Literal["hint", "default", "example"]
    reason: str


class SuggestResult(TypedDict):
    schemaVersion: Literal[1]
    draft: dict[str, Any]
    platformSelectionRequired: bool
    provenance: list[SuggestionProvenance]
    validation: ValidateResult
    assurance: Assurance


class ValueSummary(TypedDict):
    present: bool
    type: NotRequired[Literal["null", "boolean", "number", "string", "array", "object"]]
    count: NotRequired[int]


class FieldChange(TypedDict):
    path: str
    operation: Literal["add", "change", "remove"]
    before: ValueSummary
    after: ValueSummary


class ChangeCounts(TypedDict):
    added: int
    changed: int
    removed: int


class DraftComparison(TypedDict):
    baseProvided: bool
    kind: Literal["proposed-create", "compare"]
    state: Literal["complete", "partial"]
    semanticallyChanged: bool
    counts: ChangeCounts
    changes: list[FieldChange]
    unreviewedCount: int


class FieldContext(TypedDict):
    path: str
    state: Literal["required", "optional", "forbidden", "unknown"]
    present: bool
    reason: str


class PreviewResult(TypedDict):
    schemaVersion: Literal[1]
    validation: ValidateResult
    comparison: DraftComparison
    fields: list[FieldContext]
    assurance: Assurance


class GitHubProposalFacts(TypedDict):
    githubContacted: Literal[False]
    repositoryObserved: Literal[False]
    toolingRefResolved: Literal[False]
    templateCompatibility: Literal["unknown"]
    comparisonBasis: Literal["caller-supplied-digest-summary"]
    snapshotProvided: bool
    applyAvailable: Literal[False]


class GitHubTemplateSet(TypedDict):
    coreVersion: str
    resourceVersion: Literal[1]
    resourceSha256: str


class GitHubToolingReference(TypedDict):
    repository: str
    sha: str
    schemaReference: str
    state: Literal["format-only"]


class GitHubWorkflowProposal(TypedDict):
    id: Literal["preflight", "candidate", "external-testing", "production-submit"]
    path: str
    content: str
    byteLength: int
    sha256: str
    comparison: Literal["not-supplied", "reported-absent", "supplied-digest-match", "supplied-digest-differs"]


class GitHubSourcePolicy(TypedDict):
    candidateBranch: str
    productionBranch: str
    basis: Literal["configured-policy"]


class GitHubEnvironment(TypedDict):
    stage: Literal["candidate", "external-testing", "production"]
    name: Literal["mobile-candidate", "mobile-external-testing", "mobile-production"]


class GitHubSetupSettings(TypedDict):
    configPath: Literal["release/mobile-release.json"]
    sourcePolicy: GitHubSourcePolicy
    environments: list[GitHubEnvironment]
    guidanceIds: list[GitHubGuidanceId]


class GitHubInvalidProposal(TypedDict):
    schemaVersion: Literal[1]
    state: Literal["invalid"]
    validation: ValidateResult  # Exact invalid/redacted subset; no requirements.
    facts: GitHubProposalFacts
    assurance: Assurance


class GitHubSetupProposal(TypedDict):
    schemaVersion: Literal[1]
    state: Literal["proposed"]
    validation: ValidateResult  # Exact format-valid subset; no issues.
    facts: GitHubProposalFacts
    assurance: Assurance
    templateSet: GitHubTemplateSet
    tooling: GitHubToolingReference
    workflows: list[GitHubWorkflowProposal]
    settings: GitHubSetupSettings


GitHubSetupResult = GitHubInvalidProposal | GitHubSetupProposal


class ConfigObservation(TypedDict):
    path: str
    state: Literal["missing", "invalid", "format-valid", "unavailable"]
    data: dict[str, Any] | None
    issues: list[Issue]


class ScanCounts(TypedDict):
    entries: int
    sourceFiles: int
    sourceBytes: int
    excludedEntries: int


class DiscoveryObservation(TypedDict):
    state: Literal["unverified"]
    partial: bool
    hints: dict[str, Any]
    scan: ScanCounts
    limits: dict[str, int | float]


class SnapshotResult(TypedDict):
    root: str
    observedAt: str
    observationScope: Literal["single-request-non-atomic"]
    config: ConfigObservation
    discovery: DiscoveryObservation
    assurance: Assurance
    issues: list[Issue]


def assurance(basis: Literal["static-text", "schema-policy"]) -> Assurance:
    return {
        "basis": basis, "projectCodeExecuted": False, "toolsProbed": False,
        "credentialsRead": False, "gitObserved": False, "storeContacted": False,
        "writesPerformed": False, "releaseReadiness": "unknown",
    }


def issue(code: str, message: str, *, partial: bool = False) -> Issue:
    # Core policy errors name fields, not private values. Still bound diagnostics
    # independently of the request/response budget and preserve first-error order.
    return {
        "code": code, "status": "SKIP" if partial else "INVALID",
        "message": message[:1024],
        "remediation": (
            "Review the incomplete static observation; it is not release verification."
            if partial else "Correct the input and validate again; no changes were saved."
        ),
    }
