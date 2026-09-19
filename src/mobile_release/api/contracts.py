"""Versioned read-only service data. Protocol framing belongs to the engine.

All assurance flags describe what these services did, never release authority.
The UI must not turn a format-valid configuration into native/Store verification.
Supplied-input credential assessment has its own assurance, not the passive
catalogue's credentialsRead:false statement.
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


class ObservedReleaseVersion(TypedDict):
    name: str
    build: int


class ReleaseVersionInputContent(TypedDict):
    bytes: int
    sha256: str


class ReleaseVersionObservationResult(TypedDict):
    schemaVersion: Literal[2]
    source: str
    version: ObservedReleaseVersion
    savedConfig: ReleaseVersionInputContent
    savedVersion: ReleaseVersionInputContent
    observationScope: Literal["single-request-non-atomic"]
    assurance: Assurance


CandidateEvidenceKind = Literal["manifest", "receipt", "intent"]
CandidateEvidenceRole = Literal["android-aab", "android-mapping", "android-native-symbols", "ios-ipa",
                                "ios-archive", "ios-dsyms", "store-metadata", "validation-report"]


class CandidateEvidenceDocument(TypedDict):
    kind: CandidateEvidenceKind
    state: Literal["missing", "invalid", "valid"]


class CandidateEvidenceVersion(TypedDict):
    marketing: str
    build: int


class CandidateEvidenceSource(TypedDict):
    commit: str
    tree: str


class CandidateEvidenceArtifact(TypedDict):
    logicalName: CandidateEvidenceRole
    declaredBytes: str  # Positive decimal text; not a measured size or JS number.
    sha256: str


class CandidateEvidenceRun(TypedDict):
    runId: str
    attempt: str  # Preserve up to 64 decimal digits without renderer rounding.


class CandidateEvidenceRuns(TypedDict):
    authorizedBy: CandidateEvidenceRun
    executedBy: CandidateEvidenceRun
    producedBy: CandidateEvidenceRun


class CandidateEvidenceDigests(TypedDict):
    manifest: str
    receipt: str
    intent: str


class CandidateEvidenceSummary(TypedDict):
    platform: Literal["android", "ios"]
    applicationId: str
    version: CandidateEvidenceVersion
    source: CandidateEvidenceSource
    artifacts: list[CandidateEvidenceArtifact]
    recordedRuns: CandidateEvidenceRuns
    documentPayloadSha256: CandidateEvidenceDigests


class CandidateEvidenceAssurance(TypedDict):
    level: Literal["local-document-consistency"]
    documentsOnly: Literal[True]
    artifactBytesVerified: Literal[False]
    workflowAuthenticated: Literal[False]
    storeStateObserved: Literal[False]
    comparedWithSourceProject: Literal[False]
    releaseReady: Literal[False]
    recoveryAuthorized: Literal[False]


class CandidateEvidenceResult(TypedDict):
    schemaVersion: Literal[1]
    outcome: Literal["consistent", "incomplete", "invalid", "inconsistent"]
    documents: list[CandidateEvidenceDocument]  # Exactly manifest/receipt/intent, in that order.
    summary: CandidateEvidenceSummary | None  # Only present for consistent, after original cleanup.
    assurance: CandidateEvidenceAssurance


EnvironmentPlatform = Literal["android", "ios"]
EnvironmentOperation = Literal["build", "artifact-validation"]
EnvironmentRole = Literal["android-jdk", "android-gradle-wrapper", "android-sdk", "android-bundletool",
                          "apple-macos", "apple-xcode", "apple-signing-tools", "apple-codesign",
                          "apple-openssl", "apple-security-framework"]


class EnvironmentHelp(TypedDict):
    label: str
    requiredness: Literal["required", "optional", "conditional"]
    requiredWhen: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class EnvironmentContext(TypedDict):
    platform: EnvironmentPlatform
    operation: EnvironmentOperation


class EnvironmentBaseline(TypedDict):
    kind: Literal["exact-pin", "workflow-reference", "project-defined", "platform-defined", "none"]
    version: str | None
    build: str | None
    sha256: str | None
    maxBytes: int | None


class EnvironmentRequirement(TypedDict):
    id: EnvironmentRole
    kind: Literal["external-toolchain", "project-file", "bundled-helper", "native-os"]
    presence: Literal["unknown"]
    versionState: Literal["unknown"]
    inspection: Literal["not-run"]
    baseline: EnvironmentBaseline
    help: EnvironmentHelp


class EnvironmentSelectorHelp(TypedDict):
    platform: EnvironmentHelp
    operation: EnvironmentHelp


class EnvironmentRequirementsResult(TypedDict):
    schemaVersion: Literal[1]
    policyVersion: Literal["environment-requirements-v1"]
    hostPlatform: Literal["linux", "macos", "windows", "other"]
    context: EnvironmentContext
    platformEnabled: bool
    state: Literal["requirements-only", "platform-disabled"]
    coverage: Literal["toolchain-prerequisites-only"]
    nativeInspection: Literal["unavailable"]
    dependencyCompleteness: Literal["unknown"]
    requirements: list[EnvironmentRequirement]
    help: EnvironmentSelectorHelp
    limitations: list[str]
    assurance: Assurance


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


CredentialKindId = Literal["android-keystore", "android-firebase", "apple-p12", "apple-profile",
                           "asc-p8", "ios-firebase", "google-wif", "project-read-token"]
CredentialFieldId = Literal["file", "storePassword", "keyAlias", "keyPassword", "password", "keyId",
                            "issuerId", "provider", "serviceAccount", "token"]
CredentialControlId = Literal["project", "platform", "stage", "purpose", "mode", "label", "choose",
                              "prepare", "review", "save", "assign", "replace", "delete", "cancel",
                              "discard", "lock"]
CredentialStateId = Literal["unknown", "missing", "invalid", "configured", "format-valid", "native-not-run",
                            "service-not-run", "stored", "locked", "unlocked", "assigned", "stale",
                            "cleanup-unknown", "unavailable"]


class CredentialGuideField(TypedDict):
    id: CredentialFieldId
    requirement: str
    alternatives: list[str]
    input: Literal["file", "secret", "text"]
    maxBytes: int | None
    suffixes: list[str]
    label: str
    requiredness: Literal["conditional"]
    requiredWhen: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class CredentialGuideKind(TypedDict):
    id: CredentialKindId
    label: str
    platform: Literal["android", "ios", "project"]
    defaultLabel: str
    fields: list[CredentialGuideField]
    plannedChecks: list[str]
    notVerified: list[str]


class CredentialGuideControl(TypedDict):
    id: CredentialControlId
    label: str
    requiredness: Literal["required", "conditional", "optional"]
    requiredWhen: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class CredentialGuideState(TypedDict):
    id: CredentialStateId
    label: str
    meaning: str


class CredentialGuide(TypedDict):
    schemaVersion: Literal[1]
    policyVersion: Literal["credential-policy-v1"]
    availability: Literal["guide-only"]
    kinds: list[CredentialGuideKind]
    controls: list[CredentialGuideControl]
    states: list[CredentialGuideState]


AssessmentPlatform = Literal["android", "ios", "project"]
AssessmentStage = Literal["candidate", "external-testing", "production"]
AssessmentPurpose = Literal["full", "signing", "store"]
AssessmentState = Literal["not-applicable", "missing", "unknown", "invalid", "configured", "format-valid"]
AssessmentIdentity = Literal["not-applicable", "not-assessed", "match", "mismatch"]
AssessmentUnavailableReason = Literal["not-run", "incomplete", "unsupported-format", "unsupported-variant",
                                      "material-limit", "parser-limit"]
AssessmentRejectedReason = Literal["empty-file", "suffix-conflict", "malformed-container"]
AssessmentIssueCode = Literal["not-run", "incomplete", "unsupported-format", "unsupported-variant",
                              "material-limit", "parser-limit", "empty-file", "suffix-conflict",
                              "malformed-container", "required-missing", "value-nul", "scalar-format",
                              "pkcs8-algorithm", "firebase-shape", "identity-mismatch"]
AssessmentScope = Literal["value-admission", "identifier-format", "file-nonempty", "suffix-consistency",
                          "container-parse", "jks-header", "pfx-envelope", "cms-signed-data-envelope",
                          "pkcs8-envelope", "json-document", "plist-document", "ec-p256-identifiers",
                          "firebase-shape", "application-identity"]
AssessmentRequirement = Literal[
    "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
    "MOBILE_RELEASE_ANDROID_KEY_ALIAS", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
    "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD", "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", "MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID",
    "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64", "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER",
    "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT", "MOBILE_RELEASE_PROJECT_READ_TOKEN",
]


class AssessmentContext(TypedDict):
    draft: dict[str, Any]
    platform: AssessmentPlatform
    stage: AssessmentStage
    purpose: AssessmentPurpose


class AssessmentUnavailableObservation(TypedDict):
    status: Literal["unavailable"]
    reason: AssessmentUnavailableReason


class AssessmentRejectedObservation(TypedDict):
    status: Literal["rejected"]
    reason: AssessmentRejectedReason


class AssessmentJksObservation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["jks"]
    version: Literal[1, 2]


class AssessmentPfxObservation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["pkcs12"]
    version: Literal[3]
    authSafe: Literal["data", "signed-data"]


class AssessmentCmsObservation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["cms-signed-data"]
    encoding: Literal["der"]


class AssessmentP8Observation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["pkcs8"]
    encoding: Literal["pem", "der"]
    algorithm: Literal["ec", "rsa", "other"]
    curve: Literal["p256", "other"] | None


class AssessmentAndroidClientInfo(TypedDict):
    packageName: str | None


class AssessmentClientInfo(TypedDict):
    androidClientInfo: AssessmentAndroidClientInfo | None


class AssessmentAndroidClient(TypedDict):
    clientInfo: AssessmentClientInfo | None


class AssessmentAndroidProjection(TypedDict):
    root: Literal["object", "other"]
    clients: list[AssessmentAndroidClient | None] | None


class AssessmentIosProjection(TypedDict):
    root: Literal["dictionary", "other"]
    bundleId: str | None


class AssessmentAndroidJsonObservation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["firebase-json"]
    document: AssessmentAndroidProjection


class AssessmentIosPlistObservation(TypedDict):
    status: Literal["observed"]
    byteCount: int
    format: Literal["firebase-plist"]
    encoding: Literal["xml", "binary"]
    document: AssessmentIosProjection


AssessmentNoSuccessObservation = AssessmentUnavailableObservation | AssessmentRejectedObservation | None


class AssessmentKeystoreFields(TypedDict):
    storePassword: str | None
    keyAlias: str | None
    keyPassword: str | None


class AssessmentP12Fields(TypedDict):
    password: str | None


class AssessmentP8Fields(TypedDict):
    keyId: str | None
    issuerId: str | None


class AssessmentWifFields(TypedDict):
    provider: str | None
    serviceAccount: str | None


class AssessmentTokenFields(TypedDict):
    token: str | None


class AssessmentNoScalarFields(TypedDict):
    pass


class AssessmentKeystoreInput(TypedDict):
    kind: Literal["android-keystore"]
    fields: AssessmentKeystoreFields
    observation: AssessmentJksObservation | AssessmentPfxObservation | AssessmentNoSuccessObservation


class AssessmentAndroidFirebaseInput(TypedDict):
    kind: Literal["android-firebase"]
    fields: AssessmentNoScalarFields
    observation: AssessmentAndroidJsonObservation | AssessmentNoSuccessObservation


class AssessmentP12Input(TypedDict):
    kind: Literal["apple-p12"]
    fields: AssessmentP12Fields
    observation: AssessmentPfxObservation | AssessmentNoSuccessObservation


class AssessmentProfileInput(TypedDict):
    kind: Literal["apple-profile"]
    fields: AssessmentNoScalarFields
    observation: AssessmentCmsObservation | AssessmentNoSuccessObservation


class AssessmentP8Input(TypedDict):
    kind: Literal["asc-p8"]
    fields: AssessmentP8Fields
    observation: AssessmentP8Observation | AssessmentNoSuccessObservation


class AssessmentIosFirebaseInput(TypedDict):
    kind: Literal["ios-firebase"]
    fields: AssessmentNoScalarFields
    observation: AssessmentIosPlistObservation | AssessmentNoSuccessObservation


class AssessmentWifInput(TypedDict):
    kind: Literal["google-wif"]
    fields: AssessmentWifFields
    observation: None


class AssessmentTokenInput(TypedDict):
    kind: Literal["project-read-token"]
    fields: AssessmentTokenFields
    observation: None


AssessmentInput = (
    AssessmentKeystoreInput | AssessmentAndroidFirebaseInput | AssessmentP12Input | AssessmentProfileInput
    | AssessmentP8Input | AssessmentIosFirebaseInput | AssessmentWifInput | AssessmentTokenInput
)


class CredentialAssessmentRequest(TypedDict):
    schemaVersion: Literal[1]
    policyVersion: Literal["credential-policy-v1"]
    context: AssessmentContext
    input: AssessmentInput


class AssessmentResultContext(TypedDict):
    platform: AssessmentPlatform
    stage: AssessmentStage
    purpose: AssessmentPurpose


class AssessmentApplicability(TypedDict):
    state: Literal["required", "not-applicable"]
    reason: Literal["selected", "wrong-platform", "platform-disabled", "not-required"]


class AssessmentCheck(TypedDict):
    scope: AssessmentScope
    outcome: Literal["passed", "failed", "asserted-pass", "asserted-fail"]


class AssessmentFieldResult(TypedDict):
    id: CredentialFieldId
    requirement: AssessmentRequirement
    presence: Literal["missing", "supplied"]
    state: AssessmentState
    issues: list[AssessmentIssueCode]
    checks: list[AssessmentCheck]


class AssessmentAssurance(TypedDict):
    basis: Literal["supplied-input-only"]
    scalarValuesProcessed: bool
    fileObservationsProcessed: bool
    selectedFilesRead: Literal[False]
    keyringAccessed: Literal[False]
    storageWritesPerformed: Literal[False]
    projectCodeExecuted: Literal[False]
    sourceCustody: Literal["not-established"]
    nativeValidation: Literal["not-run"]
    serviceValidation: Literal["not-run"]
    releaseReadiness: Literal["unknown"]


class CredentialAssessmentResult(TypedDict):
    schemaVersion: Literal[1]
    policyVersion: Literal["credential-policy-v1"]
    kind: CredentialKindId
    context: AssessmentResultContext
    applicability: AssessmentApplicability
    state: AssessmentState
    fields: list[AssessmentFieldResult]
    identity: AssessmentIdentity
    assurance: AssessmentAssurance


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


class GitHubConnectionInputHelp(TypedDict):
    id: Literal["repository", "token"]
    label: str
    requiredness: Literal["required", "conditional"]
    what: str
    why: str
    where: str
    format: str
    failure: str


class GitHubConnectionGuidance(TypedDict):
    id: Literal["authentication", "permissions", "session-memory", "repository-identity",
                "automation-observation", "remote-changes", "revocation"]
    label: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class GitHubConnectionHelp(TypedDict):
    schemaVersion: Literal[1]
    inputs: list[GitHubConnectionInputHelp]
    guidance: list[GitHubConnectionGuidance]


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


MetadataPlatform = Literal["android", "ios"]


class MetadataTextIssue(TypedDict):
    code: Literal["metadata.empty-text", "metadata.nul", "metadata.placeholder",
                  "metadata.secret-pattern", "metadata.url", "metadata.length"]
    status: Literal["INVALID", "FAIL"]
    message: str


class MetadataTextFieldValidation(TypedDict):
    id: str
    valid: bool
    characterCount: int
    limit: int
    issues: list[MetadataTextIssue]


class MetadataValidationResult(TypedDict):
    schemaVersion: Literal[1]
    platform: MetadataPlatform
    valid: bool
    state: Literal["format-valid", "invalid"]
    fields: list[MetadataTextFieldValidation]
    assurance: Assurance


class MetadataContentDigest(TypedDict):
    byteLength: int
    sha256: str


class MetadataAbsentBaselineField(TypedDict):
    id: str
    state: Literal["absent"]


class MetadataPresentBaselineField(MetadataContentDigest):
    id: str
    state: Literal["present"]


class MetadataBaseline(TypedDict):
    config: MetadataContentDigest
    fields: list[MetadataAbsentBaselineField | MetadataPresentBaselineField]


class MetadataAbsentObservedField(MetadataAbsentBaselineField):
    path: str


class MetadataPresentObservedField(MetadataPresentBaselineField):
    path: str
    text: str


class MetadataObservationResult(TypedDict):
    schemaVersion: Literal[1]
    platform: MetadataPlatform
    locale: str
    metadataRoot: str
    observationScope: Literal["single-request-non-atomic"]
    baseline: MetadataBaseline
    fields: list[MetadataAbsentObservedField | MetadataPresentObservedField]
    assurance: Assurance


class MetadataTextHelpText(TypedDict):
    id: str
    requiredWhen: str
    label: str
    what: str
    why: str
    where: str
    format: str
    failure: str


class MetadataTextFieldHelp(MetadataTextHelpText):
    platform: MetadataPlatform
    requiredness: Literal["required"]


class MetadataTextActionHelp(MetadataTextHelpText):
    requiredness: Literal["optional"]


class MetadataTextGuideLimits(TypedDict):
    maxTextBytes: Literal[32768]
    maxCachedLocales: Literal[32]
    maxCachedTextBytes: Literal[8388608]


class MetadataTextGuide(TypedDict):
    schemaVersion: Literal[1]
    fields: list[MetadataTextFieldHelp]
    actions: list[MetadataTextActionHelp]
    limits: MetadataTextGuideLimits


class CatalogResult(TypedDict):
    schemaVersion: Literal[1]
    schema: dict[str, Any]
    fields: list[FieldHelp]
    credentials: list[CredentialHelp]
    credentialGuide: CredentialGuide | None
    metadata: dict[str, Any]
    metadataText: MetadataTextGuide | None
    githubSetup: GitHubSetupHelp
    githubConnection: GitHubConnectionHelp | None
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


class SavedConfigContent(TypedDict):
    bytes: int
    sha256: str


class ConfigObservation(TypedDict):
    path: str
    state: Literal["missing", "invalid", "format-valid", "unavailable"]
    data: dict[str, Any] | None
    content: SavedConfigContent | None
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
