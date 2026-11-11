pub(crate) const DIRECTORY: &str = "service-v1";
const PARENT_RESERVATION: &str = "service-v1.reservation";
pub(crate) const MAX_BYTES: usize = 1024 * 1024;
/// Closed native metadata, not a renderer DTO or filesystem admission. Keeping
/// this store independent of Desktop source owners preserves the client-only
/// installed CLI graph. The host supplies it only from its genuine source probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationDirectoryIdentity {
    pub(crate) device: u64, pub(crate) inode: u64, pub(crate) mode: u32,
    pub(crate) uid: u32, pub(crate) gid: u32,
}
pub(crate) type ApplicationDirectoryExpectation = (ApplicationDirectoryIdentity, Option<ApplicationDirectoryIdentity>);
const HEADER: usize = 52;
const MAGIC: &[u8; 8] = b"MRKST001";
const RESERVATION: &[u8] = b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n";
const RESERVATION_V2: &[u8] = b"MRK application references v2\nprojects\ncredential-references\nversion-allocations\napple-provisioning\n";
const RESERVATION_V3: &[u8] = b"MRK application references v3\nprojects\ncredential-references\nversion-allocations\napple-provisioning\ngit-operations\n";
const MAX_RESERVATION_BYTES: usize = RESERVATION_V3.len();
const APPLE_UPGRADE_INTENT: &str = "apple-provisioning.upgrade-intent";
const RESERVATION_V2_CANDIDATE: &str = ".reservation-v2.next";
const GIT_UPGRADE_INTENT: &str = "git-operations.upgrade-intent";
const RESERVATION_V3_CANDIDATE: &str = ".reservation-v3.next";
const UPGRADE_FILES: [&str; 4] = [APPLE_UPGRADE_INTENT, RESERVATION_V2_CANDIDATE, GIT_UPGRADE_INTENT, RESERVATION_V3_CANDIDATE];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Namespace { Projects, CredentialReferences, VersionAllocations, AppleProvisioning, GitOperations }
impl Namespace {
    fn file(self) -> &'static str { match self { Self::Projects => "projects.state", Self::CredentialReferences => "credential-references.state", Self::VersionAllocations => "version-allocations.state", Self::AppleProvisioning => "apple-provisioning.state", Self::GitOperations => "git-operations.state" } }
    fn candidate(self) -> &'static str { match self { Self::Projects => ".projects.next", Self::CredentialReferences => ".credential-references.next", Self::VersionAllocations => ".version-allocations.next", Self::AppleProvisioning => ".apple-provisioning.next", Self::GitOperations => ".git-operations.next" } }
    fn intent(self) -> &'static str { match self { Self::Projects => "projects.intent", Self::CredentialReferences => "credential-references.intent", Self::VersionAllocations => "version-allocations.intent", Self::AppleProvisioning => "apple-provisioning.intent", Self::GitOperations => "git-operations.intent" } }
    fn tag(self) -> u8 { match self { Self::Projects => 1, Self::CredentialReferences => 2, Self::VersionAllocations => 3, Self::AppleProvisioning => 4, Self::GitOperations => 5 } }
}
// Ordinary first initialization deliberately remains exactly v1/old3.
const NAMESPACES: [Namespace; 3] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations];
const NAMESPACES_V2: [Namespace; 4] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations, Namespace::AppleProvisioning];
const NAMESPACES_V3: [Namespace; 5] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations, Namespace::AppleProvisioning, Namespace::GitOperations];
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreVersion { V1, V2, V3 }
impl StoreVersion {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes == RESERVATION { Ok(Self::V1) }
        else if bytes == RESERVATION_V2 { Ok(Self::V2) }
        else if bytes == RESERVATION_V3 { Ok(Self::V3) }
        else { Err(Error::RecoveryRequired.into()) }
    }
    fn namespaces(self) -> &'static [Namespace] {
        match self { Self::V1 => &NAMESPACES, Self::V2 => &NAMESPACES_V2, Self::V3 => &NAMESPACES_V3 }
    }
    fn supports(self, namespace: Namespace) -> bool {
        self.namespaces().contains(&namespace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Revision(pub(crate) u64);
pub(crate) struct Snapshot { pub(crate) revision: Revision, pub(crate) bytes: Vec<u8> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect { None, Applied, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Durability { NotApplicable, Confirmed, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cleanup { Known, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StateError {
    pub(crate) code: Error,
    pub(crate) effect: Effect,
    pub(crate) durability: Durability,
    pub(crate) cleanup: Cleanup,
}
impl StateError {
    fn refused(code: Error) -> Self { Self { code, effect: Effect::None, durability: Durability::NotApplicable, cleanup: Cleanup::Known } }
    fn unknown(effect: Effect) -> Self { Self { code: Error::StateUnknown, effect, durability: Durability::Unknown, cleanup: Cleanup::Unknown } }
}
impl From<Error> for StateError { fn from(code: Error) -> Self { Self::refused(code) } }
type Result<T> = std::result::Result<T, StateError>;

