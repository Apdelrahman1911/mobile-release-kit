//! Qualification-only DATA result seam and the single retained file writer.
//! Never compiled by a normal production/native unit. Account lifecycle and
//! process creation remain exclusively in the cfg(test) ordinary owner.
//! Unknown retains the actual owning stack, original buffers and security inputs.
use super::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use windows_sys::Win32::Security::Cryptography as BC;

#[cfg(all(feature = "desktop-ui", any(test, feature = "windows-installed-observation")))]
#[path = "observer_diagnostic.rs"]
mod observer_diagnostic;
#[cfg(all(test, feature = "desktop-ui"))]
pub(super) use observer_diagnostic::{ObserverDiagnosticClock, ObserverDiagnosticOriginal};
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub use observer_diagnostic::ObserverDiagnostic;

pub(super) const FLAGS: [&str; 4] = ["--exact", "--ignored", "--nocapture", "--test-threads=1"];
pub(super) const LIMIT: usize = 4096;
pub(super) const OWNER_LIMIT: usize = 65536;
pub(super) const APP_ARTIFACT_LIMIT: usize = 512 << 20;
const ORDINARY_ARTIFACT_LIMIT: usize = 128 << 20;
pub(super) const FULLWALK_CHILD: &str = "installed_runtime_windows::tests::native_protected_version_walk_and_original_settlement";
pub(super) const FULLWALK_OWNER: &str = "ordinary_owner::hosted_protected_version_fullwalk_contract";
pub(super) const FULLWALK_REQUEST: &str = "fullwalk-request.txt";
pub(super) const FULLWALK_OUTPUT: &str = "fullwalk-output";
pub(super) const FULLWALK_RESULT: &str = "fullwalk-result.private.json";
pub(super) const PASSIVE_CHILD: &str = "supervisor::windows_passive_tests::native_installed_passive_original_owner_contract";
pub(super) const PASSIVE_OWNER: &str = "ordinary_owner::hosted_installed_passive_original_handle_contract";
pub(super) const PASSIVE_REQUEST: &str = "passive-request.txt";
pub(super) const PASSIVE_OUTPUT: &str = "passive-output";
pub(super) const PASSIVE_RESULT: &str = "passive-result.private.json";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ResultRole { Fullwalk, Passive }
impl ResultRole {
    fn child(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_CHILD, Self::Passive => PASSIVE_CHILD } }
    fn owner(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_OWNER, Self::Passive => PASSIVE_OWNER } }
    fn output(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_OUTPUT, Self::Passive => PASSIVE_OUTPUT } }
    fn result(self) -> &'static str { match self { Self::Fullwalk => FULLWALK_RESULT, Self::Passive => PASSIVE_RESULT } }
    fn request_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_REQUEST", Self::Passive => "MRK_WINDOWS_PASSIVE_REQUEST" } }
    fn output_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_OUTPUT", Self::Passive => "MRK_WINDOWS_PASSIVE_OUTPUT" } }
    fn identity_env(self) -> &'static str { match self { Self::Fullwalk => "MRK_WINDOWS_FULLWALK_ARTIFACT_IDENTITY", Self::Passive => "MRK_WINDOWS_PASSIVE_ARTIFACT_IDENTITY" } }
    fn command(self, path: &str, owner: bool) -> String {
        format!("\"{path}\" {} {}", if owner { self.owner() } else { self.child() }, FLAGS.join(" "))
    }
}

pub(super) fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }
// Only closed labels, original statuses and u16 ACL control facts may leave.
// This stack-owned snapshot is independent of FileBody.error, which close reuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputRole {
    Ancestor, Request, Binding, Command, Directory, Artifact, Output,
    AclRoot, AclTarget, AclTriple, AclDebug, AclDeps, AclArtifact, AclOutput, Parent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputCheck {
    AncestorCount, FileCount, PathText, PathUnits, OpenState, OpenReturned,
    InfoState, InfoClass, BasicInfoReturned, StandardInfoReturned, TagInfoReturned, IdInfoReturned,
    StampDirectory, StampDeletePending, StampSize, StampAllocation, StampLinks,
    StampAttributes, StampReparse, StampIdentity,
    NameText, NameState, NameReturned, NameCount, NameUtf16, NameExact,
    ReadFileKind, ReadSize, ReadLimit, ReadReturned, ReadCount, ReadStable,
    RequestEnvelope, RequestUtf8, RequestLines, RequestHeader, RequestKey, RequestValue,
    RequestValues, RequestArtifactPath, RequestBytes, RequestBytesRange, RequestIdentity,
    BindingSourceAvailable, BindingSource, BindingTree, BindingRun, BindingRuntimeRun,
    BindingRuntimeTree, BindingImage, CommandUnits, CommandDigest, HashLimit, HashReturned,
    ArtifactIdentity, ArtifactBytes, ArtifactDigest, ArtifactStable,
    OutputCreate, DescriptorState, DescriptorReturned, DescriptorLength,
    AclLayout, AclOwner, AclGroup, AclAccount, AclMask, AclMutation, AclCapacity,
    AclInitialize, AclDacl, AclControlInput, AclSetState, AclSetReturned, AclStamp, AclControl,
    AclOwnerEqual, AclGroupEqual, AclRevision, AclAces, AclChanged, AclDeadline,
    AclTransitions, ParentPrimary, ParentUser, ParentIdentity, ParentSettlement,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputStatus { Win32(u32), NtStatus(i32) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InputFault {
    role: InputRole, slot: Option<u8>, check: InputCheck, status: Option<InputStatus>,
    control: Option<(u16, u16)>,
}
// Fixed prerequisite-only DATA. Default/legacy InputTrace owners stay disabled.
// No native storage, output handle, path, account, SID or arbitrary text enters
// this record. Expected-negative scopes have independent local staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteStage { Entry, ParentInput, AccountProfile, Launch, ChildOutput, Settlement, Retirement, Final, Escape }
impl PrerequisiteStage {
    pub(super) fn label(self) -> &'static str { match self {
        Self::Entry => "entry",
        Self::ParentInput => "parent-input",
        Self::AccountProfile => "account-profile",
        Self::Launch => "launch",
        Self::ChildOutput => "child-output",
        Self::Settlement => "settlement",
        Self::Retirement => "retirement",
        Self::Final => "final",
        Self::Escape => "escape",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteCheck { E01, E02, E03, E04, P01, P02, P03, P04, P05, P06, A01, A02, A03, L01, L02, L03, L04, C01, C02, C03, S01, S02, R01, R02, Z01, Z02, U01, K01, K02, K03, B01, B02, B03, V01, V02, V03, V04, V05, V06, V07, V08, V09, V10, V11, F01, F02, F03, F04, F05, F06, F07, F08, F09, H01, Q01, Q02, Q03, Q04, Q05, G01, G02, N01, N02, N03, N04, N05, N06, N07, D01, D02, D03, D04, D05, D06, T01, O01, O02, O03, NB01, NB02, NB03, NB04, NB05, NB06, NB07, NB08, NB09, NB10, NB11, HT01 }
impl PrerequisiteCheck {
    pub(super) fn label(self) -> &'static str { match self {
        Self::E01 => "e01",
        Self::E02 => "e02",
        Self::E03 => "e03",
        Self::E04 => "e04",
        Self::P01 => "p01",
        Self::P02 => "p02",
        Self::P03 => "p03",
        Self::P04 => "p04",
        Self::P05 => "p05",
        Self::P06 => "p06",
        Self::A01 => "a01",
        Self::A02 => "a02",
        Self::A03 => "a03",
        Self::L01 => "l01",
        Self::L02 => "l02",
        Self::L03 => "l03",
        Self::L04 => "l04",
        Self::C01 => "c01",
        Self::C02 => "c02",
        Self::C03 => "c03",
        Self::S01 => "s01",
        Self::S02 => "s02",
        Self::R01 => "r01",
        Self::R02 => "r02",
        Self::Z01 => "z01",
        Self::Z02 => "z02",
        Self::U01 => "u01",
        Self::K01 => "k01",
        Self::K02 => "k02",
        Self::K03 => "k03",
        Self::B01 => "b01",
        Self::B02 => "b02",
        Self::B03 => "b03",
        Self::V01 => "v01",
        Self::V02 => "v02",
        Self::V03 => "v03",
        Self::V04 => "v04",
        Self::V05 => "v05",
        Self::V06 => "v06",
        Self::V07 => "v07",
        Self::V08 => "v08",
        Self::V09 => "v09",
        Self::V10 => "v10",
        Self::V11 => "v11",
        Self::F01 => "f01",
        Self::F02 => "f02",
        Self::F03 => "f03",
        Self::F04 => "f04",
        Self::F05 => "f05",
        Self::F06 => "f06",
        Self::F07 => "f07",
        Self::F08 => "f08",
        Self::F09 => "f09",
        Self::H01 => "h01",
        Self::Q01 => "q01",
        Self::Q02 => "q02",
        Self::Q03 => "q03",
        Self::Q04 => "q04",
        Self::Q05 => "q05",
        Self::G01 => "g01",
        Self::G02 => "g02",
        Self::N01 => "n01",
        Self::N02 => "n02",
        Self::N03 => "n03",
        Self::N04 => "n04",
        Self::N05 => "n05",
        Self::N06 => "n06",
        Self::N07 => "n07",
        Self::D01 => "d01",
        Self::D02 => "d02",
        Self::D03 => "d03",
        Self::D04 => "d04",
        Self::D05 => "d05",
        Self::D06 => "d06",
        Self::T01 => "t01",
        Self::O01 => "o01",
        Self::O02 => "o02",
        Self::O03 => "o03",
        Self::NB01 => "nb01",
        Self::NB02 => "nb02",
        Self::NB03 => "nb03",
        Self::NB04 => "nb04",
        Self::NB05 => "nb05",
        Self::NB06 => "nb06",
        Self::NB07 => "nb07",
        Self::NB08 => "nb08",
        Self::NB09 => "nb09",
        Self::NB10 => "nb10",
        Self::NB11 => "nb11",
        Self::HT01 => "ht01",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteClock { NotCreated, LastUnlatched, LastLatched }
impl PrerequisiteClock {
    pub(super) fn label(self) -> &'static str { match self {
        Self::NotCreated => "not-created",
        Self::LastUnlatched => "last-unlatched",
        Self::LastLatched => "last-latched",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteApi { None, CurrentDir, CurrentExe, CreateFileW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, ReadFile, WriteFile, GetKernelObjectSecurity, SetKernelObjectSecurity, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorControl, BCryptHash, BCryptGenRandom, CreateDirectoryW, LookupAccountSidW, NetUserGetInfo, NetUserGetLocalGroups, NetApiBufferSize, NetApiBufferFree, NetUserAdd, NetLocalGroupAddMembers, NetUserDel, RegOpenKeyExW, RegQueryValueExW, RegCloseKey, NtCreateFile, GetProfilesDirectoryW, DeleteProfileW, CreateProcessWithLogonW, WaitForSingleObject, TerminateProcess, GetExitCodeProcess, CloseHandle, GetSystemWindowsDirectoryW, IsWow64Process2, OpenProcessToken, OpenThreadToken, GetHandleInformation, GetTokenInformation, LookupPrivilegeValueW, QueryDosDeviceW, GetVolumeInformationByHandleW, NtQueryVolumeInformationFile }
impl PrerequisiteApi {
    pub(super) fn label(self) -> &'static str { match self {
        Self::None => "none",
        Self::CurrentDir => "std-current-dir",
        Self::CurrentExe => "std-current-exe",
        Self::CreateFileW => "CreateFileW",
        Self::GetFileInformationByHandleEx => "GetFileInformationByHandleEx",
        Self::GetFinalPathNameByHandleW => "GetFinalPathNameByHandleW",
        Self::ReadFile => "ReadFile",
        Self::WriteFile => "WriteFile",
        Self::GetKernelObjectSecurity => "GetKernelObjectSecurity",
        Self::SetKernelObjectSecurity => "SetKernelObjectSecurity",
        Self::InitializeSecurityDescriptor => "InitializeSecurityDescriptor",
        Self::SetSecurityDescriptorDacl => "SetSecurityDescriptorDacl",
        Self::SetSecurityDescriptorControl => "SetSecurityDescriptorControl",
        Self::BCryptHash => "BCryptHash",
        Self::BCryptGenRandom => "BCryptGenRandom",
        Self::CreateDirectoryW => "CreateDirectoryW",
        Self::LookupAccountSidW => "LookupAccountSidW",
        Self::NetUserGetInfo => "NetUserGetInfo",
        Self::NetUserGetLocalGroups => "NetUserGetLocalGroups",
        Self::NetApiBufferSize => "NetApiBufferSize",
        Self::NetApiBufferFree => "NetApiBufferFree",
        Self::NetUserAdd => "NetUserAdd",
        Self::NetLocalGroupAddMembers => "NetLocalGroupAddMembers",
        Self::NetUserDel => "NetUserDel",
        Self::RegOpenKeyExW => "RegOpenKeyExW",
        Self::RegQueryValueExW => "RegQueryValueExW",
        Self::RegCloseKey => "RegCloseKey",
        Self::NtCreateFile => "NtCreateFile",
        Self::GetProfilesDirectoryW => "GetProfilesDirectoryW",
        Self::DeleteProfileW => "DeleteProfileW",
        Self::CreateProcessWithLogonW => "CreateProcessWithLogonW",
        Self::WaitForSingleObject => "WaitForSingleObject",
        Self::TerminateProcess => "TerminateProcess",
        Self::GetExitCodeProcess => "GetExitCodeProcess",
        Self::CloseHandle => "CloseHandle",
        Self::GetSystemWindowsDirectoryW => "GetSystemWindowsDirectoryW",
        Self::IsWow64Process2 => "IsWow64Process2",
        Self::OpenProcessToken => "OpenProcessToken",
        Self::OpenThreadToken => "OpenThreadToken",
        Self::GetHandleInformation => "GetHandleInformation",
        Self::GetTokenInformation => "GetTokenInformation",
        Self::LookupPrivilegeValueW => "LookupPrivilegeValueW",
        Self::QueryDosDeviceW => "QueryDosDeviceW",
        Self::GetVolumeInformationByHandleW => "GetVolumeInformationByHandleW",
        Self::NtQueryVolumeInformationFile => "NtQueryVolumeInformationFile",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteSelector { None, FileBasicInfo, FileStandardInfo, FileAttributeTagInfo, FileIdInfo, FileCaseSensitiveInfo, FileIdExtdDirectoryInfo, FileFsDeviceInformation, TokenStatistics, TokenType, TokenElevation, TokenElevationType, TokenUIAccess, TokenVirtualizationEnabled, TokenUser, TokenIntegrityLevel, TokenGroups, TokenPrivileges, Lookup1, Lookup2, Lookup3, Lookup4, Lookup5, FirstWait, SettleWait, ThreadClose, ProcessClose, BeforeLogon, AfterDeletion, UserInfo23, LocalGroups0, UserAdd1, GroupAdd0, ProfileImagePath }
impl PrerequisiteSelector {
    pub(super) fn label(self) -> &'static str { match self {
        Self::None => "none",
        Self::FileBasicInfo => "FileBasicInfo",
        Self::FileStandardInfo => "FileStandardInfo",
        Self::FileAttributeTagInfo => "FileAttributeTagInfo",
        Self::FileIdInfo => "FileIdInfo",
        Self::FileCaseSensitiveInfo => "FileCaseSensitiveInfo",
        Self::FileIdExtdDirectoryInfo => "FileIdExtdDirectoryInfo",
        Self::FileFsDeviceInformation => "FileFsDeviceInformation",
        Self::TokenStatistics => "TokenStatistics",
        Self::TokenType => "TokenType",
        Self::TokenElevation => "TokenElevation",
        Self::TokenElevationType => "TokenElevationType",
        Self::TokenUIAccess => "TokenUIAccess",
        Self::TokenVirtualizationEnabled => "TokenVirtualizationEnabled",
        Self::TokenUser => "TokenUser",
        Self::TokenIntegrityLevel => "TokenIntegrityLevel",
        Self::TokenGroups => "TokenGroups",
        Self::TokenPrivileges => "TokenPrivileges",
        Self::Lookup1 => "lookup-1",
        Self::Lookup2 => "lookup-2",
        Self::Lookup3 => "lookup-3",
        Self::Lookup4 => "lookup-4",
        Self::Lookup5 => "lookup-5",
        Self::FirstWait => "first-wait",
        Self::SettleWait => "settle-wait",
        Self::ThreadClose => "thread-close",
        Self::ProcessClose => "process-close",
        Self::BeforeLogon => "before-logon",
        Self::AfterDeletion => "after-deletion",
        Self::UserInfo23 => "user-info-23",
        Self::LocalGroups0 => "local-groups-0",
        Self::UserAdd1 => "user-add-1",
        Self::GroupAdd0 => "group-add-0",
        Self::ProfileImagePath => "profile-image-path",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteKind { None, Bool, Count, Lstatus, Ntstatus, Netapi, Hresult, Wait, Exit }
impl PrerequisiteKind {
    pub(super) fn label(self) -> &'static str { match self {
        Self::None => "none",
        Self::Bool => "bool",
        Self::Count => "count",
        Self::Lstatus => "lstatus",
        Self::Ntstatus => "ntstatus",
        Self::Netapi => "netapi",
        Self::Hresult => "hresult",
        Self::Wait => "wait",
        Self::Exit => "exit",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteStatus { None, Win32, Ntstatus, Netapi, Hresult, IoOs }
impl PrerequisiteStatus {
    pub(super) fn label(self) -> &'static str { match self {
        Self::None => "none",
        Self::Win32 => "win32",
        Self::Ntstatus => "ntstatus",
        Self::Netapi => "netapi",
        Self::Hresult => "hresult",
        Self::IoOs => "io-os",
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrerequisiteDetail { Input(InputCheck), Admission(AdmissionCheck) }
impl PrerequisiteDetail {
    pub(super) fn labels(self) -> (&'static str, &'static str) { match self {
        Self::Admission(check) => ("admission.", check.label()),
        Self::Input(check) => ("input.", match check {
            InputCheck::AncestorCount => "AncestorCount",
            InputCheck::FileCount => "FileCount",
            InputCheck::PathText => "PathText",
            InputCheck::PathUnits => "PathUnits",
            InputCheck::OpenState => "OpenState",
            InputCheck::OpenReturned => "OpenReturned",
            InputCheck::InfoState => "InfoState",
            InputCheck::InfoClass => "InfoClass",
            InputCheck::BasicInfoReturned => "BasicInfoReturned",
            InputCheck::StandardInfoReturned => "StandardInfoReturned",
            InputCheck::TagInfoReturned => "TagInfoReturned",
            InputCheck::IdInfoReturned => "IdInfoReturned",
            InputCheck::StampDirectory => "StampDirectory",
            InputCheck::StampDeletePending => "StampDeletePending",
            InputCheck::StampSize => "StampSize",
            InputCheck::StampAllocation => "StampAllocation",
            InputCheck::StampLinks => "StampLinks",
            InputCheck::StampAttributes => "StampAttributes",
            InputCheck::StampReparse => "StampReparse",
            InputCheck::StampIdentity => "StampIdentity",
            InputCheck::NameText => "NameText",
            InputCheck::NameState => "NameState",
            InputCheck::NameReturned => "NameReturned",
            InputCheck::NameCount => "NameCount",
            InputCheck::NameUtf16 => "NameUtf16",
            InputCheck::NameExact => "NameExact",
            InputCheck::ReadFileKind => "ReadFileKind",
            InputCheck::ReadSize => "ReadSize",
            InputCheck::ReadLimit => "ReadLimit",
            InputCheck::ReadReturned => "ReadReturned",
            InputCheck::ReadCount => "ReadCount",
            InputCheck::ReadStable => "ReadStable",
            InputCheck::RequestEnvelope => "RequestEnvelope",
            InputCheck::RequestUtf8 => "RequestUtf8",
            InputCheck::RequestLines => "RequestLines",
            InputCheck::RequestHeader => "RequestHeader",
            InputCheck::RequestKey => "RequestKey",
            InputCheck::RequestValue => "RequestValue",
            InputCheck::RequestValues => "RequestValues",
            InputCheck::RequestArtifactPath => "RequestArtifactPath",
            InputCheck::RequestBytes => "RequestBytes",
            InputCheck::RequestBytesRange => "RequestBytesRange",
            InputCheck::RequestIdentity => "RequestIdentity",
            InputCheck::BindingSourceAvailable => "BindingSourceAvailable",
            InputCheck::BindingSource => "BindingSource",
            InputCheck::BindingTree => "BindingTree",
            InputCheck::BindingRun => "BindingRun",
            InputCheck::BindingRuntimeRun => "BindingRuntimeRun",
            InputCheck::BindingRuntimeTree => "BindingRuntimeTree",
            InputCheck::BindingImage => "BindingImage",
            InputCheck::CommandUnits => "CommandUnits",
            InputCheck::CommandDigest => "CommandDigest",
            InputCheck::HashLimit => "HashLimit",
            InputCheck::HashReturned => "HashReturned",
            InputCheck::ArtifactIdentity => "ArtifactIdentity",
            InputCheck::ArtifactBytes => "ArtifactBytes",
            InputCheck::ArtifactDigest => "ArtifactDigest",
            InputCheck::ArtifactStable => "ArtifactStable",
            InputCheck::OutputCreate => "OutputCreate",
            InputCheck::DescriptorState => "DescriptorState",
            InputCheck::DescriptorReturned => "DescriptorReturned",
            InputCheck::DescriptorLength => "DescriptorLength",
            InputCheck::AclLayout => "AclLayout",
            InputCheck::AclOwner => "AclOwner",
            InputCheck::AclGroup => "AclGroup",
            InputCheck::AclAccount => "AclAccount",
            InputCheck::AclMask => "AclMask",
            InputCheck::AclMutation => "AclMutation",
            InputCheck::AclCapacity => "AclCapacity",
            InputCheck::AclInitialize => "AclInitialize",
            InputCheck::AclDacl => "AclDacl",
            InputCheck::AclControlInput => "AclControlInput",
            InputCheck::AclSetState => "AclSetState",
            InputCheck::AclSetReturned => "AclSetReturned",
            InputCheck::AclStamp => "AclStamp",
            InputCheck::AclControl => "AclControl",
            InputCheck::AclOwnerEqual => "AclOwnerEqual",
            InputCheck::AclGroupEqual => "AclGroupEqual",
            InputCheck::AclRevision => "AclRevision",
            InputCheck::AclAces => "AclAces",
            InputCheck::AclChanged => "AclChanged",
            InputCheck::AclDeadline => "AclDeadline",
            InputCheck::AclTransitions => "AclTransitions",
            InputCheck::ParentPrimary => "ParentPrimary",
            InputCheck::ParentUser => "ParentUser",
            InputCheck::ParentIdentity => "ParentIdentity",
            InputCheck::ParentSettlement => "ParentSettlement",
        }),
    } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PrerequisiteNative {
    pub api: PrerequisiteApi, pub selector: PrerequisiteSelector,
    pub kind: PrerequisiteKind, pub value: Option<i64>,
    pub status: PrerequisiteStatus, pub code: Option<i64>,
}
impl PrerequisiteNative {
    pub(super) fn boolean(api: PrerequisiteApi, selector: PrerequisiteSelector, value: i32, error: Option<u32>) -> Option<Self> {
        (value == 0).then_some(Self { api, selector, kind: PrerequisiteKind::Bool, value: Some(i64::from(value)),
            status: if error.is_some() { PrerequisiteStatus::Win32 } else { PrerequisiteStatus::None }, code: error.map(i64::from) })
    }
    pub(super) fn count(api: PrerequisiteApi, value: u32, error: u32) -> Option<Self> {
        (value == 0).then_some(Self { api, selector: PrerequisiteSelector::None, kind: PrerequisiteKind::Count,
            value: Some(i64::from(value)), status: PrerequisiteStatus::Win32, code: Some(i64::from(error)) })
    }
    pub(super) fn nt(api: PrerequisiteApi, selector: PrerequisiteSelector, value: i32) -> Option<Self> {
        (value != 0).then_some(Self { api, selector, kind: PrerequisiteKind::Ntstatus, value: Some(i64::from(value)),
            status: PrerequisiteStatus::Ntstatus, code: Some(i64::from(value)) })
    }
    pub(super) fn net(api: PrerequisiteApi, selector: PrerequisiteSelector, value: u32) -> Option<Self> {
        (value != 0).then_some(Self { api, selector, kind: PrerequisiteKind::Netapi, value: Some(i64::from(value)),
            status: PrerequisiteStatus::Netapi, code: Some(i64::from(value)) })
    }
    pub(super) fn registry(api: PrerequisiteApi, selector: PrerequisiteSelector, value: u32) -> Option<Self> {
        (value != 0).then_some(Self { api, selector, kind: PrerequisiteKind::Lstatus, value: Some(i64::from(value)),
            status: PrerequisiteStatus::Win32, code: Some(i64::from(value)) })
    }
    pub(super) fn wait(selector: PrerequisiteSelector, value: u32, error: u32) -> Option<Self> {
        (value != F::WAIT_OBJECT_0).then_some(Self { api: PrerequisiteApi::WaitForSingleObject, selector,
            kind: PrerequisiteKind::Wait, value: Some(i64::from(value)),
            status: if value == F::WAIT_FAILED { PrerequisiteStatus::Win32 } else { PrerequisiteStatus::None },
            code: (value == F::WAIT_FAILED).then_some(i64::from(error)) })
    }
    pub(super) fn exit(value: u32) -> Option<Self> {
        (value != 0).then_some(Self { api: PrerequisiteApi::GetExitCodeProcess, selector: PrerequisiteSelector::None,
            kind: PrerequisiteKind::Exit, value: Some(i64::from(value)), status: PrerequisiteStatus::None, code: None })
    }
    pub(super) fn file_open(error: u32) -> Option<Self> {
        // CreateFileW returns a private HANDLE, never a Boolean or integer on this wire.
        Some(Self { api: PrerequisiteApi::CreateFileW, selector: PrerequisiteSelector::None,
            kind: PrerequisiteKind::None, value: None, status: PrerequisiteStatus::Win32, code: Some(i64::from(error)) })
    }
    pub(super) fn io(api: PrerequisiteApi, error: &std::io::Error) -> Option<Self> {
        let code = error.raw_os_error().map(i64::from);
        Some(Self { api, selector: PrerequisiteSelector::None, kind: PrerequisiteKind::None, value: None,
            status: if code.is_some() { PrerequisiteStatus::IoOs } else { PrerequisiteStatus::None }, code })
    }
    pub(super) fn valid(self) -> bool {
        use PrerequisiteApi as A; use PrerequisiteSelector as Q;
        use PrerequisiteKind as K; use PrerequisiteStatus as D;
        let uint = |value: Option<i64>| value.is_some_and(|v| (0..=i64::from(u32::MAX)).contains(&v));
        let sint = |value: Option<i64>| value.is_some_and(|v| (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&v));
        let selector = match self.api {
            A::GetFileInformationByHandleEx => matches!(self.selector, Q::FileBasicInfo | Q::FileStandardInfo | Q::FileAttributeTagInfo
                | Q::FileIdInfo | Q::FileCaseSensitiveInfo | Q::FileIdExtdDirectoryInfo),
            A::NtQueryVolumeInformationFile => self.selector == Q::FileFsDeviceInformation,
            A::GetTokenInformation => matches!(self.selector, Q::TokenStatistics | Q::TokenType | Q::TokenElevation | Q::TokenElevationType
                | Q::TokenUIAccess | Q::TokenVirtualizationEnabled | Q::TokenUser | Q::TokenIntegrityLevel | Q::TokenGroups | Q::TokenPrivileges),
            A::LookupPrivilegeValueW => matches!(self.selector, Q::Lookup1 | Q::Lookup2 | Q::Lookup3 | Q::Lookup4 | Q::Lookup5),
            A::WaitForSingleObject => matches!(self.selector, Q::FirstWait | Q::SettleWait),
            A::CloseHandle => matches!(self.selector, Q::None | Q::ThreadClose | Q::ProcessClose),
            A::NtCreateFile => matches!(self.selector, Q::None | Q::BeforeLogon | Q::AfterDeletion),
            A::NetUserGetInfo => self.selector == Q::UserInfo23,
            A::NetUserGetLocalGroups => self.selector == Q::LocalGroups0,
            A::NetUserAdd => self.selector == Q::UserAdd1,
            A::NetLocalGroupAddMembers => self.selector == Q::GroupAdd0,
            A::RegQueryValueExW => self.selector == Q::ProfileImagePath,
            _ => self.selector == Q::None,
        };
        if !selector { return false; }
        match self.kind {
            K::None => self.value.is_none() && match self.api {
                A::CurrentDir | A::CurrentExe => match self.status {
                    D::IoOs => sint(self.code), D::None => self.code.is_none(), _ => false,
                },
                A::CreateFileW => self.status == D::Win32 && uint(self.code),
                _ => false,
            },
            K::Bool => self.value == Some(0) && match self.api {
                A::InitializeSecurityDescriptor | A::SetSecurityDescriptorDacl | A::SetSecurityDescriptorControl =>
                    self.status == D::None && self.code.is_none(),
                A::GetFileInformationByHandleEx | A::ReadFile | A::WriteFile | A::GetKernelObjectSecurity | A::SetKernelObjectSecurity
                | A::CreateDirectoryW | A::LookupAccountSidW | A::GetProfilesDirectoryW | A::DeleteProfileW
                | A::CreateProcessWithLogonW | A::TerminateProcess | A::GetExitCodeProcess | A::CloseHandle
                | A::IsWow64Process2 | A::OpenProcessToken | A::OpenThreadToken | A::GetHandleInformation
                | A::GetTokenInformation | A::LookupPrivilegeValueW | A::GetVolumeInformationByHandleW =>
                    self.status == D::Win32 && uint(self.code),
                _ => false,
            },
            K::Count => matches!(self.api, A::GetFinalPathNameByHandleW | A::GetSystemWindowsDirectoryW | A::QueryDosDeviceW)
                && self.value == Some(0) && self.status == D::Win32 && uint(self.code),
            K::Lstatus => matches!(self.api, A::RegOpenKeyExW | A::RegQueryValueExW | A::RegCloseKey)
                && uint(self.value) && self.value != Some(0) && self.status == D::Win32 && self.code == self.value,
            K::Ntstatus => matches!(self.api, A::BCryptHash | A::BCryptGenRandom | A::NtCreateFile | A::NtQueryVolumeInformationFile)
                && sint(self.value) && self.value != Some(0) && self.status == D::Ntstatus && self.code == self.value,
            K::Netapi => matches!(self.api, A::NetUserGetInfo | A::NetUserGetLocalGroups | A::NetApiBufferSize
                | A::NetApiBufferFree | A::NetUserAdd | A::NetLocalGroupAddMembers | A::NetUserDel)
                && uint(self.value) && self.value != Some(0) && self.status == D::Netapi && self.code == self.value,
            K::Wait => self.api == A::WaitForSingleObject && uint(self.value) && self.value != Some(i64::from(F::WAIT_OBJECT_0))
                && if self.value == Some(i64::from(F::WAIT_FAILED)) { self.status == D::Win32 && uint(self.code) }
                   else { self.status == D::None && self.code.is_none() },
            K::Exit => self.api == A::GetExitCodeProcess && uint(self.value) && self.value != Some(0)
                && self.status == D::None && self.code.is_none(),
            K::Hresult => false, // No prerequisite-path API supplies an HRESULT.
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PrerequisiteFault {
    pub stage: PrerequisiteStage, pub check: PrerequisiteCheck, pub error: Error,
    pub detail: Option<PrerequisiteDetail>, pub native: Option<PrerequisiteNative>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct PrerequisiteRecord {
    pub stage: PrerequisiteStage, pub check: PrerequisiteCheck,
    pub first: Option<PrerequisiteFault>, pub clock: PrerequisiteClock,
}
macro_rules! prerequisite_result {
    ($trace:expr, $check:ident, $result:expr) => {{
        let original = $result;
        $trace.prerequisite_result(PrerequisiteCheck::$check, original)
    }};
}
pub(super) use prerequisite_result;

#[derive(Clone, Copy, Default)]
pub(super) struct InputTrace {
    role: Option<InputRole>, slot: Option<u8>, pub first: Option<InputFault>,
    pub(super) prerequisite: Option<PrerequisiteRecord>,
}
impl InputTrace {
    pub(super) fn prerequisite_only(enabled: bool) -> Self {
        Self { prerequisite: enabled.then_some(PrerequisiteRecord { stage: PrerequisiteStage::Entry,
            check: PrerequisiteCheck::E01, first: None, clock: PrerequisiteClock::NotCreated }), ..Self::default() }
    }
    pub(super) fn prerequisite_at(&mut self, stage: PrerequisiteStage, check: PrerequisiteCheck) {
        if let Some(record) = self.prerequisite.as_mut() { record.stage = stage; record.check = check; }
    }
    pub(super) fn prerequisite_check(&mut self, check: PrerequisiteCheck) {
        if let Some(record) = self.prerequisite.as_mut() { record.check = check; }
    }
    pub(super) fn prerequisite_clock(&mut self, latched: bool) {
        if let Some(record) = self.prerequisite.as_mut() {
            record.clock = if latched { PrerequisiteClock::LastLatched } else { PrerequisiteClock::LastUnlatched };
        }
    }
    pub(super) fn prerequisite_fault(&mut self, check: PrerequisiteCheck, error: Error,
        native: Option<PrerequisiteNative>, detail: Option<PrerequisiteDetail>) {
        if let Some(record) = self.prerequisite.as_mut() {
            if record.first.is_none() {
                record.first = Some(PrerequisiteFault { stage: if check == PrerequisiteCheck::U01 { PrerequisiteStage::Escape } else { record.stage },
                    check, error, detail, native });
            }
        }
    }
    pub(super) fn prerequisite_current<T>(&mut self, original: Result<T>) -> Result<T> {
        if let Some(record) = self.prerequisite { self.prerequisite_result(record.check, original) } else { original }
    }
    pub(super) fn prerequisite_result<T>(&mut self, check: PrerequisiteCheck, original: Result<T>) -> Result<T> {
        if let Err(error) = &original { self.prerequisite_fault(check, *error, None, None); }
        original
    }
    pub(super) fn prerequisite_native_result<T>(&mut self, check: PrerequisiteCheck, original: Result<T>,
        native: Option<PrerequisiteNative>, detail: Option<PrerequisiteDetail>) -> Result<T> {
        if let Err(error) = &original { self.prerequisite_fault(check, *error, native, detail); }
        original
    }
    pub(super) fn prerequisite_scope<T>(&mut self, check: PrerequisiteCheck,
        observation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let previous = self.prerequisite.map(|record| record.check);
        self.prerequisite_check(check);
        let original = observation(self);
        let original = self.prerequisite_current(original);
        if let Some(previous) = previous { self.prerequisite_check(previous); }
        original
    }
    pub(super) fn prerequisite_staged(&self) -> Self {
        let mut local = *self;
        local.first = None;
        if let Some(record) = local.prerequisite.as_mut() { record.first = None; }
        local
    }
    pub(super) fn prerequisite_expected<T>(&mut self, check: PrerequisiteCheck, original: Result<T>, expected: Error, local: Self) -> bool {
        if matches!(&original, Err(error) if *error == expected) { return true; }
        if let Some(fault) = local.prerequisite.and_then(|record| record.first) {
            if let Some(record) = self.prerequisite.as_mut() {
                if record.first.is_none() { record.first = Some(fault); }
            }
        } else {
            self.prerequisite_fault(check, original.err().unwrap_or(Error::Unsafe), None, None);
        }
        false
    }
    pub fn at(&mut self, role: InputRole, slot: Option<u8>) {
        self.role = Some(role); self.slot = slot.filter(|value| *value < 40);
    }
    pub fn record(&mut self, check: InputCheck, status: Option<InputStatus>) {
        if self.first.is_none() {
            if let Some(role) = self.role { self.first = Some(InputFault { role, slot: self.slot, check, status, control: None }); }
        }
    }
    pub(super) fn observed<T>(&mut self, result: Result<T>, check: InputCheck) -> Result<T> {
        if let Err(error) = &result {
            self.record(check, None);
            if let Some(record) = self.prerequisite {
                self.prerequisite_fault(record.check, *error, None, Some(PrerequisiteDetail::Input(check)));
            }
        }
        result
    }
    pub fn need(&mut self, value: bool, check: InputCheck) -> Result<()> { self.observed(need(value), check) }
    pub fn control(&mut self, expected: u16, observed: u16) -> Result<()> {
        let unfaulted = self.first.is_none();
        let result = self.need(expected == observed, InputCheck::AclControl);
        if unfaulted {
            if let Some(first) = self.first.as_mut() { first.control = Some((expected, observed)); }
        }
        result
    }
}

pub(super) fn hex(raw: &[u8]) -> String { raw.iter().map(|b| format!("{b:02x}")).collect() }
pub(super) fn is_hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn decimal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
}
pub(super) fn unhex(value: &str) -> Result<Vec<u8>> {
    need(value.len() <= 136 && value.len() % 2 == 0 && is_hex(value, value.len()))?;
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        Ok(digit(pair[0]) * 16 + digit(pair[1]))
    }).collect()
}
pub(super) fn digest(raw: &[u8]) -> Result<String> {
    digest_traced(raw, &mut InputTrace::default())
}
pub(super) fn digest_traced(raw: &[u8], trace: &mut InputTrace) -> Result<String> {
    digest_bounded(raw, ORDINARY_ARTIFACT_LIMIT, trace)
}
pub(super) fn digest_app_traced(raw: &[u8], trace: &mut InputTrace) -> Result<String> {
    digest_bounded(raw, APP_ARTIFACT_LIMIT, trace)
}
fn digest_bounded(raw: &[u8], ceiling: usize, trace: &mut InputTrace) -> Result<String> {
    trace.prerequisite_scope(PrerequisiteCheck::H01, |trace| {
        trace.need(matches!(ceiling, ORDINARY_ARTIFACT_LIMIT | APP_ARTIFACT_LIMIT)
            && raw.len() <= ceiling, InputCheck::HashLimit)?;
        let mut output = [0u8; 32];
        // Documented CNG pseudo-handle: borrowed, never closed. No provider/import,
        // key, random fallback, package dependency or hand-written hash algorithm.
        let status = unsafe { BC::BCryptHash(BC::BCRYPT_SHA256_ALG_HANDLE, null(), 0,
            raw.as_ptr(), raw.len() as u32, output.as_mut_ptr(), output.len() as u32) };
        if status != 0 {
            trace.record(InputCheck::HashReturned, Some(InputStatus::NtStatus(status)));
            trace.prerequisite_fault(PrerequisiteCheck::H01, Error::Unsafe,
                PrerequisiteNative::nt(PrerequisiteApi::BCryptHash, PrerequisiteSelector::None, status),
                Some(PrerequisiteDetail::Input(InputCheck::HashReturned)));
        }
        need(status == 0)?;
        Ok(hex(&output))
    })
}

pub(super) fn fixed_path(value: &str) -> Result<PathBuf> { fixed_path_traced(value, &mut InputTrace::default()) }
pub(super) fn fixed_path_traced(value: &str, trace: &mut InputTrace) -> Result<PathBuf> {
    trace.prerequisite_scope(PrerequisiteCheck::F03, |trace| {
        need(value.len() <= 1024 && value.is_ascii() && !value.bytes().any(|b| b < 32 || matches!(b, b'"' | b'%' | b'=')))?;
        let path = PathBuf::from(value);
        need(path.is_absolute() && value.as_bytes().get(1) == Some(&b':')
            && value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && value.as_bytes().get(2) == Some(&b'\\')
            && !value.contains('/') && !value.starts_with("\\\\")
            && value.split('\\').skip(1).all(|part| decode::component(part)))?;
        Ok(path)
    })
}
pub(super) fn fixed_directories(root: &Path) -> [(&'static str, PathBuf); 4] {
    let target = root.join("target");
    let triple = target.join("x86_64-pc-windows-msvc");
    let debug = triple.join("debug");
    let deps = debug.join("deps");
    [("target", target), ("target/x86_64-pc-windows-msvc", triple),
        ("target/x86_64-pc-windows-msvc/debug", debug),
        ("target/x86_64-pc-windows-msvc/debug/deps", deps)]
}

pub(super) fn complete_write(ok: bool, actual: u32, expected: usize, closed: bool) -> bool {
    complete_write_bounded(ok,actual,expected,closed,OWNER_LIMIT)
}
#[cfg(test)]
pub(super) fn complete_fixture_write(ok:bool,actual:u32,expected:usize,closed:bool) -> bool {
    complete_write_bounded(ok,actual,expected,closed,ORDINARY_ARTIFACT_LIMIT)
}
fn complete_write_bounded(ok:bool,actual:u32,expected:usize,closed:bool,limit:usize) -> bool {
    ok && expected>0 && expected<=limit && limit<=ORDINARY_ARTIFACT_LIMIT && actual as usize==expected && closed
}

pub(super) fn builtin(rid: u32) -> Vec<u8> {
    [vec![1, 2, 0, 0, 0, 0, 0, 5], 32u32.to_le_bytes().to_vec(), rid.to_le_bytes().to_vec()].concat()
}
pub(super) fn system_sid() -> Vec<u8> { [vec![1, 1, 0, 0, 0, 0, 0, 5], 18u32.to_le_bytes().to_vec()].concat() }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub volume: u64, pub id: [u8; 16], pub creation: i64, pub write: i64, pub change: i64,
    pub size: i64, pub allocation: i64, pub links: u32, pub attributes: u32,
}
impl Stamp {
    pub fn wire(&self) -> String {
        format!("{}:{}:{}:{}:{}:{}", self.volume, hex(&self.id), self.creation,
            self.write, self.change, self.attributes)
    }
    pub(super) fn json(&self) -> String {
        format!("{{\"volume\":{},\"fileId\":\"{}\",\"creation\":{},\"write\":{},\"change\":{},\"size\":{},\"allocation\":{},\"links\":{},\"attributes\":{}}}",
            self.volume, hex(&self.id), self.creation, self.write, self.change,
            self.size, self.allocation, self.links, self.attributes)
    }
}
pub(super) fn acl_stamp(before: &Stamp, after: &Stamp) -> bool {
    let mut admitted = before.clone(); admitted.change = after.change;
    admitted == *after && after.change >= before.change
}

// An absolute reporting boundary supplied by the original caller, never a new
// clock. Expiry is absorbing; it refuses effects, not original close settlement.
pub(super) fn reporting_effect(now: Instant, end: Instant, latched: &mut bool) -> Result<()> {
    *latched |= now >= end;
    need(!*latched)
}
fn deadline(end: Option<Instant>) -> Result<()> {
    match end { Some(end) => need(Instant::now() < end), None => Ok(()) }
}

pub(super) struct FileBody {
    path: Vec<u16>, pub(super) handle: F::HANDLE, pub(super) state: SlotState, pub(super) active: bool,
    pub(super) error: u32, count: u32, raw: Vec<u8>, security: Box<Aligned>,
    end: Option<Instant>, deadline_latched: bool,
    basic: FS::FILE_BASIC_INFO, standard: FS::FILE_STANDARD_INFO,
    tag: FS::FILE_ATTRIBUTE_TAG_INFO, id: FS::FILE_ID_INFO,
    final_name: Vec<u16>, _pin: PhantomPinned,
}
impl FileBody {
    fn timely(&mut self) -> Result<()> { self.timely_traced(&mut InputTrace::default()) }
    fn timely_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        let original = match self.end {
            Some(end) => reporting_effect(Instant::now(), end, &mut self.deadline_latched),
            None => Ok(()), // Ordinary owner semantics and its existing clock are unchanged.
        };
        trace.prerequisite_result(PrerequisiteCheck::F04, original)
    }
}
pub(super) struct OriginalFile { body: Held<FileBody>, pub(super) directory: bool }
impl OriginalFile {
    pub(super) fn is_closed(&self) -> bool { self.body.state == SlotState::Closed && !self.body.active }
    fn new_until(path: &Path, directory: bool, end: Instant) -> Result<Self> {
        Self::new_until_traced(path, directory, end, &mut InputTrace::default())
    }
    fn new_until_traced(path: &Path, directory: bool, end: Instant, trace: &mut InputTrace) -> Result<Self> {
        let mut file = Self::new_traced(path, directory, trace)?;
        file.body().end = Some(end);
        Ok(file)
    }
    #[cfg(test)]
    pub(super) fn fixture_new(path: &Path, directory: bool, end: Instant) -> Result<Self> {
        Self::fixture_new_traced(path, directory, end, &mut InputTrace::default())
    }
    #[cfg(test)]
    pub(super) fn fixture_new_traced(path: &Path, directory: bool, end: Instant, trace: &mut InputTrace) -> Result<Self> {
        Self::new_until_traced(path, directory, end, trace)
    }
    pub(super) fn new(path: &Path, directory: bool) -> Result<Self> {
        Self::new_traced(path, directory, &mut InputTrace::default())
    }
    pub(super) fn new_traced(path: &Path, directory: bool, trace: &mut InputTrace) -> Result<Self> {
        trace.prerequisite_scope(PrerequisiteCheck::F04, |trace| {
            let value = trace.observed(path.to_str().ok_or(Error::Unsafe), InputCheck::PathText)?;
            trace.need(value.encode_utf16().count() <= 1024, InputCheck::PathUnits)?;
            Ok(Self { body: ManuallyDrop::new(Box::pin(FileBody {
                path: wide(value), handle: null_mut(), state: SlotState::Reserved, active: false,
                error: 0, count: 0, raw: Vec::new(), security: Box::new(Aligned([0; BUFFER])),
                end: None, deadline_latched: false,
                basic: FS::FILE_BASIC_INFO::default(), standard: FS::FILE_STANDARD_INFO::default(),
                tag: FS::FILE_ATTRIBUTE_TAG_INFO::default(), id: FS::FILE_ID_INFO::default(),
                final_name: vec![0; 32768], _pin: PhantomPinned,
            })), directory })
        })
    }
    pub(super) fn body(&mut self) -> &mut FileBody {
        // No movement of the pinned body; all native pointers refer to this
        // original's retained complete buffers, never temporary output storage.
        unsafe { self.body.as_mut().get_unchecked_mut() }
    }
    pub(super) fn open(&mut self, access: u32, create: bool, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
        self.open_traced(access, create, security, &mut InputTrace::default())
    }
    pub(super) fn open_traced(&mut self, access: u32, create: bool, security: *const S::SECURITY_ATTRIBUTES, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::F04, |trace| {
            let directory = self.directory; let b = self.body();
            if b.state != SlotState::Reserved { return trace.observed(Err(Error::State), InputCheck::OpenState); }
            b.timely_traced(trace)?;
            b.state = SlotState::Acquiring; b.active = true;
            b.handle = unsafe { FS::CreateFileW(b.path.as_ptr(), access,
                FS::FILE_SHARE_READ | if directory { FS::FILE_SHARE_WRITE } else { 0 },
                security, if create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
                FS::FILE_FLAG_OPEN_REPARSE_POINT | if directory { FS::FILE_FLAG_BACKUP_SEMANTICS } else { 0 }, null_mut()) };
            b.error = if valid_handle(b.handle) { 0 } else { unsafe { F::GetLastError() } };
            if !valid_handle(b.handle) {
                trace.record(InputCheck::OpenReturned, Some(InputStatus::Win32(b.error)));
                let error = if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE { Error::Unavailable } else { Error::Unknown };
                trace.prerequisite_fault(PrerequisiteCheck::F04, error, PrerequisiteNative::file_open(b.error),
                    Some(PrerequisiteDetail::Input(InputCheck::OpenReturned)));
            }
            if valid_handle(b.handle) { b.active = false; b.state = SlotState::Owned; b.timely_traced(trace) }
            else if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE {
                b.active = false; b.state = SlotState::NoHandle; b.timely_traced(trace)?; Err(Error::Unavailable)
            } else { b.state = SlotState::Unknown; Err(Error::Unknown) }
        })
    }
    fn info(&mut self, which: u8, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::F04, |trace| {
            let b = self.body();
            if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::InfoState); }
            let (class, output, size, check) = match which {
                0 => (FS::FileBasicInfo, (&mut b.basic as *mut FS::FILE_BASIC_INFO).cast(), size_of::<FS::FILE_BASIC_INFO>(), InputCheck::BasicInfoReturned),
                1 => (FS::FileStandardInfo, (&mut b.standard as *mut FS::FILE_STANDARD_INFO).cast(), size_of::<FS::FILE_STANDARD_INFO>(), InputCheck::StandardInfoReturned),
                2 => (FS::FileAttributeTagInfo, (&mut b.tag as *mut FS::FILE_ATTRIBUTE_TAG_INFO).cast(), size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>(), InputCheck::TagInfoReturned),
                3 => (FS::FileIdInfo, (&mut b.id as *mut FS::FILE_ID_INFO).cast(), size_of::<FS::FILE_ID_INFO>(), InputCheck::IdInfoReturned),
                _ => return trace.observed(Err(Error::State), InputCheck::InfoClass),
            };
            b.timely_traced(trace)?;
            b.active = true;
            let ok = unsafe { FS::GetFileInformationByHandleEx(b.handle, class, output, size as u32) };
            b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
            if ok == 0 { trace.record(check, Some(InputStatus::Win32(b.error))); }
            b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
            let native = PrerequisiteNative::boolean(PrerequisiteApi::GetFileInformationByHandleEx,
                match which { 0 => PrerequisiteSelector::FileBasicInfo, 1 => PrerequisiteSelector::FileStandardInfo,
                    2 => PrerequisiteSelector::FileAttributeTagInfo, 3 => PrerequisiteSelector::FileIdInfo, _ => PrerequisiteSelector::None },
                ok, Some(b.error));
            if b.active {
                trace.prerequisite_fault(PrerequisiteCheck::F04, Error::Unknown, native, Some(PrerequisiteDetail::Input(check)));
                b.state = SlotState::Unknown; return Err(Error::Unknown);
            }
            // This original file deadline precedes the non-ambiguous BOOL check.
            // A saved scalar is staged DATA until that check actually rejects.
            b.timely_traced(trace)?;
            trace.prerequisite_native_result(PrerequisiteCheck::F04, need(ok != 0), native, Some(PrerequisiteDetail::Input(check)))
        })
    }
    pub(super) fn stamp(&mut self) -> Result<Stamp> {
        self.stamp_traced(&mut InputTrace::default())
    }
    pub(super) fn stamp_traced(&mut self, trace: &mut InputTrace) -> Result<Stamp> {
        trace.prerequisite_scope(PrerequisiteCheck::F04, |trace| {
            for which in 0..4 { self.info(which, trace)?; }
            let directory = self.directory; let b = self.body();
            trace.need(b.standard.Directory == directory, InputCheck::StampDirectory)?;
            trace.need(!b.standard.DeletePending, InputCheck::StampDeletePending)?;
            trace.need(b.standard.EndOfFile >= 0, InputCheck::StampSize)?;
            trace.need(b.standard.AllocationSize >= 0, InputCheck::StampAllocation)?;
            trace.need(b.standard.NumberOfLinks == 1, InputCheck::StampLinks)?;
            trace.need(b.tag.FileAttributes == b.basic.FileAttributes, InputCheck::StampAttributes)?;
            trace.need(b.basic.FileAttributes & FS::FILE_ATTRIBUTE_REPARSE_POINT == 0, InputCheck::StampReparse)?;
            trace.need(b.id.FileId.Identifier != [0; 16], InputCheck::StampIdentity)?;
            Ok(Stamp { volume: b.id.VolumeSerialNumber, id: b.id.FileId.Identifier,
                creation: b.basic.CreationTime, write: b.basic.LastWriteTime, change: b.basic.ChangeTime,
                size: b.standard.EndOfFile, allocation: b.standard.AllocationSize,
                links: b.standard.NumberOfLinks, attributes: b.basic.FileAttributes })
        })
    }
    pub(super) fn named(&mut self, expected: &Path) -> Result<()> {
        self.named_traced(expected, &mut InputTrace::default())
    }
    pub(super) fn named_traced(&mut self, expected: &Path, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::F05, |trace| {
            let text = trace.observed(expected.to_str().ok_or(Error::Unsafe), InputCheck::NameText)?;
            let b = self.body();
            if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::NameState); }
            b.timely_traced(trace)?;
            b.active = true;
            b.count = unsafe { FS::GetFinalPathNameByHandleW(b.handle, b.final_name.as_mut_ptr(),
                b.final_name.len() as u32, FS::FILE_NAME_NORMALIZED | FS::VOLUME_NAME_DOS) };
            b.error = if b.count != 0 { 0 } else { unsafe { F::GetLastError() } };
            if b.count == 0 { trace.record(InputCheck::NameReturned, Some(InputStatus::Win32(b.error))); }
            b.active = b.count == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
            let native = PrerequisiteNative::count(PrerequisiteApi::GetFinalPathNameByHandleW, b.count, b.error);
            if b.active {
                trace.prerequisite_fault(PrerequisiteCheck::F05, Error::Unknown, native, Some(PrerequisiteDetail::Input(InputCheck::NameReturned)));
                b.state = SlotState::Unknown; return Err(Error::Unknown);
            }
            b.timely_traced(trace)?;
            let original = need(b.count > 0 && (b.count as usize) < b.final_name.len());
            let detail = if native.is_some() { InputCheck::NameReturned } else { InputCheck::NameCount };
            let original = trace.prerequisite_native_result(PrerequisiteCheck::F05, original, native, Some(PrerequisiteDetail::Input(detail)));
            trace.observed(original, InputCheck::NameCount)?;
            let actual = trace.observed(String::from_utf16(&b.final_name[..b.count as usize]).map_err(|_| Error::Unsafe), InputCheck::NameUtf16)?;
            trace.need(actual.strip_prefix("\\\\?\\") == Some(text), InputCheck::NameExact)
        })
    }
    pub(super) fn read(&mut self, limit: usize) -> Result<Vec<u8>> {
        self.read_traced(limit, &mut InputTrace::default())
    }
    pub(super) fn read_traced(&mut self, limit: usize, trace: &mut InputTrace) -> Result<Vec<u8>> {
        self.read_bounded(limit, ORDINARY_ARTIFACT_LIMIT, trace)
    }
    pub(super) fn read_app_traced(&mut self, trace: &mut InputTrace) -> Result<Vec<u8>> {
        // Only the fixed fullwalk app route uses its already-admitted512MiB
        // artifact ceiling. Ordinary calls retain their original128MiB ceiling.
        self.read_bounded(APP_ARTIFACT_LIMIT, APP_ARTIFACT_LIMIT, trace)
    }
    fn read_bounded(&mut self, limit: usize, ceiling: usize, trace: &mut InputTrace) -> Result<Vec<u8>> {
        trace.prerequisite_scope(PrerequisiteCheck::F05, |trace| {
            let before = self.stamp_traced(trace)?;
            trace.need(!self.directory, InputCheck::ReadFileKind)?;
            trace.need(before.size >= 0 && before.size as usize <= limit, InputCheck::ReadSize)?;
            trace.need(matches!(ceiling, ORDINARY_ARTIFACT_LIMIT | APP_ARTIFACT_LIMIT) && limit <= ceiling, InputCheck::ReadLimit)?;
            let b = self.body();
            b.raw = vec![0; before.size as usize + 1]; b.count = 0;
            b.timely_traced(trace)?;
            b.active = true;
            let ok = unsafe { FS::ReadFile(b.handle, b.raw.as_mut_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
            b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
            if ok == 0 { trace.record(InputCheck::ReadReturned, Some(InputStatus::Win32(b.error))); }
            b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
            let native = PrerequisiteNative::boolean(PrerequisiteApi::ReadFile, PrerequisiteSelector::None, ok, Some(b.error));
            if b.active {
                trace.prerequisite_fault(PrerequisiteCheck::F05, Error::Unknown, native, Some(PrerequisiteDetail::Input(InputCheck::ReadReturned)));
                b.state = SlotState::Unknown; return Err(Error::Unknown);
            }
            b.timely_traced(trace)?;
            let original = need(ok != 0 && b.count as i64 == before.size);
            let detail = if native.is_some() { InputCheck::ReadReturned } else { InputCheck::ReadCount };
            let original = trace.prerequisite_native_result(PrerequisiteCheck::F05, original, native, Some(PrerequisiteDetail::Input(detail)));
            trace.observed(original, InputCheck::ReadCount)?;
            let value = b.raw[..b.count as usize].to_vec();
            let after = self.stamp_traced(trace)?;
            trace.need(after == before, InputCheck::ReadStable)?;
            Ok(value)
        })
    }
    pub(super) fn descriptor(&mut self) -> Result<Vec<u8>> {
        self.descriptor_traced(&mut InputTrace::default())
    }
    pub(super) fn descriptor_traced(&mut self, trace: &mut InputTrace) -> Result<Vec<u8>> {
        trace.prerequisite_scope(PrerequisiteCheck::F06, |trace| {
            let b = self.body();
            if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::DescriptorState); }
            b.timely_traced(trace)?;
            b.count = 0; b.active = true;
            let ok = unsafe { S::GetKernelObjectSecurity(b.handle,
                S::OWNER_SECURITY_INFORMATION | S::GROUP_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION,
                b.security.0.as_mut_ptr().cast(), BUFFER as u32, &mut b.count) };
            b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
            if ok == 0 { trace.record(InputCheck::DescriptorReturned, Some(InputStatus::Win32(b.error))); }
            b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
            let native = PrerequisiteNative::boolean(PrerequisiteApi::GetKernelObjectSecurity, PrerequisiteSelector::None, ok, Some(b.error));
            if b.active {
                trace.prerequisite_fault(PrerequisiteCheck::F06, Error::Unknown, native, Some(PrerequisiteDetail::Input(InputCheck::DescriptorReturned)));
                b.state = SlotState::Unknown; return Err(Error::Unknown);
            }
            b.timely_traced(trace)?;
            trace.prerequisite_native_result(PrerequisiteCheck::F06, need(ok != 0), native,
                Some(PrerequisiteDetail::Input(InputCheck::DescriptorReturned)))?;
            trace.need(b.count as usize <= BUFFER && b.count >= 20, InputCheck::DescriptorLength)?;
            Ok(b.security.0[..b.count as usize].to_vec())
        })
    }
    fn write(&mut self, value: &[u8], limit: usize) -> Result<()> {
        self.write_traced(value, limit, &mut InputTrace::default())
    }
    fn write_traced(&mut self, value: &[u8], limit: usize, trace: &mut InputTrace) -> Result<()> {
        prerequisite_result!(trace, F07, need(limit <= OWNER_LIMIT))?;
        self.write_bounded_traced(value, limit, trace)
    }
    // Only the closed cfg(test) fixture publisher can request payload writes.
    // The app-safe/result entry above retains its original64KiB bound.
    #[cfg(test)]
    pub(super) fn write_fixture_payload(&mut self, value: &[u8]) -> Result<()> {
        self.write_bounded(value, ORDINARY_ARTIFACT_LIMIT)
    }
    fn write_bounded(&mut self, value: &[u8], limit: usize) -> Result<()> {
        self.write_bounded_traced(value, limit, &mut InputTrace::default())
    }
    fn write_bounded_traced(&mut self, value: &[u8], limit: usize, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::F07, |trace| {
            need(!value.is_empty() && value.len() <= limit && limit <= ORDINARY_ARTIFACT_LIMIT)?;
            let b = self.body();
            if b.state != SlotState::Owned || b.active || !b.raw.is_empty() { return Err(Error::State); }
            b.raw = value.to_vec(); b.count = 0;
            b.timely_traced(trace)?;
            b.active = true;
            let ok = unsafe { FS::WriteFile(b.handle, b.raw.as_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
            b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
            b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
            let native = PrerequisiteNative::boolean(PrerequisiteApi::WriteFile, PrerequisiteSelector::None, ok, Some(b.error));
            if b.active {
                trace.prerequisite_fault(PrerequisiteCheck::F07, Error::Unknown, native, None);
                b.state = SlotState::Unknown; return Err(Error::Unknown);
            }
            b.timely_traced(trace)?;
            // Exactly one attempt. An ordinary short write is still failure; the
            // caller must then explicitly close the same original, not retry it.
            trace.prerequisite_native_result(PrerequisiteCheck::F07,
                need(complete_write_bounded(ok != 0, b.count, value.len(), true, limit)), native, None)
        })
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.close_traced(&mut InputTrace::default())
    }
    pub(super) fn close_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::F08, |trace| {
            let b = self.body();
            match b.state {
                SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
                SlotState::Owned if !b.active => (),
                _ => return Err(Error::Unknown),
            }
            b.state = SlotState::Closing;
            let ok = unsafe { F::CloseHandle(b.handle) };
            b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
            if ok == 0 {
                trace.prerequisite_fault(PrerequisiteCheck::F08, Error::Unknown,
                    PrerequisiteNative::boolean(PrerequisiteApi::CloseHandle, PrerequisiteSelector::None, ok, Some(b.error)), None);
            }
            b.state = if ok != 0 { SlotState::Closed } else { SlotState::Unknown };
            if ok != 0 { Ok(()) } else { Err(Error::Unknown) }
        })
    }
}
impl Drop for OriginalFile {
    fn drop(&mut self) {
        let b = self.body();
        if !b.active && matches!(b.state, SlotState::Reserved | SlotState::NoHandle | SlotState::Closed) {
            unsafe { ManuallyDrop::drop(&mut self.body); }
        }
        // Never CloseHandle in Drop. Uncertain buffers/originals are retained.
    }
}
pub(super) fn close_files(files: &mut [OriginalFile]) -> bool {
    close_files_traced(files, &mut InputTrace::default())
}
pub(super) fn close_files_traced(files: &mut [OriginalFile], trace: &mut InputTrace) -> bool {
    // A later original can be a child of any earlier directory. On the first
    // uncertain close stop, retaining every remaining ancestor without retry.
    for file in files.iter_mut().rev() {
        if file.close_traced(trace).is_err() { return false; }
    }
    true
}
pub(super) fn owned_file(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32) -> Result<usize> {
    owned_file_traced(files, path, directory, access, &mut InputTrace::default())
}
pub(super) fn owned_file_traced(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32, trace: &mut InputTrace) -> Result<usize> {
    trace.need(files.len() < 40, InputCheck::FileCount)?;
    let index = files.len(); files.push(OriginalFile::new_traced(path, directory, trace)?);
    files[index].open_traced(access, false, null(), trace)?;
    files[index].named_traced(path, trace)?; files[index].stamp_traced(trace)?;
    Ok(index)
}

pub(super) fn args_are(target: &str, image: &Path) -> Result<()> { args_are_traced(target, image, &mut InputTrace::default()) }
pub(super) fn args_are_traced(target: &str, image: &Path, trace: &mut InputTrace) -> Result<()> {
    trace.prerequisite_scope(PrerequisiteCheck::F03, |trace| {
        let args: Vec<_> = std::env::args().collect();
        need(args.len() == 6 && Path::new(&args[0]) == image && args[1] == target
            && args[2..].iter().map(String::as_str).eq(FLAGS))
    })
}

pub(super) fn write_one(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
    write_one_until(path, raw, limit, security, None)
}
#[cfg(test)]
pub(super) fn write_fixture_record(path: &Path, raw: &[u8], limit: usize, end: Instant) -> Result<()> {
    write_fixture_record_traced(path, raw, limit, end, &mut InputTrace::default())
}
#[cfg(test)]
pub(super) fn write_fixture_record_traced(path: &Path, raw: &[u8], limit: usize, end: Instant, trace: &mut InputTrace) -> Result<()> {
    prerequisite_result!(trace, F09, need(limit <= OWNER_LIMIT))?;
    write_one_until_traced(path, raw, limit, null(), Some(end), trace)
}
fn write_one_until(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES, end: Option<Instant>) -> Result<()> {
    write_one_until_traced(path, raw, limit, security, end, &mut InputTrace::default())
}
fn write_one_until_traced(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES,
    end: Option<Instant>, trace: &mut InputTrace) -> Result<()> {
    let mut file = prerequisite_result!(trace, F09, OriginalFile::new_traced(path, false, trace))?;
    file.body().end = end;
    let observation = (|| -> Result<()> {
        file.open_traced(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, security, trace)?;
        file.named_traced(path, trace)?; file.stamp_traced(trace)?;
        file.write_traced(raw, limit, trace)
    })();
    let observation = trace.prerequisite_result(PrerequisiteCheck::F09, observation);
    if matches!(observation, Err(Error::Unknown)) {
        diagnostic_data("result-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    let closed = file.close_traced(trace);
    if closed.is_err() {
        diagnostic_data("result-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    let timely = file.body().timely_traced(trace); // close is permitted late; reporting success is not
    observation?;
    timely
}

pub(super) fn child_security(parent: &[u8], account: &[u8]) -> Result<(Box<Aligned>, Box<S::SECURITY_DESCRIPTOR>)> {
    child_security_until(parent, account, None)
}
fn child_security_until(parent: &[u8], account: &[u8], end: Option<Instant>) -> Result<(Box<Aligned>, Box<S::SECURITY_DESCRIPTOR>)> {
    // Only the single new result file. No inherited grant or standard Users ACE.
    let mut acl = Box::new(Aligned([0; BUFFER]));
    let principals = [(system_sid(), FS::FILE_ALL_ACCESS), (builtin(544), FS::FILE_ALL_ACCESS),
        (parent.to_vec(), FS::FILE_ALL_ACCESS), (account.to_vec(), FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES)];
    let size = 8 + principals.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    need(size < BUFFER && size < u16::MAX as usize)?;
    acl.0[0] = 2; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl.0[4..6].copy_from_slice(&(principals.len() as u16).to_le_bytes());
    let mut at = 8;
    for (sid, rights) in principals {
        security::sid_at(&sid, 0, sid.len())?;
        let length = 8 + sid.len();
        acl.0[at + 2..at + 4].copy_from_slice(&(length as u16).to_le_bytes());
        acl.0[at + 4..at + 8].copy_from_slice(&rights.to_le_bytes());
        acl.0[at + 8..at + length].copy_from_slice(&sid); at += length;
    }
    let mut descriptor = Box::new(S::SECURITY_DESCRIPTOR::default());
    deadline(end)?;
    let initialized = unsafe { S::InitializeSecurityDescriptor((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) };
    deadline(end)?; need(initialized != 0)?;
    deadline(end)?;
    let dacl = unsafe { S::SetSecurityDescriptorDacl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
        1, acl.0.as_ptr().cast(), 0) };
    deadline(end)?; need(dacl != 0)?;
    deadline(end)?;
    let protected = unsafe { S::SetSecurityDescriptorControl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
        S::SE_DACL_PROTECTED, S::SE_DACL_PROTECTED) };
    deadline(end)?; need(protected != 0)?;
    Ok((acl, descriptor))
}

pub(super) type LaunchDiagnostic = (bool, u32, Option<u32>, [u32; 8]);
// DATA-only formatter, shared with the existing inert regression. The longest
// closed stage/role/check, optional u16 control words, null slot, max u32s
// and min NTSTATUS stay below the unchanged768-byte buffer (inert regression).
pub(super) fn write_refusal(output: &mut impl std::io::Write, stage: &'static str,
    launch: Option<LaunchDiagnostic>, unknown: bool, fault: Option<InputFault>) -> std::io::Result<()> {
    let (returned, error, exit) = launch.map_or((false, 0, None), |value| (value.0, value.1, value.2));
    write!(output, "MRK_WINDOWS_ORDINARY_OWNER_REFUSED={{\"stage\":\"{stage}\",\"createReturned\":{returned},\"createError\":{error},\"exitCode\":")?;
    match exit { Some(code) => write!(output, "{code}")?, None => write!(output, "null")? }
    if let Some((_, _, _, value)) = launch {
        write!(output, ",\"wait\":{},\"waitError\":{},\"settleWait\":{},\"settleError\":{},\"exitError\":{},\"terminateError\":{},\"processCloseError\":{},\"threadCloseError\":{}",
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7])?;
    }
    if let Some(value) = fault {
        write!(output, ",\"firstInputFault\":{{\"role\":\"{:?}\",\"slot\":", value.role)?;
        match value.slot { Some(slot) => write!(output, "{slot}")?, None => write!(output, "null")? }
        write!(output, ",\"check\":\"{:?}\",\"status\":", value.check)?;
        match value.status {
            Some(InputStatus::Win32(code)) => write!(output, "{{\"domain\":\"win32\",\"code\":{code}}}")?,
            Some(InputStatus::NtStatus(code)) => write!(output, "{{\"domain\":\"ntstatus\",\"code\":{code}}}")?,
            None => write!(output, "null")?,
        }
        if let Some((expected, observed)) = value.control {
            write!(output, ",\"control\":{{\"expected\":{expected},\"observed\":{observed}}}")?;
        }
        write!(output, "}}")?;
    }
    writeln!(output, ",\"unknown\":{unknown},\"cleanupNotRetried\":true}}")
}

pub(super) fn diagnostic_data(stage: &'static str, facts: Option<LaunchDiagnostic>, unknown: bool, fault: Option<InputFault>) {
    use std::io::Write;
    let mut raw = [0u8; 768];
    let mut output = std::io::Cursor::new(raw.as_mut_slice());
    let formatted = write_refusal(&mut output, stage, facts, unknown, fault);
    let size = output.position() as usize;
    // Never publish an ignored formatting error/truncated JSON as a record.
    // This fallback changes no owner result or settlement decision.
    let bytes: &[u8] = if formatted.is_ok() { &raw[..size] } else if unknown {
        b"MRK_WINDOWS_ORDINARY_OWNER_REFUSED={\"stage\":\"diagnostic-format\",\"unknown\":true,\"cleanupNotRetried\":true}\n"
    } else {
        b"MRK_WINDOWS_ORDINARY_OWNER_REFUSED={\"stage\":\"diagnostic-format\",\"unknown\":false,\"cleanupNotRetried\":true}\n"
    };
    let _ = std::io::stdout().lock().write(bytes);
}

// Closed owned observation DATA only. No raw SID, handle, path, arbitrary JSON,
// callback or executable selector can enter the public qualification interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullwalkFacts {
    pub target: String,
    pub manifest_sha256: String,
    pub protocol_sha256: String,
    pub inventory_sha256: String,
    pub core_sha256: String,
    pub account_sid_sha256: String,
    pub files: usize,
    /// Actual aggregate native entry observations, including ancestors and dots.
    pub entries: usize,
    pub payload_bytes: u64,
    pub version_identity: FileIdentity,
    /// Existing fixed order: python/python.exe, engine_bootstrap.py, core.zip.
    pub selected_identities: [FileIdentity; 3],
}
/// Actual original-owner observations only. The app fills these after each
/// real owner/borrow/child/IO/native/management join; this writer grants none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveFacts {
    pub version: FullwalkFacts,
    pub completed_methods: usize,
    pub settled_owners: usize,
    pub payload_images: usize,
    pub system_images: usize,
    pub stopped_before_claim: bool,
    pub stopped_owned_child: bool,
}
impl PassiveFacts {
    fn validate(&self) -> Result<()> {
        self.version.validate()?;
        need(self.completed_methods == 5 && self.settled_owners == 9
            && (22..=33).contains(&self.payload_images) && (1..=31).contains(&self.system_images)
            && self.stopped_before_claim && self.stopped_owned_child)
    }
    fn json(&self) -> String {
        format!("{{\"completedMethods\":{},\"settledOriginalOwners\":{},\"payloadImages\":{},\"systemImages\":{},\"stoppedBeforeClaim\":{},\"stoppedOwnedChild\":{},\"productionEnabled\":false}}",
            self.completed_methods, self.settled_owners, self.payload_images, self.system_images,
            self.stopped_before_claim, self.stopped_owned_child)
    }
}
impl FullwalkFacts {
    pub(super) fn validate(&self) -> Result<()> {
        need(self.target == "x86_64-pc-windows-msvc"
            && [&self.manifest_sha256, &self.protocol_sha256, &self.inventory_sha256,
                &self.core_sha256, &self.account_sid_sha256].into_iter().all(|s| is_hex(s, 64))
            && self.files > 0 && self.files < MAX_FILES
            && self.entries > self.files && self.entries <= MAX_ENTRIES
            && self.payload_bytes > 0 && self.payload_bytes <= MAX_TOTAL_BYTES)?;
        fullwalk_identities(self.version_identity, &self.selected_identities)
    }
}
fn fullwalk_identities(version: FileIdentity, selected: &[FileIdentity; 3]) -> Result<()> {
    need(version.volume_serial != 0 && version.file_id != [0; 16])?;
    for (index, identity) in selected.iter().enumerate() {
        need(identity.volume_serial == version.volume_serial && identity.file_id != [0; 16]
            && *identity != version && !selected[..index].contains(identity))?;
    }
    Ok(())
}
fn fullwalk_identity(value: &str) -> Result<FileIdentity> {
    let (volume, id) = value.split_once(':').ok_or(Error::Unsafe)?;
    need(decimal(volume) && is_hex(id, 32) && id != "0".repeat(32))?;
    let volume_serial = volume.parse::<u64>().map_err(|_| Error::Unsafe)?;
    let mut file_id = [0u8; 16]; file_id.copy_from_slice(&unhex(id)?);
    Ok(FileIdentity { volume_serial, file_id })
}
fn identity_json(identity: FileIdentity) -> String {
    format!("{{\"volume\":{},\"fileId\":\"{}\"}}", identity.volume_serial, hex(&identity.file_id))
}
fn artifact_identity(value: &str) -> Result<()> {
    need(value.len() <= 160)?;
    let fields: Vec<_> = value.split(':').collect();
    need(fields.len() == 6 && is_hex(fields[1], 32) && fields[1] != "0".repeat(32)
        && decimal(fields[0]) && fields[0].parse::<u64>().is_ok()
        && fields[2..5].iter().all(|value| decimal(value) && value.parse::<i64>().is_ok())
        && decimal(fields[5]) && fields[5].parse::<u32>().is_ok())
}
fn positive_size(value: &str, ceiling: usize) -> Result<usize> {
    need(decimal(value))?;
    let number = value.parse().map_err(|_| Error::Unsafe)?;
    need(number > 0 && number <= ceiling)?;
    Ok(number)
}

#[derive(Clone)]
pub(super) struct FullwalkArtifact {
    pub path: String, pub bytes: usize, pub sha: String, pub identity: String,
    pub command_sha: String, pub messages_bytes: usize, pub messages_sha: String, pub argv_sha: String,
}
impl FullwalkArtifact {
    pub fn matches(&self, stamp: &Stamp) -> bool { self.matches_identity(stamp, &self.identity) }
    fn matches_identity(&self, stamp: &Stamp, identity: &str) -> bool {
        stamp.wire() == identity && stamp.size == self.bytes as i64 && stamp.links == 1
    }
}
#[derive(Clone)]
pub(super) struct FullwalkRequest {
    pub role: ResultRole,
    pub source: String, pub tree: String, pub run: String,
    pub app: FullwalkArtifact, pub owner: FullwalkArtifact,
    pub manifest_sha: String, pub protocol_sha: String, pub inventory_sha: String, pub core_sha: String,
    pub files: usize, pub payload_bytes: u64,
    pub publication_bytes: usize, pub publication_sha: String,
    pub version: FileIdentity, pub selected: [FileIdentity; 3],
}
impl FullwalkRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> { Self::parse_traced(raw, &mut InputTrace::default()) }
    pub fn parse_traced(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        Self::parse_role(raw, trace, ResultRole::Fullwalk)
    }
    pub fn parse_passive(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        Self::parse_role(raw, trace, ResultRole::Passive)
    }
    fn parse_role(raw: &[u8], trace: &mut InputTrace, role: ResultRole) -> Result<Self> {
        trace.need(raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n")
            && !raw.contains(&b'\r'), InputCheck::RequestEnvelope)?;
        let text = trace.observed(std::str::from_utf8(raw).map_err(|_| Error::Unsafe), InputCheck::RequestUtf8)?;
        let lines: Vec<_> = text.lines().collect();
        trace.need(lines.len() == 35, InputCheck::RequestLines)?;
        trace.need(lines[0] == (match role { ResultRole::Fullwalk => "MRK_WINDOWS_FULLWALK_REQUEST_V1",
            ResultRole::Passive => "MRK_WINDOWS_INSTALLED_PASSIVE_REQUEST_V1" }), InputCheck::RequestHeader)?;
        let mut values = Vec::with_capacity(34);
        for (line, key) in lines[1..].iter().zip([
            "role", "test", "sourceSha", "sourceTree", "runId", "attempt",
            "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity", "appCommandSha256",
            "appCompileMessagesBytes", "appCompileMessagesSha256", "appCompileArgvSha256",
            "ownerArtifact", "ownerArtifactBytes", "ownerArtifactSha256", "ownerArtifactIdentity", "ownerCommandSha256",
            "ownerCompileMessagesBytes", "ownerCompileMessagesSha256", "ownerCompileArgvSha256",
            "manifestSha256", "protocolSha256", "inventorySha256", "coreSha256", "payloadFiles", "payloadBytes",
            "publicationReceiptBytes", "publicationReceiptSha256", "versionIdentity",
            "selectedPythonIdentity", "selectedBootstrapIdentity", "selectedCoreIdentity",
        ]) {
            let (name, value) = trace.observed(line.split_once('=').ok_or(Error::Unsafe), InputCheck::RequestKey)?;
            trace.need(name == key, InputCheck::RequestKey)?;
            trace.need(!value.is_empty(), InputCheck::RequestValue)?; values.push(value);
        }
        trace.need(values[0] == (match role { ResultRole::Fullwalk => "protected-version-fullwalk", ResultRole::Passive => "installed-passive" })
            && values[1] == role.child()
            && is_hex(values[2], 40) && values[2] != "0".repeat(40)
            && is_hex(values[3], 40) && values[3] != "0".repeat(40)
            && decimal(values[4]) && values[5] == "1", InputCheck::RequestValues)?;
        let mut artifact = |at: usize, ceiling: usize, prefix: &str| -> Result<FullwalkArtifact> {
            let path = trace.observed(fixed_path(values[at]), InputCheck::RequestArtifactPath)?;
            let name = path.file_name().and_then(|v| v.to_str()).ok_or(Error::Unsafe)?;
            let hash = name.strip_prefix(prefix).and_then(|v| v.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
            trace.need(is_hex(hash, 16), InputCheck::RequestArtifactPath)?;
            let bytes = trace.observed(positive_size(values[at + 1], ceiling), InputCheck::RequestBytesRange)?;
            for index in [at + 2, at + 4, at + 6, at + 7] {
                trace.need(is_hex(values[index], 64), InputCheck::RequestValues)?;
            }
            trace.observed(artifact_identity(values[at + 3]), InputCheck::RequestIdentity)?;
            let messages_bytes = trace.observed(positive_size(values[at + 5], 16 << 20), InputCheck::RequestBytesRange)?;
            Ok(FullwalkArtifact { path: values[at].to_owned(), bytes, sha: values[at + 2].to_owned(),
                identity: values[at + 3].to_owned(), command_sha: values[at + 4].to_owned(),
                messages_bytes, messages_sha: values[at + 6].to_owned(), argv_sha: values[at + 7].to_owned() })
        };
        let app = artifact(6, APP_ARTIFACT_LIMIT, "mobile_release_desktop-")?;
        let owner = artifact(14, ORDINARY_ARTIFACT_LIMIT, "mrk_windows_installed_native-")?;
        trace.need(app.path != owner.path
            && !app.identity.split(':').take(2).eq(owner.identity.split(':').take(2)), InputCheck::RequestArtifactPath)?;
        for index in [22, 23, 24, 25, 29] { trace.need(is_hex(values[index], 64), InputCheck::RequestValues)?; }
        let files = trace.observed(positive_size(values[26], MAX_FILES - 1), InputCheck::RequestBytesRange)?;
        let payload_bytes = trace.observed(positive_size(values[27], MAX_TOTAL_BYTES as usize), InputCheck::RequestBytesRange)? as u64;
        let publication_bytes = trace.observed(positive_size(values[28], OWNER_LIMIT), InputCheck::RequestBytesRange)?;
        let version = trace.observed(fullwalk_identity(values[30]), InputCheck::RequestIdentity)?;
        let selected = [fullwalk_identity(values[31])?, fullwalk_identity(values[32])?, fullwalk_identity(values[33])?];
        trace.observed(fullwalk_identities(version, &selected), InputCheck::RequestIdentity)?;
        Ok(Self { role, source: values[2].to_owned(), tree: values[3].to_owned(), run: values[4].to_owned(), app, owner,
            manifest_sha: values[22].to_owned(), protocol_sha: values[23].to_owned(),
            inventory_sha: values[24].to_owned(), core_sha: values[25].to_owned(), files, payload_bytes,
            publication_bytes, publication_sha: values[29].to_owned(), version, selected })
    }
    pub fn at_root(&self, root: &Path) -> Result<()> {
        let deps = fixed_directories(root)[3].1.clone();
        for artifact in [&self.app, &self.owner] {
            let path = fixed_path(&artifact.path)?;
            let basename = path.file_name().ok_or(Error::Unsafe)?;
            need(deps.join(basename).to_str() == Some(artifact.path.as_str()))?;
        }
        Ok(())
    }
    pub fn compiled_traced(&self, trace: &mut InputTrace) -> Result<()> {
        // This feature-only module cannot depend on cfg(test) hosted_tests.
        // These are compiled/environment DATA checks, not another token query.
        let source = trace.observed(option_env!("GITHUB_SHA").ok_or(Error::State), InputCheck::BindingSourceAvailable)?;
        trace.need(source == self.source, InputCheck::BindingSource)?;
        trace.need(option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str()), InputCheck::BindingTree)?;
        trace.need(option_env!("GITHUB_RUN_ID") == Some(self.run.as_str()), InputCheck::BindingRun)?;
        for (name, expected) in [
            ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"), ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"), ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"),
            ("ImageOS", "win25-vs2026"), ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", self.source.as_str()),
        ] {
            trace.need(std::env::var(name).as_deref() == Ok(expected), InputCheck::BindingSource)?;
        }
        trace.need(std::env::var("GITHUB_RUN_ID").as_deref() == Ok(self.run.as_str()), InputCheck::BindingRuntimeRun)?;
        trace.need(std::env::var("MRK_WINDOWS_SOURCE_TREE").as_deref() == Ok(self.tree.as_str()), InputCheck::BindingRuntimeTree)
    }
    pub fn check_commands(&self, trace: &mut InputTrace) -> Result<()> { self.commands_until(None, trace) }
    fn commands_until(&self, end: Option<Instant>, trace: &mut InputTrace) -> Result<()> {
        for (command, expected) in [
            (self.role.command(&self.app.path, false), &self.app.command_sha),
            (self.role.command(&self.owner.path, true), &self.owner.command_sha),
        ] {
            trace.need(command.encode_utf16().count() <= 1023, InputCheck::CommandUnits)?;
            deadline(end)?;
            let actual = digest_traced(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(), trace);
            deadline(end)?;
            trace.need(actual? == *expected, InputCheck::CommandDigest)?;
        }
        Ok(())
    }
    pub fn app_after(&self, identity: &str) -> Result<()> {
        artifact_identity(identity)?;
        let before: Vec<_> = self.app.identity.split(':').collect();
        let after: Vec<_> = identity.split(':').collect();
        need([0, 1, 2, 3, 5].into_iter().all(|index| before[index] == after[index])
            && after[4].parse::<i64>().map_err(|_| Error::Unsafe)? >= before[4].parse::<i64>().map_err(|_| Error::Unsafe)?)
    }
    pub fn expected(&self, account_sha: &str, entries: usize) -> FullwalkFacts {
        // Expected comparison DATA only. The child writer receives the actual
        // copied VersionObservation; this constructor never writes a receipt.
        FullwalkFacts { target: "x86_64-pc-windows-msvc".to_owned(), manifest_sha256: self.manifest_sha.clone(),
            protocol_sha256: self.protocol_sha.clone(), inventory_sha256: self.inventory_sha.clone(),
            core_sha256: self.core_sha.clone(), account_sid_sha256: account_sha.to_owned(), files: self.files,
            entries, payload_bytes: self.payload_bytes, version_identity: self.version, selected_identities: self.selected }
    }
    pub fn result(&self, request_sha: &str, actual: &FullwalkFacts) -> Result<String> {
        need(self.role == ResultRole::Fullwalk)?;
        self.result_kind(request_sha, actual, None)
    }
    pub fn passive_result(&self, request_sha: &str, actual: &PassiveFacts) -> Result<String> {
        need(self.role == ResultRole::Passive)?; actual.validate()?;
        self.result_kind(request_sha, &actual.version, Some(actual))
    }
    fn result_kind(&self, request_sha: &str, actual: &FullwalkFacts, passive: Option<&PassiveFacts>) -> Result<String> {
        actual.validate()?;
        need(is_hex(request_sha, 64) && *actual == self.expected(&actual.account_sid_sha256, actual.entries))?;
        let observed = format!("{{\"target\":\"{}\",\"manifestSha256\":\"{}\",\"protocolSha256\":\"{}\",\"inventorySha256\":\"{}\",\"coreSha256\":\"{}\",\"files\":{},\"entries\":{},\"payloadBytes\":{},\"versionIdentity\":{},\"selectedIdentities\":[{},{},{}],\"inspectionComplete\":true,\"bookSettled\":true}}",
            actual.target, actual.manifest_sha256, actual.protocol_sha256, actual.inventory_sha256, actual.core_sha256,
            actual.files, actual.entries, actual.payload_bytes, identity_json(actual.version_identity),
            identity_json(actual.selected_identities[0]), identity_json(actual.selected_identities[1]), identity_json(actual.selected_identities[2]));
        let child = self.role.child();
        let extra = passive.map(|facts| format!(",\"passive\":{}", facts.json())).unwrap_or_default();
        let raw = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"requestSha256\":\"{}\",\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"ownerArtifactSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"test\":\"{child}\",\"observation\":{}{extra},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
            self.source, self.tree, self.run, request_sha, self.app.bytes, self.app.sha,
            self.app.command_sha, self.owner.sha, actual.account_sid_sha256, observed);
        need(raw.len() <= LIMIT)?;
        Ok(raw)
    }
    pub fn accept_result(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<usize> {
        need(!raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii())?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let tail = text.split_once("\"entries\":").ok_or(Error::Unsafe)?.1;
        let count = tail.split_once(',').ok_or(Error::Unsafe)?.0;
        let entries = positive_size(count, MAX_ENTRIES)?;
        // All bytes, keys, actual identities, outcomes, order and final LF must
        // match. Only the bounded ACTUAL ancestor/dot-inclusive count is variable.
        need(raw == self.result(request_sha, &self.expected(account_sha, entries))?.as_bytes())?;
        Ok(entries)
    }
    pub fn accept_passive_result(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<usize> {
        need(self.role == ResultRole::Passive && !raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii())?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let count = |key: &str, limit| -> Result<usize> {
            let tail = text.split_once(&format!("\"{key}\":" )).ok_or(Error::Unsafe)?.1;
            positive_size(tail.split_once(',').ok_or(Error::Unsafe)?.0, limit)
        };
        let entries = count("entries", MAX_ENTRIES)?;
        let facts = PassiveFacts { version: self.expected(account_sha, entries), completed_methods: 5, settled_owners: 9,
            payload_images: count("payloadImages", 33)?, system_images: count("systemImages", 31)?,
            stopped_before_claim: true, stopped_owned_child: true };
        // Comparison DATA only; the writer never obtains facts from this
        // expected-value constructor. Exact bytes reject duplicate/extra keys.
        need(raw == self.passive_result(request_sha, &facts)?.as_bytes())?;
        Ok(entries)
    }
}
pub(super) fn fullwalk_command(path: &str) -> String { format!("\"{path}\" {FULLWALK_CHILD} {}", FLAGS.join(" ")) }
fn fullwalk_owner_command(path: &str) -> String { format!("\"{path}\" {FULLWALK_OWNER} {}", FLAGS.join(" ")) }
pub(super) fn passive_command(path: &str) -> String { ResultRole::Passive.command(path, false) }

#[cfg(feature = "qualification-result")]
fn fullwalk_digest(raw: &[u8], end: Instant, app: bool) -> Result<String> {
    deadline(Some(end))?;
    let result = if app { digest_app_traced(raw, &mut InputTrace::default()) } else { digest(raw) };
    deadline(Some(end))?;
    result
}
/// Write the sole fixed fullwalk result after the actual app book has settled.
/// No path/launcher/raw-SID API is exposed. Unknown never returns or drops its
/// original/security inputs; even a known late close cannot return success.
#[cfg(feature = "qualification-result")]
pub fn write_fullwalk_result_once(actual: &FullwalkFacts, end: Instant) -> Result<()> {
    write_installed_result(ResultRole::Fullwalk, actual, None, end)
}
#[cfg(feature = "qualification-result")]
pub fn write_passive_result_once(actual: &PassiveFacts, end: Instant) -> Result<()> {
    actual.validate()?;
    write_installed_result(ResultRole::Passive, &actual.version, Some(actual), end)
}
#[cfg(feature = "qualification-result")]
pub fn require_passive_qualification() -> Result<()> {
    let raw = std::env::var(ResultRole::Passive.request_env()).map_err(|_| Error::State)?;
    let request = FullwalkRequest::parse_passive(raw.as_bytes(), &mut InputTrace::default())?;
    request.compiled_traced(&mut InputTrace::default())?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(request.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(request.protocol_sha.as_str()))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    args_are(PASSIVE_CHILD, &artifact)
}
#[cfg(feature = "qualification-result")]
fn write_installed_result(role: ResultRole, actual: &FullwalkFacts, passive: Option<&PassiveFacts>, end: Instant) -> Result<()> {
    deadline(Some(end))?;
    actual.validate()?;
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let raw_request = get(role.request_env())?;
    let request = FullwalkRequest::parse_role(raw_request.as_bytes(), &mut InputTrace::default(), role)?;
    request.compiled_traced(&mut InputTrace::default())?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(request.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(request.protocol_sha.as_str()))?;
    let output = fixed_path(&get(role.output_env())?)?;
    let root = output.parent().ok_or(Error::Unsafe)?;
    need(output.file_name().and_then(|v| v.to_str()) == Some(role.output())
        && root.file_name().and_then(|v| v.to_str()) == Some(format!("mrk-windows-installed-native-{}-1", request.run).as_str()))?;
    request.at_root(root)?;
    deadline(Some(end))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    deadline(Some(end))?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    args_are(role.child(), &artifact)?;
    request.commands_until(Some(end), &mut InputTrace::default())?;
    let after_identity = get(role.identity_env())?;
    request.app_after(&after_identity)?; // request's original pre-ACL identity stays intact
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    security::sid_at(&account, 0, account.len())?;
    security::sid_at(&parent, 0, parent.len())?;
    need(account.len() == 28 && parent.len() == 28 && account != parent
        && account != system_sid() && account != builtin(544)
        && fullwalk_digest(&account, end, false)? == actual.account_sid_sha256)?;
    let request_sha = fullwalk_digest(raw_request.as_bytes(), end, false)?;
    let value = match passive { Some(facts) => request.passive_result(&request_sha, facts)?, None => request.result(&request_sha, actual)? }; // validates all copied observation DATA before IO
    deadline(Some(end))?;
    let cwd = std::env::current_dir().map_err(|_| Error::Unavailable)?;
    deadline(Some(end))?;
    need(cwd == output)?;
    let mut file = OriginalFile::new_until(&artifact, false, end)?;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_READ, false, null())?; file.named(&artifact)?;
        let before = file.stamp()?;
        need(request.app.matches_identity(&before, &after_identity))?;
        let bytes = file.read_app_traced(&mut InputTrace::default())?;
        need(bytes.len() == request.app.bytes && fullwalk_digest(&bytes, end, true)? == request.app.sha)?;
        need(file.stamp()? == before)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        diagnostic_data("result-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, &request, actual)); }
    }
    let closed = file.close(); // same original, also after ordinary read/hash/deadline refusal
    if closed.is_err() {
        diagnostic_data("result-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut file, &request, actual)); }
    }
    let timely = file.body().timely();
    observation?; timely?;
    let (acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let result = write_one_until(&output.join(role.result()), value.as_bytes(), LIMIT, &attributes, Some(end));
    // Unknown parks inside the shared writer: these actual caller-owned inputs
    // are still live on this same owning stack. No self-close receipt is emitted.
    std::hint::black_box((&acl, &descriptor, &attributes));
    result
}

// Normal-UI qualification is a separate closed wire. The historical ordinary,
// Fullwalk and intentionally poisoned Passive parsers above are not widened.
#[cfg(feature = "desktop-ui")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiRole { Prerequisite, NormalSmoke, ProjectDraft, QuitPassive, DocumentLoss }
#[cfg(feature = "desktop-ui")]
impl UiRole {
    pub fn label(self) -> &'static str { match self {
        Self::Prerequisite => "prerequisite", Self::NormalSmoke => "normal-smoke",
        Self::ProjectDraft => "project-draft", Self::QuitPassive => "quit-passive", Self::DocumentLoss => "document-loss",
    } }
    pub(super) fn parse(value: &str) -> Result<Self> { match value {
        "prerequisite" => Ok(Self::Prerequisite), "normal-smoke" => Ok(Self::NormalSmoke),
        "project-draft" => Ok(Self::ProjectDraft), "quit-passive" => Ok(Self::QuitPassive),
        "document-loss" => Ok(Self::DocumentLoss), _ => Err(Error::Unsafe),
    } }
    pub(super) fn owner(self) -> &'static str { match self {
        Self::Prerequisite => "ordinary_owner::hosted_normal_ui_prerequisite_original_handle_contract",
        Self::NormalSmoke => "ordinary_owner::hosted_normal_ui_smoke_original_handle_contract",
        Self::ProjectDraft => "ordinary_owner::hosted_normal_ui_project_original_handle_contract",
        Self::QuitPassive => "ordinary_owner::hosted_normal_ui_quit_original_handle_contract",
        Self::DocumentLoss => "ordinary_owner::hosted_normal_ui_document_original_handle_contract",
    } }
    pub(super) fn entry(self) -> &'static str { match self {
        Self::Prerequisite => "hosted_ui_tests::hosted_normal_ui_prerequisites_contract",
        Self::NormalSmoke => "normal-process-main", _ => "observer-process-main",
    } }
    pub(super) fn name(self, suffix: &str) -> String { format!("normal-ui-{}-{suffix}", self.label()) }
    pub(super) fn command(self, path: &str, owner: bool) -> String {
        if owner || self == Self::Prerequisite {
            format!("\"{path}\" {} {}", if owner { self.owner() } else { self.entry() }, FLAGS.join(" "))
        } else { format!("\"{path}\"") }
    }
    pub(super) fn app_messages(self) -> &'static str { match self {
        Self::Prerequisite => "compile-messages.jsonl", Self::NormalSmoke => "normal-app-compile-messages.jsonl",
        _ => "observer-compile-messages.jsonl",
    } }
    fn checks(self) -> &'static [&'static str] { match self {
        Self::ProjectDraft => &["native-picker-cancel", "native-project-selected", "draft-hydrated-edited",
            "validate-suggest-preview", "refresh-draft-preserved", "source-change-observed", "only-labelled-fixture-mutation"],
        Self::QuitPassive => &["native-quit-cancel", "native-quit-confirm", "passive-original-outstanding", "original-owner-retired"],
        Self::DocumentLoss => &["native-picker-outstanding", "passive-original-outstanding", "original-document-loss", "no-late-publication", "no-rebind"],
        _ => &[],
    } }
    pub(super) fn process_args(self, artifact: &Path, owner: bool) -> Result<()> {
        self.process_args_traced(artifact, owner, &mut InputTrace::default())
    }
    pub(super) fn process_args_traced(self, artifact: &Path, owner: bool, trace: &mut InputTrace) -> Result<()> {
        if owner || self == Self::Prerequisite { args_are_traced(if owner { self.owner() } else { self.entry() }, artifact, trace) }
        else {
            let args: Vec<_> = std::env::args_os().collect();
            need(args.len() == 1 && args[0] == artifact.as_os_str())
        }
    }
}

#[cfg(feature = "desktop-ui")]
pub(super) const UI_REQUEST_FIELDS: [&str; 35] = [
    "role", "test", "sourceSha", "sourceTree", "runId", "attempt",
    "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity", "appCommandSha256",
    "appCompileMessagesBytes", "appCompileMessagesSha256", "appCompileArgvSha256",
    "ownerArtifact", "ownerArtifactBytes", "ownerArtifactSha256", "ownerArtifactIdentity", "ownerCommandSha256",
    "ownerCompileMessagesBytes", "ownerCompileMessagesSha256", "ownerCompileArgvSha256",
    "manifestSha256", "protocolSha256", "inventorySha256", "coreSha256", "payloadFiles", "payloadBytes",
    "publicationReceiptBytes", "publicationReceiptSha256", "versionIdentity",
    "selectedPythonIdentity", "selectedBootstrapIdentity", "selectedCoreIdentity", "appVersion",
];
#[cfg(feature = "desktop-ui")]
#[derive(Clone)]
pub(super) struct UiRequest {
    pub role: UiRole, pub source: String, pub tree: String, pub run: String,
    pub app: FullwalkArtifact, pub owner: FullwalkArtifact,
    pub runtime: Option<FullwalkRequest>, pub app_version: String,
}
#[cfg(feature = "desktop-ui")]
fn ui_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && (2..=6).contains(&value.split('.').count())
        && value.split('.').all(|part| !part.is_empty() && part.len() <= 10 && part.bytes().all(|b| b.is_ascii_digit()))
}
#[cfg(feature = "desktop-ui")]
impl UiRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> { Self::parse_traced(raw, &mut InputTrace::default()) }
    pub fn parse_traced(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        trace.prerequisite_scope(PrerequisiteCheck::Q01, |trace| {
            need(!raw.is_empty() && raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'))?;
            let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
            let lines: Vec<_> = text.lines().collect();
            need(lines.len() == 36 && lines[0] == "MRK_WINDOWS_NORMAL_UI_REQUEST_V1")?;
            let mut v = Vec::with_capacity(UI_REQUEST_FIELDS.len());
            for (line, key) in lines[1..].iter().zip(UI_REQUEST_FIELDS) {
                let (name, value) = line.split_once('=').ok_or(Error::Unsafe)?;
                need(name == key && !value.is_empty())?; v.push(value);
            }
            let role = UiRole::parse(v[0])?;
            need(v[1] == role.entry() && is_hex(v[2], 40) && v[2] != "0".repeat(40)
                && is_hex(v[3], 40) && v[3] != "0".repeat(40) && decimal(v[4]) && v[4].parse::<u64>().is_ok()
                && v[5] == "1" && ui_version(v[34]))?;
            let artifact = |offset: usize, limit, trace: &mut InputTrace| -> Result<FullwalkArtifact> {
                fixed_path_traced(v[offset], trace)?; artifact_identity(v[offset + 3])?;
                need([2, 4, 6, 7].into_iter().all(|i| is_hex(v[offset + i], 64)))?;
                Ok(FullwalkArtifact { path: v[offset].to_owned(), bytes: positive_size(v[offset + 1], limit)?,
                    sha: v[offset + 2].to_owned(), identity: v[offset + 3].to_owned(), command_sha: v[offset + 4].to_owned(),
                    messages_bytes: positive_size(v[offset + 5], 16 << 20)?, messages_sha: v[offset + 6].to_owned(),
                    argv_sha: v[offset + 7].to_owned() })
            };
            trace.prerequisite_check(PrerequisiteCheck::Q02);
            let app = artifact(6, if role == UiRole::Prerequisite { ORDINARY_ARTIFACT_LIMIT } else { APP_ARTIFACT_LIMIT }, trace)?;
            let owner = artifact(14, ORDINARY_ARTIFACT_LIMIT, trace)?;
            let runtime = if role == UiRole::Prerequisite {
                need(v[22..34].iter().all(|value| *value == "-") && app.path == owner.path && app.bytes == owner.bytes
                    && app.sha == owner.sha && app.identity == owner.identity && app.messages_bytes == owner.messages_bytes
                    && app.messages_sha == owner.messages_sha && app.argv_sha == owner.argv_sha)?;
                None
            } else {
                need(v[22..26].iter().all(|value| is_hex(value, 64)) && is_hex(v[29], 64))?;
                let version = fullwalk_identity(v[30])?;
                let selected = [fullwalk_identity(v[31])?, fullwalk_identity(v[32])?, fullwalk_identity(v[33])?];
                fullwalk_identities(version, &selected)?;
                Some(FullwalkRequest { role: ResultRole::Passive, source: v[2].to_owned(), tree: v[3].to_owned(), run: v[4].to_owned(),
                    app: app.clone(), owner: owner.clone(), manifest_sha: v[22].to_owned(), protocol_sha: v[23].to_owned(),
                    inventory_sha: v[24].to_owned(), core_sha: v[25].to_owned(), files: positive_size(v[26], MAX_FILES - 1)?,
                    payload_bytes: positive_size(v[27], MAX_TOTAL_BYTES as usize)? as u64,
                    publication_bytes: positive_size(v[28], OWNER_LIMIT)?, publication_sha: v[29].to_owned(), version, selected })
            };
            let result = Self { role, source: v[2].to_owned(), tree: v[3].to_owned(), run: v[4].to_owned(), app, owner,
                runtime, app_version: v[34].to_owned() };
            trace.prerequisite_check(PrerequisiteCheck::Q03);
            for (path, expected, owner) in [(&result.app.path, &result.app.command_sha, false),
                (&result.owner.path, &result.owner.command_sha, true)] {
                let command = role.command(path, owner);
                need(command.encode_utf16().count() <= 1023
                    && digest_traced(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(), trace)? == *expected)?;
            }
            Ok(result)
        })
    }
    pub fn compiled(&self) -> Result<()> { self.compiled_traced(&mut InputTrace::default()) }
    pub fn compiled_traced(&self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::Q03, |trace| {
            need(option_env!("GITHUB_SHA") == Some(self.source.as_str())
                && option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str())
                && option_env!("GITHUB_RUN_ID") == Some(self.run.as_str())
                && option_env!("MRK_WINDOWS_UI_APP_VERSION") == Some(self.app_version.as_str()))?;
            for (name, expected) in [
                ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"), ("GITHUB_ACTIONS", "true"),
                ("RUNNER_ENVIRONMENT", "github-hosted"), ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"),
                ("ImageOS", "win25-vs2026"), ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", self.source.as_str()),
                ("GITHUB_RUN_ID", self.run.as_str()), ("MRK_WINDOWS_SOURCE_TREE", self.tree.as_str()),
                ("MRK_DESKTOP_DISPATCH_SCOPE", "windows-normal-project-ui"),
                ("GITHUB_REF", "refs/heads/verify/desktop-windows-normal-project-ui"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ] { need(std::env::var(name).as_deref() == Ok(expected))?; }
            Ok(())
        })
    }
    pub fn at_root(&self, root: &Path) -> Result<()> { self.at_root_traced(root, &mut InputTrace::default()) }
    pub fn at_root_traced(&self, root: &Path, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::Q04, |trace| {
            need(root.file_name().and_then(|name| name.to_str()) == Some(format!("mrk-windows-installed-native-{}-1", self.run).as_str()))?;
            let debug = root.join("target/x86_64-pc-windows-msvc/debug");
            let fixed_exe = |value: &str, prefix: &str, trace: &mut InputTrace| -> Result<()> {
                let path = fixed_path_traced(value, trace)?;
                let name = path.file_name().and_then(|value| value.to_str()).ok_or(Error::Unsafe)?;
                let hash = name.strip_prefix(prefix).and_then(|value| value.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
                need(path.parent() == Some(debug.join("deps").as_path()) && is_hex(hash, 16))
            };
            fixed_exe(&self.owner.path, "mrk_windows_installed_native-", trace)?;
            match self.role {
                UiRole::Prerequisite => need(self.app.path == self.owner.path),
                UiRole::NormalSmoke => need(Path::new(&self.app.path) == root.join("mobile-release-kit-desktop.exe")),
                _ => fixed_exe(&self.app.path, "installed_shell_observation-", trace),
            }
        })
    }
    pub fn app_after(&self, identity: &str) -> Result<()> { self.app_after_traced(identity, &mut InputTrace::default()) }
    pub fn app_after_traced(&self, identity: &str, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::Q04, |trace| {
            artifact_identity(identity)?;
            let before: Vec<_> = self.app.identity.split(':').collect(); let after: Vec<_> = identity.split(':').collect();
            need([0, 1, 2, 3, 5].into_iter().all(|index| before[index] == after[index])
                && after[4].parse::<i64>().map_err(|_| Error::Unsafe)? >= before[4].parse::<i64>().map_err(|_| Error::Unsafe)?)
        })
    }
    fn envelope(&self, request_sha: &str, account_sha: &str, observation: &str) -> Result<String> { self.envelope_traced(request_sha, account_sha, observation, &mut InputTrace::default()) }
    fn envelope_traced(&self, request_sha: &str, account_sha: &str, observation: &str, trace: &mut InputTrace) -> Result<String> {
        trace.prerequisite_scope(PrerequisiteCheck::Q05, |trace| {
            need(is_hex(request_sha, 64) && is_hex(account_sha, 64))?;
            let text = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"role\":\"{}\",\"requestSha256\":\"{request_sha}\",\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{account_sha}\",\"observation\":{observation},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
                self.source, self.tree, self.run, self.role.label(), self.app.bytes, self.app.sha, self.app.command_sha);
            need(text.len() <= LIMIT)?; Ok(text)
        })
    }
    fn case_observation(&self) -> Result<String> {
        need(!self.role.checks().is_empty())?;
        let checks = self.role.checks().iter().map(|value| format!("\"{value}\"")).collect::<Vec<_>>().join(",");
        Ok(format!("{{\"runtimeBindingMatched\":true,\"verifiedMethods\":{},\"checks\":[{checks}],\"finality\":{{\"dialogsSettled\":true,\"sourcesSettled\":true,\"passiveOwnersSettled\":true,\"documentHooksSettled\":true,\"relayJoined\":true,\"exitReady\":true}}}}",
            if self.role == UiRole::ProjectDraft { 6 } else { 0 }))
    }
    pub fn probe_result(&self, request_sha: &str, account_sha: &str, reason: Option<&str>, version: Option<&str>,
        refusal: Option<&super::ui::ManagedRuntimeRefusal>) -> Result<String> { self.probe_result_traced(request_sha, account_sha, reason, version, refusal, &mut InputTrace::default()) }
    pub fn probe_result_traced(&self, request_sha: &str, account_sha: &str, reason: Option<&str>, version: Option<&str>,
        refusal: Option<&super::ui::ManagedRuntimeRefusal>, trace: &mut InputTrace) -> Result<String> {
        trace.prerequisite_scope(PrerequisiteCheck::Q05, |trace| {
            need(self.role == UiRole::Prerequisite)?;
            let available = reason.is_none();
            need((reason == Some("managed-webview2")) == refusal.is_some())?;
            let diagnostic = refusal.map(|value| value.json()).transpose()?.unwrap_or_else(|| "null".to_owned());
            let (reason, version) = match (reason, version) {
                (None, Some(version)) if ui_version(version) => ("null".to_owned(), format!("\"{version}\"")),
                (Some(reason), None) if UI_PROBE_REASONS.contains(&reason) => (format!("\"{reason}\""), "null".to_owned()),
                _ => return Err(Error::Unsafe),
            };
            self.envelope_traced(request_sha, account_sha, &format!("{{\"available\":{available},\"reason\":{reason},\"ordinaryAccountMatched\":true,\"ordinaryContext\":{available},\"interactiveDesktop\":{available},\"managedRuntime\":{available},\"overrideFree\":{available},\"privateParent\":{available},\"runtimeVersion\":{version},\"managedRuntimeRefusal\":{diagnostic},\"originalsSettled\":true,\"noWebviewCreated\":true}}"), trace)
        })
    }
    pub fn accept_child(&self, raw: &[u8], request_sha: &str, account_sha: &str) -> Result<bool> { self.accept_child_traced(raw, request_sha, account_sha, &mut InputTrace::default()) }
    pub fn accept_child_traced(&self, raw: &[u8], request_sha: &str, account_sha: &str, trace: &mut InputTrace) -> Result<bool> {
        trace.prerequisite_scope(PrerequisiteCheck::Q05, |trace| {
            need(raw.len() <= LIMIT && raw.is_ascii())?;
            if self.role != UiRole::Prerequisite {
                need(raw == self.envelope_traced(request_sha, account_sha, &self.case_observation()?, trace)?.as_bytes())?; return Ok(true);
            }
            let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
            let diagnostic = text.split_once(",\"managedRuntimeRefusal\":").and_then(|(_, tail)|
                tail.split_once(",\"originalsSettled\":")).map(|(value, _)| value).ok_or(Error::Unsafe)?;
            let refusal = if diagnostic == "null" { None } else {
                Some(super::ui::ManagedRuntimeRefusal::parse(diagnostic).ok_or(Error::Unsafe)?)
            };
            for reason in UI_PROBE_REASONS {
                if (reason == "managed-webview2") != refusal.is_some() { continue; }
                if raw == self.probe_result_traced(request_sha, account_sha, Some(reason), None, refusal.as_ref(), trace)?.as_bytes() { return Ok(false); }
            }
            let version = text.split_once("\"runtimeVersion\":\"").and_then(|(_, tail)| tail.split_once('"'))
                .map(|(value, _)| value).ok_or(Error::Unsafe)?;
            need(raw == self.probe_result_traced(request_sha, account_sha, None, Some(version), refusal.as_ref(), trace)?.as_bytes())?;
            Ok(true)
        })
    }
}
#[cfg(feature = "desktop-ui")]
const UI_PROBE_REASONS: [&str; 7] = ["ordinary-context", "interactive-desktop", "managed-webview2", "webview2-overrides",
    "private-user-data-parent", "native-failure", "original-state"];

/// Engineering-only DATA from the actual original runtime and GUI owners.
/// Array order is fixed by UiRole::checks and the six named finality keys above.
/// A result writer validates these facts but cannot acquire or settle an owner.
#[cfg(feature = "desktop-ui")]
pub struct UiCaseFacts {
    pub version: FullwalkFacts, pub verified_methods: usize,
    pub checks: [bool; 7], pub finality: [bool; 6],
}

/// The one original native owner's uptime endpoint, not a fresh ninety seconds.
/// Call once at child process-main entry and retain the returned Instant.
#[cfg(feature = "desktop-ui")]
pub fn normal_ui_deadline() -> Result<Instant> {
    let value = std::env::var("MRK_WINDOWS_NORMAL_UI_END_TICK_MS").map_err(|_| Error::State)?;
    need(decimal(&value))?;
    let endpoint = value.parse::<u64>().map_err(|_| Error::Unsafe)?;
    let local = Instant::now();
    let now = unsafe { SI::GetTickCount64() };
    let remaining = endpoint.checked_sub(now).ok_or(Error::Unsafe)?;
    need(remaining > 0 && remaining <= 90_000)?;
    local.checked_add(std::time::Duration::from_millis(remaining)).ok_or(Error::Unsafe)
}

// Fixed synthetic project DATA, never project hooks or external signing inputs.
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_SOURCE: &[u8] = b"plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_VERSION: &[u8] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_KEEP: &[u8] = b"MRK_WINDOWS_NORMAL_UI_KEEP\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_CONFIG: &[u8] = b"{\"android\":{\"applicationId\":\"org.example.mrk.observed\",\"enabled\":true,\"identityStatus\":\"unverified\"},\"ios\":{\"enabled\":false},\"metadata\":{\"androidLocales\":[\"en-US\"],\"iosLocales\":[],\"root\":\"release/store\"},\"projectChecks\":{\"androidArtifact\":[],\"iosArtifact\":[],\"preflight\":[]},\"schemaVersion\":1,\"services\":{\"androidFirebase\":\"disabled\",\"iosFirebase\":\"disabled\"},\"source\":{\"candidateBranch\":\"main\",\"productionBranch\":\"main\"},\"version\":{\"buildKey\":\"BUILD_NUMBER\",\"nameKey\":\"VERSION_NAME\",\"source\":\"version.properties\"}}\n";
#[cfg(feature = "desktop-ui")]
pub const UI_FIXTURE_CONFIG_AFTER: &[u8] = b"{\"android\":{\"applicationId\":\"org.example.mrk.observed\",\"enabled\":true,\"identityStatus\":\"unverified\"},\"ios\":{\"enabled\":false},\"metadata\":{\"androidLocales\":[\"en-US\"],\"iosLocales\":[],\"root\":\"release/store\"},\"projectChecks\":{\"androidArtifact\":[],\"iosArtifact\":[],\"preflight\":[]},\"schemaVersion\":1,\"services\":{\"androidFirebase\":\"disabled\",\"iosFirebase\":\"disabled\"},\"source\":{\"candidateBranch\":\"next\",\"productionBranch\":\"main\"},\"version\":{\"buildKey\":\"BUILD_NUMBER\",\"nameKey\":\"VERSION_NAME\",\"source\":\"version.properties\"}}\n";

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn normal_ui_project() -> Result<PathBuf> {
    require_normal_ui_qualification()?;
    let raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(raw.as_bytes())?;
    let output = fixed_path(&std::env::var("MRK_WINDOWS_NORMAL_UI_OUTPUT").map_err(|_| Error::State)?)?;
    request.at_root(output.parent().ok_or(Error::Unsafe)?)?;
    need(output.file_name().and_then(|name| name.to_str()) == Some(request.role.name("output").as_str())
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
    Ok(output.join("project"))
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
static UI_FIXTURE_MUTATION_CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
static UI_FIXTURE_VERIFIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One explicit fixture-only CREATE_NEW, not the application's Save path.
/// The ProjectDraft fixture starts without config so genuine Suggest/Adopt is
/// visible. No caller chooses a path/bytes or receives a general write permit.
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn mutate_normal_ui_fixture(end: Instant) -> Result<()> {
    need(require_normal_ui_qualification()? == UiRole::ProjectDraft)?;
    deadline(Some(end))?;
    need(!UI_FIXTURE_MUTATION_CLAIMED.swap(true, std::sync::atomic::Ordering::SeqCst))?;
    let path = normal_ui_project()?.join("release").join("mobile-release.json");
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    let parent = unhex(&std::env::var("MRK_WINDOWS_PARENT_SID").map_err(|_| Error::State)?)?;
    need(account.len() == 28 && parent.len() == 28 && account != parent)?;
    let (mut acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    // This is readable synthetic input, unlike the write-only result file.
    // Amend only this new, private descriptor before any borrower enters it.
    let account_ace = 8 + (8 + system_sid().len()) + (8 + builtin(544).len()) + (8 + parent.len());
    need(&acl.0[account_ace + 8..account_ace + 8 + account.len()] == account.as_slice())?;
    acl.0[account_ace + 4..account_ace + 8].copy_from_slice(&(FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE).to_le_bytes());
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let mut original = OriginalFile::new_until(&path, false, end)?;
    let mut position = 0i64;
    let observed = (|| -> Result<()> {
        // Atomic absence check/creation. Collision is never opened or replaced.
        original.open(FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE, true, &attributes)?;
        original.named(&path)?;
        let before = original.stamp()?;
        need(before.size == 0 && before.links == 1)?;
        original.write(UI_FIXTURE_CONFIG_AFTER, LIMIT)?; // ONE WriteFile only.
        ui_fixture_seek(&mut original, &mut position)?;
        need(original.read(LIMIT)? == UI_FIXTURE_CONFIG_AFTER)?;
        let after = original.stamp()?;
        need(before.volume == after.volume && before.id == after.id && before.creation == after.creation
            && after.size == UI_FIXTURE_CONFIG_AFTER.len() as i64 && after.allocation >= after.size && before.links == after.links
            && before.attributes == after.attributes && after.write >= before.write && after.change >= before.change)
    })();
    if matches!(observed, Err(Error::Unknown)) {
        diagnostic_data("ui-fixture-mutation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &acl, &descriptor, &attributes)); }
    }
    if original.close().is_err() {
        diagnostic_data("ui-fixture-mutation-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut position, &acl, &descriptor, &attributes)); }
    }
    observed?; deadline(Some(end))
}

/// Complete bounded fixture readback before the child report. It cannot turn
/// the later parent original-exit/identity gate into a pre-close child receipt.
#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn verify_normal_ui_fixture(end: Instant) -> Result<()> {
    UI_FIXTURE_VERIFIED.store(false, std::sync::atomic::Ordering::SeqCst);
    let role = require_normal_ui_qualification()?;
    need(UI_FIXTURE_MUTATION_CLAIMED.load(std::sync::atomic::Ordering::SeqCst) == (role == UiRole::ProjectDraft))?;
    let project = normal_ui_project()?;
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    let mut native = NativeBook::new();
    let mut originals: Vec<(Original, Metadata)> = Vec::with_capacity(24);
    let observed = (|| -> Result<()> {
        deadline(Some(end))?;
        need(native.observe_user_once()?.user.bytes() == account.as_slice())?;
        let (drive, parts) = decode::dos_location(project.to_str().ok_or(Error::Unsafe)?)?;
        need(parts.len() < 16)?;
        let device = native.mapping(&drive)?;
        let canonical = format!("{device}\\");
        let root = native.reserve(Kind::Directory, None, &canonical, canonical.clone())?;
        native.call(Call::Open(root.index), null_mut(), Vec::new())?;
        native.noninherited(root.index)?; native.local_ntfs(&root)?;
        let metadata = native.metadata(&root)?; originals.push((root, metadata));
        for name in parts {
            deadline(Some(end))?;
            let original = native.open_child(&originals.last().ok_or(Error::State)?.0, &name, FileKind::Directory)?;
            let metadata = native.metadata(&original)?; originals.push((original, metadata));
        }
        let project_index = originals.len() - 1;
        let mut directory_indices = vec![project_index];
        for name in ["app", "release"] {
            let original = native.open_child(&originals[project_index].0, name, FileKind::Directory)?;
            let metadata = native.metadata(&original)?;
            directory_indices.push(originals.len()); originals.push((original, metadata));
        }
        let config = if role == UiRole::ProjectDraft { UI_FIXTURE_CONFIG_AFTER } else { UI_FIXTURE_CONFIG };
        let mut children: Vec<(usize, &str, usize)> = vec![(project_index, "app", directory_indices[1]),
            (project_index, "release", directory_indices[2])];
        for (parent, name, bytes) in [(directory_indices[1], "build.gradle.kts", UI_FIXTURE_SOURCE),
            (project_index, "version.properties", UI_FIXTURE_VERSION), (project_index, "keep.txt", UI_FIXTURE_KEEP),
            (directory_indices[2], "mobile-release.json", config)] {
            deadline(Some(end))?;
            let original = native.open_child(&originals[parent].0, name, FileKind::File)?;
            let metadata = native.metadata(&original)?;
            native.no_alternate_streams(&original)?;
            need(metadata.size == bytes.len() as u64 && native.read_next(&original, LIMIT)? == bytes
                && native.read_next(&original, 1)?.is_empty() && native.metadata(&original)? == metadata)?;
            children.push((parent, name, originals.len())); originals.push((original, metadata));
        }
        for index in directory_indices {
            let mut names = std::collections::BTreeSet::new();
            loop {
                deadline(Some(end))?;
                let Some(batch) = native.next_entries(&originals[index].0)? else { break; };
                for entry in batch {
                    need(names.insert(entry.name.clone()) && names.len() <= 6)?;
                    if entry.name == "." { need(entry.file_id == originals[index].1.identity.file_id)?; continue; }
                    if entry.name == ".." {
                        let parent = if index == project_index { project_index - 1 } else { project_index };
                        need(entry.file_id == originals[parent].1.identity.file_id)?; continue;
                    }
                    let (_, _, child) = children.iter().find(|(parent, name, _)| *parent == index && *name == entry.name)
                        .ok_or(Error::Unsafe)?;
                    need(entry.file_id == originals[*child].1.identity.file_id && entry.kind == originals[*child].1.kind)?;
                }
            }
            let expected: std::collections::BTreeSet<_> = children.iter().filter(|(parent, _, _)| *parent == index)
                .map(|(_, name, _)| name.to_string()).chain([".".to_owned(), "..".to_owned()]).collect();
            need(names == expected)?;
        }
        for (original, before) in originals.iter().rev() {
            deadline(Some(end))?; need(native.metadata(original)? == *before)?;
        }
        need(native.mapping(&drive)? == device)?; native.recheck_user()?; deadline(Some(end))
    })();
    if matches!(observed, Err(Error::Unknown)) || native.is_unknown() {
        diagnostic_data("ui-fixture-readback", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut native, &originals)); }
    }
    if native.settle_once() != CloseOutcome::Settled || !native.settled() {
        diagnostic_data("ui-fixture-readback-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut native, &originals)); }
    }
    observed?; deadline(Some(end))?;
    UI_FIXTURE_VERIFIED.store(true, std::sync::atomic::Ordering::SeqCst); Ok(())
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
fn ui_fixture_seek(original: &mut OriginalFile, position: &mut i64) -> Result<()> {
    let b = original.body();
    need(b.state == SlotState::Owned && !b.active)?; b.timely()?; b.active = true;
    let returned = unsafe { FS::SetFilePointerEx(b.handle, 0, position, FS::FILE_BEGIN) };
    b.error = if returned != 0 { 0 } else { unsafe { F::GetLastError() } };
    b.active = returned == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
    if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
    b.timely()?; need(returned != 0 && *position == 0)
}

#[cfg(feature = "desktop-ui")]
fn ui_digest(raw: &[u8], end: Instant, app: bool) -> Result<String> {
    deadline(Some(end))?;
    let result = if app { digest_app_traced(raw, &mut InputTrace::default()) } else { digest(raw) };
    deadline(Some(end))?; result
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn require_normal_ui_qualification() -> Result<UiRole> {
    let raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(raw.as_bytes())?; request.compiled()?;
    need(!request.role.checks().is_empty())?;
    let runtime = request.runtime.as_ref().ok_or(Error::State)?;
    need(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") == Some(runtime.manifest_sha.as_str())
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(runtime.protocol_sha.as_str()))?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?;
    request.role.process_args(&artifact, false)?;
    Ok(request.role)
}

#[cfg(all(feature = "desktop-ui", feature = "qualification-result"))]
pub fn write_normal_ui_result_once(actual: &UiCaseFacts, end: Instant) -> Result<()> {
    deadline(Some(end))?;
    let role = require_normal_ui_qualification()?;
    let request_raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(request_raw.as_bytes())?;
    let runtime = request.runtime.as_ref().ok_or(Error::State)?;
    actual.version.validate()?;
    need(UI_FIXTURE_VERIFIED.load(std::sync::atomic::Ordering::SeqCst)
        && actual.verified_methods == if role == UiRole::ProjectDraft { 6 } else { 0 }
        && actual.checks.iter().enumerate().all(|(index, value)| *value == (index < role.checks().len()))
        && actual.finality == [true; 6]
        && actual.version.manifest_sha256 == runtime.manifest_sha && actual.version.protocol_sha256 == runtime.protocol_sha
        && actual.version.inventory_sha256 == runtime.inventory_sha && actual.version.core_sha256 == runtime.core_sha
        && actual.version.files == runtime.files && actual.version.payload_bytes == runtime.payload_bytes
        && actual.version.version_identity == runtime.version && actual.version.selected_identities == runtime.selected)?;
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    need(fullwalk_digest(&account, end, false)? == actual.version.account_sid_sha256)?;
    let value = request.envelope(&fullwalk_digest(request_raw.as_bytes(), end, false)?,
        &actual.version.account_sid_sha256, &request.case_observation()?)?;
    write_ui_child(&request, &value, end)
}

#[cfg(feature = "desktop-ui")]
pub(super) fn write_ui_child(request: &UiRequest, value: &str, end: Instant) -> Result<()> {
    deadline(Some(end))?; request.compiled()?;
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let output = fixed_path(&get("MRK_WINDOWS_NORMAL_UI_OUTPUT")?)?;
    let root = output.parent().ok_or(Error::Unsafe)?; request.at_root(root)?;
    need(output.file_name().and_then(|name| name.to_str()) == Some(request.role.name("output").as_str())
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(artifact.to_str() == Some(request.app.path.as_str()))?; request.role.process_args(&artifact, false)?;
    let identity = get("MRK_WINDOWS_NORMAL_UI_ARTIFACT_IDENTITY")?; request.app_after(&identity)?;
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    security::sid_at(&account, 0, account.len())?; security::sid_at(&parent, 0, parent.len())?;
    need(account.len() == 28 && parent.len() == 28 && account != parent && account != system_sid() && account != builtin(544))?;
    let mut artifact_original = OriginalFile::new_until(&artifact, false, end)?;
    let observed = (|| -> Result<()> {
        artifact_original.open(FS::FILE_GENERIC_READ, false, null())?; artifact_original.named(&artifact)?;
        let before = artifact_original.stamp()?;
        need(request.app.matches_identity(&before, &identity))?;
        let bytes = artifact_original.read_app_traced(&mut InputTrace::default())?;
        need(bytes.len() == request.app.bytes && ui_digest(&bytes, end, true)? == request.app.sha
            && artifact_original.stamp()? == before)
    })();
    if matches!(observed, Err(Error::Unknown)) {
        diagnostic_data("ui-result-artifact", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut artifact_original, request, value)); }
    }
    if artifact_original.close().is_err() {
        diagnostic_data("ui-result-artifact-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut artifact_original, request, value)); }
    }
    observed?; deadline(Some(end))?;
    let (acl, mut descriptor) = child_security_until(&parent, &account, Some(end))?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    let written = write_one_until(&output.join(request.role.name("result.private.json")), value.as_bytes(), LIMIT, &attributes, Some(end));
    std::hint::black_box((&acl, &descriptor, &attributes)); written?; deadline(Some(end))
}
