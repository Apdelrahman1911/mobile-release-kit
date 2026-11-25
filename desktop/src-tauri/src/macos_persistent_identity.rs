//! Durable volume DATA. It never replaces live FD/name, mount, ownership,
//! signature, inventory or transaction-finality observations.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeUuid([u8; 16]);
impl VolumeUuid {
    pub fn from_bytes_data(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }
    pub fn bytes_data(self) -> [u8; 16] { self.0 }
}
impl Serialize for VolumeUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = [0u8; 32];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in self.0.iter().enumerate() {
            text[index * 2] = HEX[usize::from(byte >> 4)];
            text[index * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        serializer.serialize_str(std::str::from_utf8(&text).map_err(serde::ser::Error::custom)?)
    }
}
impl<'de> Deserialize<'de> for VolumeUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = VolumeUuid;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a nonzero lower-case 32-character volume UUID")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
                parse_uuid(text).ok_or_else(|| E::custom("volume-uuid"))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
fn parse_uuid(text: &str) -> Option<VolumeUuid> {
        if text.len() != 32 { return None; }
        fn digit(byte: u8) -> Option<u8> {
            match byte { b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10), _ => None }
        }
        let mut bytes = [0; 16];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = digit(pair[0]).zip(digit(pair[1])).map(|(a,b)| a * 16 + b)?;
        }
        VolumeUuid::from_bytes_data(bytes)
}

#[cfg(all(not(feature="macos-xcode-setup"),target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub fn observe_volume(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<VolumeUuid> {
    VolumeUuid::from_bytes_data(mrk_macos_installed_native::filesystem_identity::volume_uuid(fd)?)
        .ok_or_else(|| std::io::ErrorKind::InvalidData.into())
}
// The isolated setup graph links its own native boundary and has no ordinary
// installed-runtime volume observer. Do not pull that ABI into its build.
#[cfg(all(feature="macos-xcode-setup",target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub fn observe_volume(_fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<VolumeUuid> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Missing is the old closed record format. Present null, malformed or zero
/// values are errors; they cannot downgrade a durable identity to legacy DATA.
pub(crate) fn present_uuid<'de, D: Deserializer<'de>>(deserializer: D)
    -> Result<Option<VolumeUuid>, D::Error> {
    VolumeUuid::deserialize(deserializer).map(Some)
}

/// Persisted-to-persisted matching. Legacy remains exact; a record without a
/// UUID is never silently promoted by equality. Native compatibility admission
/// must be explicit and independently authenticate the entire old generation.
pub(crate) fn same_volume_data(left: (i64, Option<VolumeUuid>), right: (i64, Option<VolumeUuid>)) -> bool {
    match (left.1, right.1) {
        (Some(a), Some(b)) => a == b,
        (None, None) => left.0 == right.0,
        _ => false,
    }
}

/// Explicit comparison witness for a fully reobserved legacy fixed root.
/// Old records did not store a UUID; this witnesses the CURRENT rooted volume,
/// never an unavailable historical UUID. Native callers must authenticate the
/// selected predecessor, unchanged root inode, full inventory/signatures and
/// immutable transaction history before enrolling this mapping for mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyVolumeBindingData {
    recorded_device: i64, observed_device: i64, observed_uuid: VolumeUuid,
}
impl LegacyVolumeBindingData {
    pub(crate) fn root_data(recorded: crate::macos_install_record::DirectoryIdentity,
        observed: crate::macos_install_record::DirectoryIdentity) -> Option<Self> {
        if !recorded.valid() || !observed.valid() || recorded.volume_uuid.is_some()
            || !recorded.same_fields_except_volume_data(observed) { return None; }
        Some(Self {recorded_device:recorded.device,observed_device:observed.device,observed_uuid:observed.volume_uuid?})
    }
    pub fn matches_data(self, recorded: (i64, Option<VolumeUuid>), observed: (i64, Option<VolumeUuid>)) -> bool {
        recorded.1.is_none() && recorded.0==self.recorded_device && observed.0==self.observed_device
            && observed.1==Some(self.observed_uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        #[serde(default, rename="volumeUuid", skip_serializing_if="Option::is_none", deserialize_with="present_uuid")]
        volume_uuid: Option<VolumeUuid>,
    }
    #[test]
    fn volume_encoding_is_closed_and_cannot_downgrade() {
        let uuid = VolumeUuid::from_bytes_data([17; 16]).unwrap();
        let text = serde_json::to_string(&Wire { volume_uuid: Some(uuid) }).unwrap();
        assert_eq!(text, "{\"volumeUuid\":\"11111111111111111111111111111111\"}");
        assert_eq!(serde_json::from_str::<Wire>(&text).unwrap().volume_uuid, Some(uuid));
        assert_eq!(serde_json::from_value::<Wire>(serde_json::from_str(&text).unwrap()).unwrap().volume_uuid, Some(uuid));
        assert!(serde_json::from_str::<Wire>("{}").unwrap().volume_uuid.is_none());
        for bad in ["null", "0", "[]", "\"\"", "\"00000000000000000000000000000000\"",
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"", "\"111111111111111111111111111111111\""] {
            assert!(serde_json::from_str::<Wire>(&format!("{{\"volumeUuid\":{bad}}}")).is_err());
        }
        assert!(VolumeUuid::from_bytes_data([0;16]).is_none());
    }
    #[test]
    fn durable_matching_tolerates_only_device_renumbering() {
        let a = VolumeUuid::from_bytes_data([1;16]).unwrap();
        let b = VolumeUuid::from_bytes_data([2;16]).unwrap();
        assert!(same_volume_data((16777229,Some(a)),(16777232,Some(a))));
        assert!(!same_volume_data((16777229,Some(a)),(16777229,Some(b))));
        assert!(!same_volume_data((16777229,None),(16777232,None)));
        assert!(!same_volume_data((16777229,None),(16777229,Some(a))));
        assert!(same_volume_data((16777229,None),(16777229,None)));
    }
    #[test]
    fn directory_app_and_launcher_keep_object_and_protection_bindings() {
        use crate::{macos_install_record::DirectoryIdentity,macos_install_transaction::AppIdentityData,
            macos_applications_launcher::OriginalIdentityData};
        let a=VolumeUuid::from_bytes_data([1;16]).unwrap();
        let b=VolumeUuid::from_bytes_data([2;16]).unwrap();
        let old=DirectoryIdentity {device:16777229,inode:111608441,mode:0o040755,uid:0,gid:0,flags:0,volume_uuid:Some(a)};
        let live=DirectoryIdentity {device:16777232,..old};
        assert_eq!(old,live);
        for bad in [DirectoryIdentity {volume_uuid:Some(b),..live}, DirectoryIdentity {inode:live.inode+1,..live},
            DirectoryIdentity {uid:501,..live},DirectoryIdentity {gid:20,..live},DirectoryIdentity {mode:0o040777,..live},
            DirectoryIdentity {flags:1,..live},DirectoryIdentity {volume_uuid:None,..live}] { assert_ne!(old,bad); }
        let app=|dev,volume,inode|AppIdentityData::from_original_volume_fields_data(dev,inode,0o040555,0,0,0,volume).unwrap();
        assert_eq!(app(16777229,a,2),app(16777232,a,2));
        assert_ne!(app(16777229,a,2),app(16777229,b,2));
        assert_ne!(app(16777229,a,2),app(16777232,a,3));
        assert_ne!(app(16777229,a,2),AppIdentityData::from_original_fields_data(16777229,2,0o040555,0,0,0).unwrap());
        let launcher=OriginalIdentityData {device:16777229,inode:3,birth_seconds:17,birth_nanoseconds:42,volume_uuid:Some(a)};
        let current=OriginalIdentityData {device:16777232,..launcher};
        assert_eq!(launcher,current);
        for bad in [OriginalIdentityData {volume_uuid:Some(b),..current},OriginalIdentityData {inode:4,..current},
            OriginalIdentityData {birth_seconds:18,..current},OriginalIdentityData {birth_nanoseconds:43,..current},
            OriginalIdentityData {volume_uuid:None,..current}] { assert_ne!(launcher,bad); }
    }
}
