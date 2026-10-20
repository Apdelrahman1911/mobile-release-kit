//! Closed SDK-copy comparison DATA, never a source loan or registration proof.
//! The Mac adapter derives it only from its own positively closed SourceSlots.
//! A child opens NEW originals and must match this binding before vendor IO.
use super::components::Partition;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const STAMP_BYTES: usize = 68;
pub(crate) const FORMAT: &str = "mrk-sdk-copy/1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Component {
    Platform,
    BuildTools,
}
impl Component {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Platform => "sdk-platform",
            Self::BuildTools => "sdk-build-tools",
        }
    }
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Platform => 1,
            Self::BuildTools => 2,
        }
    }
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::Platform => "platforms/android-35",
            Self::BuildTools => "build-tools/35.0.0",
        }
    }
    pub(crate) fn for_partition(partition: Partition) -> Option<Self> {
        match (partition.is_compatible(1), partition.is_compatible(2)) {
            (true, false) => Some(Self::Platform),
            (false, true) => Some(Self::BuildTools),
            _ => None,
        }
    }
    pub(crate) fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "sdk-platform" => Some(Self::Platform),
            "sdk-build-tools" => Some(Self::BuildTools),
            _ => None,
        }
    }
}

/// Private bootstrap input. Intentionally no Debug/Serialize/Deserialize/Clone.
pub(crate) struct CopyInput {
    pub(crate) component: Component,
    pub(crate) root: String,
    pub(crate) root_identity: [u8; STAMP_BYTES],
    pub(crate) observation: [u8; 32],
}
impl CopyInput {
    pub(crate) fn data(&self) -> Value {
        json!({"format":FORMAT,"component":self.component.name(),"root":self.root,
            "rootIdentity":hex(&self.root_identity),"observationSha256":hex(&self.observation)})
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.root.capacity())
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}

/// Streaming, length-delimited hash. Required members are visited in canonical
/// path-component order (a directory before its sorted children). Optional
/// package.xml is comparison-only, never a copied/compiled payload authority.
pub(crate) struct Observation {
    hash: Sha256,
    count: u32,
}
impl Observation {
    pub(crate) fn new(reference: [u8; 32], component: Component, root: [u8; STAMP_BYTES]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"mrk-sdk-copy-observation/1\0");
        hash.update(reference);
        hash.update([component.index() as u8]);
        hash.update(root);
        Self { hash, count: 0 }
    }
    pub(crate) fn member(
        &mut self,
        relative: &str,
        directory: bool,
        stamp: [u8; STAMP_BYTES],
    ) -> Option<()> {
        if relative.is_empty() || relative.len() > 512 || self.count >= 32768 {
            return None;
        }
        self.hash.update([1]);
        self.hash.update((relative.len() as u32).to_le_bytes());
        self.hash.update(relative.as_bytes());
        self.hash.update([u8::from(directory)]);
        self.hash.update(stamp);
        self.count += 1;
        Some(())
    }
    pub(crate) fn finish(
        mut self,
        metadata: Option<([u8; STAMP_BYTES], [u8; 32])>,
    ) -> Option<[u8; 32]> {
        if self.count == 0 {
            return None;
        }
        self.hash.update([2, u8::from(metadata.is_some())]);
        if let Some((stamp, sha)) = metadata {
            self.hash.update(stamp);
            self.hash.update(sha);
        }
        self.hash.update([3]);
        self.hash.update(self.count.to_le_bytes());
        Some(self.hash.finalize().into())
    }
}

/// Public DATA format only. Exact native Expected separately requires the
/// copy to be the compatible half of its SAME original missing partition.
pub(crate) fn copied(value: &Value) -> Result<Option<Component>, ()> {
    match value["schemaVersion"].as_u64() {
        Some(1) if value.get("copiedSourceComponents").is_none() => Ok(None),
        Some(2) => {
            let rows = value["copiedSourceComponents"].as_array().ok_or(())?;
            if rows.len() != 1 {
                return Err(());
            }
            Component::parse(&rows[0]).map(Some).ok_or(())
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_compatible_sdk_half_is_copyable() {
        for mask in 0..16 {
            let p =
                Partition::observed(std::array::from_fn(|i| Some(mask & (1 << i) != 0))).unwrap();
            let copy = Component::for_partition(p);
            assert_eq!(copy.is_some(), p.is_compatible(1) != p.is_compatible(2));
            if let Some(copy) = copy {
                assert!(p.is_compatible(copy.index()));
                assert!(!p.missing().contains(&copy.name()));
            }
        }
    }
    #[test]
    fn old_results_and_new_exact_sdk_singleton_are_distinct() {
        assert_eq!(copied(&json!({"schemaVersion":1})), Ok(None));
        assert_eq!(
            copied(&json!({"schemaVersion":2,"copiedSourceComponents":["sdk-platform"]})),
            Ok(Some(Component::Platform))
        );
        for value in [
            json!({"schemaVersion":1,"copiedSourceComponents":[]}),
            json!({"schemaVersion":2,"copiedSourceComponents":[]}),
            json!({"schemaVersion":2,"copiedSourceComponents":["jdk"]}),
            json!({"schemaVersion":2,"copiedSourceComponents":["sdk-platform","sdk-build-tools"]}),
        ] {
            assert!(copied(&value).is_err());
        }
    }
    #[test]
    fn source_hash_binds_full_identity_order_and_optional_metadata() {
        fn hash(
            stamp: [u8; STAMP_BYTES],
            metadata: Option<([u8; STAMP_BYTES], [u8; 32])>,
        ) -> [u8; 32] {
            let mut h = Observation::new([7; 32], Component::Platform, [8; STAMP_BYTES]);
            h.member("platforms/android-35", true, stamp).unwrap();
            h.finish(metadata).unwrap()
        }
        let original = hash([0; STAMP_BYTES], None);
        assert_ne!(original, hash([1; STAMP_BYTES], None));
        assert_ne!(
            original,
            hash([0; STAMP_BYTES], Some(([0; STAMP_BYTES], [0; 32])))
        );
        assert_eq!(
            hex(&original),
            "a4eb83ad0f4a661ebfc7588871c4237580654d5ada9444dcb0dfbe2032d79fbc"
        );
    }
}
