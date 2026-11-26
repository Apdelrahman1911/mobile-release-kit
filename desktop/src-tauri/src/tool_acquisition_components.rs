//! Closed four-component comparison DATA. A partition is not a tool lease,
//! source proof, native completion or permission to download.
use serde_json::Value;

pub(crate) const ALL: [&str; 4] = ["jdk", "sdk-platform", "sdk-build-tools", "gradle"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Partition {
    compatible: u8,
}
impl Partition {
    /// None is unobserved/uncertain, NOT missing. Only an original observer may
    /// supply a negative observation for a selected directory entry.
    pub(crate) fn observed(values: [Option<bool>; 4]) -> Option<Self> {
        let mut compatible = 0;
        for (index, value) in values.into_iter().enumerate() {
            if value? {
                compatible |= 1 << index;
            }
        }
        Some(Self { compatible })
    }
    pub(crate) fn missing_all() -> Self {
        Self { compatible: 0 }
    }
    pub(crate) fn compatible_all() -> Self {
        Self { compatible: 15 }
    }
    pub(crate) fn is_compatible(self, index: usize) -> bool {
        index < 4 && self.compatible & (1 << index) != 0
    }
    pub(crate) fn needs_download(self) -> bool {
        self.compatible != 15
    }
    pub(crate) fn missing(self) -> Vec<&'static str> {
        ALL.into_iter()
            .enumerate()
            .filter_map(|(i, name)| (!self.is_compatible(i)).then_some(name))
            .collect()
    }
    pub(crate) fn compatible(self) -> Vec<&'static str> {
        ALL.into_iter()
            .enumerate()
            .filter_map(|(i, name)| self.is_compatible(i).then_some(name))
            .collect()
    }
    pub(crate) fn data(self) -> Value {
        serde_json::json!({"missing": self.missing(), "compatible": self.compatible()})
    }
    /// Strict canonical wire comparison only. Never turns a JSON array into a
    /// native inventory; the original owner separately binds its own partition.
    pub(crate) fn parse(missing: &Value, compatible: &Value) -> Option<Self> {
        let missing = missing.as_array()?;
        let compatible = compatible.as_array()?;
        let values = std::array::from_fn(|i| {
            match (
                missing.iter().any(|v| v == ALL[i]),
                compatible.iter().any(|v| v == ALL[i]),
            ) {
                (true, false) => Some(false),
                (false, true) => Some(true),
                _ => None,
            }
        });
        let partition = Self::observed(values)?;
        (missing.len() + compatible.len() == 4
            && missing.iter().zip(partition.missing()).all(|(a, b)| a == b)
            && compatible
                .iter()
                .zip(partition.compatible())
                .all(|(a, b)| a == b))
        .then_some(partition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn all_sixteen_partitions_are_canonical_and_exhaustive() {
        for mask in 0..16u8 {
            let partition =
                Partition::observed(std::array::from_fn(|i| Some(mask & (1 << i) != 0))).unwrap();
            let data = partition.data();
            assert_eq!(
                Partition::parse(&data["missing"], &data["compatible"]),
                Some(partition)
            );
            assert_eq!(partition.missing().len() + partition.compatible().len(), 4);
            assert_eq!(partition.needs_download(), mask != 15);
        }
    }
    #[test]
    fn uncertain_duplicate_foreign_and_reordered_entries_are_not_missing() {
        assert_eq!(
            Partition::observed([Some(true), None, Some(false), Some(true)]),
            None
        );
        for (missing, compatible) in [
            (
                json!(["sdk-build-tools", "sdk-platform"]),
                json!(["jdk", "gradle"]),
            ),
            (
                json!(["sdk-platform", "sdk-platform"]),
                json!(["jdk", "gradle"]),
            ),
            (
                json!(["sdk-platform"]),
                json!(["jdk", "sdk-platform", "gradle"]),
            ),
            (json!(["ndk"]), json!(["jdk", "sdk-platform", "gradle"])),
        ] {
            assert_eq!(Partition::parse(&missing, &compatible), None);
        }
    }
}
