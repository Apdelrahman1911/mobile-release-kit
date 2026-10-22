//! Bounded comparison DATA from a genuine original local candidate result.
//! This is not a journal receipt, a material loan, or permission to upload.
use serde::{Deserialize, Serialize};

pub(crate) const ANDROID_CONSENT: &str = "agent-local-android-candidate-inputs-v1";
pub(crate) const IOS_CONSENT: &str = "agent-local-ios-candidate-inputs-v1";
pub(crate) const BYTES: usize = 512;
pub(crate) const HEAP_BYTES: usize = 36 + 2 * 64 + 2 * 40;
pub(crate) const ANDROID_PRIMARY_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const IOS_PRIMARY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    pub operation_id: String,
    pub head_sequence: u32,
    pub candidate_sha256: String,
    pub source_commit: String,
    pub source_tree: String,
    pub primary_bytes: u64,
    pub primary_sha256: String,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Candidate {
    pub(crate) fn valid(&self, primary_limit: u64) -> bool {
        let b = self.operation_id.as_bytes();
        b.len() == 36
            && [8, 13, 18, 23].iter().all(|i| b[*i] == b'-')
            && b[14] == b'4'
            && matches!(b[19], b'8' | b'9' | b'a' | b'b')
            && b.iter().enumerate().all(|(i, c)| {
                matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            })
            && (3..=513).contains(&self.head_sequence)
            && hex(&self.candidate_sha256, 64)
            && hex(&self.source_commit, 40)
            && hex(&self.source_tree, 40)
            && hex(&self.primary_sha256, 64)
            && (1..=primary_limit).contains(&self.primary_bytes)
    }
    /// Compare the retained original native operation, not a caller-chosen UUID.
    pub(crate) fn matches_operation(&self, operation: &str) -> bool {
        hex(operation, 32)
            && self
                .operation_id
                .bytes()
                .filter(|b| *b != b'-')
                .eq(operation.bytes())
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        [
            &self.operation_id,
            &self.candidate_sha256,
            &self.source_commit,
            &self.source_tree,
            &self.primary_sha256,
        ]
        .iter()
        .try_fold(0usize, |n, s| n.checked_add(s.capacity()))
    }
    pub(crate) fn compact(&mut self) {
        for s in [
            &mut self.operation_id,
            &mut self.candidate_sha256,
            &mut self.source_commit,
            &mut self.source_tree,
            &mut self.primary_sha256,
        ] {
            *s = std::mem::take(s).into_boxed_str().into_string();
        }
    }
    pub(crate) fn human(&self) -> String {
        format!("Original local candidate {} at journal head {}: manifest SHA-256 {}\nSource commit {} / tree {}\nCandidate primary: {} bytes / {}\nHistorical comparison only; fresh local candidate verification is required before a separate Store action.\n",
            self.operation_id, self.head_sequence, self.candidate_sha256, self.source_commit,
            self.source_tree, self.primary_bytes, self.primary_sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate() -> Candidate {
        Candidate {
            operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            head_sequence: 513,
            candidate_sha256: "f".repeat(64),
            source_commit: "e".repeat(40),
            source_tree: "d".repeat(40),
            primary_bytes: IOS_PRIMARY_BYTES,
            primary_sha256: "c".repeat(64),
        }
    }
    #[test]
    fn exact_candidate_summary_is_bounded_and_correlates_the_native_operation() {
        let mut c = candidate();
        assert!(c.valid(IOS_PRIMARY_BYTES));
        assert!(!c.valid(ANDROID_PRIMARY_BYTES));
        c.primary_bytes = ANDROID_PRIMARY_BYTES;
        assert!(c.valid(ANDROID_PRIMARY_BYTES));
        let bytes = serde_json::to_vec(&c).unwrap();
        assert!(bytes.len() <= BYTES);
        assert!(c.matches_operation("aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"));
        assert!(!c.matches_operation(&"a".repeat(32)));
        assert!(!c.matches_operation(&c.operation_id));
        c.source_tree.reserve(1024);
        assert!(c.heap_bytes().unwrap() > HEAP_BYTES);
        c.compact();
        assert_eq!(c.heap_bytes(), Some(HEAP_BYTES));
        assert_eq!(serde_json::from_slice::<Candidate>(&bytes).unwrap(), c);
        let text = c.human();
        assert!(text.contains("Historical comparison only"));
        for field in [
            "fileName",
            "password",
            "privateKey",
            "recordId",
            "directory",
        ] {
            assert!(!String::from_utf8(bytes.clone()).unwrap().contains(field));
        }
    }
    #[test]
    fn malformed_candidate_fields_and_platform_overflow_never_validate() {
        for change in 0..9 {
            let mut c = candidate();
            match change {
                0 => c.operation_id.replace_range(14..15, "3"),
                1 => c.operation_id.replace_range(19..20, "7"),
                2 => c.head_sequence = 2,
                3 => c.head_sequence = 514,
                4 => c.source_commit.push('a'),
                5 => c.source_tree.replace_range(0..1, "A"),
                6 => c.candidate_sha256.clear(),
                7 => c.primary_bytes = IOS_PRIMARY_BYTES + 1,
                _ => c.primary_sha256.push('\n'),
            }
            assert!(!c.valid(IOS_PRIMARY_BYTES));
        }
        let mut raw = serde_json::to_value(candidate()).unwrap();
        raw["authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Candidate>(raw).is_err());
    }
}
