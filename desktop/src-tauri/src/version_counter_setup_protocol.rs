//! Fixed first-counter DATA on the existing publication wire/slot. No native
//! receipt, protected Authority, allocator or new endpoint is minted here.
use super::*;
use crate::version_enrollment_protocol::{LEDGER_BRANCH, LEDGER_PATH};

pub(crate) const COUNTER_PROTOCOL: &str = "mrk-version-counter-setup/1";
pub(crate) const CONFIRMATION: &str = "Create the FIRST shared version counter on the fixed NEW mrk-version-allocations branch? The initial version is saved project data, NOT a verified Store floor. Existing repository automation may run. No allocation, protection change, enrollment, reset or Store request is authorized. Known prior counters refuse; deleted history on another computer cannot be ruled out. Cancellation does not undo a sent request.";
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Purpose {
    #[serde(rename = "version-counter")]
    Counter,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialVersion {
    pub(crate) name: String,
    pub(crate) build: u32,
}
impl InitialVersion {
    pub(crate) fn valid(&self) -> bool {
        // Secondary bounded DATA only; the original Python Genesis enforces
        // its existing numeric automatic-version policy before review.
        !self.name.is_empty()
            && self.name.len() <= 64
            && self.name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && (1..=2_100_000_000).contains(&self.build)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionSource {
    pub(crate) path: String,
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
}
impl VersionSource {
    fn valid(&self) -> bool {
        crate::release_version_protocol::relative_display_path(&self.path)
            && self.path.len() <= 512
            && self.path.split('/').count() <= 32
            && self.bytes > 0
            && self.bytes <= 65536
            && hex(&self.sha256, 64)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CounterTarget {
    pub(crate) purpose: Purpose,
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) base: String,
    pub(crate) marker: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) project_id: Option<String>,
    pub(crate) ledger_id: String,
    pub(crate) initial_version: InitialVersion,
    pub(crate) saved_config: Fingerprint,
    pub(crate) saved_version: VersionSource,
}
fn uuid(v: &str) -> bool {
    v.len() == 36
        && [8, 13, 18, 23].into_iter().all(|i| v.as_bytes()[i] == b'-')
        && v.as_bytes()[14] == b'4'
        && b"89ab".contains(&v.as_bytes()[19])
        && v.bytes().enumerate().all(|(i, b)| {
            [8, 13, 18, 23].contains(&i) || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
        })
}
impl CounterTarget {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64)
            && coordinate(&self.repository)
            && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id)
            && branch(&self.base)
            && self.base != LEDGER_BRANCH
            && hex(&self.marker, 32)
            && self
                .project_id
                .as_deref()
                .is_none_or(|s| crate::service_protocol::Id::parse(s).is_ok())
            && uuid(&self.ledger_id)
            && self.initial_version.valid()
            && self.saved_config.valid(65536)
            && self.saved_version.valid()
    }
    pub(crate) fn resolved_matches(&self, other: &Self) -> bool {
        if !self.valid() || !other.valid() || other.project_id.is_none() {
            return false;
        }
        let mut actual = other.clone();
        if self.project_id.is_none() {
            actual.project_id = None;
        }
        self == &actual
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        strings(&[
            &self.project_binding,
            &self.repository,
            &self.account_id,
            &self.repository_id,
            &self.base,
            &self.marker,
            &self.ledger_id,
            &self.initial_version.name,
            &self.saved_config.sha256,
            &self.saved_version.path,
            &self.saved_version.sha256,
        ])?
        .checked_add(self.project_id.as_ref().map_or(0, String::capacity))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Selection {
    Setup(Target),
    Counter(CounterTarget),
}
impl From<Target> for Selection {
    fn from(v: Target) -> Self {
        Self::Setup(v)
    }
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Setup(v) => v.valid(),
            Self::Counter(v) => v.valid(),
        }
    }
    pub(crate) fn counter(&self) -> Option<&CounterTarget> {
        if let Self::Counter(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn setup(&self) -> Option<&Target> {
        if let Self::Setup(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn purpose(&self) -> Option<Purpose> {
        self.counter().map(|_| Purpose::Counter)
    }
    pub(crate) fn project_binding(&self) -> &String {
        match self {
            Self::Setup(v) => &v.project_binding,
            Self::Counter(v) => &v.project_binding,
        }
    }
    pub(crate) fn repository(&self) -> &String {
        match self {
            Self::Setup(v) => &v.repository,
            Self::Counter(v) => &v.repository,
        }
    }
    pub(crate) fn account_id(&self) -> &String {
        match self {
            Self::Setup(v) => &v.account_id,
            Self::Counter(v) => &v.account_id,
        }
    }
    pub(crate) fn repository_id(&self) -> &String {
        match self {
            Self::Setup(v) => &v.repository_id,
            Self::Counter(v) => &v.repository_id,
        }
    }
    pub(crate) fn base(&self) -> &String {
        match self {
            Self::Setup(v) => &v.base,
            Self::Counter(v) => &v.base,
        }
    }
    pub(crate) fn marker(&self) -> &String {
        match self {
            Self::Setup(v) => &v.marker,
            Self::Counter(v) => &v.marker,
        }
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.project_binding() == other.project_binding()
            && self.repository() == other.repository()
            && self.account_id() == other.account_id()
            && self.repository_id() == other.repository_id()
    }
    pub(crate) fn resolved_matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Setup(a), Self::Setup(b)) => a == b,
            (Self::Counter(a), Self::Counter(b)) => a.resolved_matches(b),
            _ => false,
        }
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        match self {
            Self::Setup(v) => v.heap(),
            Self::Counter(v) => v.heap(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CounterReview {
    pub(crate) protocol: String,
    pub(crate) target: Selection,
    pub(crate) base_commit: String,
    pub(crate) base_tree: String,
    pub(crate) desired_tree: String,
    pub(crate) ledger_blob: String,
    pub(crate) genesis_sha256: String,
    pub(crate) ledger: String,
    pub(crate) head: String,
    pub(crate) confirmation: String,
}
impl CounterReview {
    pub(crate) fn valid(&self) -> bool {
        self.summary().valid() && self.head==LEDGER_BRANCH && self.confirmation==CONFIRMATION
            && !self.ledger.is_empty() && self.ledger.len()<=8192 && self.ledger.ends_with('\n')
            && self.ledger.bytes().filter(|b|*b==b'\n').count()==1
            // Python is the existing Genesis/Ledger codec. This native check
            // independently binds the exact offered schema/identity/content;
            // it does not assert protection or allocation/store policy.
            && self.ledger_shape() && canonical(self).is_ok_and(|v|v.len()<=16384)
    }
    fn ledger_shape(&self) -> bool {
        let Some(t) = self.target.counter() else {
            return false;
        };
        let Ok(value) = strict_json(self.ledger[..self.ledger.len() - 1].as_bytes()) else {
            return false;
        };
        let genesis = serde_json::json!({"projectId":t.project_id,"repositoryId":t.repository_id,"ledgerId":t.ledger_id,
            "initialVersion":t.initial_version,"branch":LEDGER_BRANCH,"path":LEDGER_PATH});
        let expected = serde_json::json!({"schemaVersion":1,"protocol":"mrk-version-allocation/1","genesis":genesis,"reservations":[]});
        let Ok(raw) = canonical(&expected) else {
            return false;
        };
        let Ok(genesis_bytes) = canonical(&genesis) else {
            return false;
        };
        let mut hash = Sha256::new();
        hash.update(b"mrk:allocation-genesis:1\0");
        hash.update(&genesis_bytes);
        value == expected
            && self.ledger.as_bytes() == [raw.as_slice(), b"\n"].concat()
            && self.genesis_sha256 == format!("{:x}", hash.finalize())
    }
    fn summary(&self) -> CounterSummary {
        CounterSummary {
            protocol: self.protocol.clone(),
            target: self.target.clone(),
            base_commit: self.base_commit.clone(),
            base_tree: self.base_tree.clone(),
            desired_tree: self.desired_tree.clone(),
            ledger_blob: self.ledger_blob.clone(),
            genesis_sha256: self.genesis_sha256.clone(),
            ledger: Fingerprint::from(self.ledger.as_bytes()),
        }
    }
    fn heap(&self) -> Option<usize> {
        self.target.heap()?.checked_add(strings(&[
            &self.protocol,
            &self.base_commit,
            &self.base_tree,
            &self.desired_tree,
            &self.ledger_blob,
            &self.genesis_sha256,
            &self.ledger,
            &self.head,
            &self.confirmation,
        ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CounterSummary {
    pub(crate) protocol: String,
    pub(crate) target: Selection,
    pub(crate) base_commit: String,
    pub(crate) base_tree: String,
    pub(crate) desired_tree: String,
    pub(crate) ledger_blob: String,
    pub(crate) genesis_sha256: String,
    pub(crate) ledger: Fingerprint,
}
impl CounterSummary {
    fn valid(&self) -> bool {
        self.protocol == COUNTER_PROTOCOL
            && self
                .target
                .counter()
                .is_some_and(|v| v.valid() && v.project_id.is_some())
            && hex(&self.base_commit, 40)
            && hex(&self.base_tree, 40)
            && hex(&self.desired_tree, 40)
            && hex(&self.ledger_blob, 40)
            && hex(&self.genesis_sha256, 64)
            && self.ledger.valid(8192)
    }
    fn heap(&self) -> Option<usize> {
        self.target.heap()?.checked_add(strings(&[
            &self.protocol,
            &self.base_commit,
            &self.base_tree,
            &self.desired_tree,
            &self.ledger_blob,
            &self.genesis_sha256,
            &self.ledger.sha256,
        ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Review {
    Setup(Prepared),
    Counter(CounterReview),
}
impl From<Prepared> for Review {
    fn from(v: Prepared) -> Self {
        Self::Setup(v)
    }
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Setup(v) => v.valid(),
            Self::Counter(v) => v.valid(),
        }
    }
    pub(crate) fn target(&self) -> Selection {
        match self {
            Self::Setup(v) => v.target.clone().into(),
            Self::Counter(v) => v.target.clone(),
        }
    }
    pub(crate) fn setup(&self) -> Option<&Prepared> {
        if let Self::Setup(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn counter(&self) -> Option<&CounterReview> {
        if let Self::Counter(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn desired_tree(&self) -> &String {
        match self {
            Self::Setup(v) => &v.desired_tree,
            Self::Counter(v) => &v.desired_tree,
        }
    }
    pub(crate) fn sha256(&self) -> Result<String, BridgeError> {
        canonical(self).map(|v| digest(&v))
    }
    pub(crate) fn summary(&self) -> Record {
        match self {
            Self::Setup(v) => Record::Setup(v.summary()),
            Self::Counter(v) => Record::Counter(v.summary()),
        }
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        match self {
            Self::Setup(v) => v.heap(),
            Self::Counter(v) => v.heap(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Record {
    Setup(Summary),
    Counter(CounterSummary),
}
impl From<Summary> for Record {
    fn from(v: Summary) -> Self {
        Self::Setup(v)
    }
}
impl Record {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Setup(v) => v.valid(),
            Self::Counter(v) => v.valid(),
        }
    }
    pub(crate) fn target(&self) -> Selection {
        match self {
            Self::Setup(v) => v.target.clone().into(),
            Self::Counter(v) => v.target.clone(),
        }
    }
    pub(crate) fn desired_tree(&self) -> &String {
        match self {
            Self::Setup(v) => &v.desired_tree,
            Self::Counter(v) => &v.desired_tree,
        }
    }
    pub(crate) fn counter(&self) -> bool {
        matches!(self, Self::Counter(_))
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        match self {
            Self::Setup(v) => v.heap(),
            Self::Counter(v) => v.heap(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observed {
    pub(crate) commit: String,
    pub(crate) ledger_id: String,
    pub(crate) genesis_sha256: String,
}
impl Observed {
    fn valid(&self, t: &CounterTarget) -> bool {
        hex(&self.commit, 40) && self.ledger_id == t.ledger_id && hex(&self.genesis_sha256, 64)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        strings(&[&self.commit, &self.ledger_id, &self.genesis_sha256])
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CounterPublication {
    pub(crate) effect: Effect,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) counter: Option<Observed>,
    pub(crate) claimed: Option<Vec<Step>>,
    pub(crate) confirmed: Option<BTreeMap<Step, String>>,
    pub(crate) control: GitHubReadControl,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Outcome {
    Setup(Publication),
    Counter(CounterPublication),
}
impl From<Publication> for Outcome {
    fn from(v: Publication) -> Self {
        Self::Setup(v)
    }
}
impl Outcome {
    pub(crate) fn setup(&self) -> Option<&Publication> {
        if let Self::Setup(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn counter(&self) -> Option<&CounterPublication> {
        if let Self::Counter(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn effect(&self) -> Effect {
        match self {
            Self::Setup(v) => v.effect,
            Self::Counter(v) => v.effect,
        }
    }
    pub(crate) fn reason(&self) -> Reason {
        match self {
            Self::Setup(v) => v.reason,
            Self::Counter(v) => v.reason,
        }
    }
    pub(crate) fn control(&self) -> &GitHubReadControl {
        match self {
            Self::Setup(v) => &v.control,
            Self::Counter(v) => &v.control,
        }
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        let (mut n, claimed, confirmed) = match self {
            Self::Setup(v) => (
                v.pull.as_ref().map_or(Some(0), Pull::heap)?,
                &v.claimed,
                &v.confirmed,
            ),
            Self::Counter(v) => (
                v.counter.as_ref().map_or(Some(0), Observed::heap)?,
                &v.claimed,
                &v.confirmed,
            ),
        };
        if let Some(v) = claimed {
            n = n.checked_add(v.capacity().checked_mul(std::mem::size_of::<Step>())?)?;
        }
        if let Some(v) = confirmed {
            n = n.checked_add(v.len().checked_mul(512)?)?;
            for s in v.values() {
                n = n.checked_add(s.capacity())?;
            }
        }
        n.checked_add(
            self.control()
                .credential_expires_at
                .as_ref()
                .map_or(0, String::capacity),
        )
    }
}
pub(super) fn result_valid(v: &ResultData, request: &Request) -> bool {
    let Some(t) = request.target.counter() else {
        return false;
    };
    if v.schema_version != 1 || v.kind != request.kind || !v.control.valid() || v.pending.is_some()
    {
        return false;
    }
    if v.configuration.as_ref().is_some_and(|c| {
        !matches!(v.kind, Kind::Prepare | Kind::Publish)
            || c.saved_config != t.saved_config
            || !c.canonical_config.valid(512 * 1024)
            || c.saved_version.as_ref()
                != Some(&Fingerprint {
                    bytes: t.saved_version.bytes,
                    sha256: t.saved_version.sha256.clone(),
                })
    }) {
        return false;
    }
    if v.kind == Kind::Prepare {
        return v.publication.is_none()
            && (v.reason == Reason::None) == v.prepared.is_some()
            && v.prepared.as_ref().is_none_or(|r| {
                r.counter().is_some()
                    && r.valid()
                    && request.target.resolved_matches(&r.target())
                    && v.configuration.is_some()
            });
    }
    if !matches!(v.kind, Kind::Publish | Kind::Reconcile) || v.prepared.is_some() {
        return false;
    }
    let Some(outcome) = &v.publication else {
        return v.reason != Reason::None;
    };
    let Some(out) = outcome.counter() else {
        return false;
    };
    if out.reason != v.reason
        || out.control != v.control
        || out.counter.as_ref().is_some_and(|o| !o.valid(t))
    {
        return false;
    }
    if v.kind == Kind::Publish {
        let (Some(claimed), Some(confirmed)) = (&out.claimed, &out.confirmed) else {
            return false;
        };
        if !progress(claimed, confirmed)
            || claimed.len() > 3
            || confirmed.get(&Step::Tree).is_some_and(|x| {
                request
                    .prepared
                    .as_ref()
                    .is_none_or(|r| r.desired_tree() != x)
            })
        {
            return false;
        }
        match out.effect {
            Effect::NotSent => {
                claimed.is_empty()
                    && confirmed.is_empty()
                    && out.counter.is_none()
                    && v.reason != Reason::None
            }
            Effect::PotentiallyApplied => {
                !claimed.is_empty() && out.counter.is_none() && v.reason != Reason::None
            }
            Effect::CounterObserved => {
                v.reason == Reason::None
                    && claimed == &STEPS[..3]
                    && confirmed.len() == 3
                    && out.counter.as_ref().is_some_and(|o| {
                        confirmed.get(&Step::Commit) == Some(&o.commit)
                            && request
                                .prepared
                                .as_ref()
                                .and_then(Review::counter)
                                .is_some_and(|r| o.genesis_sha256 == r.genesis_sha256)
                    })
            }
            _ => false,
        }
    } else {
        v.configuration.is_none()
            && out.claimed.is_none()
            && out.confirmed.is_none()
            && match out.effect {
                Effect::Unresolved => v.reason != Reason::None && out.counter.is_none(),
                Effect::CounterObserved => v.reason == Reason::None && out.counter.is_some(),
                _ => false,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review() -> CounterReview {
        let target = CounterTarget {
            purpose: Purpose::Counter,
            project_binding: "a".repeat(64),
            repository: "owner/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
            base: "main".into(),
            marker: "b".repeat(32),
            project_id: Some("c".repeat(32)),
            ledger_id: "12345678-1234-4234-8234-123456789abc".into(),
            initial_version: InitialVersion {
                name: "1.2.3".into(),
                build: 42,
            },
            saved_config: Fingerprint {
                bytes: 100,
                sha256: "d".repeat(64),
            },
            saved_version: VersionSource {
                path: "release/version.properties".into(),
                bytes: 40,
                sha256: "e".repeat(64),
            },
        };
        let genesis = serde_json::json!({"projectId":target.project_id,"repositoryId":target.repository_id,
            "ledgerId":target.ledger_id,"initialVersion":target.initial_version,"branch":LEDGER_BRANCH,"path":LEDGER_PATH});
        let mut hash = Sha256::new();
        hash.update(b"mrk:allocation-genesis:1\0");
        hash.update(canonical(&genesis).unwrap());
        let ledger = serde_json::json!({"schemaVersion":1,"protocol":"mrk-version-allocation/1","genesis":genesis,"reservations":[]});
        CounterReview {
            protocol: COUNTER_PROTOCOL.into(),
            target: Selection::Counter(target),
            base_commit: "1".repeat(40),
            base_tree: "2".repeat(40),
            desired_tree: "3".repeat(40),
            ledger_blob: "4".repeat(40),
            genesis_sha256: format!("{:x}", hash.finalize()),
            ledger: String::from_utf8(canonical(&ledger).unwrap()).unwrap() + "\n",
            head: LEDGER_BRANCH.into(),
            confirmation: CONFIRMATION.into(),
        }
    }
    fn request(kind: Kind) -> Request {
        let reviewed = review();
        Request {
            kind,
            target: reviewed.target.clone(),
            source: matches!(kind, Kind::Prepare | Kind::Publish).then(|| Source {
                root: "/inert/project".into(),
                root_identity: SecretRootIdentity {
                    device: "1".into(),
                    inode: "2".into(),
                    mode: 0o40700,
                    uid: 123,
                    gid: 123,
                },
            }),
            home: Some("/inert/home".into()),
            prepared: (kind == Kind::Publish).then_some(Review::Counter(reviewed)),
        }
    }
    fn control() -> Value {
        serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
    }
    fn wire(value: &Value) -> Vec<u8> {
        let mut raw = serde_json::to_vec(value).unwrap();
        raw.push(b'\n');
        raw
    }
    #[test]
    fn counter_renderer_selects_purpose_only_and_private_go_resolves_required_null() {
        let mut command = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":1,"base":"main","purpose":"version-counter"});
        assert!(decode_command("github_setup_publication_prepare", &command).is_ok());
        for key in [
            "projectId",
            "ledgerId",
            "initialVersion",
            "home",
            "state",
            "token",
            "protected",
        ] {
            let mut bad = command.clone();
            bad[key] = Value::Bool(true);
            assert!(decode_command("github_setup_publication_prepare", &bad).is_err());
        }
        command["purpose"] = Value::Null;
        assert!(decode_command("github_setup_publication_prepare", &command).is_err());
        let mut original = request(Kind::Prepare);
        let Selection::Counter(target) = &mut original.target else {
            panic!("counter")
        };
        target.project_id = None;
        let mut value = serde_json::to_value(&target).unwrap();
        assert!(serde_json::from_value::<CounterTarget>(value.clone()).is_ok());
        value.as_object_mut().unwrap().remove("projectId");
        assert!(serde_json::from_value::<CounterTarget>(value).is_err());
        assert!(original.valid());
        let initial = encode_initial("counter-original", &original).unwrap();
        let digest = super::super::digest(&initial);
        assert!(encode_go("counter-original", &digest, Some("INERT"), &original, None).is_err());
        let go = encode_go(
            "counter-original",
            &digest,
            Some("INERT"),
            &original,
            Some(&"c".repeat(32)),
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&go).unwrap();
        assert_eq!(value["go"]["projectId"], "c".repeat(32));
        assert!(original.target.resolved_matches(&review().target));
        assert!(!request(Kind::Pending).valid()); // ordinary Pending alone lists the same mixed journal.
    }
    #[test]
    fn counter_review_requires_exact_empty_ledger_identity_and_canonical_original_bytes() {
        let original = review();
        assert!(original.valid());
        for modify in 0..5 {
            let mut bad = original.clone();
            match modify {
                0 => bad.ledger.push('\n'),
                1 => {
                    bad.ledger = bad
                        .ledger
                        .replace("\"reservations\":[]", "\"reservations\":[{}]")
                }
                2 => bad.genesis_sha256 = "0".repeat(64),
                3 => bad.confirmation = "approve Store floor".into(),
                _ => {
                    let Selection::Counter(t) = &mut bad.target else {
                        panic!("counter")
                    };
                    t.repository_id = "33".into();
                }
            }
            assert!(!bad.valid());
        }
        let mut pending = Pending {
            summary: Record::Counter(original.summary()),
            claimed: vec![Step::Tree],
            confirmed: BTreeMap::new(),
        };
        assert!(pending.valid());
        pending.claimed.push(Step::Commit);
        assert!(!pending.valid());
        pending.confirmed.insert(Step::Tree, original.desired_tree);
        assert!(pending.valid());
    }
    #[test]
    fn counter_observed_needs_original_three_claims_and_never_accepts_protection_or_pull() {
        let request = request(Kind::Publish);
        let reviewed = request.prepared.as_ref().unwrap().counter().unwrap();
        let mut frame = serde_json::json!({"protocol":PROTOCOL,"id":"counter-original","result":{
            "schemaVersion":1,"kind":"publish","reason":"none","prepared":null,"pending":null,"configuration":null,"control":control(),
            "publication":{"effect":"counter-observed","reason":"none","counter":{"commit":"5".repeat(40),
                "ledgerId":reviewed.target.counter().unwrap().ledger_id,"genesisSha256":reviewed.genesis_sha256},
                "claimed":["tree","commit","branch"],"confirmed":{"tree":reviewed.desired_tree,"commit":"5".repeat(40),"branch":"5".repeat(40)},"control":control()}}});
        assert!(decode_reply("counter-original", &wire(&frame), &request).is_ok());
        for edit in 0..6 {
            let mut bad = frame.clone();
            let out = &mut bad["result"]["publication"];
            match edit {
                0 => {
                    out["counter"]["ledgerId"] =
                        Value::String("12345678-1234-4234-8234-123456789abd".into())
                }
                1 => out["counter"]["genesisSha256"] = Value::String("0".repeat(64)),
                2 => out["counter"]["protected"] = Value::Bool(true),
                3 => out["claimed"]
                    .as_array_mut()
                    .unwrap()
                    .push(Value::String("pull".into())),
                4 => out["confirmed"]["branch"] = Value::String("6".repeat(40)),
                _ => out["pull"] = Value::Null,
            }
            assert!(decode_reply("counter-original", &wire(&bad), &request).is_err());
        }
        frame["result"]["publication"]["counter"] = Value::Null;
        frame["result"]["publication"]["effect"] = Value::String("potentially-applied".into());
        frame["result"]["reason"] = Value::String("cancelled".into());
        frame["result"]["publication"]["reason"] = Value::String("cancelled".into());
        assert!(decode_reply("counter-original", &wire(&frame), &request).is_ok());
    }
}
