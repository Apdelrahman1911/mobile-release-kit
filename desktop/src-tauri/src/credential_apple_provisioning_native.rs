//! Stored-P12 custody for one explicitly admitted Apple profile setup.
//! This is a child of the existing vault/Document owner, not another store or
//! credential inspector. Public references never construct a private loan.
use super::*;
use crate::credential_setup::KeyReference;
use sha2::{Digest, Sha256};
use std::sync::Weak;

#[path = "credential_apple_profile_store.rs"]
pub(in crate::asset_session) mod profile_store;
pub(crate) use profile_store::AppleProfileDestination;

pub(crate) const AUTOMATIC_P12_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const AUTOMATIC_P12_PASSWORD_BYTES: usize = 4096;

fn same_reference(left: StoredRef, right: StoredRef) -> bool {
    left.identity == right.identity
        && left.record == right.record
        && left.revision == right.revision
        && left.original == right.original
}

fn expected_certificate(draft: &[u8]) -> Result<[u8; 32], Reason> {
    // The draft is the already captured native saved configuration, not new
    // renderer configuration. Existing schema/identity checks remain in the
    // original SavedCommand admission; this only selects its exact digest.
    let value: Value = serde_json::from_slice(draft).map_err(|_| Reason::ContextStale)?;
    let expected = value
        .get("ios")
        .and_then(|ios| ios.get("distributionCertificateSha256"))
        .and_then(Value::as_str)
        .ok_or(Reason::SourceRefused)?;
    if expected.len() != 64 && expected.len() != 95 {
        return Err(Reason::SourceRefused);
    }
    let mut normalized = [0u8; 64];
    if expected.len() == 64 {
        normalized.copy_from_slice(expected.as_bytes());
    } else {
        for (i, byte) in expected.bytes().enumerate() {
            if i % 3 == 2 {
                if byte != b':' {
                    return Err(Reason::SourceRefused);
                }
            } else {
                normalized[i - i / 3] = byte;
            }
        }
    }
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut digest = [0; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = digit(normalized[index * 2]).ok_or(Reason::SourceRefused)? * 16
            + digit(normalized[index * 2 + 1]).ok_or(Reason::SourceRefused)?;
    }
    Ok(digest)
}

/// The complete original BoundLoan is copied by moving only its existing
/// Arc references. Its authenticated bytes are neither cloned nor serialized.
pub(crate) struct AppleP12Loan {
    pub(super) original: BoundLoan,
    document: Weak<Inner>,
    session_identity: Arc<()>,
    expected_certificate: [u8; 32],
    p12_digest: [u8; 32],
}

impl AppleP12Loan {
    pub(in crate::asset_session) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> Result<Arc<Self>, Reason> {
        if !document.native_qualified() || !document.persistence_qualified() {
            return Err(Reason::UnsupportedFormat);
        }
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let context = state.context.as_ref().ok_or(Reason::ContextStale)?;
        if context.platform != Platform::Ios
            || context.stage != Stage::Candidate
            || context.purpose != Purpose::Provisioning
            || context.execution_mode != commands::ExecutionMode::Local
            || !document
                .context_matches(state, context)
                .map_err(|error| error.reason)?
        {
            return Err(Reason::ContextStale);
        }
        session_kind_gate(context, Kind::AppleP12).map_err(|error| error.reason)?;
        let mut matching = session
            .bound
            .iter()
            .flatten()
            .filter(|loan| loan.payload.kind == Kind::AppleP12 && loan.current(state, session));
        let loan = matching.next().ok_or(Reason::SourceRefused)?;
        if matching.next().is_some() || !Arc::ptr_eq(context, &loan.context) {
            return Err(Reason::ContextStale);
        }
        let material = loan
            .payload
            .material
            .as_ref()
            .ok_or(Reason::SourceRefused)?;
        let MaterialOrigin::Stored(stored) = &material.origin else {
            return Err(Reason::SourceChanged);
        };
        let p12 = material.bytes();
        let password = loan
            .payload
            .fields
            .as_ref()
            .and_then(|fields| fields.borrow_value("password"))
            .ok_or(Reason::SourceRefused)?;
        if !same_reference(stored.reference, loan.reference)
            || !material.observation.is_observed()
            || p12.is_empty()
            || p12.len() > AUTOMATIC_P12_BYTES
            || password.is_empty()
            || password.len() > AUTOMATIC_P12_PASSWORD_BYTES
            || password.contains('\0')
        {
            return Err(Reason::UnsupportedFormat);
        }
        Ok(Arc::new(Self {
            original: BoundLoan {
                context: loan.context.clone(),
                payload: loan.payload.clone(),
                reference: loan.reference,
                store: loan.store.clone(),
                key: loan.key.clone(),
            },
            document: Arc::downgrade(&document.inner),
            session_identity: document.inner.session_identity.clone(),
            expected_certificate: expected_certificate(&context.draft)?,
            p12_digest: Sha256::digest(p12).into(),
        }))
    }

    pub(crate) fn reference(&self) -> KeyReference {
        let source = self.original.reference;
        KeyReference::native(source.identity, source.record, source.revision)
    }

    pub(crate) fn expected_certificate_sha256(&self) -> [u8; 32] {
        self.expected_certificate
    }

    pub(crate) fn p12_sha256(&self) -> [u8; 32] {
        self.p12_digest
    }

    /// Scalar-only native match. The original pre-GO/post-use jobs separately
    /// recheck the retained StoreBook/read witness OFF the Document guard.
    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        mutation: Option<&Arc<OriginalWork>>,
    ) -> bool {
        if !Weak::ptr_eq(&self.document, &Arc::downgrade(&document.inner))
            || !Arc::ptr_eq(&self.session_identity, &document.inner.session_identity)
        {
            return false;
        }
        let Some(session) = state.vault.as_ref() else {
            return false;
        };
        let bound = match mutation {
            None => self.original.current(state, session),
            Some(owner) => self
                .original
                .current_for_apple_profile(state, session, owner),
        };
        bound
            && document
                .context_matches(state, &self.original.context)
                .unwrap_or(false)
    }

    pub(in crate::asset_session) fn census_loan(&self) -> &BoundLoan {
        &self.original
    }

    pub(crate) fn own_retained_bytes(&self) -> usize {
        // Payload/context/key/store backing is visited by the existing Arc-
        // deduplicating Document census, not charged again as secret copies.
        std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>()
    }

    /// Borrowed exclusively by the existing fixed SelectedStoreMaterial
    /// writer. No new public/private-byte getter or custom pipe is introduced.
    pub(in crate::asset_session) fn private_parts(
        &self,
    ) -> Result<[(&'static str, &[u8]); 2], Reason> {
        let material = self
            .original
            .payload
            .material
            .as_ref()
            .ok_or(Reason::SourceRefused)?;
        let password = self
            .original
            .payload
            .fields
            .as_ref()
            .and_then(|fields| fields.borrow_value("password"))
            .ok_or(Reason::SourceRefused)?;
        if material.bytes().is_empty()
            || material.bytes().len() > AUTOMATIC_P12_BYTES
            || password.is_empty()
            || password.len() > AUTOMATIC_P12_PASSWORD_BYTES
            || password.contains('\0')
        {
            return Err(Reason::SourceChanged);
        }
        Ok([
            ("apple-p12", material.bytes()),
            ("p12-password", password.as_bytes()),
        ])
    }

    pub(super) fn recheck_store(
        &self,
        owner: &Arc<OriginalWork>,
        book: &mut store::StoreBook,
        roster: &ProjectRoster,
    ) -> Result<(), Reason> {
        if owner.interrupted()
            || !Arc::ptr_eq(&active_key(owner)?, &self.original.key)
            || !Arc::ptr_eq(&native_store(owner)?, &self.original.store)
        {
            return Err(Reason::SourceChanged);
        }
        check_exclusions(owner, book, roster)?;
        book.recheck_record(&self.original.reference.original, &mut || {
            owner.interrupted()
        })
        .map_err(problem)?;
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_fingerprint_selection_is_strict_and_is_never_created() {
        let exact = ["AB"; 32].join(":");
        let draft = serde_json::to_vec(&serde_json::json!({"ios": {
            "distributionCertificateSha256": exact
        }}))
        .unwrap();
        assert_eq!(expected_certificate(&draft).unwrap(), [0xab; 32]);
        for value in [
            serde_json::json!({}),
            serde_json::json!({"ios": {}}),
            serde_json::json!({"ios": {"distributionCertificateSha256": ""}}),
            serde_json::json!({"ios": {"distributionCertificateSha256": "x".repeat(64)}}),
            serde_json::json!({"ios": {"distributionCertificateSha256": ":".repeat(95)}}),
        ] {
            assert!(expected_certificate(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn profile_automation_does_not_change_global_vault_limits() {
        assert_eq!(AUTOMATIC_P12_BYTES, 4 * 1024 * 1024);
        assert_eq!(AUTOMATIC_P12_PASSWORD_BYTES, 4096);
        assert_eq!(format::FILE_LIMIT, 32 * 1024 * 1024);
        assert_eq!(SESSION_BYTES, 64 * 1024 * 1024);
        assert_eq!(format::WORKING_BYTES, 96 * 1024 * 1024);
    }
}
