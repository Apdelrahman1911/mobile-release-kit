//! Fixed local-key recovery comparisons, never portable custody/finality.
use super::*;
use crate::{
    apple_provisioning_journal::{
        durable_key_row, key_row_sha256, KeyOutputMetadata, KeyRecoveryOrigin, KeyRecoveryRecord,
        NativeSettlement,
    },
    credential_setup::KeyReference,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyRecoveryStamp {
    pub(crate) reference: Reference,
    pub(crate) sha256: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRecoverySelection {
    pub(crate) reference: Reference,
    pub(crate) row_sha256: String,
    pub(crate) native_settlement: NativeSettlement,
    pub(crate) output: KeyOutputMetadata,
    pub(crate) recovery: Option<KeyRecoveryStamp>,
}
impl KeyRecoverySelection {
    pub(super) fn valid(&self) -> bool {
        self.reference.valid()
            && sha(&self.row_sha256)
            && self.output.valid()
            && matches!(
                self.native_settlement,
                NativeSettlement::Pending | NativeSettlement::Known
            )
            && self.recovery.as_ref().is_none_or(|recovery| {
                self.native_settlement == NativeSettlement::Pending
                    && recovery.reference.valid()
                    && recovery.reference != self.reference
                    && sha(&recovery.sha256)
            })
    }
    pub(crate) fn needs_record(&self) -> bool {
        self.native_settlement == NativeSettlement::Pending && self.recovery.is_none()
    }
}
fn unavailable() -> BridgeError {
    BridgeError::new("apple_key_recovery_unavailable",
        "This key has no uniquely matching durable saved-key record. Keep the original key and setup history; do not generate a replacement. Missing, restored-as-new, or uncertain saved keys cannot be recovered by this action.")
}
pub(crate) fn key_recovery_selection(
    account: &AccountSnapshot,
    scope: &ScopeData,
) -> Result<KeyRecoverySelection, BridgeError> {
    account.validate_recoveries().map_err(|_| invalid())?;
    let key = scope.key.as_ref().ok_or_else(invalid)?;
    let source = key.source_key.as_ref().ok_or_else(invalid)?;
    let target = key.target(&scope.target)?;
    let mut rows = account
        .key_rows
        .iter()
        .filter(|row| row.intent.destination == *source);
    let row = rows.next().ok_or_else(unavailable)?;
    if rows.next().is_some()
        || !durable_key_row(row)
        || row.intent.context.account_ref != scope.provisioning.account_ref
        || row.intent.provenance.project_binding != scope.provenance.project_binding
        || row.intent.provenance.registered_root != scope.provenance.registered_root
        || row.intent.target != target
    {
        return Err(unavailable());
    }
    let recovery = account
        .key_recovery(row)
        .map_err(|_| invalid())?
        .map(|record| {
            Ok::<_, BridgeError>(KeyRecoveryStamp {
                reference: Reference {
                    operation_id: record.provenance.operation_id.as_str().into(),
                    owner_generation: record.provenance.owner_generation.as_str().into(),
                },
                sha256: record.sha256().map_err(|_| invalid())?,
            })
        })
        .transpose()?;
    Ok(KeyRecoverySelection {
        reference: Reference {
            operation_id: row.intent.provenance.operation_id.as_str().into(),
            owner_generation: row.intent.provenance.owner_generation.as_str().into(),
        },
        row_sha256: key_row_sha256(row).map_err(|_| invalid())?,
        native_settlement: row.native_settlement,
        output: row.update.output.clone().ok_or_else(invalid)?,
        recovery,
    })
}

pub(crate) fn key_recovery_record(
    binding: &RequestBinding,
) -> Result<KeyRecoveryRecord, BridgeError> {
    need(binding.context.mode == Mode::KeyRecover)?;
    let key = binding.scope.key.as_ref().ok_or_else(invalid)?;
    let selected = key.recovery.as_ref().ok_or_else(invalid)?;
    need(selected.valid() && selected.needs_record())?;
    let record = KeyRecoveryRecord {
        context: binding.scope.provisioning.clone(),
        provenance: binding.scope.provenance.clone(),
        target: key.target(&binding.scope.target)?,
        source_p8: key.source_p8.clone(),
        source_key: key.source_key.clone().ok_or_else(invalid)?,
        original: KeyRecoveryOrigin {
            operation_id: Id::parse(&selected.reference.operation_id).map_err(|_| invalid())?,
            owner_generation: Id::parse(&selected.reference.owner_generation)
                .map_err(|_| invalid())?,
            row_sha256: selected.row_sha256.clone(),
        },
        output: selected.output.clone(),
    };
    record.validate().map_err(|_| invalid())?;
    Ok(record)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Compared {
    source_key: KeyReference,
    csr_pem: String,
    public_key_spki_der: String,
    output: KeyOutputMetadata,
}
pub(crate) struct KeyRecoveryInput {
    pub(crate) csr: String,
    pub(crate) spki: Vec<u8>,
    pub(crate) output: KeyOutputMetadata,
    pub(crate) payload_sha256: String,
}
pub(super) fn key_recovery_input(
    binding: &RequestBinding,
    value: Value,
) -> Result<KeyRecoveryInput, BridgeError> {
    need(binding.context.mode == Mode::KeyRecover)?;
    let digest = crate::apple_provisioning_journal::certificate_phase_sha256(&value)
        .map_err(|_| invalid())?;
    let value = Compared::deserialize(value).map_err(|_| invalid())?;
    let key = binding.scope.key.as_ref().ok_or_else(invalid)?;
    let selected = key.recovery.as_ref().ok_or_else(invalid)?;
    need(
        selected.valid()
            && key.source_key.as_ref() == Some(&value.source_key)
            && value.output == selected.output
            && value.csr_pem.is_ascii()
            && !value.csr_pem.is_empty()
            && value.csr_pem.len() <= 4096
            && value
                .csr_pem
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
            && value
                .csr_pem
                .ends_with("-----END CERTIFICATE REQUEST-----\n")
            && value.output.csr_sha256 == hex(&Sha256::digest(value.csr_pem.as_bytes()))
            && !value.public_key_spki_der.is_empty()
            && value.public_key_spki_der.len() <= 4 * 1024_usize.div_ceil(3),
    )?;
    let spki = profile::unbase64(&value.public_key_spki_der, 1024)?;
    need(
        !spki.is_empty()
            && spki.len() <= 1024
            && value.output.public_key_sha256 == hex(&Sha256::digest(&spki)),
    )?;
    Ok(KeyRecoveryInput {
        csr: value.csr_pem,
        spki,
        output: value.output,
        payload_sha256: digest,
    })
}
pub(crate) fn key_recovery_ack(
    binding: &RequestBinding,
    payload_sha256: &str,
) -> Result<Vec<u8>, BridgeError> {
    need(binding.context.mode == Mode::KeyRecover && sha(payload_sha256))?;
    let selected = binding
        .scope
        .key
        .as_ref()
        .and_then(|key| key.recovery.as_ref())
        .ok_or_else(invalid)?;
    let value = json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"kind":"key-compared-ack","step":1,
        "payload":{"comparisonSha256":payload_sha256,"originalRowSha256":selected.row_sha256}});
    let mut bytes = bounded(&value, ACK_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Only full native-validated relations cross INITIAL. Python checks linkage,
/// not eligibility from hash-shaped fields. Old pending rows stay unchanged.
pub(crate) fn key_recovery_relations(account: &AccountSnapshot) -> Result<Value, BridgeError> {
    account.validate_recoveries().map_err(|_| invalid())?;
    Ok(Value::Array(account.key_recoveries.iter().map(|record| Ok(json!({
        "accountRef":record.context.account_ref,"operationId":record.provenance.operation_id,
        "ownerGeneration":record.provenance.owner_generation,"originalOperationId":record.original.operation_id,
        "originalOwnerGeneration":record.original.owner_generation,"originalRowSha256":record.original.row_sha256,
        "recordSha256":record.sha256().map_err(|_|invalid())?}))).collect::<Result<Vec<_>,BridgeError>>()?))
}
