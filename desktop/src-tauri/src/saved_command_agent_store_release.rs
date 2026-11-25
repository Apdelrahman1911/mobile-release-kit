//! Execute/Reconcile facets of the SAME Saved owner and agent Store link.
//! Context/loans remain private; public modes and receipts are comparison DATA.
use super::*;
use p::release::{Basis, Mode, Review as ReleaseReview};

pub(super) fn details(c: &Context) -> Option<ReleaseReview> {
    match c {
        Context::LocalStoreExecute(c) => Some(ReleaseReview {
            mode: match c.later.as_ref().map(|s| s.stage) {
                None => Mode::CandidateUpload,
                Some(prepare_wire::StoreStage::ExternalTesting) => Mode::ExternalTesting,
                Some(prepare_wire::StoreStage::ProductionSubmit) => Mode::ProductionSubmit,
            },
            intent_sha256: c.intent_sha256.clone(),
            stage_operation_id: c.stage_operation_id.clone(),
            basis: c.later.as_ref().map(|s| Basis {
                operation_id: s.predecessor_operation_id.clone(),
                receipt_sha256: s.predecessor_receipt_sha256.clone(),
            }),
        }),
        Context::LocalStoreReconcile(c) => {
            let mode = if c.refreshing() {
                Mode::ExternalReadiness
            } else if c.settling() {
                Mode::RecoverySettlement
            } else if c.operation == reconcile_wire::Operation::LocalStoreReconcile
                && c.readiness.is_none()
                && c.settlement.is_none()
            {
                Mode::CurrentInternal
            } else {
                return None;
            };
            Some(ReleaseReview {
                mode,
                intent_sha256: c.intent_sha256.clone(),
                stage_operation_id: c.readiness.as_ref().map(|s| s.stage_operation_id.clone()),
                basis: c.readiness.as_ref().map(|s| Basis {
                    operation_id: s.stage_operation_id.clone(),
                    receipt_sha256: s.execution_receipt_sha256.clone(),
                }),
            })
        }
        _ => None,
    }
}
pub(super) fn supported(c: &Context) -> bool {
    details(c).is_some()
}
pub(super) fn review(
    c: &Context,
    id: &str,
    generation: &str,
    revision: u32,
) -> Result<p::Review, BridgeError> {
    let release = details(c).ok_or_else(refused)?;
    let (kind, platform, config, saved_version, candidate) = match c {
        Context::LocalStoreExecute(c) => (
            p::Kind::Execute,
            if c.platform == execute_wire::Platform::Android {
                p::Platform::Android
            } else {
                p::Platform::Ios
            },
            p::Content {
                bytes: c.saved_config.bytes,
                sha256: c.saved_config.sha256.clone(),
            },
            version(&c.saved_version),
            p::Candidate {
                operation_id: c.candidate_operation_id.clone(),
                sha256: c.candidate_sha256.clone(),
            },
        ),
        Context::LocalStoreReconcile(c) => (
            p::Kind::Reconcile,
            if c.platform == reconcile_wire::Platform::Android {
                p::Platform::Android
            } else {
                p::Platform::Ios
            },
            p::Content {
                bytes: c.saved_config.bytes,
                sha256: c.saved_config.sha256.clone(),
            },
            version(&c.saved_version),
            p::Candidate {
                operation_id: c.candidate_operation_id.clone(),
                sha256: c.candidate_sha256.clone(),
            },
        ),
        _ => return Err(refused()),
    };
    let r = p::Review {
        kind,
        platform,
        saved_config: config,
        saved_version,
        candidate: Some(candidate),
        release: Some(release),
        operation_id: s::Id::parse(id).map_err(|_| refused())?,
        owner_generation: s::Id::parse(generation).map_err(|_| refused())?,
        status_revision: revision,
    };
    if !r.valid() {
        return Err(refused());
    }
    Ok(r)
}

impl SavedCommandOwner {
    pub(crate) fn start_agent_store_release(
        &self,
        entry: &Arc<requests::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: store_wire::Availability,
        material: Arc<SelectedStoreMaterial>,
        budget: Option<&crate::asset_session::ExecuteMemoryAdmission<'_>>,
    ) -> Result<AgentStoreAdmitted, BridgeError> {
        let input = Start {
            operation_id: entry.scope().review.operation_id.as_str().into(),
            owner_generation: entry.scope().review.owner_generation.as_str().into(),
        };
        let r = self.inner.lock();
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| start_matches(p, Some(entry)))
            .ok_or_else(refused)?;
        if !matches!(&prepared.material, Some(PrivateSigningMaterial::Store(m)) if Arc::ptr_eq(m, &material))
            || review(
                &prepared.projection.context,
                &input.operation_id,
                &input.owner_generation,
                entry.scope().review.status_revision,
            )? != entry.scope().review
        {
            return Err(refused());
        }
        // The agent token never substitutes the real native material consent or
        // the borrowed Execute budget. Common Start rematches before take/GO.
        match &prepared.projection.context {
            Context::LocalStoreExecute(c) if budget.is_some() => {
                let native = execute_wire::start(&serde_json::json!({
                    "operationId":input.operation_id,"ownerGeneration":input.owner_generation,"consentVersion":c.consent()
                }))?;
                if !material.accepts_execute_consent(&native) {
                    return Err(refused());
                }
            }
            Context::LocalStoreReconcile(c) if budget.is_none() => {
                let _native = reconcile_wire::start(&serde_json::json!({
                    "operationId":input.operation_id,"ownerGeneration":input.owner_generation,"consentVersion":c.consent()
                }))?;
                if !material.reconcile_accepts_consent(c.consent()) {
                    return Err(refused());
                }
            }
            _ => return Err(refused()),
        }
        drop(r);
        let admitted = self.start_bound_requests_store(
            input,
            entry.submitted_at(),
            registered,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(material)),
            budget,
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(AgentStoreAdmitted {
            release: admitted.release,
        })
    }
}

pub(super) fn report(t: &Terminal, r: &p::Review) -> Result<p::Report, BridgeError> {
    let release = r.release.as_ref().ok_or_else(refused)?;
    let bytes = match (t, r.kind) {
        (Terminal::LocalStoreExecute(t), p::Kind::Execute) => crate::edit_protocol::bounded(
            t.result.as_ref().ok_or_else(refused)?,
            execute_wire::RESPONSE_LIMIT,
        )?,
        (Terminal::LocalStoreReconcile(t), p::Kind::Reconcile) => crate::edit_protocol::bounded(
            t.result.as_ref().ok_or_else(refused)?,
            reconcile_wire::RESPONSE_LIMIT,
        )?,
        _ => return Err(refused()),
    };
    // Already validated by the original decoder, and called only after its
    // positive native retirement. Never copy the full receipt to service DATA.
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let key = match r.kind {
        p::Kind::Execute => "executionReceipt",
        p::Kind::Reconcile if release.mode == Mode::ExternalReadiness => "readinessReceipt",
        p::Kind::Reconcile => "reconciliationReceipt",
        _ => return Err(refused()),
    };
    let receipt = &v[key];
    let later = matches!(release.mode, Mode::ExternalTesting | Mode::ProductionSubmit);
    let readiness = release.mode == Mode::ExternalReadiness;
    let basis = if later {
        serde_json::json!({"operationId":receipt["predecessorOperationId"],"receiptSha256":receipt["predecessorReceiptSha256"]})
    } else if readiness {
        serde_json::json!({"operationId":receipt["operationId"],"receiptSha256":receipt["executionReceiptSha256"]})
    } else {
        serde_json::Value::Null
    };
    let projected = serde_json::json!({
        "mode":release.mode,"headSequence":v["headSequence"],"operationId":receipt["operationId"],
        "candidateOperationId":if later || readiness { &receipt["candidateOperationId"] } else { &receipt["operationId"] },
        "candidateSha256":receipt["candidateSha256"],"intentSha256":receipt["intentSha256"],
        "receiptSha256":receipt["receiptSha256"],"basis":basis,
        "target":release.mode.target(r.platform),"result":receipt["result"],
        "state":receipt.get("state").unwrap_or(&serde_json::Value::Null),
        "limitations":release.mode.limitations(),
    });
    let bounded = crate::edit_protocol::bounded(&projected, p::STATUS_LIMIT)?;
    let value: p::release::Receipt = serde_json::from_slice(&bounded).map_err(|_| refused())?;
    if !value.valid_for(r) {
        return Err(refused());
    }
    Ok(match r.kind {
        p::Kind::Execute => p::Report::Execute { release: value },
        p::Kind::Reconcile => p::Report::Reconcile { release: value },
        _ => return Err(refused()),
    })
}
