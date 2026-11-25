//! Two fixed foreground RAW handoffs into the original async Enrollment owner.
//! The same Book Claim stays live through the real original call; a compact
//! status, lost invoke or an Err cannot invent a native nonentry/return.
use super::*;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewInput {
    project_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_enrollment_raw_handoffs_keep_original_ids_and_no_private_authority() {
        let origin = serde_json::json!({"projectId":"1".repeat(32),
            "serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
        let review = serde_json::json!({"origin":origin,"input":{"projectId":"project-1"}});
        let connect = serde_json::json!({"origin":origin,"input":{"projectId":"project-1","reviewId":"a".repeat(32)}});
        let r: ReviewArgs = decode(&serde_json::to_vec(&review).unwrap()).unwrap();
        let c: ConnectArgs = decode(&serde_json::to_vec(&connect).unwrap()).unwrap();
        assert_eq!(r.origin, c.origin);
        assert_eq!(r.input.project_id, c.input.project_id);
        assert!(p::hex(&c.input.review_id, 32));
        assert!(decode::<ReviewArgs>(&serde_json::to_vec(&connect).unwrap()).is_err());
        assert!(decode::<ConnectArgs>(&serde_json::to_vec(&review).unwrap()).is_err());
        for key in [
            "token",
            "authority",
            "ledger",
            "root",
            "repositoryId",
            "state",
        ] {
            let mut bad = connect.clone();
            bad["input"][key] = serde_json::json!("not-authority");
            assert!(decode::<ConnectArgs>(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for key in ["origin", "input"] {
            let mut bad = connect.clone();
            bad[key] = serde_json::Value::Null;
            assert!(decode::<ConnectArgs>(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let raw = serde_json::to_string(&connect).unwrap();
        let duplicate = raw.replace(
            "\"projectId\":\"project-1\"",
            "\"projectId\":\"project-1\",\"projectId\":\"project-2\"",
        );
        assert_ne!(duplicate, raw);
        assert!(decode::<ConnectArgs>(duplicate.as_bytes()).is_err());
        let mut boundary = serde_json::to_vec(&review).unwrap();
        boundary.resize(p::RAW_LIMIT, b' ');
        assert!(decode::<ReviewArgs>(&boundary).is_ok());
        boundary.push(b' ');
        assert!(decode::<ReviewArgs>(&boundary).is_err());
        // Ordinary original four calls retain their previous exact grammar.
        let old = crate::version_enrollment_protocol::decode_command;
        for (name, value) in [
            ("version_enrollment_status", serde_json::json!({})),
            ("version_enrollment_review", review["input"].clone()),
            ("version_enrollment_confirm", connect["input"].clone()),
            (
                "version_enrollment_cancel",
                serde_json::json!({"operationId":"a".repeat(32)}),
            ),
        ] {
            assert!(old(name, &serde_json::to_vec(&value).unwrap()).is_ok());
        }
        assert!(old(
            "version_enrollment_confirm",
            &serde_json::to_vec(&connect).unwrap()
        )
        .is_err());
        for kind in [
            p::Kind::CounterEnrollmentReview,
            p::Kind::CounterEnrollmentConnect,
        ] {
            let mut selection = serde_json::json!({"kind":kind,"sessionId":"session-a",
                "expectedRevision":4,"expectedConnectionRevision":9});
            if kind == p::Kind::CounterEnrollmentConnect {
                selection["reviewId"] = serde_json::json!("a".repeat(32));
            }
            let raw = serde_json::to_vec(&serde_json::json!({"selection":selection,
                "consentVersion":kind.consent(),"expectedPermissionRevision":"0"}))
            .unwrap();
            let mut allow: Allow = decode(&raw).unwrap();
            assert!(allow.selection.valid() && allow.selection.retained_fits());
            assert_eq!(allow.selection.limit(), p::RAW_LIMIT);
            match &mut allow.selection {
                native::dispatch::Selection::CounterEnrollmentReview(v) => {
                    v.session_id.reserve_exact(129)
                }
                native::dispatch::Selection::CounterEnrollmentConnect(v) => {
                    v.review_id.reserve_exact(65)
                }
                _ => unreachable!(),
            }
            assert!(!allow.selection.valid()); // actual capacity, never a normalized clone
        }
    }
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectInput {
    project_id: String,
    review_id: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewArgs {
    origin: p::Query,
    input: ReviewInput,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectArgs {
    origin: p::Query,
    input: ConnectInput,
}

impl DocumentBinding {
    fn claim_counter_enrollment(
        &self,
        origin: &p::Query,
        project: &str,
        kind: p::Kind,
        review_id: Option<&str>,
    ) -> Result<(Arc<ApplicationService>, r::Claim), BridgeError> {
        if !crate::protocol::valid_id(project) {
            return Err(BridgeError::invalid());
        }
        let service = self
            .github_action_service()?
            .ok_or_else(|| public(Error::Unavailable))?;
        let claim = service
            .github_action_requests()
            .claim_enrollment(
                origin,
                &self.inner.session_identity,
                project,
                kind,
                review_id,
            )
            .map_err(public)?;
        Ok((service, claim))
    }

    fn counter_enrollment_caller_returned(
        &self,
        claim: r::Claim,
        result: &Result<crate::version_enrollment_protocol::Status, BridgeError>,
    ) {
        let entry = claim.entry();
        // This is the real installed Lane/Entry pointer, not Result::is_err or
        // a public phase. Keep the entered latch as a conservative fallback if
        // any impossible later replacement/lost lock obscured that identity.
        let attached = self.enrollment_entry_attached(entry) || entry.enrollment_has_attachment();
        if attached {
            if result.is_err() {
                entry.unknown(p::Reason::CleanupUnknown);
            }
            claim.returned(Ok(()));
        } else {
            let reason = if result.is_ok() {
                // A status can never explain away a missing native attachment.
                p::Reason::CleanupUnknown
            } else {
                entry.first_reason().unwrap_or(p::Reason::NativeRefused)
            };
            claim.returned(Err(reason));
        }
        // Existing relay performs its original history write/ACK OFF Doc.
        // This real caller return is not a fabricated history/native return.
    }

    pub(crate) async fn agent_version_enrollment_review(
        &self,
        args: ReviewArgs,
    ) -> Result<crate::version_enrollment_protocol::Status, BridgeError> {
        let (service, claim) = self.claim_counter_enrollment(
            &args.origin,
            &args.input.project_id,
            p::Kind::CounterEnrollmentReview,
            None,
        )?;
        let entry = claim.entry().clone();
        let result = match self.github_action_entry_current(&service, &entry) {
            Ok(()) => {
                self.review_version_enrollment_original(&args.input.project_id, Some(entry))
                    .await
            }
            Err(error) => Err(error),
        };
        self.counter_enrollment_caller_returned(claim, &result);
        result
    }

    pub(crate) async fn agent_version_enrollment_confirm(
        &self,
        args: ConnectArgs,
        app_data: &std::path::Path,
    ) -> Result<crate::version_enrollment_protocol::Status, BridgeError> {
        if !p::hex(&args.input.review_id, 32) {
            return Err(BridgeError::invalid());
        }
        let (service, claim) = self.claim_counter_enrollment(
            &args.origin,
            &args.input.project_id,
            p::Kind::CounterEnrollmentConnect,
            Some(&args.input.review_id),
        )?;
        let entry = claim.entry().clone();
        let result = match self.github_action_entry_current(&service, &entry) {
            Ok(()) => {
                self.confirm_version_enrollment_original(
                    &args.input.project_id,
                    &args.input.review_id,
                    app_data,
                    Some(entry),
                )
                .await
            }
            Err(error) => Err(error),
        };
        self.counter_enrollment_caller_returned(claim, &result);
        result
    }
}
