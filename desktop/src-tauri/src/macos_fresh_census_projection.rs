// Included inside the existing private Fresh native module, only for the
// exclusive nonshipping census control. No parsed DATA constructs an owner.
impl EnrolledAttemptObserved<'_> {
    pub(in crate::installer) fn control_audit_data(&self, book: &mut Install) -> Result<Vec<u8>> {
        self.source.post(book)?;
        let cut = match self.audit.facts.cut {
            PartialFreshCut::Intent => "intent",
            PartialFreshCut::Copying => "copying",
            PartialFreshCut::Prepared => "prepared",
            PartialFreshCut::Runtime => "runtime-published",
            PartialFreshCut::Metadata => "metadata-published",
            PartialFreshCut::App => "app-published",
            PartialFreshCut::State => "state-prefix",
            PartialFreshCut::Recorded => "recorded",
        };
        // This observer is deliberately not the ordinary installed-state
        // reader. A complete recorded attempt belongs to its separate scope.
        check(self.audit.facts.cut != PartialFreshCut::Recorded
            && self.audit.invocation == self.source.invocation()
            && self.audit.intent.action_data() == ActionData::FreshInstall
            && self.audit.intent.previous_data().is_none()
            && self.audit.intent.previous_state_data().is_none(),
            "fresh-census-frontier-purpose")?;
        let selected = self.source.new_selection(book)?;
        let value = bytes(&serde_json::json!({"schemaVersion":1,
            "kind":"mrk-fresh-frontier-observed-v1",
            "selectionSha256":hash(&selected.encode_data().map_err(|_|"fresh-census-selection")?),
            "invocation":self.audit.invocation,"requestId":self.audit.request,
            "intentSha256":self.audit.intent.digest_data(),"frontier":cut,
            "root":book.fresh_output_identity(self.source.root_original())?.fields_data(),
            "originSha256":hex(&self.origin),"enrollmentSha256":hex(&self.journal),
            "enrollmentHeadSha256":hex(&self.head),"enrollmentEntries":self.entries,
            "physicalCommitmentSha256":hex(&self.audit.facts.digest),
            "payloadBytes":self.audit.facts.payload_bytes,"controlBytes":self.audit.facts.control_bytes,
            "files":self.audit.facts.files,"directories":self.audit.facts.directories,
            "oldOriginalReturnReconstructed":false,"preservationPerformed":false}))?;
        self.source.post(book)?;
        Ok(value)
    }
}

pub(in crate::installer) fn control_collect_completed(book: &mut Install,
    input: &worker::ReinstallInputRead<'_>) -> Result<Vec<u8>> {
    input.post_source(book)?;
    let root = input.root_original();
    let selected = input.new_selection(book)?;
    // This standalone reader does not inherit ordinary observe's history
    // context reservation. Debit the existing parser peak plus the retained
    // State/intent/capsule raw and typed overlap before the first read. This
    // is part of the same effective control ceiling, never a second pool.
    let retained = transaction::STATE_LIMIT.checked_add(transaction::INTENT_LIMIT)
        .and_then(|n| n.checked_add(transaction::CAPSULE_LIMIT))
        .and_then(|n| n.checked_mul(2)).ok_or("fresh-census-history-budget")?;
    let history_quote = partial_fresh_parser_peak_data()?.checked_add(retained)
        .ok_or("fresh-census-history-budget")? as u64;
    check(removal_effective_control_bytes(book)?.checked_add(history_quote)
        .is_some_and(|n| n <= installation_record::CONTROL_LIMIT as u64),
        "fresh-census-history-budget")?;
    book.removal_control_reserved = book.removal_control_reserved.checked_add(history_quote)
        .ok_or("fresh-census-history-budget")?;
    let through = book.originals.len().checked_add(8)
        .filter(|n| *n <= installation_record::ORIGINAL_LIMIT)
        .ok_or("fresh-census-state-original-budget")?;
    reserve_removal_original_storage(book,through)?;
    let body = removal_archive_scope(book,|book| {
        let (state_original,raw) = metadata_original(book,root,transaction::STATE_NAME,transaction::STATE_LIMIT)?;
        let state = StateData::parse_data(&raw,selected).map_err(|_|"fresh-census-state")?;
        check(state.action_data() == ActionData::FreshInstall && state.mutation_recorded_data()
            && state.retained_data().next().is_none() && state.evidence_data().next().is_none()
            && state.recovery_data().is_none() && state.restore_recovery_data().is_none(),
            "fresh-census-completed-purpose")?;
        let reference = state.fresh_conservation_data().cloned().ok_or("fresh-census-reference-required")?;
        // Existing reader validates the actual State/intent/capsule full
        // correspondence. The prior-history refusal above keeps this scope
        // independent of migration, noop, Restore and removal history.
        let history = read_history_original(book,root,selected,state_original,raw)?;
        check(history.originals.is_empty() && history.current.intent.action_data() == ActionData::FreshInstall
            && history.current.intent.previous_data().is_none()
            && history.current.intent.previous_state_data().is_none()
            && history.current.intent.fresh_conservation_data() == Some(&reference),
            "fresh-census-completed-correspondence")?;
        let observed = namespace(book,root,selected,Some(&reference))?
            .ok_or("fresh-census-namespace-required")?;
        let body = observed.audit_data(book,selected)?;
        held_bytes(book,state_original,&history.state_bytes)?;
        input.post_source(book)?;
        Ok(body)
    })?;
    input.post_source(book)?;
    Ok(body)
}
