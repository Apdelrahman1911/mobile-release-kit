//! One finite account-recovery observation: genuine Inspect then exact Recover.
//! Only comparison/DOM DATA lives here. The existing native/core owner retains
//! both original operations, all custody, one-use admission and final joins.
use super::{Case, Command, Snapshot, Step, wire};
use crate::error::BridgeError;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Leg {
    context: Option<wire::Context>, prepared: Option<wire::Projection>, status: Option<wire::Status>,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, acknowledged: bool,
    start_requested: bool, start_returned: bool, original: Option<Snapshot>, final_visible: bool,
}
#[derive(Clone, Default)]
pub(super) struct Record {
    // These never rotate/reset. The second leg is unavailable until the first
    // actual final original and exact pending-session UI are both observed.
    legs: [Leg; 2], latest: Option<wire::Status>, status_requested: u16, status_returned: u16,
}
fn index(context: &wire::Context) -> Option<usize> {
    if !super::context_matches(Case::RecoveryPending, &context.project_id, context, None) { return None; }
    match context.recovery.as_ref()?.action {
        wire::RecoveryAction::Inspect => Some(0), wire::RecoveryAction::Account => Some(1), _ => None,
    }
}
fn step_index(step: Step) -> Option<usize> {
    match step {
        Step::Navigate | Step::Prepare | Step::Review | Step::Acknowledge | Step::Acknowledged
            | Step::Start | Step::Running | Step::Final => Some(0),
        Step::AccountPrepare | Step::AccountReview | Step::AccountAcknowledge | Step::AccountAcknowledged
            | Step::AccountStart | Step::AccountRunning | Step::AccountFinal => Some(1), _ => None,
    }
}
pub(super) fn terminal_for(snapshot: &Snapshot) -> bool {
    let t = &snapshot.terminal;
    if index(&t.context).is_none() || !t.settled() || t.outcome != wire::Outcome::Complete
        || t.reason != wire::Reason::None || t.disposition.is_some() || t.result.is_some()
        || t.activity.archive_activity().is_some() || t.activity.stage != wire::Stage::DisposingWork
        || t.lifetime.stop_observed != wire::CoreStop::None || t.lifetime.profile_calls != 0
        || t.lifetime.commands > wire::RECOVERY_COMMAND_LIMIT { return false; }
    let Some(report) = &t.report else { return false; };
    let Some(account) = &report.account else { return false; };
    let Some(token) = &account.session else { return false; };
    if !crate::edit_protocol::token(token) { return false; }
    match index(&t.context) {
        Some(0) => account.status == wire::RecoveryState::Pending && account.next == wire::RecoveryNext::Ordinary
            && t.lifetime.commands == 0 && t.lifetime.command_dispatched == Some(false)
            && report.project.as_ref().is_some_and(|row| row.status == wire::RecoveryState::Idle
                && row.session.is_none() && row.next == wire::RecoveryNext::None),
        Some(1) => account.status == wire::RecoveryState::Recovered && account.next == wire::RecoveryNext::None
            && t.context.recovery.as_ref().is_some_and(|r| r.session.as_ref() == Some(token))
            && report.project.is_none() && t.lifetime.commands > 0 && t.lifetime.command_dispatched == Some(true),
        _ => false,
    }
}
impl Record {
    fn inspected_session(&self) -> Option<&str> {
        let first = &self.legs[0];
        if !first.final_visible { return None; }
        let original = first.original.as_ref()?;
        (original.facts.final_for(Case::RecoveryPending) && terminal_for(original))
            .then_some(original.terminal.report.as_ref()?.account.as_ref()?.session.as_deref()?)
    }
    pub(super) fn start_returned_for(&self, status: &wire::Status) -> bool {
        status.operation.as_ref().and_then(|op| index(&op.context).map(|i| (&self.legs[i], op)))
            .is_some_and(|(leg, op)| leg.start_returned && leg.prepared.as_ref().is_some_and(|p|
                p.operation_id == op.operation_id && p.owner_generation == op.owner_generation))
    }
    pub(super) fn request(&mut self, step: Step, command: Command, value: &Value, project: Option<&str>) -> bool {
        if command == Command::Status {
            if wire::status_request(value).is_err() || self.status_requested >= 128 { return false; }
            self.status_requested += 1; return true;
        }
        let Some(i) = step_index(step) else { return false; };
        match command {
            Command::Prepare => {
                if !matches!(step, Step::Prepare | Step::Review | Step::AccountPrepare | Step::AccountReview)
                    || self.legs[i].prepare_requested { return false; }
                let Ok(input) = wire::prepare(value) else { return false; };
                let context = input.context();
                if index(&context) != Some(i) || !project.is_some_and(|p| p == context.project_id) { return false; }
                if i == 1 && !context.recovery.as_ref().is_some_and(|r|
                    self.inspected_session().is_some() && r.session.as_deref() == self.inspected_session()) { return false; }
                self.legs[i].context = Some(context); self.legs[i].prepare_requested = true; true
            },
            Command::Start => {
                let leg = &mut self.legs[i];
                if !matches!(step, Step::Start | Step::Running | Step::AccountStart | Step::AccountRunning)
                    || !leg.prepare_returned || !leg.review_visible || !leg.acknowledged || leg.start_requested { return false; }
                let (Ok(input), Some(prepared)) = (wire::start(value), leg.prepared.as_ref()) else { return false; };
                if input.operation_id != prepared.operation_id || input.owner_generation != prepared.owner_generation
                    || !input.consent_matches(&prepared.context) { return false; }
                leg.start_requested = true; true
            },
            Command::Cancel | Command::Status => false,
        }
    }
    pub(super) fn status(&mut self, status: &wire::Status) -> bool {
        if wire::status_bytes(status).is_err() { return false; }
        if let Some(previous) = &self.latest {
            // An older original reply never replaces the current projection,
            // grants the second operation or resets either leg's history.
            if status.status_revision < previous.status_revision { return true; }
            if status.status_revision == previous.status_revision && status.operation != previous.operation { return false; }
        }
        if let Some(op) = &status.operation {
            let Some(i) = index(&op.context) else { return false; };
            if self.legs[i].context.as_ref() != Some(&op.context) || op.phase == wire::Phase::Unknown { return false; }
            if i == 0 && self.legs[1].prepared.is_some() { return false; }
            if let Some(original) = &self.legs[i].prepared {
                if original.operation_id != op.operation_id || original.owner_generation != op.owner_generation { return false; }
            } else {
                if !self.legs[i].prepare_requested || op.phase != wire::Phase::AwaitingConsent || !op.intent_usable { return false; }
                if i == 1 && self.legs[0].prepared.as_ref().is_none_or(|first|
                    first.operation_id == op.operation_id || first.owner_generation == op.owner_generation) { return false; }
                self.legs[i].prepared = Some(op.clone());
            }
            self.legs[i].status = Some(status.clone());
        } else if self.legs.iter().any(|leg| leg.prepared.is_some()) { return false; }
        self.latest = Some(status.clone()); true
    }
    pub(super) fn result(&mut self, command: Command, result: &Result<wire::Status, BridgeError>) -> bool {
        let Ok(status) = result else { return false; };
        if command == Command::Status {
            if self.status_returned >= self.status_requested || !self.status(status) { return false; }
            self.status_returned += 1; return true;
        }
        let Some(op) = status.operation.as_ref() else { return false; };
        let Some(i) = index(&op.context) else { return false; };
        let leg = &self.legs[i];
        let valid = match command {
            Command::Prepare => leg.prepare_requested && !leg.prepare_returned
                && op.phase == wire::Phase::AwaitingConsent && op.intent_usable,
            Command::Start => leg.start_requested && !leg.start_returned,
            _ => false,
        };
        if !valid || !self.status(status) || !self.legs[i].prepared.as_ref().is_some_and(|p|
            p.operation_id == op.operation_id && p.owner_generation == op.owner_generation) { return false; }
        match command { Command::Prepare => self.legs[i].prepare_returned = true,
            Command::Start => self.legs[i].start_returned = true, _ => return false }
        true
    }
    pub(super) fn original(&mut self, snapshot: Snapshot) -> bool {
        let Some(i) = index(&snapshot.terminal.context) else { return false; };
        if i == 1 && snapshot.terminal.context.recovery.as_ref().and_then(|r| r.session.as_deref()) != self.inspected_session() { return false; }
        let leg = &mut self.legs[i];
        let Some(op) = leg.status.as_ref().and_then(|s| s.operation.as_ref()) else { return false; };
        if !leg.start_requested || !leg.start_returned || op.phase != wire::Phase::Terminal
            || !snapshot.facts.final_for(Case::RecoveryPending) || !terminal_for(&snapshot)
            || snapshot.facts.operation_id != op.operation_id || snapshot.facts.owner_generation != op.owner_generation
            || snapshot.terminal.context != op.context || op.report != snapshot.terminal.report
            || op.outcome != Some(snapshot.terminal.outcome) || op.reason != snapshot.terminal.reason
            || op.activity.as_ref() != Some(&snapshot.terminal.activity)
            || op.disposition != snapshot.terminal.disposition || op.result != snapshot.terminal.result { return false; }
        if let Some(original) = &leg.original { return original == &snapshot; }
        leg.original = Some(snapshot); true
    }
    pub(super) fn advance(&self, step: Step) -> Option<Step> {
        let i = step_index(step)?;
        if i == 1 && self.inspected_session().is_none() { return None; }
        match step {
            Step::Review | Step::AccountReview if !self.legs[i].prepare_returned => None,
            Step::Running | Step::AccountRunning => self.legs[i].original.as_ref()
                .map(|_| if i == 0 { Step::Final } else { Step::AccountFinal }),
            _ => Some(step),
        }
    }
    pub(super) fn dom(&mut self, step: Step, value: &Value) -> Result<Option<Step>, ()> {
        let i = step_index(step).ok_or(())?;
        if i == 1 && self.inspected_session().is_none() { return Err(()); }
        let ready = value == &json!({"state":"ready"});
        let next = match step {
            Step::Navigate if ready => Step::Prepare,
            Step::Prepare if ready => Step::Review,
            Step::AccountPrepare if ready => Step::AccountReview,
            Step::Review | Step::AccountReview => {
                let mut expected = json!({"state":"ready","checked":false,"startAvailable":false,"identityVisible":true});
                if i == 1 { expected["session"] = json!(self.inspected_session().ok_or(())?); }
                let leg = &mut self.legs[i];
                if !leg.prepare_returned || leg.prepared.is_none() || leg.review_visible || *value != expected { return Err(()); }
                leg.review_visible = true;
                if i == 0 { Step::Acknowledge } else { Step::AccountAcknowledge }
            },
            Step::Acknowledge if ready => Step::Acknowledged,
            Step::AccountAcknowledge if ready => Step::AccountAcknowledged,
            Step::Acknowledged | Step::AccountAcknowledged => {
                let leg = &mut self.legs[i];
                if !leg.review_visible || leg.acknowledged || *value != json!({"state":"ready","checked":true,"startAvailable":true}) { return Err(()); }
                leg.acknowledged = true; if i == 0 { Step::Start } else { Step::AccountStart }
            },
            Step::Start if ready => Step::Running,
            Step::AccountStart if ready => Step::AccountRunning,
            Step::Final | Step::AccountFinal => {
                let leg = &self.legs[i];
                let original = leg.original.as_ref().ok_or(())?;
                if leg.final_visible || !terminal_for(original) { return Err(()); }
                let token = original.terminal.report.as_ref().ok_or(())?.account.as_ref().ok_or(())?.session.as_ref().ok_or(())?;
                let expected = if i == 0 { json!({"state":"ready","phase":"terminal",
                    "outcome":["Operation outcome: complete. A complete inspection can still find pending state; it is not completed recovery."],
                    "rows":[{"heading":"Account signing state · pending","session":token,"recoveryButton":"Review ordinary account recovery","recoveryBlocked":false},
                        {"heading":"Project build-input state · idle","session":null,"recoveryButton":"Review ordinary project recovery","recoveryBlocked":true}],
                    "artifactResultPresent":false}) } else { json!({"state":"ready","phase":"terminal",
                    "outcome":["Operation outcome: complete."],
                    "rows":[{"heading":"Account signing state · recovered","session":token,"recoveryButton":null,"recoveryBlocked":null}],
                    "artifactResultPresent":false}) };
                if *value != expected { return Err(()); }
                self.legs[i].final_visible = true;
                if i == 1 { return Ok(None); }
                Step::AccountPrepare
            },
            _ => return Err(()),
        };
        Ok(Some(next))
    }
    pub(super) fn terminal(&self) -> Option<&Snapshot> {
        self.legs[1].original.as_ref().filter(|_| self.legs[1].final_visible && self.inspected_session().is_some())
    }
    pub(super) fn report(&self) -> Option<Value> {
        self.terminal()?;
        if self.status_requested != self.status_returned || self.legs.iter().any(|leg|
            !leg.prepare_requested || !leg.prepare_returned || !leg.review_visible || !leg.acknowledged
            || !leg.start_requested || !leg.start_returned || !leg.final_visible || leg.prepared.is_none()
            || !leg.original.as_ref().is_some_and(|s| s.facts.final_for(Case::RecoveryPending) && terminal_for(s))) { return None; }
        Some(json!({"protocol":wire::RECOVERY_PROTOCOL,"scope":"native-account-recovery-original-pair-v1",
            "case":"ios-recovery-pending","prepared":[self.legs[0].prepared,self.legs[1].prepared],
            "originals":[self.legs[0].original,self.legs[1].original],"requests":[1,1,1,1],"replies":[1,1,1,1],
            "statusCallsReturned":self.status_returned,"freshUncheckedReviews":true,"explicitAcknowledgements":true,
            "exactInspectedSession":true,"bothFinalResultsVisible":true,"projectRecoveryRequested":false,
            "archiveOrExportRequested":false,"workMs":120000,"cleanupMs":240000,"hardMs":250000,
            "observationMs":515000,"outerInvocationMs":525000,"shippingBinaryQualified":false}))
    }
}
pub(super) fn script(step: Step) -> Option<&'static str> {
    Some(match step {
        Step::AccountPrepare => r#"const r=recovery();if(!r||r.dataset.phase!=='terminal')return wait();
            const report=r.querySelector('[aria-label="Original native local recovery report"]');if(!report)return wait();
            const rows=[...report.querySelectorAll(':scope > div')];if(rows.length!==2)throw 0;
            const b=rows[0].querySelector('button');if(!b||b.disabled)return wait();
            if(text(rows[0].querySelector('h4'))!=='Account signing state · pending'||!rows[0].querySelector('code')
                ||text(b)!=='Review ordinary account recovery')throw 0;show(b);b.click();return ready();"#,
        Step::AccountReview => r#"const r=recovery();if(!r||r.dataset.phase!=='awaiting-consent')return wait();
            const review=r.querySelector('[aria-label="Confirm this exact local recovery action"]'),check=r.querySelector('[data-mrk-ios-recovery-action="acknowledge"]'),start=r.querySelector('[data-mrk-ios-recovery-action="start"]');
            if(!review||!check||!start)return wait();show(review);return {state:'ready',checked:check.checked,startAvailable:!start.disabled,
                identityVisible:text(review).includes('Recover this exact account session once?')&&text(start)==='Recover inspected account session',
                session:review.querySelector('code')?text(review.querySelector('code')):null};"#,
        Step::AccountAcknowledge => return super::recovery_script(Step::Acknowledge),
        Step::AccountAcknowledged => return super::recovery_script(Step::Acknowledged),
        Step::AccountStart => return super::recovery_script(Step::Start),
        Step::Final | Step::AccountFinal => r#"const r=recovery();if(!r||r.dataset.phase!=='terminal')return wait();
            const p=r.querySelector('.session-progress'),report=r.querySelector('[aria-label="Original native local recovery report"]');if(!p||!report)return wait();
            const rows=[...report.querySelectorAll(':scope > div')];if(rows.length<1||rows.length>2)throw 0;show(p);show(report);
            return {state:'ready',phase:r.dataset.phase,outcome:[...p.querySelectorAll(':scope > p')].filter(p=>text(p).startsWith('Operation outcome:')).map(text),
                rows:rows.map(row=>({heading:text(row.querySelector('h4')),session:row.querySelector('code')?text(row.querySelector('code')):null,
                    recoveryButton:row.querySelector('button')?text(row.querySelector('button')):null,
                    recoveryBlocked:row.querySelector('button')?row.querySelector('button').disabled:null})),artifactResultPresent:!!r.querySelector('.offline-report')};"#,
        _ => return super::recovery_script(step),
    })
}

/// Inert pair-admission regressions; never an observation or native witness.
pub(super) fn data_checks(unsigned: &Snapshot) -> bool {
    use super::{OriginalFacts, claim_observation_slot};
    use std::sync::atomic::{AtomicU8, Ordering};
    // Exercise the exact monotonic DATA transition, without a live admission.
    for case in Case::ALL {
        let claims = AtomicU8::new(0);
        if claim_observation_slot(case, &claims, 1) || claim_observation_slot(case, &claims, 2)
            || claims.load(Ordering::SeqCst) != 0 { return false; }
        if claim_observation_slot(case, &claims, 0) != case.operation().is_some() { return false; }
        if case.operation().is_some() {
            if claim_observation_slot(case, &claims, 0)
                || claim_observation_slot(case, &claims, 1) != (case == Case::RecoveryPending)
                || claims.load(Ordering::SeqCst) != if case == Case::RecoveryPending { 3 } else { 1 }
                || claim_observation_slot(case, &claims, 1) || claim_observation_slot(case, &claims, 0) { return false; }
        }
    }
    let inspect = json!({"projectId":"inert-account-parser","recovery":{"action":"inspect"}});
    let recover = json!({"projectId":"inert-account-parser","recovery":{"action":"account","session":"e".repeat(32)}});
    let mut pair = Record::default();
    if pair.request(Step::AccountPrepare, Command::Prepare, &recover, Some("inert-account-parser"))
        || pair.request(Step::Start, Command::Start, &json!({}), Some("inert-account-parser"))
        || pair.advance(Step::AccountPrepare).is_some() || pair.terminal().is_some() || pair.report().is_some() { return false; }
    let mut first_terminal = None;
    for i in 0..2 {
        let (prepare, review, checked, start_step, running, final_step) = if i == 0 {
            (Step::Prepare, Step::Review, Step::Acknowledged, Step::Start, Step::Running, Step::Final)
        } else { (Step::AccountPrepare, Step::AccountReview, Step::AccountAcknowledged, Step::AccountStart, Step::AccountRunning, Step::AccountFinal) };
        let input = if i == 0 { &inspect } else { &recover };
        if !pair.request(prepare, Command::Prepare, input, Some("inert-account-parser"))
            || pair.request(prepare, Command::Prepare, input, Some("inert-account-parser")) { return false; }
        let context = pair.legs[i].context.as_ref().unwrap().clone();
        let operation = (if i == 0 { "a" } else { "c" }).repeat(32);
        let generation = (if i == 0 { "b" } else { "d" }).repeat(32);
        let projection = wire::Projection { operation_id:operation.clone(), owner_generation:generation.clone(), context:context.clone(),
            phase:wire::Phase::AwaitingConsent, intent_usable:true, outcome:None, reason:wire::Reason::None,
            stage:None, activity:None, disposition:None, result:None, report:None };
        let mut status = wire::Status { schema_version:1,status_revision:1+i as u32*3,availability:wire::Availability::Busy,operation:Some(projection) };
        if i == 1 {
            let mut reused = status.clone(); reused.operation.as_mut().unwrap().operation_id = "a".repeat(32);
            if pair.clone().result(Command::Prepare, &Ok(reused)) { return false; }
        }
        if !pair.result(Command::Prepare, &Ok(status.clone())) || pair.result(Command::Prepare, &Ok(status.clone())) { return false; }
        let mut review_data = json!({"state":"ready","checked":false,"startAvailable":false,"identityVisible":true});
        if i == 1 { review_data["session"] = json!("e".repeat(32)); }
        let mut prechecked = review_data.clone(); prechecked["checked"] = json!(true);
        if pair.dom(review, &prechecked).is_ok() || pair.dom(review, &review_data).is_err() { return false; }
        let mut start = json!({"operationId":operation,"ownerGeneration":generation,"consentVersion":wire::RECOVERY_CONSENT});
        if i == 1 { start["confirmation"] = json!(wire::ACCOUNT_CONFIRMATION); }
        if pair.request(start_step, Command::Start, &start, Some("inert-account-parser"))
            || pair.dom(checked, &json!({"state":"ready","checked":true,"startAvailable":true})).is_err()
            || !pair.request(start_step, Command::Start, &start, Some("inert-account-parser"))
            || pair.request(start_step, Command::Start, &start, Some("inert-account-parser")) { return false; }
        let mut life = serde_json::to_value(&unsigned.terminal.lifetime).unwrap();
        for key in ["signingClosed", "buildInputsClosed", "materialRetired"] { life[key] = json!(true); }
        life["commands"] = json!(if i == 0 { 0 } else { 17 }); life["commandDispatched"] = json!(i == 1);
        let value = json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
            "activity":{"stage":"disposing-work"},"lifetime":life,"report":{"schemaVersion":1,"scope":"local-ios-recovery",
                "account":{"status":if i == 0 { "pending" } else { "recovered" },"session":"e".repeat(32),"next":if i == 0 { "ordinary" } else { "none" }},
                "project":if i == 0 { json!({"status":"idle","session":null,"next":"none"}) } else { Value::Null },"limitations":wire::RECOVERY_LIMITATIONS}});
        let Ok(terminal) = wire::terminal(&value, &context, &operation) else { return false; };
        let snapshot = Snapshot { facts:OriginalFacts { operation_id:operation,owner_generation:generation,
            work_ms:120000,cleanup_ms:Some(240000),hard_ms:250000,material_loan_present:Some(false),material_loan_retired:Some(true),
            ..unsigned.facts.clone() },terminal };
        if !terminal_for(&snapshot) || pair.original(snapshot.clone()) || pair.advance(running).is_some() { return false; }
        status.status_revision += 1;
        let op = status.operation.as_mut().unwrap();
        op.phase = wire::Phase::Terminal; op.intent_usable = false; op.outcome = Some(snapshot.terminal.outcome);
        op.stage = Some(snapshot.terminal.activity.stage); op.activity = Some(snapshot.terminal.activity.clone());
        op.report = snapshot.terminal.report.clone();
        if !pair.result(Command::Start, &Ok(status.clone())) { return false; }
        for field in 0..5 {
            let mut bad = snapshot.clone();
            match field { 0 => bad.facts.observer_joined=false, 1 => bad.facts.watchdog_joined=false,
                2 => bad.facts.material_loan_retired=Some(false), 3 => bad.facts.active_retained=true,
                _ => bad.facts.resource_unknown=true }
            if pair.clone().original(bad) { return false; }
        }
        if !pair.original(snapshot.clone()) || pair.advance(running) != Some(final_step) || pair.report().is_some() { return false; }
        if i == 0 && pair.request(Step::AccountPrepare, Command::Prepare, &recover, Some("inert-account-parser")) { return false; }
        let final_dom = if i == 0 { json!({"state":"ready","phase":"terminal",
            "outcome":["Operation outcome: complete. A complete inspection can still find pending state; it is not completed recovery."],
            "rows":[{"heading":"Account signing state · pending","session":"e".repeat(32),"recoveryButton":"Review ordinary account recovery","recoveryBlocked":false},
                {"heading":"Project build-input state · idle","session":null,"recoveryButton":"Review ordinary project recovery","recoveryBlocked":true}],"artifactResultPresent":false})
        } else { json!({"state":"ready","phase":"terminal","outcome":["Operation outcome: complete."],
            "rows":[{"heading":"Account signing state · recovered","session":"e".repeat(32),"recoveryButton":null,"recoveryBlocked":null}],"artifactResultPresent":false}) };
        if pair.dom(final_step, &final_dom) != Ok(if i == 0 { Some(Step::AccountPrepare) } else { None }) { return false; }
        if i == 0 {
            let mut wrong_session = recover.clone(); wrong_session["recovery"]["session"] = json!("f".repeat(32));
            if pair.request(Step::AccountPrepare, Command::Prepare, &wrong_session, Some("inert-account-parser")) { return false; }
            first_terminal = Some(status);
        } else {
            let previous = pair.latest.clone();
            if !pair.status(first_terminal.as_ref().unwrap()) || pair.latest != previous
                || !pair.original(snapshot.clone()) { return false; }
            let mut relabelled = snapshot.clone(); relabelled.terminal.context.recovery.as_mut().unwrap().session = Some("f".repeat(32));
            if pair.clone().original(relabelled) { return false; }
            let mut renewed = first_terminal.clone().unwrap(); renewed.status_revision = 7;
            if pair.status(&renewed) { return false; }
        }
    }
    let Some(report) = pair.report() else { return false; };
    if pair.terminal().is_none() || report["shippingBinaryQualified"] != false
        || pair.request(Step::AccountPrepare, Command::Prepare, &recover, Some("inert-account-parser")) { return false; }
    let mut missing_first = pair.clone(); missing_first.legs[0].original = None;
    let mut outstanding_status = pair; outstanding_status.status_requested += 1;
    missing_first.report().is_none() && outstanding_status.report().is_none()
}
