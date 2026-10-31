//! Bounded observer scheduling DATA, never a native receipt or a new clock.
//! The caller supplies the same original step under its existing Record lock.
use super::Step;
use std::time::Instant;

pub(crate) const LABELS: [&str; 14] = [
    "read-before", "read-wait-before", "allow", "submitted", "prepared",
    "started", "terminal", "checked", "read-after", "read-wait-after",
    "revoke", "denied", "done", "finish",
];
const LIMIT_MICROS: u32 = 600_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) prior_step_elapsed_micros: [Option<u32>; 14],
    pub(crate) current: usize,
    pub(crate) current_elapsed_micros: u32,
}

#[derive(Default)]
pub(in super::super) struct Timing {
    entered: Option<(usize, Instant)>,
    prior: [Option<u32>; 14],
    invalid: bool,
}

fn slot(step: Step, read_count: u8) -> Option<usize> {
    match step {
        Step::Read | Step::ReadWait if read_count > 1 => return None,
        Step::Allow | Step::Submitted | Step::Prepared | Step::Started | Step::Terminal | Step::Checked
            if read_count != 1 => return None,
        Step::Revoke | Step::Denied | Step::Done | Step::Finish if read_count != 2 => return None,
        _ => {}
    }
    Some(match step {
        Step::Read => match read_count { 0 => 0, 1 => 8, _ => return None },
        Step::ReadWait => match read_count { 0 => 1, 1 => 9, _ => return None },
        Step::Allow => 2,
        Step::Submitted => 3,
        Step::Prepared => 4,
        Step::Started => 5,
        Step::Terminal => 6,
        Step::Checked => 7,
        Step::Revoke => 10,
        Step::Denied => 11,
        Step::Done => 12,
        Step::Finish => 13,
    })
}

fn elapsed(before: Instant, at: Instant) -> Option<u32> {
    let micros = u32::try_from(at.checked_duration_since(before)?.as_micros()).ok()?;
    (micros <= LIMIT_MICROS).then_some(micros)
}

impl Timing {
    pub(in super::super) fn observe(&mut self, step: Step, read_count: u8, at: Instant) {
        if self.invalid { return; }
        let Some(next) = slot(step, read_count) else { self.invalid = true; return; };
        let Some((previous, before)) = self.entered else {
            // Missing first-entry DATA must stay absent, never become history.
            if next != 0 { self.invalid = true; return; }
            self.entered = Some((next, at));
            return;
        };
        let Some(micros) = elapsed(before, at) else { self.invalid = true; return; };
        if previous == next { return; }
        if self.prior[next].is_some() || next <= previous {
            self.invalid = true;
            return;
        }
        self.prior[previous] = Some(micros);
        self.entered = Some((next, at));
    }

    pub(in super::super) fn snapshot(&self, step: Step, read_count: u8, at: Instant) -> Option<Facts> {
        if self.invalid { return None; }
        let (current, before) = self.entered?;
        if slot(step, read_count)? != current { return None; }
        Some(Facts { prior_step_elapsed_micros: self.prior, current,
            current_elapsed_micros: elapsed(before, at)? })
    }
}

pub(in super::super) fn contract_data() -> bool {
    use std::time::Duration;
    // Synthetic Instants, closed steps and this same body only. No application,
    // source, owner, FD, timer allowance or success receipt is constructed.
    let start = Instant::now();
    let at = |micros| start.checked_add(Duration::from_micros(micros));
    let mut data = Timing::default();
    if data.snapshot(Step::Read, 0, start).is_some() { return false; }
    data.observe(Step::Read, 0, start);
    let Some(t2) = at(2) else { return false; };
    data.observe(Step::Read, 0, t2);
    let Some(t5) = at(5) else { return false; };
    data.observe(Step::ReadWait, 0, t5);
    let Some(t15) = at(15) else { return false; };
    data.observe(Step::Allow, 1, t15);
    let Some(t20) = at(20) else { return false; };
    let Some(sample) = data.snapshot(Step::Allow, 1, t20) else { return false; };
    if sample.current != 2 || sample.current_elapsed_micros != 5
        || sample.prior_step_elapsed_micros[0] != Some(5)
        || sample.prior_step_elapsed_micros[1] != Some(10)
        || sample.prior_step_elapsed_micros[2..].iter().any(Option::is_some)
        || data.snapshot(Step::Prepared, 1, t20).is_some()
        || data.snapshot(Step::ReadWait, 1, t20).is_some()
        || data.snapshot(Step::Allow, 0, t20).is_some()
        || data.snapshot(Step::Allow, 2, t20).is_some() { return false; }
    // The second read has its own source-held ordinal; it cannot overwrite one.
    data.observe(Step::Terminal, 1, t20);
    let Some(t30) = at(30) else { return false; };
    data.observe(Step::Read, 1, t30);
    let Some(sample) = data.snapshot(Step::Read, 1, t30) else { return false; };
    if sample.current != 8 || sample.prior_step_elapsed_micros[0] != Some(5)
        || sample.prior_step_elapsed_micros[6] != Some(10) { return false; }
    data.observe(Step::Read, 0, t30);
    if data.snapshot(Step::Read, 0, t30).is_some() { return false; }
    for (step, count) in [(Step::Allow, 0), (Step::Read, 2), (Step::Read, 3)] {
        let mut missing = Timing::default();
        missing.observe(step, count, start);
        if missing.snapshot(step, count, start).is_some() { return false; }
    }
    let mut backward = Timing::default();
    backward.observe(Step::Read, 0, t5);
    backward.observe(Step::ReadWait, 0, start);
    if backward.snapshot(Step::ReadWait, 0, t20).is_some() { return false; }
    let mut bounded = Timing::default();
    bounded.observe(Step::Read, 0, start);
    let Some(limit) = at(u64::from(LIMIT_MICROS)) else { return false; };
    if bounded.snapshot(Step::Read, 0, limit).is_none() { return false; }
    let Some(late) = at(u64::from(LIMIT_MICROS) + 1) else { return false; };
    if bounded.snapshot(Step::Read, 0, late).is_some() { return false; }
    bounded.observe(Step::ReadWait, 0, late);
    bounded.snapshot(Step::ReadWait, 0, late).is_none()
}
