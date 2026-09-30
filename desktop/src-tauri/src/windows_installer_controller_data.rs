//! Decisions shared by the real fixed acquisition controller and DATA tests.
//! No thread, native call, input read, process action or success receipt.
#![forbid(unsafe_code)]

use std::time::Duration;

pub(super) const STOP_AFTER: Duration = Duration::from_secs(570);
pub(super) const HARD_AFTER: Duration = Duration::from_secs(600);
pub(super) const GO: u8 = 1;
pub(super) const ARMED: u8 = 2;
pub(super) const STOP: u8 = 4;
pub(super) const RETIRE: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControllerFault {
    Duplicate,
    SpawnUnavailable,
    Barrier,
    StopRequested,
    SettlementDeadline,
    HardDeadline,
    Clock,
    NativeFinalityUnknown,
    WatchdogProtocol,
    WatchdogJoin,
    ControllerState,
    PublicationFailed,
    ActivationFailed,
    SelectionFailed,
}
impl ControllerFault {
    pub(super) fn code(self) -> u8 { self as u8 + 1 }
    pub(super) fn bit(self) -> u32 { 1u32 << (self as u8) }
    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Duplicate, 2 => Self::SpawnUnavailable, 3 => Self::Barrier,
            4 => Self::StopRequested, 5 => Self::SettlementDeadline, 6 => Self::HardDeadline,
            7 => Self::Clock, 8 => Self::NativeFinalityUnknown, 9 => Self::WatchdogProtocol,
            10 => Self::WatchdogJoin, 11 => Self::ControllerState,
            12 => Self::PublicationFailed, 13 => Self::ActivationFailed,
            14 => Self::SelectionFailed, _ => return None,
        })
    }
}

/// Closed copied fault DATA. The actual returned acquisition error is kept
/// separately and remains primary even when a watchdog error was seen first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerFailures {
    pub first: Option<ControllerFault>,
    mask: u32,
}
impl ControllerFailures {
    pub(super) fn observed(first_code: u8, mask: u32) -> Self {
        Self { first: ControllerFault::from_code(first_code), mask }
    }
    pub fn contains(self, fault: ControllerFault) -> bool { self.mask & fault.bit() != 0 }
    pub fn is_empty(self) -> bool { self.mask == 0 && self.first.is_none() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClockPhase { Work, Settlement, Expired }
pub(super) fn clock_phase(elapsed: Duration) -> ClockPhase {
    if elapsed >= HARD_AFTER { ClockPhase::Expired }
    else if elapsed >= STOP_AFTER { ClockPhase::Settlement }
    else { ClockPhase::Work }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchDecision { Abort, Stop, Retire, Arm, Wait }
pub(super) fn watch_decision(state: u8, elapsed: Duration) -> WatchDecision {
    // Expiry always wins, including a queued late retirement request.
    if clock_phase(elapsed) == ClockPhase::Expired { WatchDecision::Abort }
    else if clock_phase(elapsed) == ClockPhase::Settlement && state & STOP == 0 { WatchDecision::Stop }
    else if state & RETIRE != 0 { WatchDecision::Retire }
    else if state & GO != 0 && state & (ARMED | STOP) == 0 { WatchDecision::Arm }
    else { WatchDecision::Wait }
}
pub(super) fn may_begin(state: u8, elapsed: Duration) -> bool {
    state & (GO | ARMED) == (GO | ARMED) && state & (STOP | RETIRE) == 0
        && clock_phase(elapsed) == ClockPhase::Work
}
pub(super) fn may_succeed(state: u8, elapsed: Duration, acquisition_ok: bool,
    original_joined: bool, failures: ControllerFailures) -> bool {
    acquisition_ok && original_joined && failures.is_empty()
        && state & (GO | ARMED | RETIRE) == (GO | ARMED | RETIRE) && state & STOP == 0
        && clock_phase(elapsed) == ClockPhase::Work
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_watch_decisions_require_go_and_never_extend_fixed_deadlines() {
        let zero = Duration::ZERO;
        assert_eq!(watch_decision(0, zero), WatchDecision::Wait);
        assert_eq!(watch_decision(GO, zero), WatchDecision::Arm);
        assert!(!may_begin(GO, zero));
        assert!(may_begin(GO | ARMED, zero));
        assert_eq!(watch_decision(GO | ARMED | RETIRE, STOP_AFTER), WatchDecision::Stop);
        assert_eq!(watch_decision(GO | ARMED | RETIRE | STOP, STOP_AFTER), WatchDecision::Retire);
        assert_eq!(watch_decision(GO | ARMED | RETIRE | STOP, HARD_AFTER), WatchDecision::Abort);
        assert_eq!(watch_decision(RETIRE, HARD_AFTER), WatchDecision::Abort);
        assert!(!may_begin(GO | ARMED, STOP_AFTER));
        assert!(!may_begin(GO | ARMED | STOP, zero));
        assert!(!may_begin(GO | ARMED | RETIRE, zero));
    }
    #[test]
    fn success_requires_actual_return_actual_join_and_no_absorbing_failure() {
        let flags = GO | ARMED | RETIRE;
        let clean = ControllerFailures::observed(0, 0);
        assert!(may_succeed(flags, Duration::ZERO, true, true, clean));
        assert!(!may_succeed(flags, Duration::ZERO, false, true, clean));
        assert!(!may_succeed(flags, Duration::ZERO, true, false, clean));
        assert!(!may_succeed(GO | ARMED, Duration::ZERO, true, true, clean));
        assert!(!may_succeed(flags | STOP, Duration::ZERO, true, true, clean));
        assert!(!may_succeed(flags, STOP_AFTER, true, true, clean));
        assert!(!may_succeed(flags, HARD_AFTER, true, true, clean));
        let failed = ControllerFailures::observed(ControllerFault::Barrier.code(),
            ControllerFault::Barrier.bit() | ControllerFault::WatchdogJoin.bit());
        assert_eq!(failed.first, Some(ControllerFault::Barrier));
        assert!(failed.contains(ControllerFault::WatchdogJoin));
        assert!(!may_succeed(flags, Duration::ZERO, true, true, failed));
        let publication = ControllerFailures::observed(ControllerFault::PublicationFailed.code(),
            ControllerFault::PublicationFailed.bit());
        assert_eq!(publication.first, Some(ControllerFault::PublicationFailed));
        assert!(!may_succeed(flags, Duration::ZERO, true, true, publication));
        for stage in [ControllerFault::ActivationFailed, ControllerFault::SelectionFailed] {
            let failed = ControllerFailures::observed(stage.code(), stage.bit());
            assert_eq!(failed.first, Some(stage));
            assert!(!may_succeed(flags, Duration::ZERO, true, true, failed));
        }
    }
}
