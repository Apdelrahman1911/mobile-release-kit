//! Fixed inspection-stage DATA, never source compatibility or a close receipt.
//! The original source worker captures once, before cleanup. Only its existing
//! joined publication path may put a matching failure in Report.problems.
use super::{Problem, Reason};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InspectionStage {
    Jdk,
    Sdk,
    Gradle,
    AppSupport,
}
impl InspectionStage {
    fn problem(self) -> Problem {
        match self {
            Self::Jdk => Problem::JdkSource,
            Self::Sdk => Problem::SdkSource,
            Self::Gradle => Problem::GradleSource,
            Self::AppSupport => Problem::AppSupportSource,
        }
    }
}

#[derive(Default)]
pub(crate) struct InspectionDiagnostic {
    stage: Option<InspectionStage>,
    captured: bool,
    failure: Option<(InspectionStage, Reason, Instant)>,
}
impl InspectionDiagnostic {
    pub(crate) fn enter(&mut self, stage: Option<InspectionStage>) {
        if !self.captured {
            self.stage = stage;
        }
    }
    // None is deliberately captured too: an unattributed failure or successful
    // source pass must not acquire a misleading label from later cleanup.
    pub(crate) fn capture(&mut self, first: Option<(Reason, Instant)>) {
        if !self.captured {
            self.captured = true;
            self.failure = self
                .stage
                .zip(first)
                .map(|(stage, (reason, at))| (stage, reason, at));
        }
    }
    pub(crate) fn problem(&self, original_first: Option<(Reason, Instant)>) -> Option<Problem> {
        let (stage, reason, at) = self.failure?;
        (reason == Reason::SourceRefused && original_first == Some((reason, at)))
            .then(|| stage.problem())
    }
}

impl Problem {
    pub(crate) fn is_source_inspection(self) -> bool {
        matches!(
            self,
            Self::JdkSource | Self::SdkSource | Self::GradleSource | Self::AppSupportSource
        )
    }
}

#[cfg(test)]
mod tests {
    // Clock/enum fixtures only. No native source, close, or permission is minted.
    use super::*;
    use std::time::Duration;

    #[test]
    fn first_inspection_stage_survives_later_stage_and_cleanup_failure() {
        let at = Instant::now();
        let mut diagnostic = InspectionDiagnostic::default();
        diagnostic.enter(Some(InspectionStage::Sdk));
        diagnostic.capture(Some((Reason::SourceRefused, at)));
        diagnostic.enter(Some(InspectionStage::AppSupport));
        diagnostic.capture(Some((Reason::CleanupUnknown, at + Duration::from_secs(1))));
        assert_eq!(
            diagnostic.problem(Some((Reason::SourceRefused, at))),
            Some(Problem::SdkSource)
        );
        // The caller must still supply its unchanged actual first failure.
        assert_eq!(
            diagnostic.problem(Some((Reason::SourceRefused, at + Duration::from_nanos(1)))),
            None
        );
        assert_eq!(diagnostic.problem(Some((Reason::CleanupUnknown, at))), None);
        assert_eq!(diagnostic.problem(None), None);
    }

    #[test]
    fn stopped_changed_unknown_and_unattributed_passes_never_suggest_a_source_fix() {
        let at = Instant::now();
        for reason in [
            Reason::Cancelled,
            Reason::TimedOut,
            Reason::ContextChanged,
            Reason::SourceChanged,
            Reason::CleanupUnknown,
            Reason::InputLimit,
        ] {
            let mut diagnostic = InspectionDiagnostic::default();
            diagnostic.enter(Some(InspectionStage::Jdk));
            diagnostic.capture(Some((reason, at)));
            assert_eq!(diagnostic.problem(Some((reason, at))), None);
            assert_eq!(diagnostic.problem(Some((Reason::SourceRefused, at))), None);
        }
        for stage in [None, Some(InspectionStage::Jdk)] {
            let mut diagnostic = InspectionDiagnostic::default();
            diagnostic.enter(stage);
            diagnostic.capture(None);
            diagnostic.enter(Some(InspectionStage::Gradle));
            diagnostic.capture(Some((Reason::SourceRefused, at)));
            assert_eq!(diagnostic.problem(Some((Reason::SourceRefused, at))), None);
        }
        let mut diagnostic = InspectionDiagnostic::default();
        diagnostic.capture(Some((Reason::SourceRefused, at)));
        diagnostic.enter(Some(InspectionStage::Gradle));
        assert_eq!(diagnostic.problem(Some((Reason::SourceRefused, at))), None);
    }

    #[test]
    fn only_the_four_closed_source_stages_extend_existing_problems() {
        let at = Instant::now();
        for (stage, name) in [
            (InspectionStage::Jdk, "jdk-source"),
            (InspectionStage::Sdk, "sdk-source"),
            (InspectionStage::Gradle, "gradle-source"),
            (InspectionStage::AppSupport, "app-support-source"),
        ] {
            let mut diagnostic = InspectionDiagnostic::default();
            diagnostic.enter(Some(stage));
            diagnostic.capture(Some((Reason::SourceRefused, at)));
            let problem = diagnostic
                .problem(Some((Reason::SourceRefused, at)))
                .unwrap();
            assert!(problem.is_source_inspection());
            assert_eq!(serde_json::to_value(problem).unwrap(), name);
        }
        for problem in [
            Problem::Inventory,
            Problem::Unknown,
            Problem::Stopped,
            Problem::Native,
            Problem::Ownership,
            Problem::SupplierUnavailable,
            Problem::Bounds,
        ] {
            assert!(!problem.is_source_inspection());
        }
    }
}
