//! Read-only tool preparation decisions. No IO, executable path, download,
//! consent, registration, native lease or operation-finality authority lives
//! here. The native adapter supplies existing owners' observations. Even a
//! matching protected copy remains subject to the build owner's fresh checks.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform { Android, Ios }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Host { MacArm64, MacX64, LinuxX64, Other }
impl Host { pub(crate) fn mac(self) -> bool { matches!(self, Self::MacArm64 | Self::MacX64) } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) session_id: String,
    pub(crate) observation_revision: u32, pub(crate) saved_config_sha256: String,
    pub(crate) requirements_sha256: String, pub(crate) host: Host,
}
impl Context {
    fn valid(&self) -> bool {
        label(&self.project_id) && self.project_id.len() <= 64 && !self.project_id.contains('.')
            && label(&self.session_id) && self.observation_revision > 0
            && self.observation_revision < u32::MAX && sha(&self.saved_config_sha256) && sha(&self.requirements_sha256)
    }
    fn same_source(&self, other: &Self) -> bool {
        self.project_id == other.project_id && self.session_id == other.session_id && self.host == other.host
            && self.saved_config_sha256 == other.saved_config_sha256 && self.requirements_sha256 == other.requirements_sha256
    }
}
fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b" ._+-".contains(&b))
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Constraint { Unspecified, Unknown, Literal(String) }
impl Constraint {
    fn valid(&self) -> bool { match self { Self::Literal(value) => version(value), _ => true } }
    fn matches(&self, value: &str, java: bool) -> bool {
        match self {
            Self::Unspecified => true, Self::Unknown => false,
            Self::Literal(expected) => expected == value || java && expected.bytes().all(|b| b.is_ascii_digit())
                && value.strip_prefix(expected).is_some_and(|tail| tail.starts_with('.')),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Versions {
    pub(crate) jdk_vendor: String, pub(crate) jdk: String, pub(crate) gradle: String,
    pub(crate) agp: String, pub(crate) sdk_platform: String, pub(crate) sdk_build_tools: String,
}
impl Versions {
    fn valid(&self) -> bool { [&self.jdk_vendor, &self.jdk, &self.gradle, &self.agp, &self.sdk_platform, &self.sdk_build_tools].into_iter().all(|v| version(v)) }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Distribution { pub(crate) url: String, pub(crate) sha256: String }
impl Distribution {
    fn valid(&self) -> bool {
        self.url.len() <= 256 && self.url.is_ascii() && sha(&self.sha256)
            && ["https://services.gradle.org/distributions/gradle-", "https://downloads.gradle.org/distributions/gradle-"]
                .iter().any(|prefix| self.url.strip_prefix(prefix).and_then(|s| s.strip_suffix("-bin.zip"))
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AndroidRequirements {
    pub(crate) jdk: Constraint, pub(crate) gradle: Constraint, pub(crate) agp: Constraint,
    pub(crate) sdk_platform: Constraint, pub(crate) sdk_build_tools: Constraint,
    pub(crate) distribution: Option<Distribution>,
}
impl AndroidRequirements {
    fn valid(&self) -> bool {
        [&self.jdk, &self.gradle, &self.agp, &self.sdk_platform, &self.sdk_build_tools].into_iter().all(Constraint::valid)
            && self.distribution.as_ref().is_none_or(Distribution::valid)
    }
    fn resolved(&self) -> bool {
        [&self.jdk, &self.gradle, &self.agp, &self.sdk_platform, &self.sdk_build_tools].into_iter()
            .all(|v| !matches!(v, Constraint::Unknown))
            && [&self.gradle, &self.agp, &self.sdk_platform].into_iter().all(|v| matches!(v, Constraint::Literal(_)))
            && self.distribution.is_some()
    }
    fn matches(&self, versions: &Versions) -> bool {
        self.jdk.matches(&versions.jdk, true) && self.gradle.matches(&versions.gradle, false)
            && self.agp.matches(&versions.agp, false) && self.sdk_platform.matches(&versions.sdk_platform, false)
            && self.sdk_build_tools.matches(&versions.sdk_build_tools, false)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XcodePin { pub(crate) version: String, pub(crate) build: String }
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Requirements {
    pub(crate) platform: Platform, pub(crate) complete: bool,
    pub(crate) android: Option<AndroidRequirements>, pub(crate) xcode: XcodePin,
}
impl Requirements {
    fn valid(&self) -> bool {
        version(&self.xcode.version) && version(&self.xcode.build)
            && match (&self.android, self.platform) {
                (Some(android), Platform::Android) => android.valid(), (None, Platform::Ios) => true, _ => false,
            }
    }
}
/// Compiled supplier DATA, not a new policy and not a native qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy { pub(crate) host: Host, pub(crate) versions: Versions, pub(crate) distribution: Distribution }
impl Policy {
    /// Pure exact-pin comparison only, never native tool/installation authority.
    pub(crate) fn permits(&self,requirements:&Requirements)->bool {
        requirements.valid()&&requirements.complete&&requirements.platform==Platform::Android
            &&self.versions.valid()&&self.distribution.valid()
            &&requirements.android.as_ref().is_some_and(|a|a.resolved()&&a.matches(&self.versions)
                &&a.distribution.as_ref()==Some(&self.distribution))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct Stamp {
    pub(crate) catalog_generation: u32, pub(crate) catalog_revision: u32,
    pub(crate) source_generation: u32, pub(crate) source_revision: u32,
    pub(crate) registration_generation: u32, pub(crate) registration_revision: u32,
    pub(crate) service_generation: u32, pub(crate) service_revision: u32,
    pub(crate) diagnostics_revision: u32,
}
impl Stamp {
    fn counters(self) -> [u32; 9] { [self.catalog_generation, self.catalog_revision, self.source_generation,
        self.source_revision, self.registration_generation, self.registration_revision, self.service_generation,
        self.service_revision, self.diagnostics_revision] }
    fn valid(self) -> bool { self.counters().into_iter().all(|n| n < u32::MAX) }
    fn not_older_than(self, previous: Self) -> bool { self.counters().into_iter().zip(previous.counters()).all(|(a, b)| a >= b) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Activity { Idle, Busy, Unknown, Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogState { NotChecked, Ready, Refused }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyState { Verified, RecoveryRequired, Interrupted, Busy, Refused }
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Comparison {
    pub(crate) instance: String, pub(crate) record_sha256: String,
    pub(crate) inventory_sha256: String, pub(crate) os_provider_sha256: String,
}
impl Comparison {
    fn valid(&self) -> bool {
        self.instance.len() == 32 && self.instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && [&self.record_sha256, &self.inventory_sha256, &self.os_provider_sha256].into_iter().all(|s| sha(s))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Copy {
    pub(crate) state: CopyState, pub(crate) versions: Option<Versions>, pub(crate) comparison: Option<Comparison>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role { Jdk, Sdk, Gradle }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inspection { NotInspected, Review, Refused, Published, RetainedPartial }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Service { NotChecked, Enabled, NeedsRegistration, NeedsApproval, Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XcodeState { NotChecked, Observed, Missing, Unavailable }
#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub(crate) host: Host, pub(crate) stamp: Stamp, pub(crate) activity: Activity,
    pub(crate) catalog: CatalogState, pub(crate) copies: Vec<Copy>, pub(crate) selected: Option<Comparison>,
    pub(crate) picked: Vec<Role>, pub(crate) inspection: Inspection, pub(crate) complete_source_review: bool,
    pub(crate) service: Service, pub(crate) source_picker_available: bool, pub(crate) policies: Vec<Policy>,
    pub(crate) xcode_state: XcodeState, pub(crate) xcode_observed: Option<XcodePin>,
}
impl Observation {
    fn valid(&self) -> bool {
        self.stamp.valid() && self.copies.len() <= 32 && self.policies.len() <= 8 && self.picked.len() <= 3
            && self.picked.iter().enumerate().all(|(at, role)| !self.picked[..at].contains(role))
            && self.policies.iter().all(|p| p.host == self.host && p.versions.valid() && p.distribution.valid())
            && self.copies.iter().all(|copy| match copy.state {
                CopyState::Verified | CopyState::RecoveryRequired => copy.versions.as_ref().is_some_and(Versions::valid)
                    && copy.comparison.as_ref().is_some_and(Comparison::valid),
                _ => copy.versions.is_none() && copy.comparison.is_none(),
            }) && self.selected.as_ref().is_none_or(|selected| selected.valid() && self.catalog == CatalogState::Ready
                && self.copies.iter().any(|copy| copy.state == CopyState::Verified && copy.comparison.as_ref() == Some(selected)))
            && (self.xcode_state == XcodeState::Observed) == self.xcode_observed.is_some()
            && self.xcode_observed.as_ref().is_none_or(|pin| version(&pin.version) && version(&pin.build))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State { NeedsCheck, NeedsReview, CanReuse, NeedsPreparation, RecoveryRequired, Busy, Unsupported }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    CheckProjectRequirements, RefreshRegisteredTools, ChooseRegisteredCopy, UseSelectedCopy,
    ChooseJdk, ChooseSdk, ChooseGradle, InspectSources, ReviewProtectedCopy, ReviewSourceProblem,
    CheckToolService, RegisterToolService, OpenToolServiceSettings, ReconcileSetup, WaitForSetup,
    CheckXcode, InstallXcodeManually, InspectXcodeCopy, UnsupportedHost,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    NotChecked, RequirementsUnknown, PolicyMismatch, ExistingSelected, ExistingUnselected,
    ExistingSources, SelectionMissing, SourceProblem, ServiceRequired, OriginalUnsettled,
    OriginalBusy, HostUnavailable, XcodeMissing, XcodeMismatch, XcodeNeedsNativeCheck,
}
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) context: Context, pub(crate) stamp: Stamp, pub(crate) platform: Platform,
    pub(crate) state: State, pub(crate) action: Action, pub(crate) reason: Reason,
    pub(crate) reusable: Vec<Comparison>, pub(crate) unselected_sources: Vec<Role>,
    pub(crate) policy: Option<Policy>, pub(crate) xcode: XcodePin,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { InvalidObservation, ContextChanged, StaleObservation }

pub(crate) fn prepare(context: Context, requirements: &Requirements, observation: &Observation) -> Result<Plan, Error> {
    if !context.valid() || !requirements.valid() || !observation.valid() || context.host != observation.host {
        return Err(Error::InvalidObservation);
    }
    let mut plan = Plan { context, stamp: observation.stamp, platform: requirements.platform,
        state: State::NeedsCheck, action: Action::CheckProjectRequirements, reason: Reason::NotChecked,
        reusable: Vec::new(), unselected_sources: Vec::new(), policy: None, xcode: requirements.xcode.clone() };
    let mut decision = |state, action, reason| { plan.state = state; plan.action = action; plan.reason = reason; };
    if observation.activity == Activity::Unknown || observation.inspection == Inspection::RetainedPartial {
        decision(State::RecoveryRequired, Action::ReconcileSetup, Reason::OriginalUnsettled);
    } else if observation.activity == Activity::Busy {
        decision(State::Busy, Action::WaitForSetup, Reason::OriginalBusy);
    } else if observation.activity == Activity::Unavailable || !observation.host.mac() {
        // Portable guidance never promotes an unqualified Linux/Intel/other host.
        decision(State::Unsupported, Action::UnsupportedHost, Reason::HostUnavailable);
    } else if !requirements.complete {
        decision(State::NeedsReview, Action::CheckProjectRequirements, Reason::RequirementsUnknown);
    } else if requirements.platform == Platform::Ios {
        match observation.xcode_state {
            XcodeState::NotChecked => decision(State::NeedsCheck, Action::CheckXcode, Reason::NotChecked),
            XcodeState::Missing => decision(State::NeedsPreparation, Action::InstallXcodeManually, Reason::XcodeMissing),
            XcodeState::Unavailable => decision(State::NeedsReview, Action::CheckXcode, Reason::HostUnavailable),
            XcodeState::Observed if observation.xcode_observed.as_ref() != Some(&requirements.xcode) =>
                decision(State::NeedsPreparation, Action::InstallXcodeManually, Reason::XcodeMismatch),
            XcodeState::Observed => {
                // A version probe is not a protected-copy/SDK/license/signing proof.
                decision(State::NeedsCheck, Action::InspectXcodeCopy, Reason::XcodeNeedsNativeCheck);
            }
        }
    } else {
        let android = requirements.android.as_ref().ok_or(Error::InvalidObservation)?;
        if !android.resolved() {
            decision(State::NeedsReview, Action::CheckProjectRequirements, Reason::RequirementsUnknown);
        } else if observation.policies.is_empty() {
            decision(State::Unsupported, Action::UnsupportedHost, Reason::HostUnavailable);
        } else if let Some(policy) = observation.policies.iter().find(|p| android.matches(&p.versions)
            && android.distribution.as_ref() == Some(&p.distribution)) {
            plan.policy = Some(policy.clone());
            if observation.catalog != CatalogState::Ready {
                plan.state = State::NeedsCheck; plan.action = Action::RefreshRegisteredTools;
            } else {
                plan.reusable = observation.copies.iter().filter(|copy| copy.state == CopyState::Verified
                    && copy.versions.as_ref().is_some_and(|v| v == &policy.versions && android.matches(v)))
                    .filter_map(|copy| copy.comparison.clone()).collect();
                if observation.selected.as_ref().is_some_and(|selected| plan.reusable.contains(selected)) {
                    plan.state = State::CanReuse; plan.action = Action::UseSelectedCopy; plan.reason = Reason::ExistingSelected;
                } else if !plan.reusable.is_empty() {
                    plan.state = State::NeedsPreparation; plan.action = Action::ChooseRegisteredCopy; plan.reason = Reason::ExistingUnselected;
                } else if observation.copies.iter().any(|copy| matches!(copy.state, CopyState::RecoveryRequired | CopyState::Interrupted | CopyState::Busy)) {
                    plan.state = State::RecoveryRequired; plan.action = Action::ReconcileSetup; plan.reason = Reason::OriginalUnsettled;
                } else if observation.inspection == Inspection::Published {
                    plan.state = State::NeedsCheck; plan.action = Action::RefreshRegisteredTools;
                } else if !observation.source_picker_available {
                    plan.state = State::Unsupported; plan.action = Action::UnsupportedHost; plan.reason = Reason::HostUnavailable;
                } else {
                    plan.unselected_sources = [Role::Jdk, Role::Sdk, Role::Gradle].into_iter().filter(|role| !observation.picked.contains(role)).collect();
                    plan.state = State::NeedsPreparation;
                    if let Some(role) = plan.unselected_sources.first() {
                        plan.action = match role { Role::Jdk => Action::ChooseJdk, Role::Sdk => Action::ChooseSdk, Role::Gradle => Action::ChooseGradle };
                        plan.reason = Reason::SelectionMissing;
                    } else if observation.inspection == Inspection::Refused {
                        plan.action = Action::ReviewSourceProblem; plan.reason = Reason::SourceProblem;
                    } else if observation.inspection != Inspection::Review || !observation.complete_source_review {
                        plan.action = Action::InspectSources; plan.reason = Reason::ExistingSources;
                    } else {
                        plan.reason = Reason::ServiceRequired;
                        plan.action = match observation.service {
                            Service::NotChecked | Service::Unavailable => Action::CheckToolService,
                            Service::NeedsRegistration => Action::RegisterToolService,
                            Service::NeedsApproval => Action::OpenToolServiceSettings,
                            Service::Enabled => { plan.reason = Reason::ExistingSources; Action::ReviewProtectedCopy },
                        };
                    }
                }
            }
        } else {
            decision(State::NeedsReview, Action::CheckProjectRequirements, Reason::PolicyMismatch);
        }
    }
    Ok(plan)
}

/// Compare before forwarding an explicit click to its existing operation owner.
/// Returning true does not provide consent or bypass that owner's admission.
pub(crate) fn action_still_current(plan: &Plan, current: &Context, stamp: Stamp) -> bool {
    &plan.context == current && plan.stamp == stamp
}

/// Manual installation may legitimately change tool generations. Resume demands
/// a NEW observation of the SAME source/session/host and never repeats a write.
pub(crate) fn resume(previous: &Plan, context: Context, requirements: &Requirements, observation: &Observation) -> Result<Plan, Error> {
    if !previous.context.same_source(&context) || previous.platform != requirements.platform {
        return Err(Error::ContextChanged);
    }
    if context.observation_revision <= previous.context.observation_revision || !observation.stamp.not_older_than(previous.stamp) {
        return Err(Error::StaleObservation);
    }
    prepare(context, requirements, observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Context, Requirements, Observation) {
        let versions = Versions { jdk_vendor: "temurin".into(), jdk: "17.0.20.1".into(), gradle: "8.14.5".into(),
            agp: "8.9.2".into(), sdk_platform: "android-35".into(), sdk_build_tools: "35.0.0".into() };
        let distribution = Distribution { url: "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip".into(), sha256: "a".repeat(64) };
        let requirements = Requirements { platform: Platform::Android, complete: true, android: Some(AndroidRequirements {
            jdk: Constraint::Literal("17".into()), gradle: Constraint::Literal(versions.gradle.clone()),
            agp: Constraint::Literal(versions.agp.clone()), sdk_platform: Constraint::Literal(versions.sdk_platform.clone()),
            sdk_build_tools: Constraint::Unspecified, distribution: Some(distribution.clone()),
        }), xcode: XcodePin { version: "26.3".into(), build: "17C529".into() } };
        let context = Context { project_id: "project-a".into(), session_id: "session-a".into(), observation_revision: 1,
            saved_config_sha256: "b".repeat(64), requirements_sha256: "c".repeat(64), host: Host::MacArm64 };
        let observation = Observation { host: Host::MacArm64, stamp: Stamp { catalog_generation: 1, catalog_revision: 2, ..Stamp::default() },
            activity: Activity::Idle, catalog: CatalogState::Ready, copies: vec![], selected: None, picked: vec![],
            inspection: Inspection::NotInspected, complete_source_review: false, service: Service::NotChecked,
            source_picker_available: true, policies: vec![Policy { host: Host::MacArm64, versions, distribution }],
            xcode_state: XcodeState::NotChecked, xcode_observed: None };
        (context, requirements, observation)
    }
    fn registered(observation: &mut Observation) -> Comparison {
        let comparison = Comparison { instance: "d".repeat(32), record_sha256: "e".repeat(64), inventory_sha256: "f".repeat(64), os_provider_sha256: "0".repeat(64) };
        observation.copies.push(Copy { state: CopyState::Verified, versions: Some(observation.policies[0].versions.clone()), comparison: Some(comparison.clone()) });
        comparison
    }
    #[test]
    fn compatible_registered_tools_are_reused_before_pickers_or_installs() {
        let (context, requirements, mut observation) = fixture();
        let selected = registered(&mut observation);
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::ChooseRegisteredCopy);
        observation.selected = Some(selected);
        observation.source_picker_available = false;
        let plan = prepare(context, &requirements, &observation).unwrap();
        assert_eq!((plan.state, plan.action), (State::CanReuse, Action::UseSelectedCopy));
        assert!(plan.unselected_sources.is_empty());
    }
    #[test]
    fn acquisition_pin_comparison_rejects_workflow_java_and_unresolved_wrapper() {
        let (_,mut requirements,observation)=fixture();let policy=&observation.policies[0];
        assert!(policy.permits(&requirements));
        requirements.android.as_mut().unwrap().jdk=Constraint::Literal("21".into());
        assert!(!policy.permits(&requirements));
        requirements.android.as_mut().unwrap().jdk=Constraint::Literal("17".into());
        requirements.android.as_mut().unwrap().distribution=None;
        assert!(!policy.permits(&requirements));
        requirements.android.as_mut().unwrap().distribution=Some(policy.distribution.clone());
        requirements.complete=false;assert!(!policy.permits(&requirements));
    }
    #[test]
    fn picked_and_partial_sources_do_not_become_a_review_or_protected_copy() {
        let (context, requirements, mut observation) = fixture();
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::ChooseJdk);
        observation.picked = vec![Role::Jdk, Role::Sdk, Role::Gradle];
        observation.inspection = Inspection::Review;
        observation.service = Service::Enabled;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::InspectSources);
        observation.complete_source_review = true;
        assert_eq!(prepare(context, &requirements, &observation).unwrap().action, Action::ReviewProtectedCopy);
    }
    #[test]
    fn ambiguous_or_wrong_project_pin_never_uses_workflow_java_or_upgrades() {
        let (context, mut requirements, mut observation) = fixture();
        observation.selected = Some(registered(&mut observation));
        requirements.android.as_mut().unwrap().jdk = Constraint::Literal("21".into());
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().reason, Reason::PolicyMismatch);
        requirements.android.as_mut().unwrap().jdk = Constraint::Unknown;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().reason, Reason::RequirementsUnknown);
        requirements.android.as_mut().unwrap().jdk = Constraint::Unspecified;
        requirements.android.as_mut().unwrap().distribution = None;
        assert_eq!(prepare(context, &requirements, &observation).unwrap().reason, Reason::RequirementsUnknown);
    }
    #[test]
    fn retained_or_unsettled_originals_are_not_repeat_install_authority() {
        let (context, requirements, mut observation) = fixture();
        observation.inspection = Inspection::RetainedPartial;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::ReconcileSetup);
        observation.inspection = Inspection::NotInspected;
        observation.activity = Activity::Unknown;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().state, State::RecoveryRequired);
        observation.activity = Activity::Idle;
        observation.copies.push(Copy { state: CopyState::Interrupted, versions: None, comparison: None });
        assert_eq!(prepare(context, &requirements, &observation).unwrap().action, Action::ReconcileSetup);
    }
    #[test]
    fn service_requires_its_own_current_observation_and_approval() {
        let (context, requirements, mut observation) = fixture();
        observation.picked = vec![Role::Jdk, Role::Sdk, Role::Gradle];
        observation.inspection = Inspection::Review; observation.complete_source_review = true;
        for (service, action) in [(Service::NotChecked, Action::CheckToolService), (Service::NeedsRegistration, Action::RegisterToolService),
            (Service::NeedsApproval, Action::OpenToolServiceSettings), (Service::Enabled, Action::ReviewProtectedCopy)] {
            observation.service = service;
            assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, action);
        }
    }
    #[test]
    fn exact_context_and_every_tool_generation_guard_clicks_and_resume() {
        let (context, requirements, mut observation) = fixture();
        let plan = prepare(context.clone(), &requirements, &observation).unwrap();
        assert!(action_still_current(&plan, &context, observation.stamp));
        observation.stamp.source_generation += 1;
        assert!(!action_still_current(&plan, &context, observation.stamp));
        assert!(matches!(resume(&plan, context.clone(), &requirements, &observation), Err(Error::StaleObservation)));
        let mut fresh = context.clone(); fresh.observation_revision += 1;
        assert!(resume(&plan, fresh.clone(), &requirements, &observation).is_ok());
        for field in [0, 1, 2, 3] {
            let mut stale = fresh.clone();
            match field { 0 => stale.requirements_sha256 = "9".repeat(64), 1 => stale.saved_config_sha256 = "9".repeat(64),
                2 => stale.session_id.push('x'), _ => stale.host = Host::MacX64 }
            assert!(matches!(resume(&plan, stale, &requirements, &observation), Err(Error::ContextChanged)));
        }
        observation.stamp.catalog_revision = 1;
        assert!(matches!(resume(&plan, fresh, &requirements, &observation), Err(Error::StaleObservation)));
    }
    #[test]
    fn xcode_version_match_is_not_native_copy_sdk_or_license_readiness() {
        let (context, mut requirements, mut observation) = fixture();
        requirements.platform = Platform::Ios; requirements.android = None;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::CheckXcode);
        observation.xcode_state = XcodeState::Observed; observation.xcode_observed = Some(requirements.xcode.clone());
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::InspectXcodeCopy);
        observation.xcode_observed.as_mut().unwrap().build.push('a');
        assert_eq!(prepare(context, &requirements, &observation).unwrap().reason, Reason::XcodeMismatch);
    }
    #[test]
    fn host_and_architecture_do_not_borrow_other_profiles() {
        let (mut context, requirements, mut observation) = fixture();
        context.host = Host::MacX64;
        assert!(matches!(prepare(context.clone(), &requirements, &observation), Err(Error::InvalidObservation)));
        context.host = Host::LinuxX64; observation.host = Host::LinuxX64; observation.policies.clear();
        assert_eq!(prepare(context, &requirements, &observation).unwrap().action, Action::UnsupportedHost);
    }
    #[test]
    fn uninspected_catalog_published_copy_and_invalid_selection_require_fresh_check() {
        let (context, requirements, mut observation) = fixture();
        observation.catalog = CatalogState::NotChecked;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::RefreshRegisteredTools);
        observation.catalog = CatalogState::Ready; observation.inspection = Inspection::Published;
        assert_eq!(prepare(context.clone(), &requirements, &observation).unwrap().action, Action::RefreshRegisteredTools);
        let comparison = registered(&mut observation); observation.selected = Some(comparison);
        observation.selected.as_mut().unwrap().os_provider_sha256 = "a".repeat(64);
        assert!(matches!(prepare(context, &requirements, &observation), Err(Error::InvalidObservation)));
    }
}
