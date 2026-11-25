//! Bounded comparison DATA for the two original non-secret Setup operations.
//! No desired variable text, source object, token, or private Consent is exported.
use super::{dispatch::Hex, nullable, Effect, Kind, Reason, State};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Setting { ActionsEnabled, WorkflowTokenPolicy, EnvironmentProtection, EnvironmentVariable }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NativeReason {
    None, NoChange, PolicyUnsupported, PolicyChanged, OrganizationRestricted, RepositoryArchived,
    Unauthorized, Forbidden, NotFoundOrInaccessible, TargetChanged, RateLimited, NetworkUnavailable,
    TlsFailed, ResponseInvalid, ResponseLimit, Expired, Cancelled, Unqualified, NotConnected, Busy,
    InvalidInput, RuntimeUnavailable, ConsentExpired, MaterialUnavailable, MaterialChanged,
    MaterialTooLarge, RequirementUnsupported, ConfigurationChanged, ResourcesUnavailable,
    VariableExists, VariableMissing, VariableChanged,
}
impl NativeReason {
    pub(crate) fn successful(self) -> bool { matches!(self, Self::None | Self::NoChange) }
    pub(crate) fn reason(self) -> Reason {
        match self {
            Self::None | Self::NoChange => Reason::None,
            Self::Cancelled => Reason::UserCancelled,
            Self::Expired | Self::ConsentExpired => Reason::Expired,
            Self::TargetChanged => Reason::ContextChanged,
            Self::Busy => Reason::Busy,
            Self::NotConnected | Self::Unqualified | Self::RuntimeUnavailable => Reason::Unavailable,
            _ => Reason::NativeRefused,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub(crate) setting: Setting,
    pub(crate) reason: NativeReason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) write_claimed: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) write_acknowledged: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) consent_id: Option<Hex<16>>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) prepared_sha256: Option<Hex<32>>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) observation_sha256: Option<Hex<32>>,
}
impl Snapshot {
    pub(crate) fn valid_for(&self, kind: Kind) -> bool {
        if !kind.remote_setup_family()
            || self.write_claimed.is_some() != self.write_acknowledged.is_some()
            || self.write_acknowledged == Some(true) && self.write_claimed != Some(true)
            || self.consent_id.is_some() != self.prepared_sha256.is_some()
            || self.setting != Setting::EnvironmentVariable && matches!(self.reason,
                NativeReason::MaterialUnavailable | NativeReason::MaterialChanged | NativeReason::MaterialTooLarge
                | NativeReason::RequirementUnsupported | NativeReason::ConfigurationChanged
                | NativeReason::VariableExists | NativeReason::VariableMissing | NativeReason::VariableChanged)
        { return false; }
        match kind {
            Kind::RemoteSetupPrepare => self.write_claimed != Some(true)
                && (self.reason == NativeReason::None) == self.consent_id.is_some()
                // A failed local Consent publication may retain its actual GET observation.
                // That bounded diagnostic cannot make a refusal Apply-ready.
                && (!self.reason.successful() || self.observation_sha256.is_some())
                && (!self.reason.successful() || self.write_claimed == Some(false)),
            Kind::RemoteSetupApply => self.consent_id.is_none() && self.reason != NativeReason::NoChange
                && (self.reason == NativeReason::None) == self.observation_sha256.is_some()
                && (self.reason != NativeReason::None || self.write_acknowledged == Some(true)),
            _ => false,
        }
    }
    pub(crate) fn valid_outcome(&self, kind: Kind, reason: Reason, effect: Effect) -> bool {
        self.valid_for(kind) && reason == self.reason.reason()
            && effect.valid_for(kind)
            && if kind == Kind::RemoteSetupPrepare { effect == Effect::None } else {
                match self.reason {
                    NativeReason::None => effect == Effect::SettingsReadbackObserved,
                    _ => matches!(effect, Effect::NotSent | Effect::PotentiallyApplied)
                        && (self.write_claimed != Some(true) || effect == Effect::PotentiallyApplied),
                }
            }
    }
    pub(crate) fn valid_row(&self, kind: Kind, state: State, reason: Reason, effect: Effect) -> bool {
        self.valid_outcome(kind, reason, effect)
            && if self.reason.successful() { state == State::Complete }
                else { matches!(state, State::Refused | State::Cancelled) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(kind: Kind) -> Snapshot {
        Snapshot {setting:Setting::ActionsEnabled,reason:NativeReason::None,
            write_claimed:Some(kind==Kind::RemoteSetupApply),write_acknowledged:Some(kind==Kind::RemoteSetupApply),
            consent_id:(kind==Kind::RemoteSetupPrepare).then_some(Hex([1;16])),
            prepared_sha256:(kind==Kind::RemoteSetupPrepare).then_some(Hex([2;32])),observation_sha256:Some(Hex([3;32]))}
    }
    #[test]
    fn remote_settings_compact_data_preserves_no_change_readback_and_uncertainty() {
        let prepare=Kind::RemoteSetupPrepare; let apply=Kind::RemoteSetupApply;
        assert!(value(prepare).valid_row(prepare,State::Complete,Reason::None,Effect::None));
        let mut no_change=value(prepare);no_change.reason=NativeReason::NoChange;no_change.consent_id=None;no_change.prepared_sha256=None;
        assert!(no_change.valid_row(prepare,State::Complete,Reason::None,Effect::None));
        assert!(!no_change.valid_for(apply));
        let mut expired=no_change;expired.reason=NativeReason::ConsentExpired;
        assert!(expired.valid_row(prepare,State::Refused,Reason::Expired,Effect::None));
        assert!(expired.observation_sha256.is_some() && expired.consent_id.is_none());
        let mut v=value(apply);assert!(v.valid_row(apply,State::Complete,Reason::None,Effect::SettingsReadbackObserved));
        assert!(!v.valid_row(apply,State::Finishing,Reason::None,Effect::SettingsReadbackObserved));
        v.reason=NativeReason::NetworkUnavailable;v.observation_sha256=None;
        assert!(v.valid_row(apply,State::Refused,Reason::NativeRefused,Effect::PotentiallyApplied));
        assert!(!v.valid_row(apply,State::Complete,Reason::None,Effect::SettingsReadbackObserved));
        assert!(!v.valid_row(apply,State::Refused,Reason::NativeRefused,Effect::NotSent));
        v.write_claimed=None;v.write_acknowledged=None;
        assert!(v.valid_row(apply,State::Cancelled,Reason::NativeRefused,Effect::NotSent));
        v.reason=NativeReason::VariableChanged;assert!(!v.valid_for(apply));v.setting=Setting::EnvironmentVariable;assert!(v.valid_for(apply));
        for k in [Kind::SetupPrepare,Kind::SetupPublish,Kind::CounterPrepare,Kind::RepositoryCreate] {assert!(!v.valid_for(k));}
    }
    #[test]
    fn remote_settings_wire_has_required_nulls_no_secret_fields_and_fixed_backing() {
        let v=value(Kind::RemoteSetupPrepare); let data=serde_json::to_value(v).unwrap();
        assert_eq!(serde_json::from_value::<Snapshot>(data.clone()).unwrap(),v);
        for key in ["writeClaimed","writeAcknowledged","consentId","preparedSha256","observationSha256"] {
            let mut bad=data.clone();bad.as_object_mut().unwrap().remove(key);assert!(serde_json::from_value::<Snapshot>(bad).is_err(),"{key}");
        }
        for key in ["value","plaintext","token","source"] {let mut bad=data.clone();bad[key]=serde_json::json!("not accepted");assert!(serde_json::from_value::<Snapshot>(bad).is_err());}
        let mut bad=data.clone();bad["setting"]=serde_json::json!("environment_secret");assert!(serde_json::from_value::<Snapshot>(bad).is_err());
        let mut bad=data;bad["reason"]=serde_json::json!("secret-exists");assert!(serde_json::from_value::<Snapshot>(bad).is_err());
        assert!(std::mem::size_of::<Snapshot>()<=256);
        assert!(serde_json::to_vec(&v).unwrap().len()<1024);
    }
}
