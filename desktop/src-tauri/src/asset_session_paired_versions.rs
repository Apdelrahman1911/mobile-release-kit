//! Closed native two-key context. Each assessment is still the unchanged core
//! single-platform Store assessment; the actual Slot retains this native scope.
use super::*;

pub(super) fn scope(
    platform: Platform,
    stage: Stage,
    purpose: Purpose,
    mode: commands::ExecutionMode,
) -> bool {
    platform == Platform::Both
        && stage == Stage::Candidate
        && purpose == Purpose::VersionInventory
        && mode == commands::ExecutionMode::Local
}
pub(super) fn selected(context: &NativeContext) -> bool {
    scope(
        context.platform,
        context.stage,
        context.purpose,
        context.execution_mode,
    )
}
pub(super) fn boundary(
    platform: Platform,
    stage: Stage,
    purpose: Purpose,
    mode: commands::ExecutionMode,
) -> bool {
    !(platform == Platform::Both || purpose == Purpose::VersionInventory)
        || scope(platform, stage, purpose, mode)
}
pub(super) fn assessment_scope(
    kind: Kind,
    context: &NativeContext,
    draft: &Value,
) -> Result<(Platform, Purpose), AssetError> {
    if !boundary(
        context.platform,
        context.stage,
        context.purpose,
        context.execution_mode,
    ) {
        return Err(AssetError::invalid());
    }
    if !selected(context) {
        return Ok((context.platform, context.purpose));
    }
    if draft["android"]["enabled"] != true || draft["ios"]["enabled"] != true {
        return Err(AssetError::invalid());
    }
    let platform = match kind {
        Kind::GoogleServiceAccount => Platform::Android,
        Kind::AscP8 => Platform::Ios,
        _ => return Err(AssetError::new(Reason::UnsupportedFormat)),
    };
    Ok((platform, Purpose::Store))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paired_scope_has_no_github_signing_full_or_later_stage_alias() {
        for platform in [
            Platform::Android,
            Platform::Ios,
            Platform::Both,
            Platform::Project,
        ] {
            for stage in [Stage::Candidate, Stage::ExternalTesting, Stage::Production] {
                for purpose in [
                    Purpose::Full,
                    Purpose::Signing,
                    Purpose::Store,
                    Purpose::Provisioning,
                    Purpose::VersionInventory,
                ] {
                    for mode in [
                        commands::ExecutionMode::Github,
                        commands::ExecutionMode::Local,
                    ] {
                        let mut v = serde_json::json!({"projectId":"project-1","draft":{"android":{"enabled":true},"ios":{"enabled":true}},"platform":platform,"stage":stage,"purpose":purpose,"executionMode":mode});
                        if platform == Platform::Both || purpose == Purpose::VersionInventory {
                            assert_eq!(
                                commands::context(&v).is_ok(),
                                scope(platform, stage, purpose, mode)
                            );
                            v["draft"]["ios"]["enabled"] = Value::Bool(false);
                            assert!(commands::context(&v).is_err());
                        }
                    }
                }
            }
        }
    }
}
