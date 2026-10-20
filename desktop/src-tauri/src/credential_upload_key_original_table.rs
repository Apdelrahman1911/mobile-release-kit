//! Exact operation roster of the existing nonshipping upload journeys.
//! This comparison does NOT create an original, select a tool, authorize a
//! vault action or supply a join. The containing real SessionBook still checks
//! Control binding, strictly increasing IDs, original calls and ALL old joins.
use super::{Case, Operation};

pub(in crate::asset_session) fn original_allowed(
    case: Case,
    id: u32,
    operation: Option<Operation>,
) -> bool {
    use Operation::*;
    let route: &[Operation] = match case {
        Case::RoundTrip | Case::ColdProduce => &[
            ChooseProject,
            OpenVault,
            PrepareInitialize,
            Initialize,
            GenerateUploadKey,
            OpenVault,
            Unlock,
            Prepare,
        ],
        Case::StopBeforeGo => &[
            ChooseProject,
            OpenVault,
            PrepareInitialize,
            Initialize,
            GenerateUploadKey,
            OpenVault,
            Unlock,
            RecoverUploadKey,
        ],
        Case::StopAfterNew => &[
            ChooseProject,
            OpenVault,
            PrepareInitialize,
            Initialize,
            GenerateUploadKey,
            OpenVault,
            Unlock,
            Prepare,
            Bind,
            RecoverUploadKey,
        ],
        Case::ColdReopen => &[ChooseProject, OpenVault, Unlock, Prepare, Bind],
    };
    // None is the existing ordinary Quit original, including known-safe early
    // Quit after a refused journey. It is never a new execution/cleanup right;
    // the unchanged caller still requires every predecessor actually settled.
    match operation {
        None => (2..=route.len() as u32 + 1).contains(&id),
        Some(operation) => {
            id.checked_sub(1)
                .and_then(|index| route.get(index as usize))
                == Some(&operation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Operation::*;

    #[test]
    fn each_existing_upload_journey_registers_its_actual_service_operations() {
        // These are the actual fixed native calls, not forged OriginalWork or
        // receipt fixtures. Registration admission is still independently gated.
        for (case, route) in [
            (
                Case::RoundTrip,
                vec![
                    ChooseProject,
                    OpenVault,
                    PrepareInitialize,
                    Initialize,
                    GenerateUploadKey,
                    OpenVault,
                    Unlock,
                    Prepare,
                ],
            ),
            (
                Case::ColdProduce,
                vec![
                    ChooseProject,
                    OpenVault,
                    PrepareInitialize,
                    Initialize,
                    GenerateUploadKey,
                    OpenVault,
                    Unlock,
                    Prepare,
                ],
            ),
            (
                Case::StopBeforeGo,
                vec![
                    ChooseProject,
                    OpenVault,
                    PrepareInitialize,
                    Initialize,
                    GenerateUploadKey,
                    OpenVault,
                    Unlock,
                    RecoverUploadKey,
                ],
            ),
            (
                Case::StopAfterNew,
                vec![
                    ChooseProject,
                    OpenVault,
                    PrepareInitialize,
                    Initialize,
                    GenerateUploadKey,
                    OpenVault,
                    Unlock,
                    Prepare,
                    Bind,
                    RecoverUploadKey,
                ],
            ),
            (
                Case::ColdReopen,
                vec![ChooseProject, OpenVault, Unlock, Prepare, Bind],
            ),
        ] {
            for (index, operation) in route.into_iter().enumerate() {
                assert!(original_allowed(case, index as u32 + 1, Some(operation)));
                assert!(!original_allowed(case, 0, Some(operation)));
                assert!(!original_allowed(case, u32::MAX, Some(operation)));
            }
        }
    }

    #[test]
    fn a_different_journey_cannot_borrow_initialize_generate_bind_or_recovery() {
        assert!(original_allowed(
            Case::StopBeforeGo,
            8,
            Some(RecoverUploadKey)
        ));
        assert!(!original_allowed(Case::StopBeforeGo, 8, Some(Prepare)));
        assert!(!original_allowed(
            Case::RoundTrip,
            8,
            Some(RecoverUploadKey)
        ));
        assert!(!original_allowed(Case::RoundTrip, 9, Some(Bind)));
        assert!(original_allowed(Case::StopAfterNew, 9, Some(Bind)));
        assert!(original_allowed(
            Case::StopAfterNew,
            10,
            Some(RecoverUploadKey)
        ));
        assert!(!original_allowed(
            Case::StopAfterNew,
            9,
            Some(RecoverUploadKey)
        ));
        for operation in [
            PrepareInitialize,
            Initialize,
            GenerateUploadKey,
            RecoverUploadKey,
            PrepareBackupExport,
            ImportBackup,
            ChooseFile,
            ChooseProjectPath,
            Commit,
            Discard,
            Lock,
        ] {
            for id in 1..=6 {
                assert!(!original_allowed(Case::ColdReopen, id, Some(operation)));
            }
        }
        assert!(!original_allowed(Case::ColdProduce, 3, Some(Unlock)));
        assert!(!original_allowed(
            Case::ColdReopen,
            5,
            Some(GenerateUploadKey)
        ));
    }

    #[test]
    fn ordinary_early_quit_remains_bounded_and_never_aliases_a_vault_operation() {
        for (case, maximum) in [
            (Case::RoundTrip, 9),
            (Case::ColdProduce, 9),
            (Case::StopBeforeGo, 9),
            (Case::StopAfterNew, 11),
            (Case::ColdReopen, 6),
        ] {
            assert!(!original_allowed(case, 0, None));
            assert!(!original_allowed(case, 1, None));
            for id in 2..=maximum {
                assert!(original_allowed(case, id, None));
            }
            assert!(!original_allowed(case, maximum + 1, None));
            assert!(!original_allowed(case, u32::MAX, None));
            assert!(!original_allowed(case, maximum, Some(Unlock)));
        }
    }
}
