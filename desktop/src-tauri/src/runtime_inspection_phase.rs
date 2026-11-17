//! Fixed diagnostic DATA. No runtime path, native error text or authority.
//!
//! The step is reported twice: as the historical stderr line (retained only by
//! launches that capture stderr) and appended to the fixed public category
//! text. LaunchServices puts an ordinary app's stderr on /dev/null, so the
//! visible reason is the only report that survives an owner's normal launch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Admission,
    RecordReservation,
    ProtectedApplication,
    // Fixed sub-steps of the installed-application proof. Each covers a
    // small, named group of native/identity checks instead of ~20 sites.
    ProtectedProfile,
    ProtectedInstallRoot,
    ProtectedBundleOpen,
    ProtectedEntryAttributes,
    ProtectedPayloadAttributes,
    ProtectedBinary,
    ProtectedCodeGroup,
    RuntimeRoot,
    RuntimeRootAttributes,
    ManifestOpen,
    ManifestRead,
    ManifestDecode,
    Inventory,
    PayloadWalk,
    FinalValidation,
}

/// Prefix + every code + suffix stay well inside this public reason bound.
#[cfg(test)]
pub(super) const REASON_LIMIT: usize = 192;

impl Phase {
    #[cfg(test)]
    pub(super) const ALL: [Phase; 18] = [Phase::Admission, Phase::RecordReservation, Phase::ProtectedApplication,
        Phase::ProtectedProfile, Phase::ProtectedInstallRoot, Phase::ProtectedBundleOpen,
        Phase::ProtectedEntryAttributes, Phase::ProtectedPayloadAttributes, Phase::ProtectedBinary,
        Phase::ProtectedCodeGroup, Phase::RuntimeRoot, Phase::RuntimeRootAttributes, Phase::ManifestOpen,
        Phase::ManifestRead, Phase::ManifestDecode, Phase::Inventory, Phase::PayloadWalk, Phase::FinalValidation];

    pub(super) fn report<E>(self, failure: E, sink: &mut impl std::io::Write) -> E {
        let _ = sink.write_all(self.failure_line());
        failure
    }

    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::RecordReservation => "record-reservation",
            Self::ProtectedApplication => "protected-application",
            Self::ProtectedProfile => "protected-profile",
            Self::ProtectedInstallRoot => "protected-install-root",
            Self::ProtectedBundleOpen => "protected-bundle-open",
            Self::ProtectedEntryAttributes => "protected-entry-attributes",
            Self::ProtectedPayloadAttributes => "protected-payload-attributes",
            Self::ProtectedBinary => "protected-binary",
            Self::ProtectedCodeGroup => "protected-code-group",
            Self::RuntimeRoot => "runtime-root",
            Self::RuntimeRootAttributes => "runtime-root-attributes",
            Self::ManifestOpen => "manifest-open",
            Self::ManifestRead => "manifest-read",
            Self::ManifestDecode => "manifest-decode",
            Self::Inventory => "inventory",
            Self::PayloadWalk => "payload-walk",
            Self::FinalValidation => "final-validation",
        }
    }

    pub(super) fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Admission => b"MRK_RUNTIME_INSPECTION_FAILED=admission\n",
            Self::RecordReservation => b"MRK_RUNTIME_INSPECTION_FAILED=record-reservation\n",
            Self::ProtectedApplication => b"MRK_RUNTIME_INSPECTION_FAILED=protected-application\n",
            Self::ProtectedProfile => b"MRK_RUNTIME_INSPECTION_FAILED=protected-profile\n",
            Self::ProtectedInstallRoot => b"MRK_RUNTIME_INSPECTION_FAILED=protected-install-root\n",
            Self::ProtectedBundleOpen => b"MRK_RUNTIME_INSPECTION_FAILED=protected-bundle-open\n",
            Self::ProtectedEntryAttributes => b"MRK_RUNTIME_INSPECTION_FAILED=protected-entry-attributes\n",
            Self::ProtectedPayloadAttributes => b"MRK_RUNTIME_INSPECTION_FAILED=protected-payload-attributes\n",
            Self::ProtectedBinary => b"MRK_RUNTIME_INSPECTION_FAILED=protected-binary\n",
            Self::ProtectedCodeGroup => b"MRK_RUNTIME_INSPECTION_FAILED=protected-code-group\n",
            Self::RuntimeRoot => b"MRK_RUNTIME_INSPECTION_FAILED=runtime-root\n",
            Self::RuntimeRootAttributes => b"MRK_RUNTIME_INSPECTION_FAILED=runtime-root-attributes\n",
            Self::ManifestOpen => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-open\n",
            Self::ManifestRead => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-read\n",
            Self::ManifestDecode => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-decode\n",
            Self::Inventory => b"MRK_RUNTIME_INSPECTION_FAILED=inventory\n",
            Self::PayloadWalk => b"MRK_RUNTIME_INSPECTION_FAILED=payload-walk\n",
            Self::FinalValidation => b"MRK_RUNTIME_INSPECTION_FAILED=final-validation\n",
        }
    }

    /// The unchanged fixed category sentence, then one fixed step sentence.
    /// Only `&'static` program text is accepted: the category is never a
    /// path, native error, request or credential, and nothing else is added.
    pub(super) fn visible_reason(self, category: &'static str) -> String {
        const STEP: &str = " Inspection step: ";
        let code = self.code();
        let mut reason = String::with_capacity(category.len() + STEP.len() + code.len() + 1);
        reason.push_str(category);
        reason.push_str(STEP);
        reason.push_str(code);
        reason.push('.');
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::{Phase, REASON_LIMIT};
    const CATEGORIES: [&str; 9] = [
        "Installed Mac runtime inspection stopped before completion.",
        "Installed Mac runtime inspection exceeded its deadline.",
        "Installed Mac runtime inspection exceeded its resource limit.",
        "Installed Mac runtime native or data inspection could not finish.",
        "Installed Mac runtime ownership or filesystem protections could not be verified.",
        "Installed Mac runtime inventory could not be verified.",
        "Installed Mac runtime original file identity could not be confirmed.",
        "Installed Mac runtime inspection was already used.",
        "Installed Mac runtime original custody could not be confirmed.",
    ];

    #[test]
    fn diagnostics_distinguish_every_step_without_dynamic_data() {
        let mut seen = std::collections::BTreeSet::new();
        let mut codes = std::collections::BTreeSet::new();
        for phase in Phase::ALL {
            let line = phase.failure_line();
            assert!(line.len() < 80 && line.ends_with(b"\n"));
            assert!(line.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase()
                || b"_=\n-".contains(c)));
            // The stderr line and the visible code are the same fixed token.
            assert_eq!(line, format!("MRK_RUNTIME_INSPECTION_FAILED={}\n", phase.code()).as_bytes());
            seen.insert(line);
            codes.insert(phase.code());
        }
        assert_eq!((seen.len(), codes.len()), (18, 18));
    }

    #[test]
    fn visible_reason_keeps_the_exact_category_and_adds_only_a_fixed_step() {
        for category in CATEGORIES {
            for phase in Phase::ALL {
                let reason = phase.visible_reason(category);
                // Existing exact-text consumers (UI observers use `contains`)
                // still find the unchanged original category sentence first.
                assert!(reason.starts_with(category));
                assert_eq!(&reason[category.len()..], format!(" Inspection step: {}.", phase.code()));
                assert!(reason.len() <= REASON_LIMIT, "{reason}");
                assert!(reason.bytes().all(|c| c.is_ascii_alphanumeric() || b" .:-".contains(&c)));
                assert!(!reason.contains('/') && !reason.contains('=') && !reason.contains('\n'));
            }
        }
        assert_eq!(Phase::ProtectedEntryAttributes.visible_reason(CATEGORIES[3]),
            "Installed Mac runtime native or data inspection could not finish. Inspection step: protected-entry-attributes.");
    }

    #[test]
    fn closed_sink_preserves_original_failure_without_retry() {
        struct Closed(usize);
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.0 += 1;
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> { unreachable!() }
        }
        let mut closed = Closed(0);
        let original = Box::new(42);
        let identity = &*original as *const i32;
        let returned = Phase::ManifestRead.report(original, &mut closed);
        assert_eq!(&*returned as *const i32, identity);
        assert_eq!(closed.0, 1);
        // A discarded (/dev/null-like) or failed sink cannot remove the step
        // from the visible reason: the reason is built from the phase alone.
        assert_eq!(Phase::ManifestRead.visible_reason(CATEGORIES[3]),
            "Installed Mac runtime native or data inspection could not finish. Inspection step: manifest-read.");
        let mut later = Vec::new();
        Phase::RuntimeRoot.report((), &mut later);
        assert_eq!(later, Phase::RuntimeRoot.failure_line());
        assert_eq!(Phase::default(), Phase::Admission);
    }
}
