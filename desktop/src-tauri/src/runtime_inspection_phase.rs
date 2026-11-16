//! Fixed diagnostic DATA. No runtime path, native error text or authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Admission,
    RecordReservation,
    ProtectedApplication,
    RuntimeRoot,
    ManifestOpen,
    ManifestRead,
    ManifestDecode,
    Inventory,
    PayloadWalk,
    FinalValidation,
}

impl Phase {
    pub(super) fn report<E>(self, failure: E, sink: &mut impl std::io::Write) -> E {
        let _ = sink.write_all(self.failure_line());
        failure
    }

    pub(super) fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Admission => b"MRK_RUNTIME_INSPECTION_FAILED=admission\n",
            Self::RecordReservation => b"MRK_RUNTIME_INSPECTION_FAILED=record-reservation\n",
            Self::ProtectedApplication => b"MRK_RUNTIME_INSPECTION_FAILED=protected-application\n",
            Self::RuntimeRoot => b"MRK_RUNTIME_INSPECTION_FAILED=runtime-root\n",
            Self::ManifestOpen => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-open\n",
            Self::ManifestRead => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-read\n",
            Self::ManifestDecode => b"MRK_RUNTIME_INSPECTION_FAILED=manifest-decode\n",
            Self::Inventory => b"MRK_RUNTIME_INSPECTION_FAILED=inventory\n",
            Self::PayloadWalk => b"MRK_RUNTIME_INSPECTION_FAILED=payload-walk\n",
            Self::FinalValidation => b"MRK_RUNTIME_INSPECTION_FAILED=final-validation\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Phase;
    #[test]
    fn diagnostics_distinguish_every_step_without_dynamic_data() {
        let phases = [Phase::Admission, Phase::RecordReservation, Phase::ProtectedApplication,
            Phase::RuntimeRoot, Phase::ManifestOpen, Phase::ManifestRead, Phase::ManifestDecode,
            Phase::Inventory, Phase::PayloadWalk, Phase::FinalValidation];
        let mut seen = std::collections::BTreeSet::new();
        for phase in phases {
            let line = phase.failure_line();
            assert!(line.len() < 80 && line.ends_with(b"\n"));
            assert!(line.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase()
                || b"_=\n-".contains(c)));
            assert!(seen.insert(line));
        }
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
        let mut later = Vec::new();
        Phase::RuntimeRoot.report((), &mut later);
        assert_eq!(later, Phase::RuntimeRoot.failure_line());
        assert_eq!(Phase::default(), Phase::Admission);
    }
}
