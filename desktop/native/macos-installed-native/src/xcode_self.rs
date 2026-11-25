//! Fixed Developer ID setup SELF signer, not package or provisioning authority.
//!
//! Caller supplies original W/F and retained protected SetupSource originals.
//! Synchronous Security calls are not interruptible: a real enclosing Parent
//! must retain and bound the calling child under original H. No implicit Drop,
//! arbitrary signer requirement, FD duplication, source execution or mutation.
//! Static/dynamic code identity and hardened empty-entitlement policy are separate
//! from caller's full ancestry/bytes POST and genuine signed-package admission.
use std::time::{Duration, Instant};

pub const OWNED_BYTES: usize = 20 * 1024; // inline cell+wrapper+bounded native stack, not framework RSS
pub const CF_REFERENCES: usize = 10;
const CELL_BYTES: usize = 12288;
const CLEANUP: Duration = Duration::from_secs(120);

fn path_accepts(path: &[u8]) -> bool {
    if !path.starts_with(b"/") || path.len() > 4096 {
        return false;
    }
    let mut count = 0;
    let mut previous: &[u8] = b"";
    let mut last: &[u8] = b"";
    for part in path[1..].split(|b| *b == b'/') {
        count += 1;
        if count > 10
            || part.is_empty()
            || part.len() > 255
            || part == b"."
            || part == b".."
            || !part
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+ ".contains(b))
        {
            return false;
        }
        previous = last;
        last = part;
    }
    count >= 3 && previous == b"setup" && last == b"mrk-macos-xcode-setup"
}

// DATA lifecycle shared by native wrapper and focused tests. No synthetic DATA
// instance can manufacture the native SELF owner or its accepted() result.
struct State {
    work: Instant,
    finish: Instant,
    last: Option<Instant>,
    first: Option<Instant>,
    failed: bool,
    unknown: bool,
    entered: bool,
    matched: bool,
    post: bool,
    settled: bool,
}
impl State {
    fn new(work: Instant, finish: Instant) -> Self {
        let valid = finish >= work && finish.duration_since(work) <= CLEANUP;
        Self {
            work,
            finish,
            last: None,
            first: None,
            failed: !valid,
            unknown: !valid,
            entered: false,
            matched: false,
            post: false,
            settled: false,
        }
    }
    fn fail(&mut self, at: Instant) {
        self.failed = true;
        self.first = Some(self.first.map_or(at, |first| first.min(at)));
    }
    fn cleanup_end(&self) -> Instant {
        self.first
            .and_then(|at| at.checked_add(CLEANUP))
            .map_or(self.finish, |end| self.finish.min(end))
    }
    fn observe(&mut self, now: Instant, cleanup: bool) -> bool {
        if self.last.is_some_and(|last| now < last) {
            self.unknown = true;
            self.failed = true;
            return false;
        }
        self.last = Some(now);
        let end = if cleanup {
            self.cleanup_end()
        } else {
            self.work
        };
        if now >= end {
            // The deadline itself, not delayed observation, is the earliest
            // known failure. Never extend cleanup by waiting for a late return.
            self.fail(end);
            if cleanup {
                self.unknown = true;
            }
            return false;
        }
        true
    }
    fn accepted_at(&self, now: Instant) -> bool {
        now < self.work
            && self.last.is_none_or(|last| now >= last)
            && self.entered
            && self.matched
            && self.post
            && self.settled
            && !self.failed
            && !self.unknown
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{
        ffi::{c_int, c_void},
        marker::PhantomData,
        os::{
            fd::{AsRawFd, BorrowedFd},
            unix::ffi::OsStrExt,
        },
        path::Path,
        rc::Rc,
    };

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Report {
        phase: u32,
        unknown: u32,
        verified: u32,
        status: i32,
        states: [u32; CF_REFERENCES],
    }
    const _: [(); 56] = [(); std::mem::size_of::<Report>()];
    #[repr(C, align(8))]
    struct Cell([u64; CELL_BYTES / 8]);
    unsafe extern "C" {
        fn mrk_xcode_self_begin(
            cell: *mut c_void,
            bytes: usize,
            path: *const u8,
            length: usize,
            parent: c_int,
            bundle: c_int,
            out: *mut Report,
        ) -> c_int;
        fn mrk_xcode_self_step(cell: *mut c_void, phase: u32, out: *mut Report) -> c_int;
        fn mrk_xcode_self_release(cell: *mut c_void, slot: u32, out: *mut Report) -> c_int;
        fn mrk_xcode_self_retire(cell: *mut c_void) -> c_int;
    }
    /// One use, one original thread. Borrowed FDs are never duplicated/closed.
    /// No Drop invokes CF: caller MUST settle and retain unknown custody until
    /// the sole copier exits. Losing this value never constitutes finality.
    pub struct SelfSigner<'a> {
        cell: Cell,
        report: Report,
        state: State,
        live: bool,
        closing: bool,
        originals: Option<(BorrowedFd<'a>, BorrowedFd<'a>)>,
        _same_thread: PhantomData<Rc<()>>,
    }
    const _: () = assert!(std::mem::size_of::<SelfSigner<'static>>() + 6144 <= OWNED_BYTES);
    impl<'a> SelfSigner<'a> {
        pub fn new(original_work: Instant, original_finish: Instant) -> Self {
            Self {
                cell: Cell([0; CELL_BYTES / 8]),
                report: Report::default(),
                state: State::new(original_work, original_finish),
                live: false,
                closing: false,
                originals: None,
                _same_thread: PhantomData,
            }
        }
        fn pointer(&mut self) -> *mut c_void {
            self.cell.0.as_mut_ptr().cast()
        }
        fn returned(&mut self, result: c_int, report: Report, phase: u32, cleanup: bool) -> bool {
            let at = Instant::now();
            let valid = report.phase == phase
                && report.unknown <= 1
                && report.verified <= 1
                && report.states.iter().all(|s| matches!(s, 0 | 2 | 3 | 4));
            if !valid {
                self.state.unknown = true;
                self.state.fail(at);
                return false;
            }
            self.report = report;
            if result < 0 || result > 1 || report.unknown != 0 {
                self.state.unknown = true;
            }
            if result != 1 {
                self.state.fail(at);
            }
            self.state.observe(at, cleanup) && result == 1 && !self.state.unknown
        }
        /// Returns a PROVISIONAL matched+POST fact. It is not accepted until
        /// settle succeeds and accepted() is true. The caller still owes complete
        /// SOURCE POST and signed-package authorization; this is not that grant.
        pub fn verify(
            &mut self,
            path: &Path,
            parent: BorrowedFd<'a>,
            bundle: BorrowedFd<'a>,
        ) -> bool {
            let now = Instant::now();
            if self.state.entered
                || self.closing
                || self.live
                || self.state.failed
                || !path_accepts(path.as_os_str().as_bytes())
                || parent.as_raw_fd() == bundle.as_raw_fd()
            {
                self.state.fail(now);
                return false;
            }
            self.state.entered = true;
            self.originals = Some((parent, bundle));
            if !self.state.observe(now, false) {
                return false;
            }
            let bytes = path.as_os_str().as_bytes();
            let mut report = Report::default();
            // SAFETY: inline aligned cell, exact-sized report, borrowed original
            // FDs and bounded canonical bytes stay alive for this synchronous call.
            let result = unsafe {
                mrk_xcode_self_begin(
                    self.pointer(),
                    CELL_BYTES,
                    bytes.as_ptr(),
                    bytes.len(),
                    parent.as_raw_fd(),
                    bundle.as_raw_fd(),
                    &mut report,
                )
            };
            // A valid closed input begins the native cell even if PRE refuses.
            self.live = true;
            if !self.returned(result, report, 0, false) {
                return false;
            }
            for phase in 1..=11 {
                if !self.state.observe(Instant::now(), false) {
                    return false;
                }
                let mut report = Report::default();
                // SAFETY: one original initialized cell, sequential fixed phase,
                // same thread, stable borrowed originals, exact out-report.
                let result = unsafe { mrk_xcode_self_step(self.pointer(), phase, &mut report) };
                let ok = self.returned(result, report, phase, false);
                if phase == 10 {
                    self.state.matched = ok && self.report.verified == 1;
                }
                if phase == 11 {
                    self.state.post = ok;
                }
                if !ok {
                    return false;
                }
            }
            self.state.matched && self.state.post && !self.state.failed
        }
        /// Import the Parent's earlier actual failure if present. Contraction
        /// only; this never creates a new cleanup budget. Independent owned CF
        /// references are each released once, including a returned error object.
        pub fn settle(&mut self, parent_first_failure: Option<Instant>) -> bool {
            let now = Instant::now();
            if let Some(first) = parent_first_failure {
                if first > now {
                    self.state.unknown = true;
                    self.state.fail(now);
                } else {
                    self.state.fail(first);
                }
            }
            if self.closing {
                return self.state.settled && !self.state.unknown;
            }
            self.closing = true;
            if !self.state.observe(now, true) {
                return false;
            }
            if self.live {
                for slot in (0..CF_REFERENCES).rev() {
                    if self.report.states[slot] != 2 {
                        continue;
                    }
                    if !self.state.observe(Instant::now(), true) {
                        return false;
                    }
                    let mut report = Report::default();
                    let phase = self.report.phase;
                    // SAFETY: exact original owned slot, never retry a release;
                    // synchronous return tracked separately from signature success.
                    let result =
                        unsafe { mrk_xcode_self_release(self.pointer(), slot as u32, &mut report) };
                    self.returned(result, report, phase, true);
                    // Unknown one slot does not erase other positively known
                    // independent originals; continue while original F admits.
                }
                if !self.state.observe(Instant::now(), true) {
                    return false;
                }
                // SAFETY: native retirement itself rejects live/unknown references.
                let retired = unsafe { mrk_xcode_self_retire(self.pointer()) };
                let at = Instant::now();
                if retired == 1 {
                    self.live = false;
                } else {
                    self.state.unknown = true;
                    self.state.fail(at);
                }
                if !self.state.observe(at, true) {
                    return false;
                }
            }
            self.state.settled = !self.live
                && !self.state.unknown
                && self.report.states.iter().all(|s| matches!(s, 0 | 4));
            self.state.settled
        }
        pub fn accepted(&self) -> bool {
            self.state.accepted_at(Instant::now())
        }
        pub fn settled(&self) -> bool {
            self.state.settled && !self.state.unknown
        }
        pub fn unknown(&self) -> bool {
            self.state.unknown
        }
        pub fn first_failure(&self) -> Option<Instant> {
            self.state.first
        }
        /// Finite public OSStatus only. Never exports raw CFError/user paths.
        pub fn security_status(&self) -> i32 {
            self.report.status
        }
    }
}
#[cfg(target_os = "macos")]
pub use native::SelfSigner;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_path_is_only_bounded_original_setup_image_shape() {
        for good in [
            "/Library/InstallerSandboxes/task/setup/mrk-macos-xcode-setup",
            "/private/tmp/Package Scripts/pkg/setup/mrk-macos-xcode-setup",
        ] {
            assert!(path_accepts(good.as_bytes()));
        }
        for bad in [
            "/setup/mrk-macos-xcode-setup",
            "/tmp/pkg/setup/other",
            "/tmp/pkg/mrk-macos-xcode-setup",
            "/tmp/../setup/mrk-macos-xcode-setup",
            "/tmp//setup/mrk-macos-xcode-setup",
            "tmp/pkg/setup/mrk-macos-xcode-setup",
            "/tmp/pkg/setup/mrk-macos-xcode-setup\0",
            "/a/b/c/d/e/f/g/h/i/setup/mrk-macos-xcode-setup",
        ] {
            assert!(!path_accepts(bad.as_bytes()), "{bad:?}");
        }
        assert!(!path_accepts(
            format!("/tmp/{}/setup/mrk-macos-xcode-setup", "x".repeat(256)).as_bytes()
        ));
        assert!(!path_accepts("/".repeat(4096).as_bytes()));
    }
    #[test]
    fn matched_is_not_accepted_without_post_and_positive_finality() {
        let now = Instant::now();
        let mut s = State::new(
            now + Duration::from_secs(10),
            now + Duration::from_secs(130),
        );
        s.entered = true;
        s.matched = true;
        assert!(!s.accepted_at(now));
        s.post = true;
        assert!(!s.accepted_at(now));
        s.settled = true;
        assert!(s.accepted_at(now));
        s.fail(now);
        assert!(!s.accepted_at(now));
        s.unknown = true;
        assert!(!s.accepted_at(now));
    }
    #[test]
    fn original_cutoffs_contract_and_late_returns_cannot_renew_them() {
        let start = Instant::now();
        let work = start + Duration::from_secs(3600);
        let finish = work + CLEANUP;
        let mut s = State::new(work, finish);
        assert!(s.observe(start, false));
        s.fail(start + Duration::from_secs(2));
        assert_eq!(s.cleanup_end(), start + Duration::from_secs(122));
        s.fail(start + Duration::from_secs(9));
        assert_eq!(s.cleanup_end(), start + Duration::from_secs(122));
        s.fail(start + Duration::from_secs(1));
        assert_eq!(s.cleanup_end(), start + Duration::from_secs(121));
        assert!(!s.observe(start + Duration::from_secs(121), true));
        assert!(s.unknown);
        let mut late = State::new(work, finish);
        assert!(!late.observe(work + Duration::from_secs(80), false));
        assert_eq!(late.first, Some(work));
        assert_eq!(late.cleanup_end(), finish);
        assert!(!late.accepted_at(work + Duration::from_secs(80)));
        // Genuine cleanup may complete under F but cannot permit later work.
        let mut clean_late = State::new(work, finish);
        clean_late.entered = true;
        clean_late.matched = true;
        clean_late.post = true;
        assert!(clean_late.observe(work + Duration::from_secs(1), true));
        clean_late.settled = true;
        assert!(clean_late.settled && !clean_late.unknown);
        assert!(!clean_late.accepted_at(work + Duration::from_secs(1)));
        assert!(!clean_late.accepted_at(work - Duration::from_secs(1)));
    }
    #[test]
    fn regressed_clock_and_invalid_original_tuple_never_finalize() {
        let now = Instant::now();
        let mut s = State::new(now + CLEANUP, now + CLEANUP + CLEANUP);
        assert!(s.observe(now + Duration::from_secs(1), false));
        assert!(!s.observe(now, false));
        assert!(s.unknown);
        for finish in [now, now + Duration::from_secs(241)] {
            let invalid = State::new(now + CLEANUP, finish);
            assert!(invalid.unknown);
            assert!(!invalid.accepted_at(now));
        }
    }
}
