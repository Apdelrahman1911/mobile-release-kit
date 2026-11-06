//! Diagnostic DATA only. No paths, native observations, acceptance, or finality.
//! Field order: device, inode, type, permissions, UID, GID, links, size,
//! mtime seconds/nanoseconds, ctime seconds/nanoseconds.
use std::cell::Cell;

pub const FIELD_MASK: u16 = (1 << 12) - 1;
const SAME_OBJECT_MASK: u16 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4) | (1 << 5);
pub const NO_PARENT: u32 = u32::MAX;
pub const WIRE_EXTRA_LIMIT: usize = 128;
pub const SITE_LINE_LIMIT: u32 = 100_000;

pub fn source_site(file: &str, line: u32) -> Option<u32> {
    // Compile-literal file names only; no path is retained or emitted.
    let file_code=match file.rsplit('/').next()? {
        "macos_install.rs"=>0,"macos_applications_native.rs"=>1,
        "macos_noop_recovery_native.rs"=>2,"macos_restore_recovery_native.rs"=>3,
        "macos_fresh_conservation_native.rs"=>4,"macos_app_absence_fixture.rs"=>5,_=>return None,
    };
    (line>0 && line<SITE_LINE_LIMIT).then_some(file_code*SITE_LINE_LIMIT+line)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin { Parent, WriterReadyFrame, WriterResultFrame }

// Counting sink only: do not allocate a second serialized frame just to decide
// whether an optional hint fits the original unchanged transport bound.
pub struct FrameHeadroom { remaining: usize }
impl FrameHeadroom {
    pub fn new(limit: usize) -> Option<Self> {
        Some(Self { remaining: limit.checked_sub(WIRE_EXTRA_LIMIT)? })
    }
}
impl std::io::Write for FrameHeadroom {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self.remaining.checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WriteZero))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

pub fn mismatch(left: [i128; 12], right: [i128; 12]) -> u16 {
    left.into_iter().zip(right).enumerate().fold(0, |mask, (bit, (a, b))|
        mask | if a != b { 1 << bit } else { 0 })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    site: u32,
    pass: u8,
    role: u8,
    original: u32,
    parent: u32,
    category: u8,
    exact: bool,
    held_named: u16,
    held_expected: u16,
}

impl Context {
    // Fixed nine integers are diagnostic hints only. Reject malformed hints
    // without modifying the separately validated worker outcome or reason.
    pub fn from_wire(row: &[u64], original_limit: usize) -> Option<Self> {
        if original_limit > NO_PARENT as usize || row.len() != 9 || row[0]>=6*SITE_LINE_LIMIT as u64
            || row[0]%(SITE_LINE_LIMIT as u64)==0
            || !(1..=2).contains(&row[1]) || row[2] > 9
            || row[3] >= original_limit as u64
            || !(row[4] == NO_PARENT as u64 || row[4] < original_limit as u64)
            || row[5] > 15 || row[6] > 1
            || row[7] > FIELD_MASK as u64 || row[8] > FIELD_MASK as u64 {
            return None;
        }
        let exact = row[6] == 1;
        let held_named = row[7] as u16;
        let held_expected = row[8] as u16;
        if held_named == 0 && (if exact { held_expected == 0 }
            else { held_expected & SAME_OBJECT_MASK == 0 }) {
            return None; // A passing comparison is never a failure record.
        }
        Some(Self { site: row[0] as u32, pass: row[1] as u8, role: row[2] as u8,
            original: row[3] as u32, parent: row[4] as u32, category: row[5] as u8,
            exact, held_named, held_expected })
    }

    pub fn wire(self) -> [u64; 9] {
        [self.site as u64, self.pass as u64, self.role as u64, self.original as u64,
            self.parent as u64, self.category as u64, u64::from(self.exact),
            self.held_named as u64, self.held_expected as u64]
    }

    pub fn line(self, origin: Origin) -> Option<String> {
        let origin=match origin { Origin::Parent=>"parent", Origin::WriterReadyFrame=>"writer-ready-frame",
            Origin::WriterResultFrame=>"writer-result-frame" };
        let line = format!("MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC=origin={};basis=first-observed;site={};pass={};role={};original={};parent={};category={};exact={};heldNamed={};heldExpected={}\n",
            origin, self.site, self.pass, self.role,
            self.original, self.parent, self.category, u8::from(self.exact),
            self.held_named, self.held_expected);
        (line.len() <= 256).then_some(line)
    }
}

pub fn retain_first(slot: &Cell<Option<Context>>, context: Option<Context>) {
    if slot.get().is_none() { slot.set(context); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMIT: usize = 196_608;
    fn row(exact: bool, named: u16, expected: u16) -> [u64; 9] {
        [732, 1, 0, 17, 16, 0, u64::from(exact), named as u64, expected as u64]
    }

    #[test]
    fn distinct_fields_and_comparison_pairs_preserve_every_sampled_scalar() {
        let base = [i64::MIN as i128, u64::MAX as i128, 0o100000, 0o555, 0, 0, 1,
            i64::MAX as i128, -1, 999_999_999, 7, 0];
        assert_eq!(mismatch(base, base), 0);
        for bit in 0..12 {
            let mut other = base;
            other[bit] += 1;
            assert_eq!(mismatch(base, other), 1 << bit);
            assert_eq!(mismatch(other, base), 1 << bit);
        }
        let mut named = base;
        named[1] = 0;
        let mut expected = base;
        expected[10] += 1;
        let data = Context::from_wire(&row(true, mismatch(base, named), mismatch(base, expected)), LIMIT).unwrap();
        assert_eq!(&data.wire()[7..], &[2, 1024]);
    }

    #[test]
    fn diagnostic_masks_match_exact_and_same_object_failure_conditions() {
        for expected in 0..=FIELD_MASK {
            for named in [0, 1, FIELD_MASK] {
                for exact in [false, true] {
                    let original_failed = named != 0 || if exact { expected != 0 }
                        else { expected & SAME_OBJECT_MASK != 0 };
                    assert_eq!(Context::from_wire(&row(exact, named, expected), LIMIT).is_some(), original_failed);
                }
            }
        }
    }

    #[test]
    fn first_failure_is_bounded_and_cannot_be_replaced_by_cleanup() {
        let slot = Cell::new(None);
        let first = Context::from_wire(&row(true, 0, 1024), LIMIT).unwrap();
        let later = Context::from_wire(&row(true, 2, 0), LIMIT).unwrap();
        retain_first(&slot, None);
        retain_first(&slot, Some(first));
        retain_first(&slot, Some(later));
        assert_eq!(slot.get(), Some(first));
        assert!(std::mem::size_of::<Cell<Option<Context>>>() <= 40);
    }

    #[test]
    fn malformed_wire_hints_are_ignored_and_output_has_only_fixed_scalars() {
        let maximum = [599_999, 2, 9, (LIMIT - 1) as u64, NO_PARENT as u64, 15, 1,
            FIELD_MASK as u64, FIELD_MASK as u64];
        let context = Context::from_wire(&maximum, LIMIT).unwrap();
        for origin in [Origin::Parent, Origin::WriterReadyFrame, Origin::WriterResultFrame] {
            let line = context.line(origin).unwrap();
            assert!(line.len() <= 256 && line.is_ascii() && !line.contains('/'));
            assert!(line.ends_with("heldNamed=4095;heldExpected=4095\n"));
        }
        for (field, bad) in [(0, 0), (0, 600_000), (0, 100_000), (1, 0), (1, 3), (2, 10),
            (3, LIMIT as u64), (4, LIMIT as u64), (5, 16), (6, 2), (7, 4096), (8, 4096)] {
            let mut invalid = maximum;
            invalid[field] = bad;
            assert!(Context::from_wire(&invalid, LIMIT).is_none());
        }
        assert!(Context::from_wire(&maximum[..8], LIMIT).is_none());
        assert!(Context::from_wire(&[0; 10], LIMIT).is_none());
        if usize::BITS>32 { assert!(Context::from_wire(&maximum,NO_PARENT as usize+1).is_none()); }
    }

    #[test]
    fn optional_wire_data_cannot_consume_original_frame_headroom() {
        use std::io::Write;
        assert!(FrameHeadroom::new(WIRE_EXTRA_LIMIT-1).is_none());
        let mut exact=FrameHeadroom::new(65536).unwrap();
        exact.write_all(&[0; 65536-WIRE_EXTRA_LIMIT]).unwrap();
        assert!(exact.write_all(&[0]).is_err());
        let mut empty=FrameHeadroom::new(WIRE_EXTRA_LIMIT).unwrap();
        assert!(empty.write_all(&[0]).is_err());
    }

    #[test]
    fn compile_literal_file_codes_disambiguate_included_source_lines() {
        for (code,file) in ["macos_install.rs","macos_applications_native.rs","macos_noop_recovery_native.rs",
            "macos_restore_recovery_native.rs","macos_fresh_conservation_native.rs","macos_app_absence_fixture.rs"].into_iter().enumerate() {
            assert_eq!(source_site(file,732),Some(code as u32*SITE_LINE_LIMIT+732));
            assert_eq!(source_site(&format!("arbitrary/compile/location/{file}"),732),source_site(file,732));
            assert_eq!(source_site(file,0),None);assert_eq!(source_site(file,SITE_LINE_LIMIT),None);
        }
        assert_eq!(source_site("unknown.rs",732),None);
    }
}
