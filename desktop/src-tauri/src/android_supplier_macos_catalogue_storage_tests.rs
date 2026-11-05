//! DATA-only representation checks; never original-custody or native evidence.
use super::*;
use std::collections::BTreeSet;

struct Stream { bytes: usize, hash: Sha256 }
impl std::io::Write for Stream {
    fn write(&mut self, raw: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(raw.len()).ok_or(std::io::ErrorKind::InvalidData)?;
        if self.bytes > REFERENCE_STREAM_BYTES { return Err(std::io::ErrorKind::InvalidData.into()); }
        self.hash.update(raw); Ok(raw.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn check<T: Serialize + ?Sized>(value: &T, expected: &serde_json::Value) {
    let mut stream = Stream { bytes: 0, hash: Sha256::new() };
    serde_json::to_writer(&mut stream, value).unwrap();
    assert_eq!(stream.bytes as u64, expected["bytes"].as_u64().unwrap());
    assert_eq!(format!("{:x}", stream.hash.finalize()), expected["sha256"].as_str().unwrap());
}
fn section<'a>(oracle: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    let rows = oracle["sections"].as_array().unwrap();
    assert_eq!(rows.iter().filter(|r| r["name"] == name).count(), 1);
    rows.iter().find(|r| r["name"] == name).unwrap()
}
#[test]
fn actual_decoded_arrays_and_full_reference_match_frozen_public_serde() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!("../../../tests/desktop/data/macos-android-catalogue-typed-oracle.json")).unwrap();
    assert_eq!(oracle["schemaVersion"], 1);
    let profiles = oracle["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    for (reference, expected) in [(&REFERENCES[0], &profiles[0]), (&intel_catalogue::REFERENCES[0], &profiles[1])] {
        assert_eq!(reference.profile, expected["profile"].as_str().unwrap());
        check(reference, &expected["reference"]);
        let mut seen = BTreeSet::new();
        for (index, archive) in reference.archives.iter().enumerate() {
            let name = format!("CAT_A{index}"); let pin = section(expected, &name);
            assert_eq!(archive.members.len() as u64, pin["count"].as_u64().unwrap());
            check(archive.members, pin); assert!(seen.insert(name));
        }
        macro_rules! table {
            ($name:literal, $value:expr) => {{
                let pin = section(expected, $name);
                assert_eq!($value.len() as u64, pin["count"].as_u64().unwrap());
                check($value, pin); assert!(seen.insert($name.to_owned()));
            }};
        }
        table!("CAT_SOURCES", reference.source_members);
        table!("CAT_BINDINGS", reference.source_bindings);
        table!("CAT_PAYLOAD", reference.payload);
        table!("CAT_CLASSES", reference.classes);
        table!("CAT_ALIASES", reference.aliases);
        table!("CAT_DIRECTORIES", reference.directories);
        for (ordinal, class) in reference.classes.iter().enumerate() {
            if let FileClass::JvmArchive { native_members } = class {
                if native_members.is_empty() { continue; }
                let name = format!("CAT_N{ordinal}"); let pin = section(expected, &name);
                assert_eq!(native_members.len() as u64, pin["count"].as_u64().unwrap());
                check(*native_members, pin); assert!(seen.insert(name));
            }
        }
        assert_eq!(seen.len(), expected["sections"].as_array().unwrap().len());
        for pin in expected["sections"].as_array().unwrap() { assert!(seen.contains(pin["name"].as_str().unwrap())); }
    }
}
#[test]
fn decoded_storage_keeps_both_profile_roster_and_payload_pointers() {
    for (profile, reference) in [(Profile::MacArm64, &REFERENCES[0]), (Profile::MacX64, &intel_catalogue::REFERENCES[0])] {
        prepare_compiled_catalogue_for(profile);
        for jdk in [JdkLayout::Bundle, JdkLayout::HomeInSameBundle] {
            let selected = recipe_for(profile, &SourceLayouts { jdk, jdk_vendor: reference.observed_jdk_vendor, jdk_version: reference.observed_jdk_version }).unwrap();
            let roster = selected.source_roster();
            assert!(std::ptr::eq(roster.members, reference.source_members));
            assert!(std::ptr::eq(roster.trees, reference.trees));
            assert!(std::ptr::eq(roster.support, reference.support));
            assert!(std::ptr::eq(roster.archive_members, reference.support_members));
            assert!(std::ptr::eq(roster.optional_sdk_metadata, &sdk_metadata::OPTIONAL));
            tests::complete_compiled_observations(reference, |observations, provider| {
                let proposal = selected.finalize_proposal(&"a".repeat(32), 501, &observations, provider).unwrap();
                assert!(std::ptr::eq(proposal.payload_map(), reference.payload));
                assert!(proposal.retained_bytes().unwrap() <= selected.working_reservation_bytes().unwrap());
            });
        }
    }
}

// Tiny fixed envelopes only: no full production pack is cloned/leaked. The
// entire finite malformed suite retains under 64 KiB of inert byte fixtures.
fn retain(raw: Vec<u8>) -> &'static [u8] { Box::leak(raw.into_boxed_slice()) }
fn put(raw: &mut [u8], at: usize, value: u32) { raw[at..at+4].copy_from_slice(&value.to_le_bytes()); }
fn tiny_strings() -> Vec<u8> {
    let mut raw = b"MRKSTR01".to_vec();
    for value in [1u32, 2, 0, 0, 1] { raw.extend_from_slice(&value.to_le_bytes()); }
    raw.push(b'a'); raw
}
fn tiny_records(kind: u8, record: &[u8]) -> Vec<u8> {
    let keys = [(1u8,0u16),(1,1),(1,2),(1,3),(1,4),(1,5),(2,0),(3,0),(4,0),(5,0),(6,0),(7,0),(8,0)];
    let stride = |k| match k { 1|2=>32, 3|7=>16, 4=>48, 5=>24, 6=>40, 8=>4, _=>unreachable!() };
    assert_eq!(record.len(), stride(kind));
    let base = 24+keys.len()*20; let mut raw = vec![0; base]; raw[..8].copy_from_slice(b"MRKTBL01");
    put(&mut raw,8,1); put(&mut raw,12,keys.len() as u32); put(&mut raw,16,base as u32);
    let mut offset=base;
    for (i,(k,index)) in keys.into_iter().enumerate() {
        let at=24+i*20; raw[at]=k; raw[at+2..at+4].copy_from_slice(&index.to_le_bytes()); put(&mut raw,at+4,stride(k) as u32);
        let count=u32::from(k==kind && index==0); put(&mut raw,at+8,count); put(&mut raw,at+12,offset as u32);
        let length=count*stride(k) as u32; put(&mut raw,at+16,length); offset+=length as usize;
    }
    raw.extend_from_slice(record); raw
}
fn refuses(run: impl FnOnce() + std::panic::UnwindSafe) { assert!(std::panic::catch_unwind(run).is_err()); }
#[test]
fn actual_safe_decoder_refuses_finite_malformed_envelopes_and_records() {
    let strings = catalogue_binary::Strings::new(retain(tiny_strings()),1);
    let valid=tiny_strings();
    for offset in [0usize,8,12,16,20,24] {
        let mut bad=valid.clone(); bad[offset..offset+4].fill(255);
        refuses(|| { catalogue_binary::Strings::new(retain(bad),1); });
    }
    let mut utf8=valid.clone(); *utf8.last_mut().unwrap()=255;
    refuses(|| { catalogue_binary::Strings::new(retain(utf8),1); });
    refuses(|| { catalogue_binary::Strings::new(retain(valid.clone()),2); });
    let records=tiny_records(8,&0u32.to_le_bytes());
    for offset in [0usize,8,12,16,20,24,25,28,32,36,40] {
        let mut bad=records.clone(); bad[offset..offset+4].fill(255);
        refuses(|| { catalogue_binary::Tables::new(retain(bad),1); });
    }
    refuses(|| { catalogue_binary::Tables::new(retain(records.clone()),2); });
    for (kind,offset) in [(1,4),(1,5),(1,7),(2,0),(2,1),(2,2),(2,28),(3,0),(3,1),(3,2),(3,3),(4,20),(4,21),(4,40),(5,0),(5,1),(5,2),(5,4),(5,8),(6,20),(6,21),(6,22),(7,0),(8,0)] {
        let stride=match kind {1|2=>32,3|7=>16,4=>48,5=>24,6=>40,8=>4,_=>unreachable!()};
        let mut record=vec![0u8;stride]; record[offset]=255;
        let tables=catalogue_binary::Tables::new(retain(tiny_records(kind,&record)),1);
        refuses(|| { match kind {
            1=>{catalogue_binary::official::<1>(tables,strings,0);},
            2=>{catalogue_binary::sources::<1>(tables,strings,0,&[&[0o755]]);},
            3=>{catalogue_binary::bindings::<1>(tables,strings,0);},
            4=>{catalogue_binary::payload::<1>(tables,strings,0,CAT_PROJECTED);},
            5=>{catalogue_binary::classes::<1>(tables,strings,0,&[],&[&[]]);},
            6=>{catalogue_binary::nested::<1>(tables,strings,0,&[]);},
            7=>{catalogue_binary::aliases::<1>(tables,strings,0);},
            8=>{catalogue_binary::directories::<1>(tables,strings,0);},
            _=>unreachable!(),
        }});
    }
    let mut header_class=vec![0u8;24]; header_class[0]=7;
    put(&mut header_class,12,1); put(&mut header_class,16,1); put(&mut header_class,20,32);
    let good=catalogue_binary::Tables::new(retain(tiny_records(5,&header_class)),1);
    let accepted=catalogue_binary::classes::<1>(good,strings,0,&[0;64],&[&[]]);
    assert!(matches!(accepted[0],FileClass::MachO(_)));
    for (offset,value) in [(8,64),(12,0),(12,4097),(16,64),(20,31),(20,16417)] {
        let mut bad=header_class.clone(); put(&mut bad,offset,value);
        let tables=catalogue_binary::Tables::new(retain(tiny_records(5,&bad)),1);
        refuses(|| { catalogue_binary::classes::<1>(tables,strings,0,&[0;64],&[&[]]); });
    }
    accepted_variant_records_reach_specific_guards();
}

// Every variant below is decoded successfully before its own selected field is
// corrupted. Expected caught panics retain their ordinary bounded hook output.
fn accepted_variant_records_reach_specific_guards() {
    let strings = catalogue_binary::Strings::new(retain(tiny_strings()), 1);
    let tables = |kind, row: &[u8]| catalogue_binary::Tables::new(retain(tiny_records(kind, row)), 1);
    let mut official = vec![0u8; 32]; official[5] = 1;
    let accepted = catalogue_binary::official::<1>(tables(1, &official), strings, 0);
    assert!(matches!(accepted[0].disposition, ArchiveDisposition::SealedSupport(SupportAsset::BundletoolJar)));
    official[6] = 255;
    refuses(|| { catalogue_binary::official::<1>(tables(1, &official), strings, 0); });

    for origin in [1u8, 2, 3] {
        let mut row = vec![0u8; 48]; row[20] = origin;
        if origin == 3 { row[22] = 1; }
        let accepted = catalogue_binary::payload::<1>(tables(4, &row), strings, 0, CAT_PROJECTED);
        match origin {
            1 => assert!(matches!(accepted[0].origin, PayloadOrigin::DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar)))),
            2 => assert!(matches!(accepted[0].origin, PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::Platform35Revision2))),
            3 => assert!(matches!(accepted[0].origin, PayloadOrigin::MemberOfSameOriginalArchive { asset: SupportAsset::Aapt2OsxJar, .. })),
            _ => unreachable!(),
        }
        row[if origin == 2 { 23 } else { 22 }] = 255;
        refuses(|| { catalogue_binary::payload::<1>(tables(4, &row), strings, 0, CAT_PROJECTED); });
    }

    for tag in [5u8, 6] {
        let mut row = vec![0u8; 24]; row[0] = tag;
        if tag == 6 { put(&mut row, 12, 1); put(&mut row, 16, 1); put(&mut row, 20, 32); }
        let accepted = catalogue_binary::classes::<1>(tables(5, &row), strings, 0, &[0; 64], &[&[]]);
        if tag == 5 { assert!(matches!(accepted[0], FileClass::SdkBash(policy::Sdk35File::D8))); }
        else { assert!(matches!(accepted[0], FileClass::SdkLegacyIntel(policy::Sdk35File::D8, _))); }
        row[1] = 255;
        refuses(|| { catalogue_binary::classes::<1>(tables(5, &row), strings, 0, &[0; 64], &[&[]]); });
    }

    let mut jvm = vec![0u8; 24]; jvm[0] = 8;
    let accepted = catalogue_binary::classes::<1>(tables(5, &jvm), strings, 0, &[], &[&[]]);
    assert!(matches!(&accepted[0], FileClass::JvmArchive { native_members } if native_members.is_empty()));
    put(&mut jvm, 4, 1);
    refuses(|| { catalogue_binary::classes::<1>(tables(5, &jvm), strings, 0, &[], &[&[]]); });

    let mut nested = vec![0u8; 40]; nested[21] = 1;
    put(&mut nested, 28, 1); put(&mut nested, 32, 1); put(&mut nested, 36, 32);
    let accepted = catalogue_binary::nested::<1>(tables(6, &nested), strings, 0, &[0; 64]);
    assert!(matches!(accepted[0].kind, NativeResourceKind::Arm64) && accepted[0].header.is_some());
    for (offset, value) in [(20, 255), (21, 255)] {
        let mut bad = nested.clone(); bad[offset] = value;
        refuses(|| { catalogue_binary::nested::<1>(tables(6, &bad), strings, 0, &[0; 64]); });
    }
    for (offset, value) in [(24, 64), (28, 0), (28, 4097), (32, 64), (36, 31), (36, 16417)] {
        let mut bad = nested.clone(); put(&mut bad, offset, value);
        refuses(|| { catalogue_binary::nested::<1>(tables(6, &bad), strings, 0, &[0; 64]); });
    }

    let source = [0u8; 32];
    let accepted = catalogue_binary::sources::<1>(tables(2, &source), strings, 0, &[&[0o755]]);
    assert!(matches!(accepted[0].kind, SourceKindSpec::Directory { modes } if modes == [0o755]));
    for invalid_modes in [&[][..], &[0o1000][..], &[0o644, 0o644][..]] {
        refuses(|| { catalogue_binary::sources::<1>(tables(2, &source), strings, 0, retain_modes(invalid_modes)); });
    }
}
fn retain_modes(values: &[u32]) -> &'static [&'static [u32]] {
    let values: &'static [u32] = Box::leak(values.to_vec().into_boxed_slice());
    Box::leak(vec![values].into_boxed_slice())
}

// Added immutable fixture storage is below16KiB; existing finite owned helpers
// remain unchanged. No production pack, new leak, or runtime parser is added.
const fn chunk_put<const N: usize>(raw: &mut [u8; N], at: usize, value: u32) {
    let bytes = value.to_le_bytes(); let mut i = 0;
    while i < 4 { raw[at + i] = bytes[i]; i += 1; }
}
const fn chunk_strings(profile: u32) -> [u8; 414] {
    let mut raw = [0; 414]; let magic = *b"MRKSTR01"; let mut i = 0;
    while i < 8 { raw[i] = magic[i]; i += 1; }
    chunk_put(&mut raw, 8, profile); chunk_put(&mut raw, 12, 66);
    i = 1;
    while i <= 66 { chunk_put(&mut raw, 16 + i * 4, ((i - 1) * 2) as u32); i += 1; }
    i = 1;
    while i < 66 { raw[284 + (i - 1) * 2] = b'A' + (i / 10) as u8; raw[285 + (i - 1) * 2] = b'0' + (i % 10) as u8; i += 1; }
    raw
}
const fn chunk_bad_string(case: u8) -> [u8; 414] {
    let mut raw = chunk_strings(1);
    if case == 0 { raw[284 + 31 * 2] = 255; }
    else if case == 1 { raw[284 + 31 * 2] = b'A'; }
    else { chunk_put(&mut raw, 16 + 33 * 4, 61); }
    raw
}
const fn chunk_long_predecessor() -> [u8; 2335] {
    let mut raw = [b'a'; 2335]; let original = chunk_strings(1); let mut i = 0;
    while i < 284 { raw[i] = original[i]; i += 1; }
    chunk_put(&mut raw, 16 + 31 * 4, 0); chunk_put(&mut raw, 16 + 32 * 4, 2049);
    chunk_put(&mut raw, 16 + 33 * 4, 2051); chunk_put(&mut raw, 16 + 66 * 4, 2051);
    raw
}
const fn chunk_records<const N: usize>(profile: u32, selected: u8) -> [u8; N] {
    let mut raw = [0; N]; let magic = *b"MRKTBL01"; let mut i = 0;
    while i < 8 { raw[i] = magic[i]; i += 1; }
    chunk_put(&mut raw, 8, profile); chunk_put(&mut raw, 12, 13); chunk_put(&mut raw, 16, 284);
    let mut next = 284; i = 0;
    while i < 13 {
        let kind = if i < 6 { 1 } else { (i - 4) as u8 };
        let step = match kind { 1 | 2 => 32, 3 | 7 => 16, 4 => 48, 5 => 24, 6 => 40, 8 => 4, _ => 0 };
        let count = if kind == selected { 33 } else { 0 };
        let at = 24 + i * 20; raw[at] = kind; raw[at + 2] = if i < 6 { i as u8 } else { 0 };
        chunk_put(&mut raw, at + 4, step as u32); chunk_put(&mut raw, at + 8, count);
        chunk_put(&mut raw, at + 12, next as u32); chunk_put(&mut raw, at + 16, count * step as u32);
        next += count as usize * step; i += 1;
    }
    assert!(next == N);
    i = 0;
    while i < 33 {
        if selected == 8 { chunk_put(&mut raw, 284 + i * 4, 1); }
        else if selected == 7 {
            let at = 284 + i * 16; chunk_put(&mut raw, at, 1); chunk_put(&mut raw, at + 4, 2);
            chunk_put(&mut raw, at + 8, 3); chunk_put(&mut raw, at + 12, i as u32);
        }
        i += 1;
    }
    if selected == 5 {
        raw[284 + 31 * 24] = 8;
        let at = 284 + 32 * 24; raw[at] = 7;
        chunk_put(&mut raw, at + 8, 0); chunk_put(&mut raw, at + 12, 1);
        chunk_put(&mut raw, at + 16, 1); chunk_put(&mut raw, at + 20, 32);
    }
    raw
}
static CHUNK_STRINGS_ARM: [u8; 414] = chunk_strings(1);
static CHUNK_STRINGS_INTEL: [u8; 414] = chunk_strings(2);
static CHUNK_BAD_UTF8: [u8; 414] = chunk_bad_string(0);
static CHUNK_BAD_ORDER: [u8; 414] = chunk_bad_string(1);
static CHUNK_BAD_OFFSET: [u8; 414] = chunk_bad_string(2);
static CHUNK_LONG_PREDECESSOR: [u8; 2335] = chunk_long_predecessor();
static CHUNK_DIR_ARM: [u8; 416] = chunk_records(1, 8);
static CHUNK_DIR_INTEL: [u8; 416] = chunk_records(2, 8);
static CHUNK_CLASS_ARM: [u8; 1076] = chunk_records(1, 5);
static CHUNK_CLASS_INTEL: [u8; 1076] = chunk_records(2, 5);
static CHUNK_ALIAS_ARM: [u8; 812] = chunk_records(1, 7);
static CHUNK_ALIAS_INTEL: [u8; 812] = chunk_records(2, 7);
#[test]
fn string_chunk_boundaries_validate_real_bytes_and_predecessors() {
    for (raw, profile) in [(&CHUNK_STRINGS_ARM[..], 1), (&CHUNK_STRINGS_INTEL[..], 2)] {
        for ordinal in 0..3 { catalogue_binary::test_string_unit(raw, profile, ordinal); }
        catalogue_binary::test_string_coverage(raw, profile, &[0, 1, 2]);
        for order in [&[0, 1][..], &[0, 1, 1][..], &[1, 0, 2][..], &[0, 1, 2, 0][..]] {
            refuses(|| catalogue_binary::test_string_coverage(raw, profile, order));
        }
        refuses(|| catalogue_binary::test_string_unit(raw, profile, 3));
    }
    for raw in [&CHUNK_BAD_UTF8[..], &CHUNK_BAD_ORDER[..], &CHUNK_BAD_OFFSET[..], &CHUNK_LONG_PREDECESSOR[..]] {
        refuses(|| catalogue_binary::test_string_unit(raw, 1, 1));
    }
}
#[test]
fn section_chunk_coverage_preserves_empty_tail_and_metadata() {
    for (records, strings, profile) in [(&CHUNK_DIR_ARM[..], &CHUNK_STRINGS_ARM[..], 1), (&CHUNK_DIR_INTEL[..], &CHUNK_STRINGS_INTEL[..], 2)] {
        catalogue_binary::test_directory_chunks(records, strings, profile, 0);
        catalogue_binary::test_directory_chunks(records, strings, profile, 10);
        let (foreign, foreign_profile) = if profile == 1 { (&CHUNK_STRINGS_INTEL[..], 2) } else { (&CHUNK_STRINGS_ARM[..], 1) };
        refuses(|| catalogue_binary::test_mixed_profile(records, foreign, profile, foreign_profile));
        for case in [1, 2, 3, 4, 5, 6, 7, 8, 9, 11] {
            refuses(|| catalogue_binary::test_directory_chunks(records, strings, profile, case));
        }
    }
}
#[test]
fn noncopy_chunk_assembly_preserves_fields_and_final_references() {
    catalogue_binary::test_noncopy_chunks(&CHUNK_CLASS_ARM, &CHUNK_ALIAS_ARM, &CHUNK_STRINGS_ARM, 1);
    catalogue_binary::test_noncopy_chunks(&CHUNK_CLASS_INTEL, &CHUNK_ALIAS_INTEL, &CHUNK_STRINGS_INTEL, 2);
}
