//! Synthetic in-memory parser contracts only. No selected file, native owner,
//! service, signing, credential, whole-app feature or allocator qualification.
use super::*;
use super::super::{inspect as observe, FileKind, JSON_LIMIT};
use serde_json::{json, Value};
use std::cell::Cell;

fn wrapped(value: &str) -> String { format!("<plist version=\"1.0\">{value}</plist>") }
fn bundle(value: &str) -> String { wrapped(&format!("<dict><key>BUNDLE_ID</key><string>{value}</string></dict>")) }
fn wire(bytes: &[u8]) -> Value {
    let result = observe(FileKind::IosFirebase, bytes, &mut || false).ok().expect("unexpected interruption");
    serde_json::to_value(result).expect("bounded observation DTO")
}
fn observed(bytes: &[u8], root: &str, id: Value) {
    assert_eq!(wire(bytes), json!({"status":"observed","byteCount":bytes.len(),"format":"firebase-plist","encoding":"xml",
        "document":{"root":root,"bundleId":id}}));
}
fn refusal(bytes: &[u8], status: &str, reason: &str) {
    assert_eq!(wire(bytes), json!({"status":status,"reason":reason}));
}
fn malformed(bytes: &[u8]) { refusal(bytes, "rejected", "malformed-container"); }
fn limit(bytes: &[u8]) { refusal(bytes, "unavailable", "parser-limit"); }

#[test]
fn ordinary_apple_xml_checks_all_scalars_and_returns_only_the_small_projection() {
    let source = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE {APPLE_DOCTYPE}>
<plist version="1.0"><dict>
  <key>BUNDLE_ID</key><string>org.synthetic.ios</string>
  <key>PRIVATE_KEY_CANARY</key><string>PRIVATE_VALUE_CANARY</string>
  <key>ignored</key><array>
    <string/><string>&lt;&amp;&gt;&apos;&quot;</string>
    <integer>-9223372036854775808</integer><integer>18446744073709551615</integer><integer>0xFF</integer>
    <real>-1.25e3</real><date>2026-09-26T01:02:03.123Z</date>
    <data>AAEC /w==</data><data/>
    <true/><false></false><true><!-- inert --></true>
    <dict><key>same</key><string>inert</string></dict>
    <dict><key>same</key><array/></dict>
  </array>
</dict></plist><!-- inert tail -->
"#);
    observed(source.as_bytes(), "dictionary", json!("org.synthetic.ios"));
    let output = wire(source.as_bytes()).to_string();
    for private in ["PRIVATE_KEY_CANARY", "PRIVATE_VALUE_CANARY", "ignored", "inert"] { assert!(!output.contains(private)); }
    // The BOM belongs to captured bytes, never to a fabricated scalar span or
    // a rewritten DOCTYPE. Both canonical quote styles are inertly supported.
    for doctype in [APPLE_DOCTYPE, APPLE_DOCTYPE_SINGLE] {
        let source = format!("\u{feff}<!DOCTYPE {doctype}>{}", bundle("org.synthetic.ios"));
        observed(source.as_bytes(), "dictionary", json!("org.synthetic.ios"));
    }
    let source = format!("\u{feff}<?xml version='1.0' encoding='utf-8' standalone='yes'?>{}", wrapped("<dict/>"));
    observed(source.as_bytes(), "dictionary", Value::Null);
}

#[test]
fn root_and_missing_or_nonstring_bundle_are_mechanical_facts_not_core_policy() {
    for root in ["<array/>", "<string>org.synthetic</string>", "<integer>1</integer>", "<real>1.0</real>",
        "<date>2026-09-26T00:00:00Z</date>", "<data/>", "<true/>", "<false/>",
        "<array><dict><key>BUNDLE_ID</key><string>nested</string></dict></array>"] {
        observed(wrapped(root).as_bytes(), "other", Value::Null);
    }
    for contents in ["", "<key>bundle_id</key><string>wrong case</string>",
        "<key> BUNDLE_ID </key><string>not folded</string>",
        "<key>nested</key><dict><key>BUNDLE_ID</key><string>nested</string></dict>"] {
        observed(wrapped(&format!("<dict>{contents}</dict>")).as_bytes(), "dictionary", Value::Null);
    }
    for value in ["<integer>1</integer>", "<array/>", "<dict><key>BUNDLE_ID</key><string>nested</string></dict>", "<true/>", "<data/>"] {
        observed(wrapped(&format!("<dict><key>BUNDLE_ID</key>{value}</dict>")).as_bytes(), "dictionary", Value::Null);
    }
    for id in ["", " org.MixedCase ", "not an identifier"] { observed(bundle(id).as_bytes(), "dictionary", json!(id)); }
}

#[test]
fn decoded_keys_and_projection_use_xml_eol_rules_without_other_folding() {
    let source = wrapped("<dict><key>BUND&#76;E_<!-- join -->ID</key><string> org\r\nMixed\rID&#13;&#xA;&amp;&lt;&gt;&apos;&quot;é😀 </string></dict>");
    observed(source.as_bytes(), "dictionary", json!(" org\nMixed\nID\r\n&<>'\"é😀 "));
    // No NFC, case, whitespace, or reference-after-EOL re-normalization.
    let source = wrapped("<dict><key>é</key><true/><key>e\u{301}</key><false/><key>Case</key><true/><key>case</key><false/><key>x\r</key><true/><key>x&#13;</key><false/></dict>");
    observed(source.as_bytes(), "dictionary", Value::Null);
    observed(bundle("]]&#62;").as_bytes(), "dictionary", json!("]]>"));
}

#[test]
fn normalized_duplicates_are_rejected_in_every_dictionary_not_across_siblings() {
    for keys in [("BUNDLE_ID", "BUND&#76;E_ID"), ("x\r\ny", "x\ny"), ("x\ry", "x&#10;y"),
        ("é😀", "&#233;&#x1F600;"), ("joined", "join<!-- c -->ed"), ("&amp;", "&#38;"), ("", "")] {
        let dictionary = format!("<dict><key>{}</key><string>early</string><key>{}</key><string>later</string></dict>", keys.0, keys.1);
        for root in [dictionary.clone(), format!("<array>{dictionary}</array>"),
            format!("<dict><key>ignored</key>{dictionary}</dict>")] { malformed(wrapped(&root).as_bytes()); }
    }
    observed(wrapped("<array><dict><key>same</key><true/></dict><dict><key>same</key><false/></dict></array>").as_bytes(), "other", Value::Null);
}

#[test]
fn ignored_bad_scalars_and_a_bad_tail_discard_an_early_bundle_id() {
    for bad in ["<integer>private-canary</integer>", "<integer>18446744073709551616</integer>",
        "<integer>-9223372036854775809</integer>", "<integer>0x0x1</integer>",
        "<integer>0x<!-- inert -->0&#120;1</integer>", "<real>private-canary</real>",
        "<date>2026-02-30T00:00:00Z</date>", "<date>private-canary</date>",
        "<data>PRIVATE%CANARY</data>", "<data>QQ=</data>", "<true> </true>", "<false>&#32;</false>",
        "<string><string>nested</string></string>", "<dict><key>odd</key></dict>",
        "<array><key>wrong parent</key></array>", "<unknown/>"] {
        let source = wrapped(&format!("<dict><key>BUNDLE_ID</key><string>org.early</string><key>ignored</key>{bad}</dict>"));
        malformed(source.as_bytes());
    }
    for tail in ["private-canary", "<dict/>", "</plist>", "<!-- unterminated", "\u{feff}"] {
        malformed(format!("{}{tail}", bundle("org.early")).as_bytes());
    }
}

#[test]
fn wrapper_framing_declaration_and_all_attributes_are_closed() {
    for source in [" ", "<dict/>", "<plist><dict/></plist>", "<plist version=\"1.0\"/>",
        "<plist version=\"1.0\"><dict/><array/></plist>", "<plist version=\"1.0\"><key>root</key></plist>",
        "<plist version=\"1.0\"><dict></array></plist>", "<plist version=\"1.0\"><dict/>",
        "<plist version=\"1.0\"><dict><plist version=\"1.0\"><dict/></plist></dict></plist>",
        "<plist version=\"1.0\" version=\"1.0\"><dict/></plist>",
        "<plist version=\"1.0\"version=\"1.0\"><dict/></plist>",
        "<plist version=1.0><dict/></plist>", "<plist version=\"1.0\" xmlns=\"private\"><dict/></plist>",
        "<p:plist version=\"1.0\"><dict/></p:plist>",
        "<plist version=\"1.0\"><dict extra=\"private\"/></plist>",
        "<plist version=\"1.0\"><string extra=\"private\"/></plist>",
        "<plist version=\"1.0\"><dict>not whitespace</dict></plist>",
        "<plist version=\"1.0\"><dict><key>key</key></dict></plist>"] { malformed(source.as_bytes()); }
    for declaration in ["<?xml?>", "<?xml encoding=\"UTF-8\" version=\"1.0\"?>",
        "<?xml version=\"1.0\"encoding=\"UTF-8\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"standalone=\"yes\"?>",
        "<?xml version=\"1.0\" version=\"1.0\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\" standalone=\"yes\" encoding=\"UTF-8\"?>", "<?xml version=\"1.0\" standalone=\"maybe\"?>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" extra=\"private\"?>",
        " <?xml version=\"1.0\"?>", "<!-- before --><?xml version=\"1.0\"?>",
        "<?xml version=\"1.0\"?><?xml version=\"1.0\"?>"] { malformed(format!("{declaration}{}", wrapped("<dict/>")).as_bytes()); }
    for comment in ["<!-- two--hyphens -->", "<!-- trailing--->"] { malformed(format!("{comment}{}", bundle("early")).as_bytes()); }
}

#[test]
fn binary_encoding_and_other_xml_variants_have_fixed_unavailable_results() {
    for bytes in [b"bplist00private".as_slice(), b"\xff\xfe<\0", b"\xfe\xff\0<", b"\xff\xfe\0\0<\0\0\0", b"\0\0\xfe\xff\0\0\0<"] {
        refusal(bytes, "unavailable", "unsupported-variant");
    }
    for before in ["<?xml version=\"1.1\"?>", "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
        "<!DOCTYPE plist SYSTEM \"https://invalid.example/no-fetch\">",
        "<!DOCTYPE plist [<!ENTITY private \"not expanded\">]>", "<?private never-executed?>"] {
        refusal(format!("{before}{}", wrapped("<dict/>")).as_bytes(), "unavailable", "unsupported-variant");
    }
    refusal(format!("<!doctype {APPLE_DOCTYPE}>{}", wrapped("<dict/>")).as_bytes(), "unavailable", "unsupported-variant");
    for body in ["<string>&private;</string>", "<string><![CDATA[private]]></string>", "<string><?private x?></string>"] {
        refusal(wrapped(body).as_bytes(), "unavailable", "unsupported-variant");
    }
    refusal(b"<plist version=\"2.0\"><dict/></plist>", "unavailable", "unsupported-variant");
    // Repeated or misplaced DTD is invalid XML framing, not a parser fallback.
    malformed(format!("<!DOCTYPE {APPLE_DOCTYPE}><!DOCTYPE {APPLE_DOCTYPE}>{}", wrapped("<dict/>")).as_bytes());
}

#[test]
fn utf8_legal_xml_characters_references_and_raw_text_terminators_are_checked() {
    for text in ["\0", "\u{b}", "\u{1f}", "\u{fffe}", "\u{ffff}", "&#0;", "&#xD800;", "&#x110000;", "&#xFFFE;",
        "&#;", "&#x;", "&#xGG;", "&#-1;", "&", "&amp", "]]>"] { malformed(bundle(text).as_bytes()); }
    for raw in [b"\xff".as_slice(), b"\xc0\xaf", b"\xed\xa0\x80", b"\xe2\x82"] {
        let mut source = b"<plist version=\"1.0\"><string>".to_vec(); source.extend_from_slice(raw); source.extend_from_slice(b"</string></plist>");
        malformed(&source);
    }
    for ch in ['\0', '\u{b}', '\u{fffe}'] { malformed(format!("<!-- {ch} -->{}", wrapped("<dict/>")).as_bytes()); }
    observed(bundle("\t\n\r &#9;&#10;&#13;&#x10FFFF;").as_bytes(), "dictionary", json!("\t\n\n \t\n\r\u{10ffff}"));
}

#[test]
fn markup_and_reference_spelling_caps_are_inclusive() {
    for size in [MARKUP_LIMIT, MARKUP_LIMIT + 1] {
        let wrappers = [
            format!("<plist version=\"1.0\"{}><dict/></plist>", " ".repeat(size - "<plist version=\"1.0\">".len())),
            format!("<plist version=\"1.0\"><dict/></plist{}>", " ".repeat(size - "</plist>".len())),
            format!("<?xml version=\"1.0\"{}?>{}", " ".repeat(size - "<?xml version=\"1.0\"?>".len()), wrapped("<dict/>")),
            format!("<!DOCTYPE {APPLE_DOCTYPE}{}>{}", " ".repeat(size - APPLE_DOCTYPE.len() - "<!DOCTYPE >".len()), wrapped("<dict/>")),
            format!("<!--{}-->{}", "c".repeat(size - 7), wrapped("<dict/>")),
        ];
        for source in wrappers {
            if size == MARKUP_LIMIT { observed(source.as_bytes(), "dictionary", Value::Null); } else { limit(source.as_bytes()); }
        }
    }
    observed(bundle(&format!("&#{}65;", "0".repeat(REFERENCE_LIMIT - 5))).as_bytes(), "dictionary", json!("A"));
    limit(bundle(&format!("&#{}65;", "0".repeat(REFERENCE_LIMIT - 4))).as_bytes());
    limit(wrapped(&format!("<{}>", "n".repeat(MARKUP_LIMIT))).as_bytes());
}

#[test]
fn a_scalar_span_includes_original_tags_comments_and_references_across_events() {
    let plain = format!("<string>{}</string>", "x".repeat(SCALAR_SPAN_LIMIT - 17));
    assert_eq!(plain.len(), SCALAR_SPAN_LIMIT);
    observed(wrapped(&plain).as_bytes(), "other", Value::Null);
    limit(wrapped(&plain.replacen("<string>", "<string>x", 1)).as_bytes());
    let mut body = "x<!--c-->&#65;".repeat(500);
    assert!(body.len() < SCALAR_SPAN_LIMIT - 17);
    body.push_str(&"x".repeat(SCALAR_SPAN_LIMIT - 17 - body.len()));
    let source = wrapped(&format!("<string>{body}</string>"));
    observed(source.as_bytes(), "other", Value::Null);
    limit(wrapped(&format!("<string>{body}x</string>")).as_bytes());
    assert!(scalar_value(Tag::Integer, b"<integer>1</integer>", &mut || false).is_ok());
    for bytes in [b"<string>wrong type</string>".as_slice(), b"<integer>1</integer><integer>2</integer>", b"<integer>1</integer>private"] {
        assert!(matches!(scalar_value(Tag::Integer, bytes, &mut || false), Err(Failure::Malformed)));
    }
}

#[test]
fn numeric_key_and_projection_bounds_are_charged_before_the_library_or_copy() {
    observed(wrapped(&format!("<integer>{}</integer>", "0".repeat(NUMBER_DATE_LIMIT))).as_bytes(), "other", Value::Null);
    for tag in ["integer", "real", "date"] {
        limit(wrapped(&format!("<{tag}>{}</{tag}>", "0".repeat(NUMBER_DATE_LIMIT + 1))).as_bytes());
    }
    observed(wrapped(&format!("<dict><key>{}</key><true/></dict>", "k".repeat(KEY_LIMIT))).as_bytes(), "dictionary", Value::Null);
    limit(wrapped(&format!("<dict><key>{}</key><true/></dict>", "k".repeat(KEY_LIMIT + 1))).as_bytes());
    let id = "é".repeat(BUNDLE_LIMIT / 2);
    observed(bundle(&id).as_bytes(), "dictionary", json!(id));
    limit(bundle(&format!("{id}x")).as_bytes());
    let escaped = bundle(&"&quot;".repeat(BUNDLE_LIMIT));
    observed(escaped.as_bytes(), "dictionary", json!("\"".repeat(BUNDLE_LIMIT)));
    assert!(serde_json::to_vec(&wire(escaped.as_bytes())).unwrap().len() <= PLIST_OBSERVATION_LIMIT);
    assert!(matches!(reserved::<u8>(usize::MAX), Err(Failure::Limit(Limit::Allocation))));
}

#[test]
fn depth_counts_the_root_value_as_one_and_nodes_count_keys() {
    let deep = format!("{}<string/>{}", "<array>".repeat(DEPTH_LIMIT - 1), "</array>".repeat(DEPTH_LIMIT - 1));
    observed(wrapped(&deep).as_bytes(), "other", Value::Null);
    limit(wrapped(&format!("<array>{deep}</array>")).as_bytes());
    // 1 root array + 6666 * (dict + key + string) + 1 string = 20,000.
    let values = "<dict><key>same</key><string/></dict>".repeat(6666);
    observed(wrapped(&format!("<array>{values}<string/></array>")).as_bytes(), "other", Value::Null);
    limit(wrapped(&format!("<array>{values}<string/><string/></array>")).as_bytes());
}

#[test]
fn event_count_includes_comments_and_eof_but_never_creates_a_value_tree() {
    let source = format!("{}{}", "<!---->".repeat(EVENT_COUNT - 4), wrapped("<array/>"));
    observed(source.as_bytes(), "other", Value::Null);
    limit(format!("<!---->{source}").as_bytes());
}

#[test]
fn material_limit_is_inclusive_and_long_tail_tokens_cannot_bypass_event_limits() {
    let mut source = wrapped("<dict/>");
    let comment = format!("<!--{}-->", "c".repeat(MARKUP_LIMIT - 7));
    source.push_str(&comment.repeat((JSON_LIMIT - source.len()) / comment.len()));
    source.push_str(&" ".repeat(JSON_LIMIT - source.len()));
    assert_eq!(source.len(), JSON_LIMIT);
    observed(source.as_bytes(), "dictionary", Value::Null);
    source.push(' '); refusal(source.as_bytes(), "unavailable", "material-limit");
    limit(format!("{}{}", wrapped("<dict/>"), " ".repeat(EVENT_LIMIT + 1)).as_bytes());
    refusal(b"", "rejected", "empty-file");
}

#[test]
fn duplicate_work_and_key_arena_limits_are_precharged() {
    fn dictionary(count: usize, length: usize) -> String {
        let mut source = String::from("<dict>");
        for index in 0..count { source.push_str(&format!("<key>{index:0length$}</key><true/>")); }
        source.push_str("</dict>"); wrapped(&source)
    }
    observed(dictionary(632, 4).as_bytes(), "dictionary", Value::Null);
    limit(dictionary(633, 4).as_bytes()); // 200,028 prospective comparisons.
    observed(dictionary(181, KEY_LIMIT).as_bytes(), "dictionary", Value::Null);
    limit(dictionary(182, KEY_LIMIT).as_bytes()); // Compared-byte cap dominates.
    // All-key bytes/slots are otherwise dominated by source/node/work bounds.
    // These private state tests check refusal before append, not a native RSS.
    let mut guard = Guard::new(KEY_BYTES_LIMIT, &mut || false).ok().unwrap();
    assert_eq!(guard.keys.capacity(), KEY_BYTES_LIMIT);
    assert_eq!(guard.slots.capacity(), NODE_LIMIT);
    assert_eq!(guard.scalar.capacity(), SCALAR_LIMIT);
    guard.keys.resize(KEY_BYTES_LIMIT, 0);
    guard.scalar.push(b'x');
    assert!(matches!(guard.key(1, &mut || false), Err(Failure::Limit(Limit::KeyStorage))));
    assert_eq!(guard.keys.len(), KEY_BYTES_LIMIT); assert!(guard.slots.is_empty());
    guard.keys.clear();
    guard.slots.resize(NODE_LIMIT, KeySlot { start: 0, length: 0, next: NO_KEY, _reserved: 0 });
    assert!(matches!(guard.key(1, &mut || false), Err(Failure::Limit(Limit::KeyStorage))));
    assert!(guard.keys.is_empty()); assert_eq!(guard.slots.len(), NODE_LIMIT);
}

#[test]
fn source_exposes_only_a_bounded_chunk_and_never_recovers_a_latched_failure() {
    let bytes = vec![b'x'; EVENT_LIMIT * 3]; let mut stop = || false;
    let mut source = SliceSource::new(&bytes, &mut stop);
    source.event(None).ok().unwrap();
    for _ in 0..2 { assert_eq!(source.fill_buf().unwrap().len(), STOP_STRIDE); source.consume(STOP_STRIDE); }
    assert_eq!(source.position, EVENT_LIMIT);
    assert_eq!(source.fill_buf().unwrap_err().kind(), io::ErrorKind::Other);
    assert!(matches!(source.result(), Err(Failure::Limit(Limit::Lexical))));
    source.event(None).ok().unwrap();
    assert_eq!(source.fill_buf().unwrap_err().kind(), io::ErrorKind::Other);
    let mut source = SliceSource::new(&bytes, &mut stop);
    source.consume(1); // A reader may not consume a slice it was never shown.
    assert_eq!(source.position, 0);
    assert!(matches!(source.result(), Err(Failure::Limit(Limit::Lexical))));
}

#[test]
fn scalar_source_allowance_does_not_reset_with_each_event() {
    let bytes = vec![b'x'; EVENT_LIMIT * 3]; let mut stop = || false;
    let mut source = SliceSource::new(&bytes, &mut stop);
    source.event(None).ok().unwrap();
    assert_eq!(source.fill_buf().unwrap().len(), STOP_STRIDE); source.consume(17);
    source.event(Some(0)).ok().unwrap();
    assert_eq!(source.end, SCALAR_SPAN_LIMIT);
    while source.position < SCALAR_SPAN_LIMIT {
        let size = source.fill_buf().unwrap().len(); source.consume(size);
        source.event(Some(0)).ok().unwrap();
    }
    assert_eq!(source.fill_buf().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(source.position, SCALAR_SPAN_LIMIT);
}

#[test]
fn selected_readers_cannot_retry_stop_as_interrupted_io_or_skip_final_eof_stop() {
    let cancelled = Cell::new(false); let mut stop = || cancelled.get();
    let mut source = SliceSource::new(b"x", &mut stop);
    assert_eq!(source.fill_buf().unwrap(), b"x"); source.consume(1);
    cancelled.set(true);
    assert_eq!(source.fill_buf().unwrap_err().kind(), io::ErrorKind::Other);
    cancelled.set(false);
    assert!(matches!(source.result(), Err(Failure::Interrupted)));
    assert_eq!(source.fill_buf().unwrap_err().kind(), io::ErrorKind::Other);
    let mut calls = 0;
    assert!(matches!(scalar_value(Tag::String, b"<string>body</string>", &mut || { calls += 1; calls == 4 }), Err(Failure::Interrupted)));
    assert!(calls < 16); // No selected-reader retry loop.
}

#[test]
fn long_unterminated_tokens_stop_at_source_exposure_before_private_buffer_growth() {
    for prefix in ["", "<", "<!--", "&"] {
        let bytes = format!("{prefix}{}", "x".repeat(64 * 1024));
        let mut stop = || false;
        let mut reader = Reader::from_reader(SliceSource::new(bytes.as_bytes(), &mut stop));
        reader.get_mut().event(None).ok().unwrap();
        let mut scratch = reserved(EVENT_LIMIT).ok().unwrap();
        assert!(reader.read_event_into(&mut scratch).is_err());
        assert_eq!(reader.get_ref().position, EVENT_LIMIT);
        assert!(matches!(reader.get_mut().result(), Err(Failure::Limit(Limit::Lexical))));
        assert!(scratch.len() <= EVENT_LIMIT && scratch.capacity() <= EVENT_LIMIT);
    }
}

#[test]
fn stop_wins_at_every_polled_boundary_in_success_refusal_and_original_scalar_work() {
    let mut sources = vec![bundle("org.synthetic"), wrapped("<data>QUJDRA==</data>"),
        wrapped("<dict><key>BUNDLE_ID</key><string>early</string><key>bad</key><integer>private</integer></dict>"),
        wrapped("<string>&private;</string>"), "bplist00private".into(), String::new(),
        "x".repeat(JSON_LIMIT + 1), wrapped(&format!("<string>{}</string>", "x".repeat(SCALAR_SPAN_LIMIT - 17)))];
    for prefix in ["<string>", "<", "<!--", "&"] { sources.push(wrapped(&format!("{prefix}{}", "x".repeat(EVENT_LIMIT + 5000)))); }
    for source in sources {
        let mut total = 0;
        let _ = observe(FileKind::IosFirebase, source.as_bytes(), &mut || { total += 1; false });
        assert!(total >= 2);
        for boundary in 1..=total {
            let mut calls = 0;
            let result = observe(FileKind::IosFirebase, source.as_bytes(), &mut || { calls += 1; calls == boundary });
            assert!(result.is_err(), "STOP boundary {boundary} of {total} was not interruption");
        }
    }
}
