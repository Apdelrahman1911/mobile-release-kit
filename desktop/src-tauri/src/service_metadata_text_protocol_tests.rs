//! Inert closed DATA parsing/capacity tests, not a native Load or write receipt.
use super::*;
use crate::service_protocol as s;
fn id(n: char) -> Id {
    Id::parse(&n.to_string().repeat(32)).unwrap()
}
fn query() -> Query {
    Query {
        service_instance: id('1'),
        project_id: id('2'),
        request_id: id('3'),
    }
}
fn fields(platform: Platform) -> Fields {
    Fields {
        platform,
        fields: platform
            .ids()
            .iter()
            .map(|id| Field {
                id: (*id).into(),
                text: "Public listing text".into(),
            })
            .collect(),
    }
}
fn envelope(proposal: Fields) -> s::Request {
    s::Request {
        version: s::VERSION,
        request_id: id('4'),
        request: s::RequestBody::MetadataTextPrepare(Prepare {
            origin: query(),
            proposal,
        }),
    }
}
#[test]
fn conventional_complete_ios_and_android_unicode_bundles_cross_old_limit_without_truncation() {
    for (platform, limits) in [
        (Platform::Ios, vec![4000, 100, 2048, 2048, 4000]),
        (Platform::Android, vec![30, 80, 4000]),
    ] {
        let mut proposed = fields(platform);
        for (f, n) in proposed.fields.iter_mut().zip(limits) {
            f.text = "😀".repeat(n);
        }
        let request = envelope(proposed.clone());
        let bytes = s::encode_request(&request).unwrap();
        assert!(bytes.len() > s::REQUEST_BYTES && bytes.len() < REQUEST_BYTES);
        match s::decode_request(&bytes).unwrap().request {
            s::RequestBody::MetadataTextPrepare(p) => assert_eq!(p.proposal, proposed),
            _ => panic!("wrong fixed method"),
        }
        // Escaped surrogate pairs are conventional valid JSON too; not only
        // UTF-8 serialization's smaller representation.
        let escaped = String::from_utf8(bytes)
            .unwrap()
            .replace('😀', "\\ud83d\\ude00");
        assert!(escaped.len() < REQUEST_BYTES);
        assert!(s::decode_request(escaped.as_bytes()).is_ok());
    }
}
#[test]
fn strict_large_entry_refuses_old_methods_duplicates_extras_and_unbounded_containers() {
    let mut proposal = fields(Platform::Ios);
    proposal.fields[0].text = "x".repeat(4000);
    let original = String::from_utf8(s::encode_request(&envelope(proposal)).unwrap()).unwrap();
    assert!(original.len() > 4096);
    for method in [
        "info",
        "observe",
        "request.list",
        "configuration.read",
        "configuration.prepare",
        "configuration.apply",
        "git-remote.prepare",
        "metadata-text.read",
        "metadata-text.apply",
        "metadata-text.status",
        "metadata-text.cancel",
    ] {
        assert!(
            s::decode_request(original.replace("metadata-text.prepare", method).as_bytes())
                .is_err(),
            "{method}"
        );
    }
    for bad in [
        original.replace("\"version\":1", "\"version\":1,\"version\":1"),
        original.replace("\"text\":", "\"text\":\"shadow\",\"text\":"),
        original.replace(
            "\"platform\":\"ios\"",
            "\"platform\":\"ios\",\"root\":\"/foreign\"",
        ),
        original.replace(
            "metadata-text.prepare",
            "metadata-text.prepare\" , \"method\":\"metadata-text.prepare",
        ),
    ] {
        assert!(s::decode_request(bad.as_bytes()).is_err());
    }
    assert!(decode_fields(
        format!(
            "{{\"platform\":\"ios\",\"fields\":[{}]}}",
            vec!["{}"; 129].join(",")
        )
        .as_bytes()
    )
    .is_err());
    assert!(decode_fields(format!("{}0{}", "[".repeat(9), "]".repeat(9)).as_bytes()).is_err());
    assert!(s::decode_request(&vec![b' '; REQUEST_BYTES + 1]).is_err());
}
#[test]
fn ordinary_four_kib_and_complete_field_order_limits_remain_exact() {
    let request = s::Request {
        version: s::VERSION,
        request_id: id('4'),
        request: s::RequestBody::Info(s::Empty {}),
    };
    let mut bytes = s::encode_request(&request).unwrap();
    bytes.resize(s::REQUEST_BYTES, b' ');
    assert!(s::decode_request(&bytes).is_ok());
    bytes.push(b' ');
    assert!(s::decode_request(&bytes).is_err());
    let good = fields(Platform::Android);
    assert!(good.validate().is_ok());
    let mut bad = good.clone();
    bad.fields.swap(0, 1);
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.fields.pop();
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.fields[0] = bad.fields[1].clone();
    assert!(bad.validate().is_err());
    let mut bad = good;
    bad.fields[0].text = "x".repeat(TEXT_BYTES + 1);
    assert!(bad.validate().is_err());
    assert!(decode_fields(br#"{"platform":"android","fields":[],"locale":"en-US"}"#).is_err());
}
#[test]
fn bounded_encoder_counts_real_escaping_before_allocation_and_names_same_eight_callers() {
    let text = "\0".repeat(200);
    let wire = serde_json::to_vec(&text).unwrap();
    assert!(encoded(&text, wire.len() - 1).is_err());
    let exact = encoded(&text, wire.len()).unwrap();
    assert_eq!(exact, wire);
    assert_eq!(exact.capacity(), exact.len());
    assert_eq!(IPC_PEAK, 1_613_824);
    assert_eq!(SMALL_INPUT_PEAK, 196_608 + 2 * std::mem::size_of::<s::Request>());
    assert_eq!(IPC_BACKING, IPC_PEAK + 8 * SMALL_INPUT_PEAK);
    assert_eq!(IPC_BACKING, 3_186_688 + 16 * std::mem::size_of::<s::Request>());
    assert!(IPC_BACKING < 8 * IPC_PEAK);
    assert_eq!(NATIVE_FRAME_BYTES, (768 + 16) * 1024);
    assert_eq!(NATIVE_COMMAND_BYTES, 272 * 1024);
}
#[test]
fn native_load_data_requires_all_paths_hashes_baseline_and_empty_absent_distinction() {
    let platform = Platform::Android;
    let mut o = Observation {
        schema_version: 1,
        platform,
        locale: "en-US".into(),
        metadata_root: "release/store".into(),
        observation_scope: "single-request-non-atomic".into(),
        baseline: Baseline {
            config: DigestData {
                byte_length: 2,
                sha256: sha(b"{}"),
            },
            fields: platform
                .ids()
                .iter()
                .map(|id| BaselineField::Absent { id: (*id).into() })
                .collect(),
        },
        fields: platform
            .ids()
            .iter()
            .map(|id| ObservedField::Absent {
                id: (*id).into(),
                path: format!("release/store/android/en-US/{id}"),
            })
            .collect(),
        assurance: Assurance {
            basis: "static-text".into(),
            project_code_executed: false,
            tools_probed: false,
            credentials_read: false,
            git_observed: false,
            store_contacted: false,
            writes_performed: false,
            release_readiness: "unknown".into(),
        },
    };
    assert!(o.validate().is_ok());
    o.fields[0] = ObservedField::Present {
        id: platform.ids()[0].into(),
        path: "release/store/android/en-US/title.txt".into(),
        text: String::new(),
        byte_length: 0,
        sha256: sha(b""),
    };
    assert!(o.validate().is_err());
    o.baseline.fields[0] = BaselineField::Present {
        id: platform.ids()[0].into(),
        byte_length: 0,
        sha256: sha(b""),
    };
    assert!(o.validate().is_ok());
    let mut bad = o.clone();
    if let ObservedField::Present { path, .. } = &mut bad.fields[0] {
        *path = "release/store/android/en-US/../other.txt".into()
    };
    assert!(bad.validate().is_err());
    let mut bad = o;
    if let ObservedField::Present { text, .. } = &mut bad.fields[0] {
        text.push('x')
    };
    assert!(bad.validate().is_err());
}
