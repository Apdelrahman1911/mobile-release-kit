use super::*;
#[test]
fn original_collector_and_options_parser_accept_only_read_proposal() {
    let ids = format!("{} {}", "1".repeat(32), "2".repeat(32));
    for suffix in ["", " --json"] {
        let args = collect_arguments(
            format!("version-reserve-review {ids} --stdin{suffix}")
                .split_whitespace()
                .map(OsString::from),
        );
        assert!(super::super::recognizes(&args));
        assert!(matches!(
            super::super::parse(&args).unwrap().command,
            super::super::Command::Review { .. }
        ));
    }
    let data=br#"{"reference":"refs/heads/main","increment":"build","newCandidate":false,"acknowledgeLimitations":true}"#;
    assert!(options(data).is_ok());
    assert!(options(&vec![b' '; 513]).is_err());
    for extra in [
        ",\"source\":{}",
        ",\"platform\":\"ios\"",
        ",\"token\":\"not-secret\"",
        ",\"increment\":\"major\"",
    ] {
        let mut bytes = data[..data.len() - 1].to_vec();
        bytes.extend(extra.bytes());
        bytes.push(b'}');
        assert!(options(&bytes).is_err())
    }
    assert!(super::super::parse(
        &format!("version-reserve-review {ids} --stdin --reviewed")
            .split_whitespace()
            .map(OsString::from)
            .collect::<Vec<_>>()
    )
    .is_err());
}
#[test]
fn capabilities_keep_review_distinct_from_separate_reserve_consent() {
    let v: serde_json::Value = serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let cap = &v["versionReservation"];
    assert_eq!(cap["sourceReviewUnderRead"], true);
    assert_eq!(cap["reviewQueriesStore"], false);
    assert_eq!(cap["reserveNeedsSeparateDesktopAllow"], true);
    assert_eq!(cap["commands"].as_array().unwrap().len(), 4);
    assert_eq!(cap["maxRetainedRequests"], 32);
}
