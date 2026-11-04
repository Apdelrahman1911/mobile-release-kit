    #[test]
    fn rejects_duplicates_at_every_object_depth() {
        assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json(br#"{"a":{"b":1,"b":2}}"#).is_err());
    }
    #[test]
    fn rejects_nonfinite_and_invalid_utf8() {
        for bytes in [b"NaN".as_slice(), b"Infinity", b"1e9999", &[0xff]] { assert!(strict_json(bytes).is_err()); }
    }
    #[test]
    fn macos_manifest_node_bounds_are_separate_from_ipc() {
        for count in [8_622usize,16_384] {
            let files: Vec<_>=(0..count).map(|i|json!({"path":format!("store/files/{i:05}"),
                "sha256":"a".repeat(64),"size":1})).collect();
            let runtime=serde_json::to_vec(&json!({"files":files})).unwrap();
            assert!(strict_macos_runtime_manifest_json(&runtime).is_ok());
            assert!(strict_json(&runtime).is_err());
            let files: Vec<_>=(0..count).map(|i|json!({"path":format!("runtime/store/files/{i:05}"),
                "sha256":"a".repeat(64),"size":1,"executable":false})).collect();
            let installed=serde_json::to_vec(&json!({"files":files})).unwrap();
            assert!(strict_macos_inventory_json(&installed).is_ok());
            assert!(strict_json(&installed).is_err());
        }
        let nodes=serde_json::to_vec(&vec![Value::Null;120_000]).unwrap();
        assert!(strict_macos_runtime_manifest_json(&nodes).is_err());
        let nodes=serde_json::to_vec(&vec![Value::Null;150_000]).unwrap();
        assert!(strict_macos_inventory_json(&nodes).is_err());
        for raw in [br#"{"files":[],"files":[]}"#.as_slice(),b"NaN",b"{} {}",&[0xff]] {
            assert!(strict_macos_runtime_manifest_json(raw).is_err());
            assert!(strict_macos_inventory_json(raw).is_err());
        }
        assert!(strict_macos_inventory_json(&vec![b' ';crate::macos_install_record::INVENTORY_LIMIT+1]).is_err());
        assert_eq!((NODE_LIMIT,DEPTH_LIMIT),(20_000,32));
    }
