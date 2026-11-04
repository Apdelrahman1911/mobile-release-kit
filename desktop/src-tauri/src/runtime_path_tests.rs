    #[test]
    fn mac_store_paths_are_scoped_and_depth_bounded() {
        let suffix = "bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/lib/fastlane/plugin/%plugin_name%/helper/%plugin_name%_helper.rb.erb";
        assert_eq!(suffix.split('/').count(), 16);
        for suffix in [suffix, "bundle/gems/terminal-notifier/Terminal Notifier/Credits.rtf"] {
            assert!(safe_macos_runtime_path(&format!("store/{suffix}")));
            assert!(safe_macos_install_path(&format!("runtime/store/{suffix}")));
            assert!(!safe_payload_path(&format!("store/{suffix}")));
            assert!(!safe_macos_runtime_path(&format!("python/{suffix}")));
            assert!(!safe_macos_install_path(&format!("app/Contents/{suffix}")));
        }
        assert!(!safe_macos_runtime_path(&format!("store/extra/{suffix}")));
        assert!(!safe_macos_install_path(&format!("runtime/store/extra/{suffix}")));
        for bad in ["../x", "a//b", "a/./b", " space/x", "space /x", "dot./x", "a\\b", "a:b", "a\tb", "NUL.txt", "COM1", "é"] {
            assert!(!safe_macos_runtime_path(&format!("store/{bad}")), "{bad}");
            assert!(!safe_macos_install_path(&format!("runtime/store/{bad}")), "{bad}");
        }
        assert!(!safe_macos_runtime_path("store%/file"));
        assert!(!safe_macos_install_path("runtime/storeish/a b"));
        assert!(safe_payload_path("python/lib/libstdc++.so.6"));
    }
