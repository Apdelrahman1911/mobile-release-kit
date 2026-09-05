# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "tmpdir"
require "tempfile"
require "fileutils"
require_relative "../../fastlane/release_support"

class FastlaneReleaseSupportTest < Minitest::Test
  Testers = Struct.new(:google_groups)
  StoreVersion = Struct.new(:release_type, :earliest_release_date)

  def test_shared_android_note_corpus_validates_raw_text_and_files
    corpus = JSON.parse(File.read(File.expand_path("../fixtures/android-release-notes-corpus.json", __dir__), encoding: "UTF-8"))
    Dir.mktmpdir("mrk-notes-") do |temporary|
      root = File.realpath(temporary)
      metadata = File.join(root, "android")
      directory = File.join(metadata, "en-US/changelogs")
      FileUtils.mkdir_p(directory)
      path = File.join(directory, "default.txt")
      %w[valid invalid].each do |group|
        corpus.fetch(group).each do |entry|
          text = entry.fetch("text") * entry.fetch("repeat", 1) + entry.fetch("suffix", "")
          File.binwrite(path, text)
          if group == "valid"
            assert_equal text, MobileReleaseKit.validate_android_release_note(text), entry.fetch("name")
            assert_equal [{ "language" => "en-US", "text" => text }], MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: ["en-US"], version_code: 42), entry.fetch("name")
          else
            assert_raises(MobileReleaseKit::ContractError, entry.fetch("name")) { MobileReleaseKit.validate_android_release_note(text) }
            assert_raises(MobileReleaseKit::ContractError, entry.fetch("name")) { MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: ["en-US"], version_code: 42) }
          end
        end
      end
      corpus.fetch("invalidUtf8").each do |entry|
        File.binwrite(path, [entry.fetch("hex")].pack("H*"))
        assert_raises(MobileReleaseKit::ContractError, entry.fetch("name")) { MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: ["en-US"], version_code: 42) }
      end
    end
  end

  def test_android_note_path_scope_precedence_and_nonregular_inputs
    Dir.mktmpdir("mrk-notes-") do |temporary|
      root = File.realpath(temporary)
      metadata = File.join(root, "android")
      directory = File.join(metadata, "en-US/changelogs")
      FileUtils.mkdir_p(directory)
      fallback = File.join(directory, "default.txt")
      exact = File.join(directory, "42.txt")
      read = -> { MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: ["en-US"], version_code: 42) }
      assert_raises(MobileReleaseKit::ContractError) { read.call }
      File.write(fallback, "Default copy")
      assert_equal "Default copy", read.call.first.fetch("text")
      File.binwrite(exact, "Exact copy\r\n")
      assert_equal "Exact copy\r\n", read.call.first.fetch("text")
      ["", "TODO", "x" * 501].each do |text|
        File.write(exact, text)
        assert_raises(MobileReleaseKit::ContractError) { read.call }
      end
      File.delete(exact)
      [:in_root, :broken, :outside, :directory, :fifo].each do |kind|
        case kind
        when :in_root then File.symlink(fallback, exact)
        when :broken then File.symlink(File.join(root, "absent.txt"), exact)
        when :outside then File.symlink(__FILE__, exact)
        when :directory then Dir.mkdir(exact)
        when :fifo then File.mkfifo(exact)
        end
        begin
          assert_raises(MobileReleaseKit::ContractError, kind.to_s) { read.call }
        ensure
          kind == :directory ? Dir.rmdir(exact) : File.delete(exact)
        end
      end
      moved = File.join(root, "saved")
      File.rename(directory, moved)
      File.symlink(moved, directory)
      assert_raises(MobileReleaseKit::ContractError) { read.call }
      File.delete(directory)
      File.rename(moved, directory)
      [nil, [], ["en-US", "en-US"], ["../../escape"], [1], ["en-US", "fr-FR"]].each do |languages|
        assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: languages, version_code: 42) }
      end
      [nil, "42", 0, 42.0, true, 2_100_000_001].each do |version|
        assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit.android_release_notes(root, metadata_path: metadata, languages: ["en-US"], version_code: version) }
      end
    end
  end

  def version_parser_corpus
    @version_parser_corpus ||= JSON.parse(
      File.read(File.expand_path("../fixtures/version-parser-corpus.json", __dir__), encoding: "UTF-8"),
    )
  end

  def test_closed_tester_assignment_reports_only_presence
    refute MobileReleaseKit.closed_tester_assignment?(Testers.new(nil))
    refute MobileReleaseKit.closed_tester_assignment?(Testers.new([" "]))
    assert MobileReleaseKit.closed_tester_assignment?(
      Testers.new(["release-testers@example.test"]),
    )
  end

  def test_strict_json_rejects_duplicate_input_but_returns_plain_nested_values
    ["{\"a\":1,\"a\":2}", "{\"nested\":[{\"a\":1,\"a\":2}]}"].each do |text|
      assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit.strict_json(text) }
    end
    value = MobileReleaseKit.strict_json('{"nested":[{"category":"before"}]}')
    assert_instance_of Hash, value
    assert_instance_of Hash, value.fetch("nested").first
    copy = value.fetch("nested").first.dup
    copy["category"] = "target"
    assert_equal "target", copy.fetch("category")
    assert_equal "before", value.fetch("nested").first.fetch("category")
    assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit.strict_json('{"fraction":0.5}') }
  end

  def test_safe_path_rejects_symlink_escape_for_reads_and_outputs
    Dir.mktmpdir("mobile-release-root") do |root|
      Dir.mktmpdir("mobile-release-outside") do |outside|
        File.write(File.join(root, "inside.txt"), "inside")
        File.symlink(outside, File.join(root, "escape"))

        assert_equal(
          File.join(File.realpath(root), "inside.txt"),
          MobileReleaseKit.safe_path(root, "inside.txt"),
        )
        assert_raises(MobileReleaseKit::ContractError) do
          MobileReleaseKit.safe_path(root, "escape/input.txt", must_exist: false)
        end
        assert_raises(MobileReleaseKit::ContractError) do
          MobileReleaseKit.safe_path(root, "escape", must_exist: true)
        end
      end
    end
  end

  def test_manual_app_store_release_requires_manual_without_schedule
    assert MobileReleaseKit.manual_app_store_release?(StoreVersion.new("MANUAL", nil))
    refute MobileReleaseKit.manual_app_store_release?(StoreVersion.new("AFTER_APPROVAL", nil))
    refute MobileReleaseKit.manual_app_store_release?(
      StoreVersion.new("MANUAL", "2026-09-01T00:00:00Z"),
    )
    refute MobileReleaseKit.manual_app_store_release?(StoreVersion.new(nil, nil))
  end

  def test_secret_environment_values_are_not_normalized
    environment = { "SECRET" => "  password with edge whitespace\t" }
    assert_equal(
      "  password with edge whitespace\t",
      MobileReleaseKit.required_environment(environment, "SECRET", strip: false),
    )
    assert_equal(
      "password with edge whitespace",
      MobileReleaseKit.required_environment(environment, "SECRET", strip: true),
    )
    assert_raises(MobileReleaseKit::ContractError) do
      MobileReleaseKit.required_environment({ "SECRET" => "" }, "SECRET", strip: false)
    end
  end

  def test_parses_xcconfig_comments_and_configured_keys
    path = File.expand_path("fixtures/version.xcconfig", __dir__)
    version = MobileReleaseKit.release_version(
      path,
      name_key: "APP_VERSION_NAME",
      build_key: "APP_BUILD_NUMBER",
    )

    assert_equal({ marketing: "1.2.3", build: 123 }, version)
  end

  def test_rejects_duplicate_keys
    Tempfile.create("mobile-release-version") do |file|
      file.write("VERSION_NAME=1.0\nVERSION_NAME=2.0\nVERSION_CODE=1\n")
      file.flush

      assert_raises(MobileReleaseKit::ContractError) do
        MobileReleaseKit.release_version(
          file.path,
          name_key: "VERSION_NAME",
          build_key: "VERSION_CODE",
        )
      end
    end
  end

  def test_rejects_non_positive_build_number
    Tempfile.create("mobile-release-version") do |file|
      file.write("VERSION_NAME=1.0\nVERSION_CODE=0\n")
      file.flush

      assert_raises(MobileReleaseKit::ContractError) do
        MobileReleaseKit.release_version(
          file.path,
          name_key: "VERSION_NAME",
          build_key: "VERSION_CODE",
        )
      end
    end
  end

  def test_release_version_matches_shared_valid_corpus
    version_parser_corpus.fetch("valid").each do |entry|
      Tempfile.create("mobile-release-version") do |file|
        file.write(entry.fetch("text"))
        file.flush
        assert_equal(
          { marketing: entry.fetch("marketing"), build: entry.fetch("build") },
          MobileReleaseKit.release_version(
            file.path,
            name_key: "VERSION_NAME",
            build_key: "BUILD_NUMBER",
          ),
          entry.fetch("name"),
        )
      end
    end
  end

  def test_release_version_rejects_shared_invalid_corpus
    version_parser_corpus.fetch("invalid").each do |entry|
      Tempfile.create("mobile-release-version") do |file|
        file.write(entry.fetch("text"))
        file.flush
        assert_raises(MobileReleaseKit::ContractError, entry.fetch("name")) do
          MobileReleaseKit.release_version(
            file.path,
            name_key: "VERSION_NAME",
            build_key: "BUILD_NUMBER",
          )
        end
      end
    end
  end
end
