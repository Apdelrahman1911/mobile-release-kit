# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "tmpdir"
require "tempfile"
require_relative "../../fastlane/release_support"

class FastlaneReleaseSupportTest < Minitest::Test
  Testers = Struct.new(:google_groups)
  StoreVersion = Struct.new(:release_type, :earliest_release_date)

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
