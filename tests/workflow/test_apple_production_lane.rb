# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "apple_production_fixture"

# Executes the real Fastfile lane and production adapter. Only credential
# acquisition and HTTP transport are synthetic; metadata loading, intent checks,
# SDK requests, Store reconciliation, journals and atomic receipt writes are real.
class AppleProductionLaneTest < Minitest::Test
  LANE = :ios_app_store_submit

  def setup
    @environment = ENV.to_h
    @old_client = Spaceship::ConnectAPI.client
    @root = File.realpath(Dir.mktmpdir("mrk-production-lane-"))
    FileUtils.mkdir_p(File.join(@root, "release/store/review"))
    File.write(File.join(@root, "release/store/review/ios-notes.txt"), "Lane private review instructions")
    %w[en-US fr-FR de-DE].each do |locale|
      directory = File.join(@root, "release/store/ios", locale)
      FileUtils.mkdir_p(directory)
      File.write(File.join(directory, "description.txt"), "Lane approved description #{locale}")
      File.write(File.join(directory, "name.txt"), "Lane approved app #{locale}")
      File.write(File.join(directory, "release_notes.txt"), "Lane approved notes #{locale}")
    end
    File.write(File.join(@root, "release/store/ios/copyright.txt"), "Lane approved copyright")
    File.write(File.join(@root, "release/store/ios/primary_category.txt"), "PRODUCTIVITY")
    File.write(File.join(@root, "version.properties"), "VERSION_NAME=1.2.3\nVERSION_CODE=123\n")
    File.write(File.join(@root, "release/mobile-release.json"), JSON.generate(
      "version" => { "source" => "version.properties", "nameKey" => "VERSION_NAME", "buildKey" => "VERSION_CODE" },
      "ios" => { "bundleId" => "test.example.release", "appStoreAppId" => "12345",
                 "review" => { "demoAccountRequired" => true, "usesNonExemptEncryption" => false } },
      "metadata" => { "root" => "release/store", "iosLocales" => %w[en-US fr-FR de-DE] },
    ))
    @private = {
      "contactFirstName" => "LanePrivateFirst", "contactLastName" => "LanePrivateLast",
      "contactEmail" => "lane-review@example.test", "contactPhone" => "+12025550124",
      "demoAccountRequired" => true, "demoAccountName" => "lane-private-demo",
      "demoAccountPassword" => "lane-private-password", "notes" => "Lane private review instructions",
    }
    @authority = {
      "workflow" => "Synthetic production", "runId" => "333", "attempt" => 1,
      "callerPath" => ".github/workflows/mobile-production-submit.yml", "reusableRepository" => "test/toolkit",
      "reusablePath" => ".github/workflows/reusable-production-submit.yml", "reusableCommit" => "a" * 40,
      "event" => "workflow_dispatch", "headSha" => "b" * 40, "ref" => "refs/heads/main",
    }
    ENV.update(
      "MOBILE_RELEASE_APP_ROOT" => @root, "MOBILE_RELEASE_CONFIG_PATH" => "release/mobile-release.json",
      "MOBILE_RELEASE_OPERATION" => LANE.to_s, "MOBILE_RELEASE_PLATFORM" => "ios",
      "MOBILE_RELEASE_APP_IDENTITY" => "test.example.release", "MOBILE_RELEASE_OPERATION_INTENT_PATH" => "intent.json",
      "MOBILE_RELEASE_APPLE_STATE_PATH" => "journal.json",
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64" => Base64.strict_encode64("k" * 32),
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION" => "fictional-v1",
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME" => @private.fetch("contactFirstName"),
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME" => @private.fetch("contactLastName"),
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL" => @private.fetch("contactEmail"),
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE" => @private.fetch("contactPhone"),
      "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME" => @private.fetch("demoAccountName"),
      "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD" => @private.fetch("demoAccountPassword"),
      "MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON" => JSON.generate(@authority),
    )
    ENV.delete("MOBILE_RELEASE_RECOVERY_RUN_ID")
    ENV.delete("MOBILE_RELEASE_RECOVERY_CONFIRMATION")
    @service = AppleProductionFixture.new
    Spaceship::ConnectAPI.client = @service.client
    fresh_process
  end

  def teardown
    Spaceship::ConnectAPI.client = @old_client
    ENV.replace(@environment)
    FileUtils.remove_entry(@root)
  end

  def fresh_process
    verbose = $VERBOSE
    $VERBOSE = nil
    @fastfile = Fastlane::FastFile.new(File.expand_path("../../fastlane/Fastfile", __dir__))
    @fastfile.define_singleton_method(:asc_api_key) { {} }
    test = self
    %i[upload_to_app_store deliver upload_to_testflight build_app gym].each do |action|
      @fastfile.define_singleton_method(action) { |*_, **_| test.flunk("production lane invoked forbidden aggregate/build action #{action}") }
    end
  ensure
    $VERBOSE = verbose
  end

  def lane = @fastfile.runner.lanes.fetch(nil).fetch(LANE).call({})
  def read_document(name) = JSON.parse(File.read(File.join(@root, name)))
  def receipt = read_document("receipt.json")
  def journal = read_document("journal.json")
  def copy(value) = Marshal.load(Marshal.dump(value))

  def prepare
    ENV["MOBILE_RELEASE_STORE_MODE"] = "prepare"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "precondition.json"
    lane
    @precondition = read_document("precondition.json")
    payload = {
      "schemaVersion" => 1, "documentType" => "store-operation-intent", "stage" => "production-submit", "platform" => "ios",
      "storePrecondition" => @precondition, "authorizedBy" => @authority.dup,
      "privateStateCommitments" => @precondition.fetch("snapshot").fetch("privateStateCommitments"),
    }
    @intent_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(payload))
    payload["integrity"] = { "algorithm" => "sha256", "sha256" => @intent_digest }
    File.write(File.join(@root, "intent.json"), JSON.generate(payload))
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "receipt.json"
  end

  def assert_observed_manual_submission
    actual = receipt
    assert_equal 3, actual.fetch("schemaVersion")
    assert_equal "ios_app_store_submit", actual.fetch("operation")
    assert_equal "ios", actual.fetch("platform")
    assert_equal "test.example.release", actual.fetch("appIdentity")
    assert_equal "12345", actual.fetch("appStoreAppId")
    assert_equal "1.2.3", actual.fetch("marketingVersion")
    assert_equal 123, actual.fetch("buildNumber")
    assert_equal "build-1", actual.fetch("buildResourceId")
    assert_equal "VALID", actual.fetch("processingState")
    assert_equal "WAITING_FOR_REVIEW", actual.fetch("submissionState")
    assert_equal "submitted-for-review", actual.fetch("state")
    assert_equal false, actual.fetch("automaticRelease")
    assert_equal @intent_digest, actual.fetch("operationIntentSha256")
    assert_equal "version-target", actual.fetch("appStoreVersionId")
    version = @service.resources.fetch("appStoreVersions").fetch(actual.fetch("appStoreVersionId"))
    assert_equal actual.fetch("buildResourceId"), @service.parent_id(version, "build")
    assert_equal "MANUAL", version.dig("attributes", "releaseType")
    assert_nil version.dig("attributes", "earliestReleaseDate")
    assert_equal actual.fetch("submissionState"), version.dig("attributes", "appVersionState")
    submission = @service.resources.fetch("reviewSubmissions").fetch(actual.fetch("reviewSubmissionId"))
    assert_equal "WAITING_FOR_REVIEW", submission.dig("attributes", "state")
    items = @service.children("reviewSubmissionItems", "reviewSubmission", submission.fetch("id"))
    assert_equal 1, items.length
    assert_equal actual.fetch("appStoreVersionId"), @service.parent_id(items.first, "appStoreVersion")
    final = journal.fetch("history").reverse.find { |entry| entry.fetch("phase") == "committed-and-read-back" }
    assert_equal actual.fetch("appStoreVersionId"), final.fetch("versionId")
    assert_equal actual.fetch("reviewSubmissionId"), final.fetch("reviewSubmissionId")
    assert_equal actual.fetch("storeStateSha256"), final.fetch("storeStateSha256")
    assert_match(/\A[a-f0-9]{64}\z/, actual.fetch("storeStateSha256"))
    assert_equal 0o600, File.stat(File.join(@root, "receipt.json")).mode & 0o777
    details = @service.children("appStoreReviewDetails", "appStoreVersion", "version-target")
    assert_equal @private, details.fetch(0).fetch("attributes")
    assert_empty Dir.glob(File.join(@root, "**", "*.ipa")), "production must never build another IPA"
  end

  def assert_private_values_excluded
    documents = %w[precondition.json intent.json receipt.json journal.json].map { |name| File.read(File.join(@root, name)) }.join("\n")
    secrets = @private.values.grep(String) + [AppleProductionFixture::PRIVATE.fetch("demoAccountPassword"), AppleProductionFixture::PRIVATE.fetch("contactEmail"), ENV.fetch("MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64")]
    secrets.each { |value| refute_includes documents, value }
  end

  def test_real_fastfile_prepares_and_submits_the_exact_candidate_without_bulk_deliver_or_public_release
    unrelated = @service.baseline_records
    prepare
    assert_empty @service.writes
    assert_equal "store-precondition", @precondition.fetch("documentType")
    assert_equal LANE.to_s, @precondition.fetch("operation")
    assert_equal "build-1", @precondition.dig("snapshot", "build", "id")
    assert_nil @precondition.dig("snapshot", "production")
    lane
    assert_equal "accepted", receipt.fetch("result")
    assert_equal @authority, receipt.fetch("authorizedBy")
    assert_equal @authority, receipt.fetch("executedBy")
    assert_observed_manual_submission
    assert_private_values_excluded
    assert_equal unrelated, @service.existing_records_like(unrelated)
    assert_equal 14, @service.writes.length
    assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/reviewSubmissions" }
    assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/reviewSubmissionItems" }
  end

  def test_receipt_publication_failure_after_store_success_recovers_final_state_without_another_mutation
    unrelated = @service.baseline_records
    prepare
    real_link = File.method(:link)
    receipt_path = File.join(@root, "receipt.json")
    File.stub(:link, lambda { |source, destination|
      raise Errno::EIO, "Synthetic raw receipt publication failure" if destination == receipt_path
      real_link.call(source, destination)
    }) do
      assert_raises(Errno::EIO) { lane }
    end
    refute File.exist?(receipt_path)
    assert_empty Dir.glob("#{receipt_path}.tmp-*")
    assert_equal "WAITING_FOR_REVIEW", @service.attributes("appStoreVersions", "version-target").fetch("appVersionState")
    before_retry = copy(@service.writes)
    assert_equal 14, before_retry.length
    original_authority = @authority.dup
    @authority = @authority.merge("attempt" => 2)
    ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(@authority)
    fresh_process
    lane
    assert_equal before_retry, @service.writes, "evidence failure triggered a second Store mutation"
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal original_authority, receipt.fetch("authorizedBy")
    assert_equal @authority, receipt.fetch("executedBy")
    refute receipt.key?("createRetry"), "final-state recovery must not claim a new create authorization"
    assert_observed_manual_submission
    assert_private_values_excluded
    assert_equal unrelated, @service.existing_records_like(unrelated)
  end
end
