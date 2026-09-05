# frozen_string_literal: true

# Regenerate credential-free Python/Ruby boundary fixtures, never Store data:
# bundle exec ruby tests/workflow/export_apple_contract_fixtures.rb /tmp/apple-contract.json
# Compare the result with tests/fixtures/apple-store-contract.json. The selected
# lane harnesses install a Faraday test adapter that rejects unknown endpoints.
require_relative "test_apple_lanes"
require_relative "test_apple_production_lane"
require_relative "../../fastlane/apple_production"
require "zlib"

abort "usage: #{$PROGRAM_NAME} NEW_OUTPUT.json" unless ARGV.length == 1
destination = File.expand_path(ARGV.fetch(0))
abort "output already exists" if File.exist?(destination) || File.symlink?(destination)

# The imported files expose the real lane harnesses. Run only the explicitly
# selected scenarios below; this utility is not another Minitest suite runner.
Minitest::Runnable.runnables.clear
samples = {}
clock = 0
MobileReleaseKit::AppleProduction.prepend(Module.new do
  define_method(:now) { clock }
  define_method(:sleep) { |seconds| clock += seconds }
end)

def capture_case(klass, stage)
  test = klass.new("cross_language_contract_export")
  test.setup
  authority = test.instance_variable_get(:@authority)
  authority["callerPath"] = ".github/workflows/mobile-#{stage}.yml"
  authority["reusablePath"] = ".github/workflows/reusable-#{stage}.yml"
  ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(authority)
  if test.is_a?(AppleProductionLaneTest)
    # Keep screenshot part traffic on the same synthetic Store as JSON:API.
    MobileReleaseKit::AppleAssetUpload.stub(:put, test.instance_variable_get(:@service).method(:upload)) { yield test }
  else
    yield test
  end
  root = test.instance_variable_get(:@root)
  documents = %w[precondition intent receipt].to_h do |name|
    [name, JSON.parse(File.read(File.join(root, "#{name}.json")))]
  end
  # No private HTTP request/response bodies, review inputs, journals, tokens,
  # signed binaries or asset-upload URLs are included in these public samples.
  serialized = JSON.generate(documents)
  forbidden = %w[contactFirstName contactEmail demoAccountName demoAccountPassword]
  abort "sample leaked private review fields" if forbidden.any? { |field| serialized.include?(%Q("#{field}")) }
  documents
ensure
  test&.teardown
end

def screenshot(path, color)
  chunk = ->(name, bytes) { [bytes.bytesize].pack("N") + name + bytes + [Zlib.crc32(name + bytes)].pack("N") }
  bytes = "\x89PNG\r\n\x1a\n".b + chunk.call("IHDR", [750, 1334, 8, 2, 0, 0, 0].pack("NNCCCCC")) +
          chunk.call("IDAT", Zlib::Deflate.deflate(("\0" + color.chr * (750 * 3)) * 1334)) + chunk.call("IEND", "")
  FileUtils.mkdir_p(File.dirname(path))
  File.binwrite(path, bytes)
end

# The lane harness itself uses Time.stub to advance its simulated clock. Two
# nested Minitest stubs of the same method corrupt each other's restore alias.
# Install only the deterministic default here; each real harness may still
# replace/advance it for polling and current-upload eligibility checks.
original_now = Time.method(:now)
Time.define_singleton_method(:now) { Time.utc(2026, 1, 1) }
begin
  SecureRandom.stub(:hex, ->(bytes = 16) { "f" * (bytes * 2) }) do
    %w[candidate candidate-retry external external-retry external-available].each do |name|
      stage = name.start_with?("candidate") ? "candidate" : "external-testing"
      samples[name] = capture_case(AppleReleaseLanesTest, stage) do |test|
        service = test.instance_variable_get(:@service)
        service.visible = false if stage == "candidate"
        if name == "external-available"
          # Model a fresh external dispatch after asynchronous Beta Review.
          # Do not relabel the earlier immutable pending receipt as available.
          authority = test.instance_variable_get(:@authority)
          authority["runId"] = "112"
          ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(authority)
          service.add("betaAppReviewSubmissions", "review-approved", "betaReviewState" => "APPROVED")
          service.link(service.resources.fetch("builds").fetch("build-1"), "betaAppReviewSubmission", "betaAppReviewSubmissions", "review-approved")
          service.attributes("buildBetaDetails", "detail-1")["externalBuildState"] = "IN_BETA_TESTING"
        end
        test.prepare(stage)
        if name == "candidate-retry"
          test.retry_process(cross_run: true)
          digest = test.instance_variable_get(:@intent_digest)
          ipa = test.instance_variable_get(:@payload).fetch("artifacts").first.fetch("sha256")
          ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{digest}:#{ipa}"
        elsif name == "external-retry"
          test.recover_external
          next
        end
        test.execute
      end
    end

    %w[production production-retry production-receipt-recovery production-screenshot-retry production-automatic-appinfo-retry].each do |name|
      samples[name] = capture_case(AppleProductionLaneTest, "production-submit") do |test|
        if name == "production-receipt-recovery"
          test.test_receipt_publication_failure_after_store_success_recovers_final_state_without_another_mutation
          next
        end
        if name == "production-screenshot-retry"
          root = test.instance_variable_get(:@root)
          %w[en-US de-DE].each_with_index do |locale, index|
            screenshot(File.join(root, "release/store/ios/screenshots", locale, "APP_IPHONE_47/01.png"), index + 1)
          end
        elsif name == "production-automatic-appinfo-retry"
          service = test.instance_variable_get(:@service)
          service.resources.fetch("appInfos").delete("info-editable")
          service.resources.fetch("appInfoLocalizations").delete_if { |_id, record| service.parent_id(record, "appInfo") == "info-editable" }
        end
        test.prepare
        if name.end_with?("-retry")
          authority = test.instance_variable_get(:@authority)
          authority["attempt"] = 2
          ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(authority)
          test.fresh_process
          test.assert_raises(MobileReleaseKit::ContractError) { test.lane }
          confirmation = test.journal.fetch("history").last.fetch("confirmation")
          authority["runId"] = "444"
          authority["attempt"] = 1
          ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(authority)
          ENV["MOBILE_RELEASE_RECOVERY_RUN_ID"] = "333"
          ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = confirmation
          test.fresh_process
        end
        test.lane
        test.assert_observed_manual_submission
        test.assert_private_values_excluded
      end
    end
  end
ensure
  Time.define_singleton_method(:now, original_now)
end

payload = { "format" => "mrk-synthetic-apple-contract-v1", "cases" => samples }
File.write(destination, JSON.pretty_generate(payload) + "\n", mode: "wx")
puts "Wrote #{samples.length} synthetic Store contract cases to #{destination}"
