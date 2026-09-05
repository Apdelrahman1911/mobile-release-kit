# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "zlib"
require_relative "apple_production_fixture"
require_relative "../../fastlane/apple_production"
require_relative "../../fastlane/apple_create_retry"

class AppleProductionTest < Minitest::Test
  def setup
    @environment = ENV.to_h
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    @root = File.realpath(Dir.mktmpdir("mrk-apple-production-"))
    @service = AppleProductionFixture.new
    @secret_environment = {
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64" => Base64.strict_encode64("k" * 32),
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION" => "fictional-test-v1",
    }
    @private = AppleProductionFixture::PRIVATE.merge("contactFirstName" => "Approved", "notes" => "Approved private notes")
    @time = 0
    @journals = []
    @snapshot = nil
    @intent_digest = "f" * 64
    @authorized = { "runId" => "101", "attempt" => 1, "event" => "workflow_dispatch" }
    @authority = @authorized.dup
    @next_recovery_run = 200
    %w[en-US fr-FR de-DE].each do |locale|
      FileUtils.mkdir_p(File.join(@root, locale))
      File.write(File.join(@root, locale, "description.txt"), "Approved description #{locale}")
      File.write(File.join(@root, locale, "name.txt"), "Approved name #{locale}")
      File.write(File.join(@root, locale, "release_notes.txt"), "Approved notes #{locale}")
    end
    File.write(File.join(@root, "copyright.txt"), "Approved copyright")
    File.write(File.join(@root, "primary_category.txt"), "PRODUCTIVITY")
  end

  def teardown
    ENV.replace(@environment)
    FileUtils.remove_entry(@root)
  end

  def copy(value) = Marshal.load(Marshal.dump(value))

  def reset_case
    teardown
    setup
  end

  def build
    value = @service.attributes("builds", "build-1")
    { "id" => "build-1", "appId" => "12345", "marketingVersion" => "1.2.3", "buildNumber" => "123",
      "uploadedDate" => value.fetch("uploadedDate"), "expirationDate" => value.fetch("expirationDate"),
      "processingState" => value.fetch("processingState"), "expired" => value.fetch("expired"),
      "usesNonExemptEncryption" => value.fetch("usesNonExemptEncryption"),
      "autoNotifyEnabled" => @service.attributes("buildBetaDetails", "detail-1").fetch("autoNotifyEnabled") }
  end

  def adapter
    journal = ->(phase, data) { @journals << [phase, copy(data)] }
    prior_claim = @journals.any? { |phase, data| phase == "execution-claimed" && data["executedBy"] == @authority }
    create_guard = MobileReleaseKit::AppleCreateRetry.new(
      intent_sha256: @intent_digest, stage: "production-submit", bundle_id: "test.example.release", app_id: "12345",
      version: "1.2.3", build_number: 123, build_id: "build-1", authority: @authority,
      authorized_by: @authorized, environment: @secret_environment, journal: journal, prior_claim: prior_claim,
    )
    value = MobileReleaseKit::AppleProduction.new(
      client: @service.client, app_id: "12345", bundle_id: "test.example.release", version: "1.2.3",
      build: @snapshot ? @snapshot.fetch("build") : build, metadata_root: @root,
      locales: %w[en-US fr-FR de-DE], private_target: @private, environment: @secret_environment,
      read_build: method(:build), journal: journal, upload_part: @service.method(:upload), create_guard: create_guard,
    )
    test = self
    value.define_singleton_method(:sleep) { |seconds| test.advance(seconds) }
    value.define_singleton_method(:now) { test.clock }
    value
  end

  def clock = @time
  def advance(seconds) = @time += seconds

  def prepare
    ENV["MOBILE_RELEASE_STORE_MODE"] = "prepare"
    @snapshot = adapter.prepare(server_time: Time.now.utc.iso8601)
    @intent_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(@snapshot))
  ensure
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
  end

  def execute(resuming: false) = adapter.execute(@snapshot, resuming: resuming)

  # This test helper deliberately models two protected invocations, rather than
  # silently letting a later process repeat missing POSTs. The first is read-only
  # reconciliation. Only its exact inventory can authorize a new run's attempt 1.
  def recover
    @secret_environment.delete("MOBILE_RELEASE_RECOVERY_CONFIRMATION")
    @authority = @authority.merge("attempt" => @authority.fetch("attempt") + 1)
    before_writes = copy(@service.writes)
    begin
      return execute(resuming: true)
    rescue MobileReleaseKit::ContractError
      phase, data = @journals.last
      raise unless phase == "create-retry-required"
      assert_equal before_writes, @service.writes, "read-only recovery changed Store state before create authorization"
      @secret_environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = data.fetch("confirmation")
    end
    @secret_environment["MOBILE_RELEASE_RECOVERY_RUN_ID"] = @authorized.fetch("runId")
    @authority = @authorized.merge("runId" => (@next_recovery_run += 1).to_s, "attempt" => 1)
    execute(resuming: true)
  end

  def assert_preserved(baseline)
    assert_equal baseline, @service.existing_records_like(baseline), "the operation changed or removed unrelated Store state"
  end

  def assert_final
    version = @service.resources.fetch("appStoreVersions").fetch(AppleProductionFixture::VERSION_ID)
    assert_equal "MANUAL", version.dig("attributes", "releaseType")
    assert_nil version.dig("attributes", "earliestReleaseDate")
    assert_equal "WAITING_FOR_REVIEW", version.dig("attributes", "appVersionState")
    assert_equal "build-1", @service.parent_id(version, "build")
    %w[en-US fr-FR de-DE].each do |locale|
      version_locale = @service.children("appStoreVersionLocalizations", "appStoreVersion", AppleProductionFixture::VERSION_ID).find { |record| record.dig("attributes", "locale") == locale }
      assert_equal "Approved description #{locale}", version_locale.dig("attributes", "description")
      info_locale = @service.children("appInfoLocalizations", "appInfo", AppleProductionFixture::INFO_ID).find { |record| record.dig("attributes", "locale") == locale }
      assert_equal "Approved name #{locale}", info_locale.dig("attributes", "name")
    end
    detail = @service.children("appStoreReviewDetails", "appStoreVersion", AppleProductionFixture::VERSION_ID).first
    assert_equal @private, detail.fetch("attributes")
    assert_equal "committed-and-read-back", @journals.last.first
  end

  def png(width = 750, height = 1334, color = 0)
    chunk = ->(name, bytes) { [bytes.bytesize].pack("N") + name + bytes + [Zlib.crc32(name + bytes)].pack("N") }
    "\x89PNG\r\n\x1a\n".b + chunk.call("IHDR", [width, height, 8, 2, 0, 0, 0].pack("NNCCCCC")) +
      chunk.call("IDAT", Zlib::Deflate.deflate(("\0" + color.chr * (width * 3)) * height)) + chunk.call("IEND", "")
  end

  def screenshot(locale, name = "01.png", display: "APP_IPHONE_47", color: 1)
    root = File.join(@root, "screenshots", locale, display)
    FileUtils.mkdir_p(root)
    path = File.join(root, name)
    File.binwrite(path, png(750, 1334, color))
    path
  end

  def retained_live_screenshot
    locale = @service.children("appStoreVersionLocalizations", "appStoreVersion", "version-live").first
    set = @service.add_set(locale.fetch("id"))
    @service.add_shot(set.fetch("id"), name: "keep-original.png", bytes: png)
  end

  def stop_after(path, method: :post)
    @service.after_write = ->(actual_method, actual_path, _body) { raise Interrupt, "Synthetic cancellation" if actual_method == method && actual_path == path }
    assert_raises(Interrupt) { execute }
    @service.after_write = nil
  end

  def test_preparation_is_read_only_binds_all_targets_and_excludes_private_values
    baseline = @service.baseline_records
    prepare
    assert_empty @service.writes
    assert_preserved(baseline)
    assert_nil @snapshot.fetch("production")
    assert_equal %w[before inherited target], @snapshot.dig("privateStateCommitments", "domains", "app-review").keys.sort
    assert_equal "privacyChoicesUrl", @snapshot.dig("metadataTarget", "appInfo", "localizations").first.keys.find { |key| key == "privacyChoicesUrl" }
    serialized = JSON.generate(@snapshot)
    [@private["notes"], @private["demoAccountPassword"], @private["contactEmail"], @secret_environment.values.first].each do |secret|
      refute_includes serialized, secret
    end
    assert_match(/\A[0-9a-f]{32}\z/, @snapshot.fetch("operationNonce"))
  end

  def test_full_production_uses_scoped_sdk_requests_preserves_all_unrelated_state_and_stops_at_manual_review
    baseline = @service.baseline_records
    prepare
    result = execute
    assert_equal "accepted", result.fetch(:result)
    assert_final
    assert_preserved(baseline)
    assert_equal 14, @service.writes.length
    posts = @service.writes.select { |method, _path, _body| method == :post }
    assert_equal %w[/v1/appStoreVersions /v1/appStoreVersionLocalizations /v1/appInfoLocalizations /v1/reviewSubmissions /v1/reviewSubmissionItems], posts.map { |_method, path, _body| path }
    app_info_post = posts.find { |_method, path, _body| path == "/v1/appInfoLocalizations" }.last
    assert_equal({ "appInfo" => { "data" => { "type" => "appInfos", "id" => "info-editable" } } }, app_info_post.dig("data", "relationships"))
    assert_equal "Approved name de-DE", app_info_post.dig("data", "attributes", "name")
    locales = @service.children("appInfoLocalizations", "appInfo", "info-editable")
    assert_equal "https://example.test/choices", locales.find { |item| item.dig("attributes", "locale") == "en-US" }.dig("attributes", "privacyChoicesUrl")
    assert_equal "reconciled", execute(resuming: true).fetch(:result)
    assert_equal 14, @service.writes.length, "a completed operation must be read-only on reuse"
  end

  def test_every_mutating_http_response_can_be_lost_without_repeating_the_write
    prepare
    @service.after_write = ->(*) { raise Faraday::TimeoutError, "Synthetic accepted request with lost response" }
    result = execute
    assert_equal "accepted", result.fetch(:result)
    assert_equal 14, @service.writes.length
    assert_final
  end

  def test_cancellation_after_each_http_mutation_resumes_only_missing_work
    14.times do |boundary|
      reset_case
      baseline = @service.baseline_records
      prepare
      @service.after_write = lambda do |*_args|
        raise Interrupt, "Synthetic cancellation after wire request #{boundary + 1}" if @service.writes.length == boundary + 1
      end
      assert_raises(Interrupt) { execute }
      previous_writes = copy(@service.writes)
      @service.after_write = nil
      recover
      assert_equal previous_writes, @service.writes.first(previous_writes.length)
      assert_equal 14, @service.writes.length, "repeated a completed write after boundary #{boundary + 1}"
      assert_final
      assert_preserved(baseline)
    end
  end

  def hide_record(type, id)
    @service.transform_read = lambda do |_path, data|
      if data.is_a?(Array)
        data.reject { |record| record["type"] == type && record["id"] == id }
      elsif data.is_a?(Hash) && data["type"] == type && data["id"] == id
        nil
      else
        data
      end
    end
  end

  def test_accepted_but_invisible_create_at_every_post_boundary_is_never_automatically_repeated
    %w[appStoreVersions appStoreVersionLocalizations appInfoLocalizations appStoreReviewDetails appScreenshotSets appScreenshots reviewSubmissions reviewSubmissionItems].each do |type|
      reset_case
      @service.inherit_private = false
      screenshot("en-US")
      baseline = @service.baseline_records
      prepare
      @service.after_write = lambda do |method, path, _body|
        next unless method == :post && path == "/v1/#{type}"
        hide_record(type, @service.resources.fetch(type).keys.last)
        raise Faraday::TimeoutError, "Accepted #{type} is still invisible"
      end
      assert_raises(MobileReleaseKit::ContractError, type) { execute }
      assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/#{type}" }
      before_retry = copy(@service.writes)
      @service.after_write = nil
      @authority = @authorized.merge("attempt" => 2)
      error = assert_raises(MobileReleaseKit::ContractError, type) { execute(resuming: true) }
      assert_includes error.message, "retry-ios-operation-creates:#{@intent_digest}:"
      assert_equal before_retry, @service.writes, "absence authorized a duplicate #{type} POST"
      assert @journals.last.last.fetch("createRetryInventory").fetch("creates").any? { |node| node.fetch("resourceType") == type }
      # Later visibility proves which original resource is present; any remaining
      # creates still require their separately scoped fresh-dispatch inventory.
      @service.transform_read = nil
      recover
      assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/#{type}" }, "visible original #{type} was substituted"
      assert_final
      assert_preserved(baseline)
    end
  end

  def test_delayed_last_create_visibility_completes_without_a_duplicate_or_an_absence_grant
    prepare
    @service.after_write = lambda do |method, path, _body|
      next unless method == :post && path == "/v1/reviewSubmissionItems"
      hide_record("reviewSubmissionItems", @service.resources.fetch("reviewSubmissionItems").keys.last)
      raise Faraday::TimeoutError, "Accepted review item is temporarily invisible"
    end
    assert_raises(MobileReleaseKit::ContractError) { execute }
    @service.after_write = nil
    visible_after = @time + 15
    @service.before_read = ->(_path) { @service.transform_read = nil if @time >= visible_after }
    @authority = @authorized.merge("attempt" => 2)
    result = execute(resuming: true)
    assert_final
    assert_equal "accepted", result.fetch(:result) # missing submit PATCH, not another create
    assert_nil result.fetch(:create_retry)
    assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/reviewSubmissionItems" }
    refute @journals.any? { |phase, _data| phase == "create-retry-required" }
  end

  def test_successful_create_response_identity_must_match_subsequent_readback
    %w[appStoreVersions appStoreVersionLocalizations appInfoLocalizations appStoreReviewDetails appScreenshotSets appScreenshots reviewSubmissions reviewSubmissionItems].each do |type|
      reset_case
      @service.inherit_private = false
      screenshot("en-US")
      prepare
      @service.transform_write_response = lambda do |method, path, data|
        method == :post && path == "/v1/#{type}" ? data.merge("id" => "unexpected-response-id") : data
      end
      assert_raises(MobileReleaseKit::ContractError, type) { execute }
      assert_equal "/v1/#{type}", @service.writes.last[1], "a mismatch did not stop the next mutation"
      assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == "/v1/#{type}" }
      refute_equal "committed-and-read-back", @journals.last.first
    end
  end

  def test_create_retry_requires_a_new_run_even_when_original_confirmation_and_empty_store_are_unchanged
    prepare
    @authority = @authorized.merge("attempt" => 2)
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    token = @journals.last.last.fetch("confirmation")
    inventory = copy(@journals.last.last.fetch("createRetryInventory"))
    assert_empty @service.writes
    # Independent inspection time is excluded, but intrinsic/public Store state
    # is retained, so a later identical read produces the same exact token.
    @time += 3600
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    assert_equal token, @journals.last.last.fetch("confirmation")
    assert_equal inventory, @journals.last.last.fetch("createRetryInventory")
    serialized = JSON.generate(inventory)
    [@private.fetch("demoAccountPassword"), @private.fetch("contactEmail"), @private.fetch("notes"), "serverObservedAt", "uploadOperations"].each { |secret| refute_includes serialized, secret }
    @secret_environment["MOBILE_RELEASE_RECOVERY_RUN_ID"] = "101"
    @secret_environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = token
    @authority = @authorized.merge("runId" => "201")
    # Simulate a process whose single POST was not observably accepted. No finite
    # timeout can establish whether it actually failed at Apple's boundary.
    @service.before_write = ->(*) { raise Faraday::TimeoutError, "Synthetic pre-response ambiguity" }
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    assert_equal 1, @service.writes.length
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) } # same-runner local restart, claim persists
    assert_equal 1, @service.writes.length
    @authority = @authority.merge("attempt" => 2)
    @journals.clear # clean runner: attempt identity alone must stop grant replay
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    assert_equal 1, @service.writes.length
    @service.before_write = nil
    @authority = @authorized.merge("runId" => "202")
    result = execute(resuming: true)
    assert_equal "operator_authorized_retry", result.fetch(:result)
    evidence = result.fetch(:create_retry)
    assert_equal "operator-authorized-create-retry", evidence.fetch("mode")
    assert_equal inventory, evidence.fetch("inventory")
    assert_equal @authority, evidence.fetch("executedBy")
    assert_final
  end

  def test_failed_final_evidence_creation_does_not_strand_a_successful_submission
    prepare
    current = adapter
    current.instance_variable_set(:@journal, lambda do |phase, data|
      @journals << [phase, data]
      raise IOError, "Synthetic local journal/evidence failure" if phase == "committed-and-read-back"
    end)
    assert_raises(IOError) { current.execute(@snapshot, resuming: false) }
    writes = copy(@service.writes)
    assert_equal "reconciled", execute(resuming: true).fetch(:result)
    assert_equal writes, @service.writes
    assert_final
  end

  def test_claim_or_create_dispatch_journal_failure_prevents_the_http_request
    %w[execution-claimed create-dispatched].each do |failed_phase|
      reset_case
      prepare
      current = adapter
      guard = current.instance_variable_get(:@create_guard)
      guard.instance_variable_set(:@journal, lambda do |phase, data|
        @journals << [phase, copy(data)]
        raise IOError, "Synthetic pre-dispatch persistence failure" if phase == failed_phase
      end)
      expected_error = failed_phase == "execution-claimed" ? IOError : MobileReleaseKit::ContractError
      assert_raises(expected_error, failed_phase) { current.execute(@snapshot, resuming: false) }
      assert_empty @service.writes
      assert_empty @service.uploads
      refute @service.resources.fetch("appStoreVersions").key?("version-target")
      # Even though this particular fake proves no wire request, a later generic
      # executor must not infer create permission merely from an absent resource.
      assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
      assert_empty @service.writes
      recover
      assert_final
    end
  end

  def test_new_version_accepts_only_precommitted_empty_or_inherited_private_defaults
    [true, false].each do |inherit_private|
      reset_case
      @service.inherit_private = inherit_private
      prepare
      execute
      assert_final
      private_calls = @service.writes.select { |_method, path, _body| path.start_with?("/v1/appStoreReviewDetails") }
      assert_equal 1, private_calls.length
      assert_equal inherit_private ? :patch : :post, private_calls.first.first
    end
  end

  def test_empty_public_defaults_and_auto_created_app_info_are_authorized_not_required_to_match_inheritance
    [true, false].each do |inherit_public|
      reset_case
      @service.inherit_version = inherit_public
      @service.resources.fetch("appInfos").delete("info-editable")
      @service.resources.fetch("appInfoLocalizations").delete_if { |_id, record| @service.parent_id(record, "appInfo") == "info-editable" }
      prepare
      assert_nil @snapshot.fetch("appInfo")
      execute
      assert_final
    end
  end

  def test_inherited_private_equal_to_target_is_final_without_a_redundant_private_write
    @private = copy(AppleProductionFixture::PRIVATE)
    prepare
    execute
    assert_final
    assert_empty @service.writes.select { |_method, path, _body| path.start_with?("/v1/appStoreReviewDetails") }
  end

  def test_private_target_changed_under_same_key_is_rejected_before_any_write
    prepare
    @private = @private.merge("notes" => "Changed after approval")
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_empty @service.writes
  end

  def test_mixed_third_private_record_or_changed_live_reference_is_never_adopted
    %i[third_value mixed_record changed_reference masked_reference].each do |kind|
      reset_case
      prepare
      @service.clone_version
      details = @service.children("appStoreReviewDetails", "appStoreVersion", "version-target").first.fetch("attributes")
      reference = @service.children("appStoreReviewDetails", "appStoreVersion", "version-live").first.fetch("attributes")
      case kind
      when :third_value then details["notes"] = "Unapproved review notes"
      when :mixed_record then details["contactFirstName"] = @private.fetch("contactFirstName")
      when :changed_reference then reference["notes"] = "Changed live instructions"
      when :masked_reference then reference["demoAccountPassword"] = "••••••"
      end
      assert_raises(MobileReleaseKit::ContractError, kind.to_s) { execute(resuming: true) }
      assert_empty @service.writes
    end
  end

  def test_existing_partial_version_cannot_be_reauthorized_under_a_new_intent
    @service.clone_version
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
  end

  def test_already_submitted_version_can_be_observed_with_new_intent_but_never_resubmitted
    prepare
    execute
    writes = copy(@service.writes)
    prepare
    assert @snapshot.fetch("production")
    assert_equal "already_present", execute.fetch(:result)
    assert_equal writes, @service.writes
    assert_final
  end

  def test_unsafe_version_release_or_build_state_is_rejected_before_recovery_mutation
    variants = {
      automatic: ->(version) { version.fetch("attributes")["releaseType"] = "AFTER_APPROVAL" },
      scheduled: ->(version) { version.fetch("attributes")["earliestReleaseDate"] = "2030-01-01T00:00:00Z" },
      another_build: ->(version) { version.dig("relationships", "build")["data"] = { "type" => "builds", "id" => "substituted-build" } },
    }
    %w[REJECTED DEVELOPER_REJECTED READY_FOR_SALE READY_FOR_DISTRIBUTION REMOVED_FROM_SALE INVALID_BINARY UNKNOWN].each do |state|
      variants[state] = ->(version) { version.fetch("attributes")["appVersionState"] = state }
    end
    variants.each do |name, mutation|
      reset_case
      prepare
      version = @service.clone_version
      mutation.call(version)
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { execute(resuming: true) }
      assert_empty @service.writes
    end
  end

  def test_in_process_regression_or_unrelated_edit_stops_before_any_further_write
    mutations = {
      localized_regression: lambda { |service|
        service.children("appStoreVersionLocalizations", "appStoreVersion", "version-target").find { |record| record.dig("attributes", "locale") == "en-US" }.fetch("attributes")["description"] = "Previous description"
      },
      private_third_value: ->(service) { service.children("appStoreReviewDetails", "appStoreVersion", "version-target").first.fetch("attributes")["notes"] = "Concurrent unapproved value" },
      unrelated_app_change: ->(service) { service.attributes("appStoreVersions", "version-old")["copyright"] = "Concurrent edit" },
    }
    mutations.each do |name, mutate|
      reset_case
      prepare
      @service.after_write = lambda do |_method, _path, _body|
        mutate.call(@service) if @service.writes.length == 4 # first locale is already at target; second locale just changed
      end
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { execute }
      assert_equal 4, @service.writes.length, "the adapter continued writing after #{name}"
    end
  end

  def test_prepare_to_first_dispatch_appearance_fails_without_mutation
    prepare
    @service.clone_version
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_empty @service.writes
  end

  def test_unrelated_metadata_build_categories_or_public_state_drift_is_rejected_without_mutation
    mutations = {
      live_text: ->(service) { service.children("appStoreVersionLocalizations", "appStoreVersion", "version-live").first.fetch("attributes")["keywords"] = "unapproved" },
      editable_text: ->(service) { service.children("appInfoLocalizations", "appInfo", "info-editable").first.fetch("attributes")["subtitle"] = "unapproved" },
      build_expired: ->(service) { service.attributes("builds", "build-1")["expired"] = true },
      notify_changed: ->(service) { service.attributes("buildBetaDetails", "detail-1")["autoNotifyEnabled"] = true },
      category: ->(service) { service.relate(service.resources.fetch("appInfos").fetch("info-editable"), "primaryCategory", "appCategories", "GAMES") },
      unrelated_version: ->(service) { service.attributes("appStoreVersions", "version-old")["copyright"] = "unapproved" },
    }
    mutations.each do |name, mutation|
      reset_case
      prepare
      mutation.call(@service)
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { execute(resuming: true) }
      assert_empty @service.writes
    end
  end

  def test_new_app_info_locale_requires_approved_name_before_any_mutation
    File.delete(File.join(@root, "de-DE", "name.txt"))
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
  end

  def test_unsupported_metadata_and_invalid_category_parent_fail_in_read_only_preparation
    File.write(File.join(@root, "price_tier.txt"), "1")
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
    File.delete(File.join(@root, "price_tier.txt"))
    File.write(File.join(@root, "primary_first_sub_category.txt"), "GAMES_ACTION")
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
  end

  def test_empty_orphan_review_is_reused_without_creating_another_submission
    @service.add_submission("review-orphan")
    prepare
    baseline = @service.baseline_records
    baseline.fetch("reviewSubmissions").delete("review-orphan") # this exact orphan is explicitly authorized
    result = execute
    assert_equal "review-orphan", result.fetch(:review_submission_id)
    assert_empty @service.writes.select { |_method, path, _body| path == "/v1/reviewSubmissions" }
    assert_final
    assert_preserved(baseline)
  end

  def test_wrong_or_ambiguous_review_membership_and_unsafe_states_are_read_only_rejections
    mutations = {
      other_version: ->(service) { service.add_submission("wrong", version_id: "version-old") },
      other_item_type: ->(service) { service.add_submission("wrong", version_id: "event-1", item_type: "appEvents") },
      duplicate: ->(service) { service.add_submission("first"); service.add_submission("second") },
      unresolved: ->(service) { service.add_submission("bad", state: "UNRESOLVED_ISSUES") },
      canceling: ->(service) { service.add_submission("bad", state: "CANCELING") },
      unscoped_item: lambda { |service|
        record = service.add_submission("bad", version_id: "version-old")
        service.children("reviewSubmissionItems", "reviewSubmission", record.fetch("id")).first.fetch("relationships").delete("appStoreVersion")
      },
    }
    mutations.each do |name, mutation|
      reset_case
      mutation.call(@service)
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { prepare }
      assert_empty @service.writes
    end
  end

  def test_raw_unhydrated_relationships_and_paginated_lists_are_fully_observed
    @service.page_size = 1
    prepare
    execute
    assert_final
    assert @service.queries.any? { |_path, query| query["cursor"] }, "the fixture must actually exercise pagination"
    assert_equal 14, @service.writes.length
  end

  def test_review_completing_and_completed_approved_states_are_read_only_observations
    prepare
    result = execute
    writes = copy(@service.writes)
    submission = @service.resources.fetch("reviewSubmissions").fetch(result.fetch(:review_submission_id))
    item = @service.children("reviewSubmissionItems", "reviewSubmission", submission.fetch("id")).first
    [["COMPLETING", "IN_REVIEW", "ACCEPTED"], ["COMPLETE", "PENDING_DEVELOPER_RELEASE", "APPROVED"]].each do |review_state, version_state, item_state|
      submission.fetch("attributes")["state"] = review_state
      @service.attributes("appStoreVersions", "version-target")["appVersionState"] = version_state
      item.fetch("attributes")["state"] = item_state
      assert_equal "reconciled", execute(resuming: true).fetch(:result)
      assert_equal writes, @service.writes
    end
    item.fetch("attributes")["state"] = "ACCEPTED"
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    assert_equal writes, @service.writes
  end

  def test_explicit_mismatched_app_relationship_is_rejected_even_from_scoped_list_endpoints
    { "/v1/apps/12345/appStoreVersions" => "appStoreVersions", "/v1/apps/12345/appInfos" => "appInfos", "/v1/apps/12345/reviewSubmissions" => "reviewSubmissions" }.each do |endpoint, type|
      reset_case
      @service.transform_read = lambda do |path, data|
        if path == endpoint
          value = copy(data)
          record = value.find { |item| item.fetch("type") == type }
          @service.relate(record, "app", "apps", "unrelated-app")
          value
        else
          data
        end
      end
      assert_raises(MobileReleaseKit::ContractError, type) { prepare }
      assert_empty @service.writes
    end
  end

  def test_unscoped_active_submission_is_rejected_and_known_other_platform_is_preserved
    @service.add_submission("review-missing-platform", platform: nil)
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
    @service.resources.fetch("reviewSubmissions").delete("review-missing-platform")
    baseline = @service.baseline_records
    prepare
    assert @snapshot.fetch("reviewSubmissions").any? { |item| item.fetch("id") == "review-mac" }
    execute
    assert_final
    assert_preserved(baseline)
  end

  def test_another_platform_returned_despite_ios_version_filter_is_rejected
    @service.transform_read = lambda do |path, data|
      if path == "/v1/apps/12345/appStoreVersions"
        data + [copy(@service.resources.fetch("appStoreVersions").fetch("version-mac"))]
      else
        data
      end
    end
    assert_raises(MobileReleaseKit::ContractError) { prepare }
    assert_empty @service.writes
  end

  def test_screenshot_locales_and_order_are_correlated_with_uploaded_bytes_and_originals_preserved
    retained_live_screenshot
    paths = [screenshot("en-US", "01.png"), screenshot("fr-FR", "01.png", color: 2)]
    baseline = @service.baseline_records
    prepare
    execute
    assert_final
    assert_preserved(baseline)
    targets = @snapshot.dig("metadataTarget", "screenshots")
    assert_equal 2, targets.length
    assert_equal 4, @service.uploads.length
    targets.each do |target|
      shot = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName") == target.fetch("fileName") }
      assert_match(/\Amrk-#{@snapshot.fetch('operationNonce')}-[0-9a-f]{64}\.png\z/, shot.dig("attributes", "fileName"))
      assert_equal File.binread(File.join(@root, target.fetch("localPath"))), @service.assembled_upload(shot.fetch("id"))
      assert_equal "COMPLETE", shot.dig("attributes", "assetDeliveryState", "state")
      assert_equal target.fetch("sourceFileChecksum"), shot.dig("attributes", "sourceFileChecksum")
    end
    assert_equal paths.map { |path| Digest::SHA256.file(path).hexdigest }, targets.map { |target| target.fetch("sha256") }
    assert_empty @service.deleted_screenshots
    # The fake's resource collection is reversed; the relationship order wins.
    version_locale = @service.children("appStoreVersionLocalizations", "appStoreVersion", "version-target").find { |record| record.dig("attributes", "locale") == "en-US" }
    set = @service.children("appScreenshotSets", "appStoreVersionLocalization", version_locale.fetch("id")).first
    ids = set.dig("relationships", "appScreenshots", "data").map { |item| item.fetch("id") }
    assert_equal %w[keep-original.png] + [targets.first.fetch("fileName")], ids.map { |id| @service.attributes("appScreenshots", id).fetch("fileName") }
  end

  def test_identical_screenshot_names_and_content_across_locales_are_distinct_reservations
    screenshot("en-US")
    screenshot("fr-FR")
    prepare
    targets = @snapshot.dig("metadataTarget", "screenshots")
    assert_equal 1, targets.map { |target| target.fetch("fileName") }.uniq.length
    execute
    assert_final
    shots = @service.all("appScreenshots").select { |record| record.dig("attributes", "fileName") == targets.first.fetch("fileName") }
    assert_equal 2, shots.length
    assert_equal 2, shots.map { |record| @service.parent_id(record, "appScreenshotSet") }.uniq.length
    assert_equal 4, @service.uploads.length
  end

  def test_changed_screenshot_bytes_fail_before_store_mutation
    path = screenshot("en-US")
    prepare
    File.binwrite(path, png(750, 1334, 2))
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_empty @service.writes
    assert_empty @service.uploads
  end

  def test_screenshot_timeout_after_accepted_part_is_resumed_without_new_reservation
    path = screenshot("en-US")
    prepare
    @service.after_upload = ->(*) { raise IOError, "Synthetic lost part response" }
    assert_raises(IOError) { execute }
    assert_equal 1, @service.uploads.length
    @service.after_upload = nil
    recover
    assert_final
    assert_equal 1, @service.writes.count { |method, endpoint, _body| method == :post && endpoint == "/v1/appScreenshots" }
    assert_equal 3, @service.uploads.length
    shot_id = @service.uploads.last.first
    assert_equal File.binread(path), @service.assembled_upload(shot_id)
  end

  def test_screenshot_cancellation_after_reservation_each_part_and_commit_preserves_exact_candidate
    %i[reservation first_part last_part commit].each do |boundary|
      reset_case
      retained_live_screenshot
      path = screenshot("en-US")
      baseline = @service.baseline_records
      prepare
      if %i[first_part last_part].include?(boundary)
        count = boundary == :first_part ? 1 : 2
        @service.after_upload = ->(*) { raise Interrupt, "Synthetic interrupted part upload" if @service.uploads.length == count }
      else
        @service.after_write = lambda do |method, endpoint, _body|
          matches = boundary == :reservation ? method == :post && endpoint == "/v1/appScreenshots" : method == :patch && endpoint.start_with?("/v1/appScreenshots/")
          raise Interrupt, "Synthetic interrupted screenshot mutation" if matches
        end
      end
      assert_raises(Interrupt) { execute }
      @service.after_upload = @service.after_write = nil
      recover
      assert_final
      assert_preserved(baseline)
      reservations = @service.writes.select { |method, endpoint, _body| method == :post && endpoint == "/v1/appScreenshots" }
      assert_equal 1, reservations.length, "reservation duplicated after #{boundary}"
      commits = @service.writes.select { |method, endpoint, _body| method == :patch && endpoint.start_with?("/v1/appScreenshots/") }
      assert_equal 1, commits.length, "commit repeated after #{boundary}"
      shot = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName") == @snapshot.dig("metadataTarget", "screenshots").first.fetch("fileName") }
      assert_equal File.binread(path), @service.assembled_upload(shot.fetch("id"))
      assert_equal boundary == :commit ? 2 : (boundary == :first_part ? 3 : boundary == :last_part ? 4 : 2), @service.uploads.length
    end
  end

  def test_committed_screenshot_processing_timeout_preserves_reservation_and_never_reuploads
    screenshot("en-US")
    @service.screenshot_complete_on_commit = false
    prepare
    assert_raises(MobileReleaseKit::ContractError) { execute }
    writes = copy(@service.writes)
    assert_equal 2, @service.uploads.length
    assert_empty @service.deleted_screenshots
    owned = @service.all("appScreenshots").select { |record| record.dig("attributes", "fileName").start_with?("mrk-") }
    assert_equal 1, owned.length
    owned.first.fetch("attributes")["assetDeliveryState"]["state"] = "COMPLETE"
    recover
    assert_final
    assert_equal 2, @service.uploads.length
    assert_equal writes.select { |_method, endpoint, _body| endpoint.include?("appScreenshot") }, @service.writes.select { |_method, endpoint, _body| endpoint.include?("appScreenshot") }
  end

  def test_expired_or_failed_owned_reservation_only_is_replaced_and_all_originals_survive
    %w[expired FAILED].each do |mode|
      reset_case
      retained_live_screenshot
      screenshot("en-US")
      baseline = @service.baseline_records
      prepare
      stop_after("/v1/appScreenshots")
      owned = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName").start_with?("mrk-") }
      if mode == "expired"
        @service.set_upload_operations(owned, expires: Time.now.to_i - 1)
      else
        owned.fetch("attributes")["assetDeliveryState"]["state"] = "FAILED"
      end
      recover
      assert_final
      assert_preserved(baseline)
      assert_equal [owned.fetch("id")], @service.deleted_screenshots.map { |record| record.fetch("id") }
      assert_equal 2, @service.writes.count { |method, endpoint, _body| method == :post && endpoint == "/v1/appScreenshots" }
    end
  end

  def test_a_newly_created_failed_reservation_is_not_deleted_after_its_post_budget_is_consumed
    screenshot("en-US")
    prepare
    @service.after_write = lambda do |method, endpoint, _body|
      next unless method == :post && endpoint == "/v1/appScreenshots"
      @service.all("appScreenshots").last.fetch("attributes")["assetDeliveryState"]["state"] = "FAILED"
    end
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_equal 1, @service.writes.count { |method, endpoint, _body| method == :post && endpoint == "/v1/appScreenshots" }
    assert_empty @service.deleted_screenshots
    assert_empty @service.uploads
    assert_equal "FAILED", @service.all("appScreenshots").last.dig("attributes", "assetDeliveryState", "state")
  end

  def test_cancellation_after_owned_reservation_deletion_does_not_implicitly_authorize_recreation
    retained_live_screenshot
    screenshot("en-US")
    baseline = @service.baseline_records
    prepare
    stop_after("/v1/appScreenshots")
    owned = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName").start_with?("mrk-") }
    @service.set_upload_operations(owned, expires: Time.now.to_i - 1)
    @service.after_write = ->(method, _endpoint, _body) { raise Interrupt, "Synthetic cancellation after DELETE" if method == :delete }
    assert_raises(Interrupt) { recover }
    @service.after_write = nil
    before = copy(@service.writes)
    assert_raises(MobileReleaseKit::ContractError) { execute(resuming: true) }
    assert_equal before, @service.writes
    assert_equal 1, @service.deleted_screenshots.length
    recover
    assert_final
    assert_preserved(baseline)
    assert_equal 1, @service.deleted_screenshots.length
    assert_equal 2, @service.writes.count { |method, endpoint, _body| method == :post && endpoint == "/v1/appScreenshots" }
  end

  def test_owned_replacement_is_not_misrepresented_as_a_create_authorized_by_an_absence_inventory
    screenshot("en-US")
    prepare
    stop_after("/v1/appScreenshots")
    owned = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName").start_with?("mrk-") }
    @service.set_upload_operations(owned, expires: Time.now.to_i - 1)
    result = recover
    evidence = result.fetch(:create_retry)
    refute_nil evidence, "still-missing review resources require explicit retry authority"
    authorized_keys = evidence.fetch("inventory").fetch("creates").map { |node| node.fetch("logicalKeySha256") }
    used_keys = evidence.fetch("usedCreates").map { |node| node.fetch("logicalKeySha256") }
    assert_empty used_keys - authorized_keys, "owned replacement has different authority; do not claim it was in the absence grant"
    assert_equal 1, @service.deleted_screenshots.length
  end

  def test_foreign_duplicate_reordered_or_wrong_checksum_screenshot_is_not_touched
    mutations = {
      foreign_name: ->(shot, _set) { shot.fetch("attributes")["fileName"] = "somebody-elses-reservation.png" },
      wrong_size: ->(shot, _set) { shot.fetch("attributes")["fileSize"] += 1 },
      committed_wrong_checksum: lambda { |shot, _set|
        shot.fetch("attributes")["sourceFileChecksum"] = "a" * 32
        shot.fetch("attributes")["assetDeliveryState"]["state"] = "COMPLETE"
      },
      reorder: ->(_shot, set) { set.dig("relationships", "appScreenshots", "data").reverse! },
    }
    mutations.each do |kind, mutation|
      reset_case
      retained_live_screenshot
      screenshot("en-US")
      prepare
      stop_after("/v1/appScreenshots")
      shot = @service.all("appScreenshots").find { |record| record.dig("attributes", "fileName").start_with?("mrk-") }
      set = @service.resources.fetch("appScreenshotSets").fetch(@service.parent_id(shot, "appScreenshotSet"))
      mutation.call(shot, set)
      writes = copy(@service.writes)
      assert_raises(MobileReleaseKit::ContractError, kind.to_s) { execute(resuming: true) }
      assert_equal writes, @service.writes
      assert_empty @service.deleted_screenshots
    end
  end
end

class AppleCreateRetryContractTest < Minitest::Test
  def setup
    @journal = []
    @authorized = { "runId" => "101", "attempt" => 1, "event" => "workflow_dispatch" }
    @authority = @authorized.merge("runId" => "202")
    @environment = { "MOBILE_RELEASE_RECOVERY_RUN_ID" => "101" }
    @public = { "production" => nil, "publicDescription" => "Approved Français العربية", "unrelatedVersions" => [{ "id" => "untouched", "state" => "READY_FOR_DISTRIBUTION" }] }
  end

  def guard(authority: @authority, prior_claim: false)
    MobileReleaseKit::AppleCreateRetry.new(
      intent_sha256: "f" * 64, stage: "production-submit", bundle_id: "test.example.release", app_id: "12345",
      version: "1.2.3", build_number: 123, build_id: "build-1", authority: authority,
      authorized_by: @authorized, environment: @environment, journal: ->(phase, data) { @journal << [phase, data] }, prior_claim: prior_claim,
    )
  end

  def nodes(value)
    [value.node("appStoreVersions", locator: {}, parent: value.present("apps", "12345"), target: { "version" => "1.2.3", "releaseType" => "MANUAL" }),
     value.node("appStoreVersionLocalizations", locator: { "locale" => "fr-FR" }, parent: value.missing("appStoreVersions"), target: { "description" => "Français" })]
  end

  def authorization(public_state = @public)
    value = guard
    assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: public_state, nodes: nodes(value), resuming: true) }
    phase, data = @journal.last
    assert_equal "create-retry-required", phase
    data.fetch("confirmation")
  end

  def test_absence_emits_bounded_public_inventory_without_authorizing_a_post
    value = guard
    error = assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: nodes(value), resuming: true) }
    assert_match(/NEW protected first-attempt recovery dispatch/, error.message)
    inventory = value.inventory
    assert_equal "ios-create-retry-inventory", inventory.fetch("documentType")
    assert_equal "production-submit", inventory.fetch("stage")
    assert_equal 2, inventory.fetch("creates").length
    assert_equal "12345", inventory.dig("application", "appStoreAppId")
    assert_equal "build-1", inventory.dig("candidate", "storeBuildId")
    assert_equal inventory.fetch("creates").map { |node| node.fetch("logicalKeySha256") }.sort,
                 inventory.fetch("creates").map { |node| node.fetch("logicalKeySha256") }
    assert_raises(MobileReleaseKit::ContractError) { value.consume!("appStoreVersions", locator: {}, parent_id: "12345") }
  end

  def test_new_dispatch_can_consume_exact_dag_once_after_parent_readback
    @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = authorization
    value = guard
    value.arm!(public_state: @public, nodes: nodes(value), resuming: true)
    assert_raises(MobileReleaseKit::ContractError) do
      value.consume!("appStoreVersionLocalizations", locator: { "locale" => "fr-FR" }, parent_id: "some-version")
    end
    assert_raises(MobileReleaseKit::ContractError) { value.consume!("appStoreVersions", locator: {}, parent_id: "different-app") }
    value.consume!("appStoreVersions", locator: {}, parent_id: "12345")
    assert_raises(MobileReleaseKit::ContractError) { value.consume!("appStoreVersions", locator: {}, parent_id: "12345") }
    assert_raises(MobileReleaseKit::ContractError) { value.retry_evidence }
    value.observe!("appStoreVersions", locator: {}, id: "original-version")
    assert_raises(MobileReleaseKit::ContractError) do
      value.consume!("appStoreVersionLocalizations", locator: { "locale" => "fr-FR" }, parent_id: "substituted-version")
    end
    value.consume!("appStoreVersionLocalizations", locator: { "locale" => "fr-FR" }, parent_id: "original-version")
    value.observe!("appStoreVersionLocalizations", locator: { "locale" => "fr-FR" }, id: "locale-fr")
    evidence = value.retry_evidence
    assert_equal "operator-authorized-create-retry", evidence.fetch("mode")
    assert_equal %w[locale-fr original-version], evidence.fetch("usedCreates").map { |entry| entry.fetch("resourceId") }.sort
    assert_equal @authority, evidence.fetch("executedBy")
  end

  def test_retry_token_cannot_be_replayed_by_a_rerun_or_local_restart
    @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = authorization
    [@authority.merge("attempt" => 2), @authorized, @authority.merge("event" => "push")].each do |authority|
      value = guard(authority: authority)
      assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: nodes(value), resuming: true) }
    end
    value = guard(prior_claim: true)
    assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: nodes(value), resuming: true) }
  end

  def test_snapshot_drift_extra_text_or_changed_scope_cannot_reuse_a_retry_token
    token = authorization
    @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = token
    value = guard
    changed = @public.merge("publicDescription" => "Unapproved")
    assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: changed, nodes: nodes(value), resuming: true) }
    [" #{token}", "#{token}\n", token.sub("retry-ios-", "RETRY-ios-")].each do |confirmation|
      @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = confirmation
      value = guard
      assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: nodes(value), resuming: true) }
    end
    @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = token
    value = guard
    omitted_child = nodes(value).first(1)
    assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: omitted_child, resuming: true) }
  end

  def test_duplicate_cyclic_or_missing_create_dependencies_are_rejected
    value = guard
    values = nodes(value)
    assert_raises(MobileReleaseKit::ContractError) { value.build_inventory(@public, [values.first, values.first]) }
    assert_raises(MobileReleaseKit::ContractError) { value.build_inventory(@public, [values.last]) }
    cycle = Marshal.load(Marshal.dump(values))
    cycle.first.fetch("dependencies") << cycle.last.fetch("logicalKeySha256")
    assert_raises(MobileReleaseKit::ContractError) { value.build_inventory(@public, cycle) }
  end

  def test_resolved_parent_identity_is_frozen_and_initial_authority_does_not_claim_operator_retry
    value = guard(authority: @authorized)
    value.arm!(public_state: @public, nodes: nodes(value), resuming: false)
    value.consume!("appStoreVersions", locator: {}, parent_id: "12345")
    value.observe!("appStoreVersions", locator: {}, id: "version-original")
    assert_raises(MobileReleaseKit::ContractError) { value.observe!("appStoreVersions", locator: {}, id: "version-substituted") }
    assert_nil value.retry_evidence
    assert_raises(MobileReleaseKit::ContractError) { value.arm!(public_state: @public, nodes: nodes(value), resuming: false) }
  end
end
