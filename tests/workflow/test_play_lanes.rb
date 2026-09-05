# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "play_fixture"
require_relative "../../fastlane/play_store"

class PlayReleaseLanesTest < Minitest::Test
  LANES = {
    "candidate" => "android_internal_upload",
    "external-testing" => "android_external_promote",
    "production-submit" => "android_production_draft",
  }.freeze

  def setup
    @environment = ENV.to_h
    @root = File.realpath(Dir.mktmpdir("mrk-play-lanes-"))
    @aab = "fictional candidate; final signing/identity validation is tested in Python"
    FileUtils.mkdir_p(File.join(@root, "release/store/android/en-US/changelogs"))
    File.write(File.join(@root, "candidate.aab"), @aab)
    File.write(File.join(@root, "mapping.txt"), "fictional mapping bytes")
    File.write(File.join(@root, "adc.json"), "{}")
    File.write(File.join(@root, "version.properties"), "VERSION_NAME=2.0.0\nVERSION_CODE=200\n")
    File.write(File.join(@root, "release/store/android/en-US/title.txt"), "Approved title")
    File.write(File.join(@root, "release/store/android/en-US/changelogs/default.txt"), "Approved changelog")
    File.write(File.join(@root, "release/mobile-release.json"), JSON.generate(
      "version" => { "source" => "version.properties", "nameKey" => "VERSION_NAME", "buildKey" => "VERSION_CODE" },
      "android" => { "applicationId" => "test.example.release", "externalTrack" => { "kind" => "closed", "name" => "closed-qa" } },
      "metadata" => { "root" => "release/store", "androidLocales" => ["en-US"] },
    ))
    ENV.update(
      "MOBILE_RELEASE_APP_ROOT" => @root, "MOBILE_RELEASE_CONFIG_PATH" => "release/mobile-release.json",
      "MOBILE_RELEASE_PLATFORM" => "android", "MOBILE_RELEASE_APP_IDENTITY" => "test.example.release",
      "MOBILE_RELEASE_OPERATION_INTENT_PATH" => "intent.json", "MOBILE_RELEASE_PLAY_STATE_PATH" => "journal.json",
      "MOBILE_RELEASE_ANDROID_AAB_PATH" => "candidate.aab", "GOOGLE_APPLICATION_CREDENTIALS" => File.join(@root, "adc.json"),
    )
    ENV.delete("MOBILE_RELEASE_ANDROID_MAPPING_PATH")
    @authority = {
      "workflow" => "Synthetic", "runId" => "111", "attempt" => 1,
      "callerPath" => ".github/workflows/mobile-candidate.yml", "reusableRepository" => "test/toolkit",
      "reusablePath" => ".github/workflows/reusable-candidate.yml", "reusableCommit" => "a" * 40,
      "event" => "workflow_dispatch", "headSha" => "b" * 40, "ref" => "refs/heads/main",
    }
    ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(@authority)
    @service = PlayFixture.new
    @validation_calls = []
    @validation_hook = nil
    @unrelated = [
      release(90, status: "inProgress", fraction: 0.25),
      release(91, status: "halted", fraction: 0.75),
      release(92, status: "draft"),
      release(93),
    ]
    %w[internal closed-qa production].each { |name| @service.add_track(name, @unrelated) }
    @service.state.fetch("listings")["en-US"] = listing("en-US", "Existing title")
    @service.state.fetch("listings")["fr-FR"] = listing("fr-FR", "Untouched French")
    fresh_process
  end

  def teardown
    ENV.replace(@environment)
    FileUtils.remove_entry(@root) if @root && File.directory?(@root)
  end

  def release(code, status: "completed", fraction: nil)
    value = { "name" => "Version #{code}", "status" => status, "versionCodes" => [code.to_s],
              "releaseNotes" => [{ "language" => "en-US", "text" => "Existing notes #{code}" }] }
    value["userFraction"] = fraction unless fraction.nil?
    value
  end

  def listing(locale, title)
    { "language" => locale, "title" => title, "shortDescription" => "Existing short", "fullDescription" => "Existing long",
      "video" => "https://www.youtube.com/watch?v=fictional" }
  end

  def fresh_process
    verbosity = $VERBOSE
    $VERBOSE = nil
    @fastfile = Fastlane::FastFile.new(File.expand_path("../../fastlane/Fastfile", __dir__))
    owner = self
    @fastfile.define_singleton_method(:play_service) { owner.service.service }
    @fastfile.define_singleton_method(:validate_current_android_upload!) { |aab| owner.validate_upload(aab) }
  ensure
    $VERBOSE = verbosity
  end

  def service = @service

  def validate_upload(aab)
    # Only native validation is substituted here. The actual lane, precondition
    # classification, upload request/options, readback and persistence run.
    @validation_calls << aab
    @validation_hook&.call(aab)
  end

  def lane(name)
    Supply::Client.stub(:make_from_config, @service.supply_client) do
      Net::HTTP.stub(:new, ->(host, port, proxy) { @service.image_connection(host, port, proxy) }) do
        FastlaneCore::PrintTable.stub(:print_values, nil) do
          @fastfile.runner.lanes.fetch(nil).fetch(name.to_sym).call({})
        end
      end
    end
  end

  def prepare(stage, mapping: false, populate_source: true)
    @stage = stage
    @lane_name = LANES.fetch(stage)
    if stage != "candidate"
      @service.add_bundle(@aab) unless @service.state.fetch("bundles").any?
      source = stage == "external-testing" ? "internal" : "closed-qa"
      if populate_source && !@service.state.fetch("tracks").fetch(source).fetch("releases").any? { |row| row["versionCodes"].include?("200") }
        @service.state.fetch("tracks").fetch(source).fetch("releases") << release(200)
      end
    end
    ENV["MOBILE_RELEASE_OPERATION"] = @lane_name
    ENV["MOBILE_RELEASE_STORE_MODE"] = "prepare"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "precondition.json"
    ENV["MOBILE_RELEASE_ANDROID_MAPPING_PATH"] = "mapping.txt" if mapping
    lane(@lane_name)
    precondition = JSON.parse(File.read(File.join(@root, "precondition.json")))
    @payload = {
      "schemaVersion" => 1, "documentType" => "store-operation-intent", "stage" => stage, "platform" => "android",
      "storePrecondition" => precondition, "authorizedBy" => @authority.dup,
      "artifacts" => [{ "logicalName" => "android-aab", "fileName" => "candidate.aab", "size" => @aab.bytesize,
                        "sha256" => Digest::SHA256.hexdigest(@aab) }],
    }
    if mapping
      @payload["artifacts"] << { "logicalName" => "android-mapping", "fileName" => "mapping.txt",
                                 "size" => File.size(File.join(@root, "mapping.txt")), "sha256" => Digest::SHA256.file(File.join(@root, "mapping.txt")).hexdigest }
    end
    save_intent
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "receipt.json"
  end

  def save_intent
    @intent_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(@payload))
    File.write(File.join(@root, "intent.json"), JSON.generate(@payload.merge("integrity" => { "algorithm" => "sha256", "sha256" => @intent_digest })))
  end

  def execute = lane(@lane_name)
  def receipt = JSON.parse(File.read(File.join(@root, "receipt.json")))
  def snapshot = @payload.fetch("storePrecondition").fetch("snapshot")

  def retry_process
    @authority["attempt"] += 1
    ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(@authority)
    @service.supply_client.current_edit = nil
    @service.supply_client.current_package_name = nil
    fresh_process
  end

  def reset_case
    teardown
    setup
  end

  def assert_no_receipt
    refute File.exist?(File.join(@root, "receipt.json"))
  end

  def target_state!
    destination = snapshot.fetch("destinationTrack")
    @service.state.fetch("tracks")[destination] = @service.clone(snapshot.fetch("destinationTargetState").reject { |key, _value| key == "canonicalization" })
    @service.add_bundle(@aab) unless @service.state.fetch("bundles").any? { |bundle| bundle["versionCode"] == 200 }
  end

  def test_candidate_prepare_is_read_only_and_real_supply_preserves_all_track_records
    prepare("candidate")
    assert_empty @service.mutations
    execute
    assert_equal 3, receipt.fetch("schemaVersion")
    assert_equal "accepted", receipt.fetch("result")
    assert_equal @intent_digest, receipt.fetch("operationIntentSha256")
    assert_equal @authority, receipt.fetch("executedBy")
    assert_equal @unrelated, @service.state.fetch("tracks").fetch("internal").fetch("releases").reject { |row| row["versionCodes"] == ["200"] }
    assert_equal 1, @service.commits.length
    assert_equal 0, @service.commits.first.fetch(:retries)
    assert_equal false, @service.commits.first.fetch(:query).fetch("changesNotSentForReview")
    assert_equal "ERROR_IF_IN_REVIEW", @service.commits.first.fetch(:query).fetch("changesInReviewBehavior")
  end

  def test_owned_single_bundle_request_overrides_global_retry_defaults_and_keeps_resumable_protocol
    previous = Google::Apis::RequestOptions.default.retries
    Google::Apis::RequestOptions.default.retries = 5
    ENV["SUPPLY_UPLOAD_MAX_RETRIES"] = "7"
    prepare("candidate")
    @service.supply_client.define_singleton_method(:upload_bundle) { |*| raise "inherited retrying Supply upload must never be used" }
    execute
    uploads = @service.mutations.select { |item| item[:path].end_with?("/bundles") }
    assert_equal 1, uploads.length
    assert_equal 0, uploads.first.fetch(:retries)
    assert_equal "Google::Apis::Core::ResumableUploadCommand", uploads.first.fetch(:command_class)
    assert_equal true, uploads.first.fetch(:query).fetch("ackBundleInstallationWarning")
    assert_equal [File.join(@root, "candidate.aab")], @validation_calls
  ensure
    Google::Apis::RequestOptions.default.retries = previous
  end

  def test_current_validation_failure_or_cancellation_prevents_all_candidate_mutations
    [MobileReleaseKit::ContractError.new("current signing warning/missing tool"), Interrupt.new("stopped during native checks")].each do |error|
      reset_case
      prepare("candidate", mapping: true)
      @validation_hook = ->(_) { raise error }
      expected_error = error.is_a?(MobileReleaseKit::ContractError) ? FastlaneCore::Interface::FastlaneError : error.class
      assert_raises(expected_error) { execute }
      assert_empty @service.mutations
      assert_no_receipt
      history = JSON.parse(File.read(File.join(@root, "journal.json"))).fetch("history")
      refute history.any? { |row| row["phase"] == "mutation-dispatched" }
    end
  end

  def test_exact_bundle_appearance_during_validation_requires_genuine_prior_execution_authority
    [false, true].each do |prior_attempt|
      reset_case
      prepare("candidate", mapping: true)
      retry_process if prior_attempt
      @validation_hook = lambda do |_|
        bundle = @service.add_bundle(@aab)
        @service.edits.each_value { |state| state.fetch("bundles") << @service.clone(bundle) }
      end
      if prior_attempt
        execute
        assert_equal "accepted", receipt.fetch("result")
        refute @service.mutations.any? { |row| row[:path].end_with?("/bundles") }
        assert_equal 1, @service.commits.length
        assert_equal 1, @service.mutations.count { |row| row[:path].include?("/deobfuscationFiles/") }
      else
        error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
        assert_includes error.message, "before this operation dispatched"
        assert_empty @service.mutations
        assert_no_receipt
      end
      assert_equal 1, @validation_calls.length
    end
  end

  def test_foreign_bundle_and_complete_track_drift_during_validation_stop_without_writes
    %i[foreign_bundle unrelated_bundle unrelated_release].each do |change|
      reset_case
      prepare("candidate", mapping: true)
      retry_process
      @validation_hook = lambda do |_|
        @service.edits.each_value do |state|
          if change == :unrelated_release
            state.fetch("tracks").fetch("internal").fetch("releases").first["name"] = "Another operator's edit"
          else
            state.fetch("bundles") << { "versionCode" => change == :foreign_bundle ? 200 : 201, "sha256" => "c" * 64 }
          end
        end
      end
      assert_raises(FastlaneCore::Interface::FastlaneError, change.to_s) { execute }
      assert_empty @service.mutations
      assert_no_receipt
    end
  end

  def test_failed_or_expired_final_edit_read_never_opens_another_edit_to_upload
    %i[expired timeout].each do |change|
      reset_case
      prepare("candidate")
      @validation_hook = lambda do |_|
        if change == :expired
          @service.edits.clear
        else
          @service.before_request = ->(row) { raise Google::Apis::RequestTimeOutError, "final reread unavailable" if row[:method] == :get }
        end
      end
      assert_raises(KeyError, Google::Apis::RequestTimeOutError) { execute }
      assert_empty @service.mutations
      assert_no_receipt
      # Preparation + execution classification + one mutation edit, never a
      # transparent replacement edit after native validation invalidates it.
      assert_equal 3, @service.requests.count { |row| row[:method] == :post && row[:path].end_with?("/edits") }
    end
  end

  def test_aab_change_during_last_store_reread_fails_immediate_presend_check
    %i[bytes symlink].each do |change|
      reset_case
      prepare("candidate")
      @validation_hook = lambda do |_|
        @service.after_request = lambda do |row|
          next unless row[:method] == :get && row[:path].end_with?("/bundles")
          path = File.join(@root, "candidate.aab")
          if change == :bytes
            File.write(path, "x" * @aab.bytesize)
          else
            other = File.join(@root, "substitute.aab")
            File.write(other, @aab)
            File.delete(path)
            File.symlink(other, path)
          end
          @service.after_request = nil
        end
      end
      error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
      assert_includes error.message, "exact regular original"
      assert_empty @service.mutations
      assert_no_receipt
      history = JSON.parse(File.read(File.join(@root, "journal.json"))).fetch("history")
      assert history.any? { |row| row["phase"] == "mutation-dispatched" }, "a consumed marker must survive presend failure"
    end
  end

  def test_ambiguous_new_bundle_send_is_not_retried_and_exact_readback_bypasses_current_gate
    prepare("candidate", mapping: true)
    @service.persist_bundles_outside_edit = true
    @service.after_request = ->(row) { raise Google::Apis::TransmissionError, "synthetic lost bundle response" if row[:mutation] && row[:path].end_with?("/bundles") }
    assert_raises(Google::Apis::TransmissionError) { execute }
    assert_equal 1, @service.mutations.length
    assert_no_receipt
    assert_equal 1, @validation_calls.length
    @service.after_request = nil
    retry_process
    @validation_hook = ->(_) { raise "accepted bundle must not require current upload eligibility" }
    execute
    assert_equal 1, @service.mutations.count { |row| row[:path].end_with?("/bundles") }
    assert_equal 1, @validation_calls.length
    assert_equal 1, @service.commits.length
  end

  def test_same_attempt_recovery_preserves_dispatch_after_an_intervening_validation_failure_or_cancellation
    [MobileReleaseKit::ContractError.new("current signing policy rejects"), Interrupt.new("cancelled")].each do |failure|
      reset_case
      prepare("candidate", mapping: true)
      @service.persist_bundles_outside_edit = true
      @service.after_request = lambda do |row|
        raise Google::Apis::TransmissionError, "accepted upload response lost" if row[:mutation] && row[:path].end_with?("/bundles")
      end
      assert_raises(Google::Apis::TransmissionError) { execute }
      journal = File.join(@root, "journal.json")
      first = JSON.parse(File.read(journal)).fetch("history").find { |row| row["phase"] == "mutation-dispatched" }
      refute_nil first
      accepted_bundle = @service.state.fetch("bundles").pop
      @service.after_request = nil
      fresh_process # Same authenticated run AND attempt; the prior journal matters.
      @validation_hook = ->(_) { raise failure }
      expected = failure.is_a?(Interrupt) ? Interrupt : FastlaneCore::Interface::FastlaneError
      assert_raises(expected) { execute }
      assert_includes JSON.parse(File.read(journal)).fetch("history"), first
      assert_no_receipt

      @service.state.fetch("bundles") << accepted_bundle
      fresh_process
      @validation_hook = ->(_) { raise "accepted bytes must not require new-upload eligibility" }
      execute
      assert_equal 2, @validation_calls.length
      assert_equal 1, @service.mutations.count { |row| row[:path].end_with?("/bundles") }
      assert_equal 1, @service.commits.length
      assert_equal 200, receipt.fetch("versionCode")
    end
  end

  def test_each_new_logical_retry_requires_current_validation_but_complete_readback_does_not
    prepare("candidate", mapping: true)
    @service.before_request = ->(row) { raise Google::Apis::ServerError, "synthetic unaccepted upload" if row[:mutation] && row[:path].end_with?("/bundles") }
    assert_raises(Google::Apis::ServerError) { execute }
    @service.before_request = nil
    retry_process
    execute
    assert_equal 2, @validation_calls.length
    File.delete(File.join(@root, "receipt.json"))
    retry_process
    @validation_hook = ->(_) { raise "complete readback/mapping replay is not a new upload" }
    execute
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 2, @validation_calls.length
    assert_equal 2, @service.mutations.count { |row| row[:path].end_with?("/bundles") }
  end

  def test_external_and_production_use_exact_bundle_without_upload_and_preserve_unrelated_state
    %w[external-testing production-submit].each do |stage|
      reset_case
      prepare(stage)
      before = @service.clone(@service.state)
      execute
      assert_equal 3, receipt.fetch("schemaVersion")
      destination = snapshot.fetch("destinationTrack")
      target = @service.state.fetch("tracks").fetch(destination).fetch("releases").find { |row| row["versionCodes"] == ["200"] }
      assert_equal(stage == "production-submit" ? "draft" : "completed", target.fetch("status"))
      assert_equal @unrelated, @service.state.fetch("tracks").fetch(destination).fetch("releases").reject { |row| row["versionCodes"] == ["200"] }
      assert_equal before.fetch("bundles"), @service.state.fetch("bundles")
      refute @service.mutations.any? { |entry| entry.fetch(:path).end_with?("/bundles") }
      assert_equal before.fetch("listings").fetch("fr-FR"), @service.state.fetch("listings").fetch("fr-FR")
      if stage == "production-submit"
        assert_equal "Approved title", @service.state.fetch("listings").fetch("en-US").fetch("title")
        assert_equal before.fetch("listings").fetch("en-US").fetch("video"), @service.state.fetch("listings").fetch("en-US").fetch("video")
        assert_equal [{ "language" => "en-US", "text" => "Approved changelog" }], target.fetch("releaseNotes")
      end
    end
  end

  def test_lost_commit_response_is_read_back_without_second_commit
    prepare("candidate")
    @service.after_request = ->(entry) { raise Google::Apis::TransmissionError, "Synthetic lost commit response" if entry.fetch(:path).end_with?(":commit") }
    execute
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 1, @service.commits.length
  end

  def test_cancellation_after_committed_store_mutation_recovers_in_new_process_without_reupload
    prepare("candidate")
    @service.after_request = ->(entry) { raise Interrupt, "Synthetic killed process" if entry.fetch(:path).end_with?(":commit") }
    assert_raises(Interrupt) { execute }
    assert_no_receipt
    @service.after_request = nil
    retry_process
    execute
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 1, @service.commits.length
    assert_equal 1, @service.mutations.count { |entry| entry.fetch(:path).end_with?("/bundles") }
  end

  def test_receipt_creation_failure_recovers_original_candidate_without_reupload
    prepare("candidate")
    original = @fastfile.method(:atomic_store_document)
    @fastfile.define_singleton_method(:atomic_store_document) do |contents, label:|
      raise IOError, "Synthetic final receipt persistence failure" if label == "a Store receipt"
      original.call(contents, label: label)
    end
    assert_raises(IOError) { execute }
    assert_no_receipt
    retry_process
    execute
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 1, @service.commits.length
  end

  def test_every_candidate_mutation_boundary_recovers_with_original_mapping_bytes
    %i[bundle mapping track commit].each do |boundary|
      reset_case
      prepare("candidate", mapping: true)
      @service.persist_bundles_outside_edit = true
      patterns = { bundle: /\/bundles\z/, mapping: /\/deobfuscationFiles\//, track: /\/tracks\//, commit: /:commit\z/ }
      @service.after_request = lambda do |entry|
        raise Interrupt, "Synthetic cancellation after #{boundary}" if entry.fetch(:mutation) && entry.fetch(:path).match?(patterns.fetch(boundary))
      end
      assert_raises(Interrupt, boundary.to_s) { execute }
      assert_no_receipt
      @service.after_request = nil
      retry_process
      execute
      assert_equal "fictional mapping bytes", @service.state.fetch("mappings")[["200", "proguard"]], boundary.to_s
      assert_equal 1, @service.mutations.count { |entry| entry.fetch(:path).end_with?("/bundles") }, boundary.to_s
      mappings = @service.mutations.select { |entry| entry.fetch(:path).include?("/deobfuscationFiles/") }
      assert mappings.all? { |entry| entry.fetch(:path).include?("/apks/200/deobfuscationFiles/proguard") }, boundary.to_s
      assert mappings.all? { |entry| entry.fetch(:upload_sha256) == Digest::SHA256.hexdigest("fictional mapping bytes") }, boundary.to_s
    end
  end

  def test_mapping_recovery_ambiguous_commit_cannot_be_proven_by_track_readback
    prepare("candidate", mapping: true)
    execute
    File.unlink(File.join(@root, "receipt.json")) # model final evidence lost after successful mutation
    retry_process
    @service.after_request = ->(entry) { raise Google::Apis::TransmissionError, "Synthetic mapping commit ambiguity" if entry.fetch(:path).end_with?(":commit") }
    assert_raises(Google::Apis::TransmissionError) { execute }
    assert_no_receipt
    @service.after_request = nil
    retry_process
    execute
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 3, @service.commits.length # original, ambiguous scoped replay, acknowledged scoped replay
  end

  def test_mapping_not_bound_to_intent_or_renamed_endpoint_type_fails_before_any_write
    prepare("candidate")
    ENV["MOBILE_RELEASE_ANDROID_MAPPING_PATH"] = "mapping.txt"
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations

    reset_case
    prepare("candidate", mapping: true)
    FileUtils.cp(File.join(@root, "mapping.txt"), File.join(@root, "mapping.zip"))
    ENV["MOBILE_RELEASE_ANDROID_MAPPING_PATH"] = "mapping.zip"
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
  end

  def test_existing_external_target_can_be_observed_after_automatic_source_deactivation
    @service.state.fetch("tracks").fetch("closed-qa").fetch("releases") << release(200)
    prepare("external-testing", populate_source: false)
    before = @service.clone(@service.state)
    execute
    assert_equal before, @service.state
    assert_empty @service.mutations
    assert_equal "already_present", receipt.fetch("result")
    assert_equal "already-deactivated", receipt.dig("storeState", "sourceTargetTransition")
    assert_equal [snapshot.fetch("sourceState")], snapshot.fetch("sourceAllowedStates")
  end

  def test_newly_appeared_bundle_is_not_reused_by_initial_attempt
    prepare("candidate")
    @service.add_bundle(@aab)
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
    assert_no_receipt
  end

  def test_later_attempt_reuses_exact_bundle_from_abandoned_edit_but_not_a_substitute
    prepare("candidate")
    @service.add_bundle(@aab)
    retry_process
    execute
    assert_equal "accepted", receipt.fetch("result")
    refute @service.mutations.any? { |entry| entry.fetch(:path).end_with?("/bundles") }
    assert_equal 1, @service.commits.length

    reset_case
    prepare("candidate")
    @service.add_bundle("different bytes")
    retry_process
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
    assert_no_receipt
  end

  def test_unsuccessful_ambiguous_commit_does_not_claim_success_and_next_attempt_uses_fresh_edit
    prepare("candidate")
    @service.persist_bundles_outside_edit = true
    @service.before_request = lambda do |entry|
      raise Google::Apis::TransmissionError, "Synthetic commit did not reach Store" if entry.fetch(:path).end_with?(":commit")
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_no_receipt
    previous_edit = @service.commits.first.fetch(:params).fetch("editId")
    @service.before_request = nil
    retry_process
    execute
    assert_equal "accepted", receipt.fetch("result")
    refute_equal previous_edit, @service.commits.last.fetch(:params).fetch("editId")
    assert_equal 1, @service.mutations.count { |entry| entry.fetch(:path).end_with?("/bundles") }
  end

  def test_mapping_recovery_verifies_full_target_before_mapping_write
    prepare("candidate", mapping: true)
    execute
    File.unlink(File.join(@root, "receipt.json"))
    retry_process
    before_count = @service.mutations.length
    @service.state.fetch("tracks").fetch("internal").fetch("releases").first["name"] = "Unrelated drift"
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal before_count, @service.mutations.length
    assert_no_receipt
  end

  def test_preexisting_production_draft_requires_original_intent_not_a_fresh_prepare
    @service.state.fetch("tracks").fetch("production").fetch("releases") << release(200, status: "draft")
    assert_raises(FastlaneCore::Interface::FastlaneError) { prepare("production-submit") }
    assert_empty @service.mutations
  end

  def test_target_appearing_between_initial_read_and_mutation_edit_is_rejected
    prepare("candidate")
    reads = 0
    @service.after_request = lambda do |entry|
      next unless entry.fetch(:method) == :get && entry.fetch(:path).end_with?("/bundles")
      reads += 1
      target_state! if reads == 1
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
    assert_no_receipt
  end

  def test_newly_appeared_target_is_not_adopted_by_the_initial_attempt
    prepare("candidate")
    target_state!
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
    assert_no_receipt
  end

  def test_forged_bundle_digest_or_unrelated_track_state_fails_before_any_write
    %i[digest track unrelated_bundle].each do |damage|
      reset_case
      prepare("candidate")
      retry_process
      target_state!
      case damage
      when :digest then @service.state.fetch("bundles").last["sha256"] = "f" * 64
      when :track then @service.state.fetch("tracks").fetch("internal").fetch("releases").first["name"] = "drifted"
      when :unrelated_bundle then @service.add_bundle("unrelated", code: 777)
      end
      assert_raises(FastlaneCore::Interface::FastlaneError, damage.to_s) { execute }
      assert_empty @service.mutations, damage.to_s
      assert_no_receipt
    end
  end

  def test_production_metadata_drift_fails_before_mutation_and_bad_write_aborts_before_commit
    prepare("production-submit")
    @service.state.fetch("listings").fetch("fr-FR")["title"] = "Concurrent change"
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.mutations
    assert_no_receipt

    reset_case
    prepare("production-submit")
    @service.after_request = lambda do |entry|
      if entry.fetch(:method) == :put && entry.fetch(:path).include?("/listings/")
        @service.edits.fetch(entry.fetch(:params).fetch("editId")).fetch("listings").fetch("fr-FR")["title"] = "Collateral API write"
      end
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.commits
    assert_equal "Untouched French", @service.state.fetch("listings").fetch("fr-FR").fetch("title")
    assert_no_receipt
  end

  def test_precommit_bundle_digest_mismatch_is_rejected_without_commit
    prepare("candidate")
    @service.after_request = lambda do |entry|
      if entry.fetch(:path).end_with?("/bundles") && entry.fetch(:method) == :post
        @service.edits.fetch(entry.fetch(:params).fetch("editId")).fetch("bundles").last["sha256"] = "e" * 64
      end
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.commits
    assert_no_receipt
  end

  def test_prepare_rejects_wrong_status_and_multicode_source_without_mutating
    [release(200, status: "draft"), release(200).merge("versionCodes" => %w[199 200])].each do |invalid|
      reset_case
      @service.state.fetch("tracks").fetch("internal").fetch("releases") << invalid
      assert_raises(FastlaneCore::Interface::FastlaneError) { prepare("external-testing") }
      assert_empty @service.mutations
    end
  end

  def test_production_recovery_verifies_metadata_target_and_leaves_entire_state_unchanged
    prepare("production-submit")
    @service.after_request = ->(entry) { raise Interrupt, "Synthetic terminated after production draft" if entry.fetch(:path).end_with?(":commit") }
    assert_raises(Interrupt) { execute }
    committed = @service.clone(@service.state)
    @service.after_request = nil
    retry_process
    execute
    assert_equal committed, @service.state
    assert_equal 1, @service.commits.length
    assert_equal "draft", receipt.fetch("state")
    assert_equal "reconciled", receipt.fetch("result")
  end

  def test_real_supply_image_order_replacement_is_proved_before_commit_and_retains_untouched_assets
    local = File.join(@root, "release/store/android/en-US/images/phoneScreenshots")
    FileUtils.mkdir_p(local)
    File.binwrite(File.join(local, "01.png"), "retained-first")
    File.binwrite(File.join(local, "02.png"), "approved-second")
    first = @service.add_image("en-US", "phoneScreenshots", "retained-first")
    @service.add_image("en-US", "phoneScreenshots", "obsolete-second")
    untouched = @service.add_image("fr-FR", "phoneScreenshots", "untouched-french")
    @service.add_image("en-US", "tvBanner", "untouched-banner")
    prepare("production-submit")
    execute
    actual = @service.state.fetch("images")[["en-US", "phoneScreenshots"]]
    assert_equal [Digest::SHA256.hexdigest("retained-first"), Digest::SHA256.hexdigest("approved-second")], actual.map { |row| row.fetch("sha256") }
    assert_equal first.fetch("id"), actual.first.fetch("id")
    assert_equal [untouched], @service.state.fetch("images")[["fr-FR", "phoneScreenshots"]]
    assert_equal 1, @service.commits.length
    assert_equal receipt.dig("storeState", "metadataExpectedSha256"), receipt.dig("storeState", "metadataCommittedSha256")
  end

  def add_production_images
    folder = File.join(@root, "release/store/android/en-US/images/phoneScreenshots")
    FileUtils.mkdir_p(folder)
    File.binwrite(File.join(folder, "01.png"), "approved-first")
    File.binwrite(File.join(folder, "02.png"), "approved-second")
    @service.add_image("en-US", "phoneScreenshots", "obsolete-first")
    @service.add_image("fr-FR", "phoneScreenshots", "preserved-french")
  end

  def test_production_cancellation_after_every_real_metadata_request_recovers_without_collateral_changes
    add_production_images
    prepare("production-submit")
    execute
    operations = @service.mutations.map { |entry| [entry.fetch(:method), entry.fetch(:path).sub(/edit-[0-9]+/, "EDIT")] }
    assert_operator operations.length, :>=, 7 # track, listing, delete, two images, notes, commit
    operations.each_index do |boundary|
      reset_case
      add_production_images
      prepare("production-submit")
      initial = @service.clone(@service.state)
      @service.after_request = lambda do |entry|
        if entry.fetch(:mutation) && @service.mutations.length == boundary + 1
          raise Interrupt, "Synthetic cancellation at production mutation #{boundary}"
        end
      end
      # Interrupt is deliberately not rescued as an ordinary API error.
      old_report = Thread.report_on_exception
      Thread.report_on_exception = false
      begin
        assert_raises(Interrupt, "mutation #{boundary}") { execute }
      ensure
        Thread.report_on_exception = old_report
      end
      assert_no_receipt
      @service.after_request = nil
      retry_process
      execute
      assert_equal initial.fetch("listings").fetch("fr-FR"), @service.state.fetch("listings").fetch("fr-FR"), "mutation #{boundary}"
      assert_equal initial.fetch("images")[["fr-FR", "phoneScreenshots"]], @service.state.fetch("images")[["fr-FR", "phoneScreenshots"]], "mutation #{boundary}"
      assert_equal @unrelated, @service.state.fetch("tracks").fetch("production").fetch("releases").reject { |row| row["versionCodes"] == ["200"] }, "mutation #{boundary}"
      assert_equal "draft", receipt.fetch("state")
      assert_equal 1, @service.commits.length, "a cancelled uncommitted edit should not need a second successful commit"
    end
  end

  def test_production_bad_image_upload_is_rejected_inside_edit_without_commit
    add_production_images
    prepare("production-submit")
    @service.after_request = lambda do |entry|
      next unless entry.fetch(:method) == :post && entry.fetch(:path).include?("/listings/")
      pending = @service.edits.fetch(entry.fetch(:params).fetch("editId"))
      image = pending.fetch("images")[["en-US", "phoneScreenshots"]].last
      image["sha256"] = Digest::SHA256.hexdigest("unapproved Store transform")
      @service.image_bytes[image.fetch("id")] = "unapproved Store transform"
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_empty @service.commits
    assert_no_receipt
  end

  def test_unchanged_image_group_cannot_be_replaced_with_new_ids_during_recovery
    @service.add_image("fr-FR", "phoneScreenshots", "unrelated bytes")
    prepare("production-submit")
    execute
    File.unlink(File.join(@root, "receipt.json"))
    retry_process
    @service.state.fetch("images")[["fr-FR", "phoneScreenshots"]] = []
    @service.add_image("fr-FR", "phoneScreenshots", "unrelated bytes")
    count = @service.mutations.length
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal count, @service.mutations.length
    assert_no_receipt
  end

  def test_external_can_recover_allowed_source_deactivation_but_not_unrelated_drift
    prepare("external-testing")
    @service.after_request = lambda do |entry|
      next unless entry.fetch(:path).end_with?(":commit")
      @service.state.fetch("tracks").fetch("internal").fetch("releases").reject! { |row| row["versionCodes"] == ["200"] }
      raise Interrupt, "Synthetic source deactivation and response loss"
    end
    assert_raises(Interrupt) { execute }
    @service.after_request = nil
    retry_process
    execute
    assert_equal "deactivated", receipt.dig("storeState", "sourceTargetTransition")
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal 1, @service.commits.length
  end

  def test_unconfigured_disk_locale_is_not_mutated_by_supply
    FileUtils.mkdir_p(File.join(@root, "release/store/android/fr-FR"))
    File.write(File.join(@root, "release/store/android/fr-FR/title.txt"), "Unapproved filesystem data")
    prepare("production-submit")
    execute
    assert_equal "Untouched French", @service.state.fetch("listings").fetch("fr-FR").fetch("title")
    refute @service.mutations.any? { |entry| entry.fetch(:path).include?("/listings/fr-FR") }
  end
end

class BoundedPlayImageTest < Minitest::Test
  def setup
    verbosity = $VERBOSE
    $VERBOSE = nil
    @fastfile = Fastlane::FastFile.new(File.expand_path("../../fastlane/Fastfile", __dir__))
  ensure
    $VERBOSE = verbosity
  end

  def verify(responses, url: "https://play-fixture.googleusercontent.com/one", bytes: "expected")
    @connections = []
    factory = lambda do |host, port, proxy|
      assert_equal 443, port
      assert_nil proxy
      connection = PlayFixture::ImageConnection.new({}, responses: responses)
      @connections << [host, connection]
      connection
    end
    Net::HTTP.stub(:new, factory) { @fastfile.bounded_play_image(url, Digest::SHA256.hexdigest(bytes)) }
  end

  def test_streams_chunks_without_body_buffer_and_without_ambient_proxy_or_credentials
    response = PlayFixture::ImageConnection.response(chunks: %w[ex pected])
    assert_equal({ "sha256" => Digest::SHA256.hexdigest("expected"), "size" => 8 }, verify([response]))
    connection = @connections.first.last
    assert_equal 0, connection.max_retries
    assert_equal "identity", connection.requests.first["Accept-Encoding"]
    assert_nil connection.requests.first["Authorization"]
  end

  def test_oversized_chunked_response_stops_reading_immediately
    read = 0
    response = PlayFixture::ImageConnection.response
    response.define_singleton_method(:read_body) do |&block|
      100.times do
        read += 1
        block.call("x" * 1024 * 1024)
      end
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { verify([response]) }
    assert_equal 11, read
  end

  def test_bad_declared_length_rejected_before_reading
    response = PlayFixture::ImageConnection.response(headers: { "Content-Length" => (11 * 1024 * 1024).to_s })
    response.define_singleton_method(:read_body) { raise "Should not read oversized declared body" }
    assert_raises(FastlaneCore::Interface::FastlaneError) { verify([response]) }
  end

  def test_unsafe_origins_credentials_ports_and_redirects_never_receive_a_request
    %w[http://play-fixture.googleusercontent.com/one https://evil.example/one https://googleusercontent.com.evil.example/one https://user:secret@play-fixture.googleusercontent.com/one https://play-fixture.googleusercontent.com:8443/one https://play-fixture.googleusercontent.com/one#fragment].each do |url|
      assert_raises(FastlaneCore::Interface::FastlaneError) { verify([], url: url) }
      assert_empty @connections
    end
    response = PlayFixture::ImageConnection.response(code: 302, headers: { "Location" => "http://127.0.0.1/private" })
    assert_raises(FastlaneCore::Interface::FastlaneError) { verify([response]) }
    assert_equal 1, @connections.length
  end

  def test_checksum_mismatch_and_redirect_limit_fail_closed
    assert_raises(FastlaneCore::Interface::FastlaneError) { verify([PlayFixture::ImageConnection.response("substituted")]) }
    redirects = Array.new(4) { PlayFixture::ImageConnection.response(code: 302, headers: { "Location" => "/again" }) }
    assert_raises(FastlaneCore::Interface::FastlaneError) { verify(redirects) }
    assert_equal 4, @connections.length
  end
end
