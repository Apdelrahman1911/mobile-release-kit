# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "time"
require_relative "apple_fixture"
require_relative "../../fastlane/store_lane_fastlane_bridges"
require "fastlane_core/itunes_transporter"
require "fastlane_core/ipa_upload_package_builder"
require "fastlane_core/fastlane_pty"
require "pilot/build_manager"

class AppleReleaseLanesTest < Minitest::Test
  def setup
    @environment = ENV.to_h
    @old_client = Spaceship::ConnectAPI.client
    @root = File.realpath(Dir.mktmpdir("mrk-apple-lanes-"))
    FileUtils.mkdir_p(File.join(@root, "release/store/testflight"))
    FileUtils.mkdir_p(File.join(@root, "release/store/review"))
    File.write(File.join(@root, "release/store/testflight/what-to-test.txt"), "Test the fictional workflow")
    %w[ios-beta-notes ios-notes].each do |name|
      File.write(File.join(@root, "release/store/review/#{name}.txt"), "Fictional review notes")
    end
    File.write(File.join(@root, "version.properties"), "VERSION_NAME=1.2.3\nVERSION_CODE=123\n")
    File.write(File.join(@root, "candidate.ipa"), "not a real binary; Python validation is tested separately")
    File.write(File.join(@root, "archive.zip"), "opaque archive; Python correlation is tested separately")
    File.write(File.join(@root, "dsyms.zip"), "opaque symbols; Python correlation is tested separately")
    File.write(File.join(@root, "release/mobile-release.json"), JSON.generate(
      "version" => { "source" => "version.properties", "nameKey" => "VERSION_NAME", "buildKey" => "VERSION_CODE" },
      "ios" => { "bundleId" => "test.example.release", "appStoreAppId" => "12345", "externalTestFlightGroup" => "External QA",
                 "review" => { "demoAccountRequired" => false, "usesNonExemptEncryption" => false } },
      "metadata" => { "root" => "release/store", "iosLocales" => %w[en-US fr-FR de-DE] },
    ))
    ENV.update(
      "MOBILE_RELEASE_APP_ROOT" => @root,
      "MOBILE_RELEASE_CONFIG_PATH" => "release/mobile-release.json",
      "MOBILE_RELEASE_PLATFORM" => "ios",
      "MOBILE_RELEASE_APP_IDENTITY" => "test.example.release",
      "MOBILE_RELEASE_OPERATION_INTENT_PATH" => "intent.json",
      "MOBILE_RELEASE_APPLE_STATE_PATH" => "journal.json",
      "MOBILE_RELEASE_IOS_IPA_PATH" => "candidate.ipa",
      "MOBILE_RELEASE_IOS_ARCHIVE_PATH" => "archive.zip",
      "MOBILE_RELEASE_IOS_DSYMS_PATH" => "dsyms.zip",
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64" => Base64.strict_encode64("k" * 32),
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION" => "test-v1",
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME" => "Fictional",
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME" => "Reviewer",
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL" => "review@example.test",
      "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE" => "+12025550124",
    )
    @authority = {
      "workflow" => "Synthetic", "runId" => "111", "attempt" => 1,
      "callerPath" => ".github/workflows/mobile-candidate.yml", "reusableRepository" => "test/toolkit",
      "reusablePath" => ".github/workflows/reusable-candidate.yml", "reusableCommit" => "a" * 40,
      "event" => "workflow_dispatch", "headSha" => "b" * 40, "ref" => "refs/heads/main",
    }
    ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(@authority)
    @service = AppleFixture.new
    Spaceship::ConnectAPI.client = @service.client
    @time = 0
    @wall_clock = Time.now.utc
    @signing_expires_at = @wall_clock + 86_400
    @upload_validation_calls = []
    @upload_count = 0
    @upload_error = false
    @upload_unobserved = false
    @next_recovery_run = 221
    fresh_process
  end

  def teardown
    ENV.replace(@environment)
    Spaceship::ConnectAPI.client = @old_client
    FileUtils.remove_entry(@root)
  end

  def fresh_process
    verbose = $VERBOSE
    $VERBOSE = nil
    @fastfile = Fastlane::FastFile.new(File.expand_path("../../fastlane/Fastfile", __dir__))
    @fastfile.define_singleton_method(:asc_api_key) { {} }
    test = self
    @fastfile.define_singleton_method(:sleep) { |seconds| test.advance(seconds) }
    @fastfile.define_singleton_method(:upload_to_testflight) { |**options| test.upload(options) }
    @fastfile.define_singleton_method(:validate_current_ios_upload!) { |ipa| test.validate_upload(ipa) }
  ensure
    $VERBOSE = verbose
  end

  def advance(seconds) = @time += seconds

  def upload(options)
    assert_equal true, options.fetch(:skip_waiting_for_build_processing)
    assert_equal true, options.fetch(:skip_submission)
    assert_equal false, options.fetch(:distribute_external)
    assert_equal @payload.fetch("artifacts").find { |artifact| artifact["logicalName"] == "ios-ipa" }.fetch("sha256"), Digest::SHA256.file(options.fetch(:ipa)).hexdigest
    @upload_count += 1
    raise Faraday::TimeoutError, "Synthetic unobservable Transporter outcome" if @upload_unobserved
    @service.attributes("builds", "build-1")["uploadedDate"] = Time.now.utc.iso8601
    @service.visible = true
    raise Faraday::TimeoutError, "Synthetic Transporter response loss" if @upload_error
  end

  def validate_upload(ipa)
    @upload_validation_calls << { "ipa" => ipa, "at" => @time }
    interval = {
      "notBefore" => (@wall_clock - 86_400).iso8601,
      "notAfter" => @signing_expires_at.iso8601,
    }
    # The full Python/native validator is tested separately. This seam retains
    # the real interval failure guard while exercising the actual lane state
    # machine and every prohibited Transporter boundary.
    MobileReleaseKit::IosUploadValidation.require_current!(interval)
    interval
  end

  def lane(name)
    Process.stub(:clock_gettime, ->(*) { @time }) do
      Time.stub(:now, -> { @wall_clock + @time }) { @fastfile.runner.lanes.fetch(nil).fetch(name.to_sym).call({}) }
    end
  end

  def prepare(stage)
    @lane_name = stage == "candidate" ? "ios_testflight_internal" : "ios_testflight_external"
    ENV["MOBILE_RELEASE_OPERATION"] = @lane_name
    ENV["MOBILE_RELEASE_STORE_MODE"] = "prepare"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "precondition.json"
    lane(@lane_name)
    precondition = JSON.parse(File.read(File.join(@root, "precondition.json")))
    if stage == "candidate" && !@service.visible
      # The fixture's invisible record represents a future accepted upload, not
      # a build that predates authorization just because setup crossed a second.
      @service.attributes("builds", "build-1")["uploadedDate"] = precondition.fetch("snapshot").fetch("serverObservedAt")
    end
    @payload = {
      "schemaVersion" => 1, "documentType" => "store-operation-intent", "stage" => stage, "platform" => "ios",
      "storePrecondition" => precondition, "authorizedBy" => @authority.dup,
      "privateStateCommitments" => precondition.fetch("snapshot").fetch("privateStateCommitments", {}),
      "artifacts" => { "ios-ipa" => "candidate.ipa", "ios-archive" => "archive.zip", "ios-dsyms" => "dsyms.zip" }.map do |name, file|
        { "logicalName" => name, "size" => File.size(File.join(@root, file)),
          "sha256" => Digest::SHA256.file(File.join(@root, file)).hexdigest }
      end,
    }
    @intent_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(@payload))
    File.write(File.join(@root, "intent.json"), JSON.generate(@payload.merge("integrity" => { "algorithm" => "sha256", "sha256" => @intent_digest })))
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    ENV["MOBILE_RELEASE_STORE_RECEIPT_PATH"] = "receipt.json"
  end

  def execute = lane(@lane_name)
  def receipt = JSON.parse(File.read(File.join(@root, "receipt.json")))
  def journal = JSON.parse(File.read(File.join(@root, "journal.json")))

  def retry_process(cross_run: false)
    if cross_run
      ENV["MOBILE_RELEASE_RECOVERY_RUN_ID"] = "111"
      @authority["runId"] = (@next_recovery_run += 1).to_s
      @authority["attempt"] = 1
    else
      @authority["attempt"] += 1
    end
    ENV["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = JSON.generate(@authority)
    fresh_process
  end

  def recover_external
    ENV.delete("MOBILE_RELEASE_RECOVERY_CONFIRMATION")
    retry_process
    prior = Marshal.load(Marshal.dump(@service.writes))
    begin
      return execute
    rescue MobileReleaseKit::ContractError
      entry = journal.fetch("history").last
      raise unless entry.fetch("phase") == "create-retry-required"
      assert_equal prior, @service.writes, "recovery wrote to Store before absent-create authorization"
      confirmation = entry.fetch("confirmation")
    end
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = confirmation
    execute
  end

  class BridgeEndpoint
    attr_accessor :autoclose, :close_error, :prepared
    attr_reader :close_calls
    def initialize = @close_calls = 0
    def close_on_exec=(value)
      @close_on_exec = value
      prepared&.call
    end
    def close
      @close_calls += 1
      raise close_error if close_error
    end
    def gets(*) = nil
  end

  def with_real_upload_bridge(cut:, conversion: :none, close_fails: false, foreign_build: false, response_loss: false)
    # Real Pilot/package/key/transporter/PipeAdapter code, including the pinned
    # executor's StandardError#exit_status rescue. Native creation/wait/IO are
    # inert before entry; this is not native process or macOS evidence.
    lifetime, bridges = MobileReleaseKit::StoreLaneLifetime, MobileReleaseKit::StoreLaneFastlaneBridges
    private_root = File.join(@root, "bridge-private")
    [private_root, File.join(private_root, "tmp"), File.join(private_root, "runner")].each { |path| Dir.mkdir(path, 0o700) }
    stat = File.stat(private_root)
    artifact = File.join(@root, "candidate.ipa")
    deadline = MobileReleaseKit::NativeUploadProcess.monotonic_ns + 3_600_000_000_000
    record = lifetime::Invocation.new(lane: "ios_testflight_internal", mode: "execute", nonce: "n" * 16,
      output: File.join(@root, "receipt.json"), run_deadline_ns: deadline)
    binding = {"root" => private_root, "root_device" => stat.dev, "root_inode" => stat.ino,
      "lane" => "ios_testflight_internal", "mode" => "execute", "shell_home" => false, "macos" => true,
      "app_id" => "12345", "key_id" => "KEY123", "artifact" => artifact, "run_deadline_ns" => deadline}.freeze
    resources = MobileReleaseKit::StoreLaneResources::Inventory.new(invocation: record, binding: binding)
    record.bind_resources!(resources)
    resources.admit!
    runtime = Object.new
    runtime.define_singleton_method(:resources) { resources }
    runtime.define_singleton_method(:invocation) { record }
    runtime.define_singleton_method(:binding) { binding }
    runtime.define_singleton_method(:xml_template) { '<package><%= @data[:ipa_path] %></package>' }
    runtime.define_singleton_method(:require_active!) { record.require_upload_continuation! }
    runtime.define_singleton_method(:mark_unknown!) { |error, cleanup: false| record.mark_unknown!(error, cleanup: cleanup) }
    expire = -> { @time = (@signing_expires_at - @wall_clock).to_i }
    boundary = {package: :copy_package_ipa!, key: :write_api_key!}[cut]
    if boundary
      actual = resources.method(boundary)
      resources.define_singleton_method(boundary) do |*args, **keywords|
        result = actual.call(*args, **keywords)
        expire.call
        result
      end
    end
    key = {key_id: "KEY123", issuer_id: "synthetic-issuer", key: "synthetic non-credential bytes"}
    executor = FastlaneCore::AltoolTransporterExecutor.allocate
    executor.singleton_class.prepend(bridges.const_get(:KeyBridge, false))
    executor.define_singleton_method(:build_upload_command) { |*| "inert-upload-never-executed" }
    execute = executor.method(:execute)
    executor_calls = []
    executor.define_singleton_method(:execute) do |command, hide_output|
      executor_calls << command
      expire.call if cut == :executor
      result = execute.call(command, hide_output)
      raise Faraday::TimeoutError, "synthetic response loss after valid native admission" if response_loss
      result
    end
    transporter = FastlaneCore::ItunesTransporter.allocate
    transporter.singleton_class.prepend(bridges.const_get(:TransporterBridge, false))
    transporter.instance_variable_set(:@transporter_executor, executor)
    transporter.instance_variable_set(:@api_key, key)
    transporter.instance_variable_set(:@jwt, "synthetic-token")
    builder = FastlaneCore::IpaUploadPackageBuilder.allocate
    builder.singleton_class.prepend(bridges.const_get(:PackageBridge, false))
    pilot = Pilot::BuildManager.allocate
    pilot.singleton_class.prepend(bridges.const_get(:PilotBridge, false))
    pilot.define_singleton_method(:start) { |options, should_login:| @config = options }
    pilot.define_singleton_method(:config) { @config }
    pilot.define_singleton_method(:fetch_app_id) { "12345" }
    pilot.define_singleton_method(:fetch_app_platform) { "ios" }
    pilot.define_singleton_method(:check_for_changelog_or_whats_new!) { |*| nil }
    pilot.define_singleton_method(:transporter_for_selected_team) { |*| transporter }
    test = self
    @fastfile.define_singleton_method(:asc_api_key) { key }
    @fastfile.define_singleton_method(:upload_to_testflight) do |**options|
      begin
        pilot.upload(options)
      rescue StandardError
        test.instance_variable_get(:@service).visible = true if foreign_build
        raise Faraday::TimeoutError, "synthetic outer conversion of no-send" if conversion == :converted
        raise unless conversion == :swallowed
        true
      end
    end
    @fastfile.define_singleton_method(:validate_current_ios_upload!) do |ipa|
      test.instance_variable_get(:@upload_validation_calls) << {"ipa" => ipa, "at" => test.instance_variable_get(:@time)}
      MobileReleaseKit::IosUploadValidation.current!(python: RbConfig.ruby,
        module_root: File.expand_path("../../src", __dir__), app_root: test.instance_variable_get(:@root),
        config_path: File.join(test.instance_variable_get(:@root), "release/mobile-release.json"),
        intent_path: File.join(test.instance_variable_get(:@root), "intent.json"), ipa_path: ipa,
        intent_sha256: test.instance_variable_get(:@intent_digest), environment: {},
        tooling_directory: File.expand_path("../../fastlane", __dir__))
    end
    type = MobileReleaseKit::NativeUploadValidation.const_get(:CaptureSession, false)
    output = JSON.generate("documentType" => "ios-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => @intent_digest, "ipaSha256" => Digest::SHA256.file(artifact).hexdigest,
      "ipaSize" => File.size(artifact), "notBefore" => (@wall_clock - 86_400).iso8601,
      "notAfter" => @signing_expires_at.iso8601).freeze
    constructor = lambda do |**request|
      session = type.allocate
      session.instance_variable_set(:@store_binding, request.fetch(:store_binding))
      session.instance_variable_set(:@stdout, output)
      session.instance_variable_set(:@phase, :accepted)
      session.define_singleton_method(:execute) { output }
      session.define_singleton_method(:successful_offer?) { true }
      session.define_singleton_method(:finality_confirmed?) { true }
      session
    end
    endpoints = Array.new(4) { BridgeEndpoint.new }
    endpoints.last.prepared = expire if cut == :pipe
    endpoints.first.close_error = IOError.new("synthetic no-send close uncertainty") if close_fails
    pipes, waits = 0, []
    pipe = lambda do
      pipes += 1
      flunk "unexpected additional pipe" unless pipes.between?(1, 2)
      endpoints.slice((pipes - 1) * 2, 2)
    end
    status = Struct.new(:pid, :exitstatus) do
      def exited? = true
      def signaled? = false
    end.new(4242, 0)
    spawn = lambda do |command, **_options|
      assert_equal "inert-upload-never-executed", command
      @upload_count += 1
      @service.attributes("builds", "build-1")["uploadedDate"] = Time.now.utc.iso8601
      @service.visible = true
      expire.call if cut == :after_send
      status.pid
    end
    pipe_bridge = Object.new.extend(bridges.const_get(:PipeBridge, false))
    forbidden = ->(*) { flunk "unexpected native operation in inert real-bridge model" }
    lifetime.stub(:current_invocation, record) do
      bridges.stub(:runtime!, runtime) do
        type.stub(:new, constructor) do
          FastlaneCore::Helper.stub(:test?, false) do
            FastlaneCore::IpaUploadPackageBuilder.stub(:new, builder) do
              FastlaneCore::FastlanePty.stub(:spawn, pipe_bridge.method(:spawn)) do
                IO.stub(:pipe, pipe) do
                  Process.stub(:spawn, spawn) do
                    Process.stub(:waitpid2, ->(pid, flags) { waits << [pid, flags]; [pid, status] }) do
                      Process.stub(:kill, forbidden) do
                        Process.stub(:detach, forbidden) do
                          Process.stub(:setsid, forbidden) { yield record, resources, endpoints, executor_calls, waits }
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  ensure
    resources&.close_independent!
  end

  def test_candidate_lost_upload_reply_reconciles_in_process_and_turns_off_notifications
    @service.visible = false
    prepare("candidate")
    @upload_error = true
    execute
    assert_equal 1, @upload_count
    assert_equal "reconciled", receipt.fetch("result")
    assert_equal false, receipt.fetch("autoNotifyEnabled")
    assert_equal ["/v1/builds/build-1", "/v1/buildBetaDetails/detail-1"], @service.writes.map { |_, path, _| path }
  end

  def assert_latched_upload_stops_continuation(converted:)
    @service.visible = false
    prepare("candidate")
    lifetime = MobileReleaseKit::StoreLaneLifetime
    record = lifetime::Invocation.new(lane: @lane_name, nonce: "n" * 16,
      output: File.join(@root, "receipt.json"), mode: "execute", run_deadline_ns: 60_000_000_000)
    primary = IOError.new("synthetic original adapter uncertainty")
    test = self
    @fastfile.define_singleton_method(:upload_to_testflight) do |**options|
      test.upload(options)
      record.mark_unknown!(primary)
      raise Faraday::TimeoutError, "synthetic upstream error conversion" if converted
      true # A swallowed/converted original error is still latched.
    end
    @fastfile.define_singleton_method(:poll_exact_ios_build) { |*_, **_| test.flunk "uncertain upload reached readback" }
    lifetime.stub(:current_invocation, record) do
      error = assert_raises(lifetime::LifetimeError) { execute }
      assert_same primary, error.primary
    end
    assert_equal 1, @upload_count
    assert_empty @service.writes
    refute File.exist?(File.join(@root, "receipt.json"))
    refute journal.fetch("history").any? { |entry| entry["phase"] == "upload-response-ambiguous" }
  end

  def test_candidate_normal_upload_return_cannot_bypass_latched_lifetime
    assert_latched_upload_stops_continuation(converted: false)
  end

  def test_candidate_converted_upload_error_checks_lifetime_before_ambiguity_journal
    assert_latched_upload_stops_continuation(converted: true)
  end

  def test_common_precondition_and_receipt_publication_require_original_continuation
    @service.visible = false
    prepare("candidate")
    lifetime = MobileReleaseKit::StoreLaneLifetime
    record = lifetime::Invocation.new(lane: @lane_name, nonce: "n" * 16,
      output: File.join(@root, "receipt.json"), mode: "execute", run_deadline_ns: 60_000_000_000)
    record.mark_unknown!(IOError.new("synthetic unresolved nested consumer"))
    test = self
    @fastfile.define_singleton_method(:atomic_store_document) { |*_, **_| test.flunk "uncertain lifetime reached publication" }
    lifetime.stub(:current_invocation, record) do
      assert_raises(lifetime::LifetimeError) do
        @fastfile.write_precondition(operation: @lane_name, platform: "ios", identity: "model", snapshot: {})
      end
      assert_raises(lifetime::LifetimeError) do
        @fastfile.write_receipt(operation: @lane_name, platform: "ios", identity: "model", result: "accepted", extra: {})
      end
    end
  end

  def test_candidate_retained_archive_and_symbols_are_checked_before_any_mutation
    @service.visible = false
    prepare("candidate")
    %w[archive.zip dsyms.zip].each do |name|
      path = File.join(@root, name)
      original = File.binread(path)
      File.binwrite(path, "X" + original.byteslice(1..)) # Same size, different hash.
      error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
      assert_includes error.message, "differs from the authenticated operation intent"
      assert_equal 0, @upload_count
      assert_empty @service.writes
      File.binwrite(path, original)
    end
    %w[MOBILE_RELEASE_IOS_ARCHIVE_PATH MOBILE_RELEASE_IOS_DSYMS_PATH].each do |name|
      path = ENV.delete(name)
      error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
      assert_includes error.message, "artifact is missing"
      assert_equal 0, @upload_count
      assert_empty @service.writes
      ENV[name] = path
    end
    execute
    assert_equal 1, @upload_count
  end

  def test_prior_attempt_absence_is_never_authority_to_upload_again
    @service.visible = false
    prepare("candidate")
    retry_process
    error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_includes error.message, "retry-ios-candidate-upload:#{@intent_digest}:"
    assert_equal 0, @upload_count
    assert_empty @service.writes
    assert_operator @time, :>=, 600
  end

  def test_delayed_visible_candidate_requires_explicit_new_dispatch_even_on_same_run_retry
    @service.visible = false
    prepare("candidate")
    retry_process
    @service.before_read = ->(_path) { @service.visible = true if @time >= 90 }
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal 0, @upload_count
    assert_empty @service.writes
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "recover-ios-candidate:#{@intent_digest}:build-1"
    execute
    assert_equal "operator_authorized_reconciliation", receipt.fetch("result")
    assert_equal 0, @upload_count
  end

  def test_operator_authorized_retry_uses_original_ipa_only_after_absence_poll
    @service.visible = false
    prepare("candidate")
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
    execute
    assert_equal "operator_authorized_retry", receipt.fetch("result")
    assert_equal 1, @upload_count
    assert_operator @time, :>=, 600
    assert_equal 1, @upload_validation_calls.length
    assert_operator @upload_validation_calls.first.fetch("at"), :>=, 600
  end

  def test_original_upload_expiry_during_approval_does_not_dispatch_transporter
    @service.visible = false
    prepare("candidate")
    @signing_expires_at = @wall_clock + 30
    advance(31)
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_equal 0, @upload_count
    assert_empty @service.writes
    assert_equal 1, @upload_validation_calls.length
    refute File.exist?(File.join(@root, "journal.json")), "failed current validation must precede mutation-dispatched"
  end

  def test_authorized_retry_checks_expiry_after_absence_poll_not_before_it
    @service.visible = false
    prepare("candidate")
    @signing_expires_at = @wall_clock + 599
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_operator @time, :>=, 600
    assert_equal 0, @upload_count
    assert_empty @service.writes
    assert_equal 1, @upload_validation_calls.length
    assert_operator @upload_validation_calls.first.fetch("at"), :>=, 600
    refute journal.fetch("history").any? { |entry| entry["phase"] == "mutation-dispatched" }
  end

  def test_original_and_retry_expiry_during_final_absence_read_prevents_dispatch
    [false, true].each do |retrying|
      teardown
      setup
      @service.visible = false
      prepare("candidate")
      if retrying
        retry_process(cross_run: true)
        ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
      end
      @signing_expires_at = @wall_clock + (retrying ? 602 : 2)
      @service.before_read = ->(_path) { advance(3) unless @upload_validation_calls.empty? }
      assert_raises(MobileReleaseKit::ContractError) { execute }
      assert_equal 0, @upload_count
      assert_empty @service.writes
      assert_equal 1, @upload_validation_calls.length
      if File.exist?(File.join(@root, "journal.json"))
        refute journal.fetch("history").any? { |entry| entry["phase"] == "mutation-dispatched" }
      end
    end
  end

  def test_original_and_retry_expiry_during_durable_dispatch_claim_prevents_upload
    [false, true].each do |retrying|
      teardown
      setup
      @service.visible = false
      prepare("candidate")
      if retrying
        retry_process(cross_run: true)
        ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
      end
      @signing_expires_at = @wall_clock + (retrying ? 602 : 2)
      write_journal = @fastfile.method(:write_apple_state_journal)
      test = self
      @fastfile.define_singleton_method(:write_apple_state_journal) do |phase, *rest|
        result = write_journal.call(phase, *rest)
        test.advance(3) if phase == "mutation-dispatched"
        result
      end
      assert_raises(MobileReleaseKit::ContractError) { execute }
      assert_equal 0, @upload_count
      assert_empty @service.writes
      assert_equal 1, @upload_validation_calls.length
      # The durable claim remains consumed even when eligibility expires. A
      # retry may not treat a missing receipt as proof of no possible upload.
      assert journal.fetch("history").any? { |entry| entry["phase"] == "mutation-dispatched" }
    end
  end

  def test_original_and_retry_expiry_in_real_bridges_prevents_native_send_and_store_writes
    [false, true].product(%i[package key executor pipe]).each do |retrying, cut|
      teardown
      setup
      @wall_clock = Time.at(@wall_clock.to_i).utc
      @service.visible = false
      prepare("candidate")
      if retrying
        retry_process(cross_run: true)
        ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
      end
      @signing_expires_at = @wall_clock + (retrying ? 602 : 2)
      original_bytes = File.binread(File.join(@root, "candidate.ipa"))
      with_real_upload_bridge(cut: cut) do |record, resources, endpoints, calls, waits|
        error = assert_raises(MobileReleaseKit::StoreLaneLifetime::IosDispatchRefused) { execute }
        assert_same error, record.first_primary
        assert_equal 0, @upload_count
        assert_empty @service.writes
        assert_empty waits
        assert_equal(%i[package key].include?(cut) ? 0 : 1, calls.length)
        assert endpoints.all? { |endpoint| endpoint.close_calls == (%i[package key].include?(cut) ? 0 : 1) }
        assert_equal 1, @upload_validation_calls.length
        assert_equal File.join(@root, "candidate.ipa"), @upload_validation_calls.first.fetch("ipa")
        assert_equal original_bytes, File.binread(File.join(@root, "candidate.ipa"))
        assert journal.fetch("history").any? { |entry| entry["phase"] == "mutation-dispatched" }
        refute journal.fetch("history").any? { |entry| entry["phase"] == "upload-response-ambiguous" }
        refute File.exist?(File.join(@root, "receipt.json"))
        refute record.unknown?
        assert record.seal_uploads!
        resources.finish!
        assert record.uploads_sealed_and_retired?
      end
    end
  end

  def test_real_bridge_no_send_primary_survives_outer_conversion_swallow_and_close_uncertainty
    [false, true].product(%i[converted swallowed], [false, true]).each do |retrying, conversion, close_fails|
      teardown
      setup
      @wall_clock = Time.at(@wall_clock.to_i).utc
      @service.visible = false
      prepare("candidate")
      if retrying
        retry_process(cross_run: true)
        ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
      end
      @signing_expires_at = @wall_clock + (retrying ? 602 : 2)
      with_real_upload_bridge(cut: :pipe, conversion: conversion, close_fails: close_fails, foreign_build: true) do |record, _resources, endpoints, _calls, waits|
        lifetime = MobileReleaseKit::StoreLaneLifetime
        error = assert_raises(close_fails ? lifetime::LifetimeError : lifetime::IosDispatchRefused) { execute }
        assert_instance_of lifetime::IosDispatchRefused, record.first_primary
        assert_same record.first_primary, close_fails ? error.primary : error
        assert_equal close_fails, record.unknown?
        assert_equal 0, @upload_count
        assert_empty waits
        assert_empty @service.writes, "a foreign matching build must not turn no-send into reconciliation writes"
        assert endpoints.all? { |endpoint| endpoint.close_calls == 1 }
        assert_equal 1, @upload_validation_calls.length
        assert journal.fetch("history").any? { |entry| entry["phase"] == "mutation-dispatched" }
        refute journal.fetch("history").any? { |entry| entry["phase"] == "upload-response-ambiguous" }
        refute File.exist?(File.join(@root, "receipt.json"))
        assert_includes record.cleanup_errors, endpoints.first.close_error if close_fails
      end
    end
  end

  def test_real_valid_original_retry_and_response_loss_can_finish_after_signing_expiry
    [false, true].product([false, true]).each do |retrying, response_loss|
      teardown
      setup
      @wall_clock = Time.at(@wall_clock.to_i).utc
      @service.visible = false
      prepare("candidate")
      if retrying
        retry_process(cross_run: true)
        ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
      end
      @signing_expires_at = @wall_clock + (retrying ? 602 : 2)
      with_real_upload_bridge(cut: :after_send, response_loss: response_loss) do |record, resources, endpoints, calls, waits|
        execute
        assert_equal 1, @upload_count
        assert_equal 1, calls.length
        assert_equal [[4242, 0]], waits
        assert endpoints.all? { |endpoint| endpoint.close_calls == 1 }
        assert_equal 1, @upload_validation_calls.length
        expected = retrying ? "operator_authorized_retry" : (response_loss ? "reconciled" : "accepted")
        assert_equal expected, receipt.fetch("result")
        assert_operator @wall_clock + @time, :>=, @signing_expires_at
        assert record.require_ios_dispatch_not_refused!
        refute record.unknown?
        assert record.seal_uploads!
        resources.finish!
        assert record.uploads_sealed_and_retired?
      end
    end
  end

  def test_visible_original_candidate_reconciles_without_current_signing_validation
    @service.visible = false
    prepare("candidate")
    @upload_error = true
    execute
    File.delete(File.join(@root, "receipt.json")) # accepted, final persistence lost
    @upload_validation_calls.clear
    advance(86_400)
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "recover-ios-candidate:#{@intent_digest}:build-1"
    before = Marshal.load(Marshal.dump(@service.writes))
    execute
    assert_equal "operator_authorized_reconciliation", receipt.fetch("result")
    assert_equal 1, @upload_count
    assert_empty @upload_validation_calls
    assert_equal before, @service.writes
  end

  def test_candidate_upload_retry_token_does_not_replay_after_local_restart_or_clean_rerun
    @service.visible = false
    prepare("candidate")
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = "retry-ios-candidate-upload:#{@intent_digest}:#{@payload.fetch('artifacts').first.fetch('sha256')}"
    @upload_unobserved = true
    assert_raises(Faraday::TimeoutError) { execute }
    assert_equal 1, @upload_count
    assert_empty @service.writes
    fresh_process # same runner: durable local execution claim still applies
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal 1, @upload_count
    retry_process
    File.delete(File.join(@root, "journal.json")) # a GitHub rerun's clean workspace
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal 1, @upload_count
    assert_empty @service.writes
    @upload_unobserved = false
    retry_process(cross_run: true)
    execute
    assert_equal 2, @upload_count
    assert_equal "operator_authorized_retry", receipt.fetch("result")
    assert_equal 1, @authority.fetch("attempt")
  end

  def test_build_appearing_between_preparation_and_initial_dispatch_is_not_adopted
    @service.visible = false
    prepare("candidate")
    @service.visible = true
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_equal 0, @upload_count
    assert_empty @service.writes
  end

  def test_external_converges_each_resource_and_preserves_unrelated_records
    unrelated = Marshal.load(Marshal.dump(@service.resources.fetch("apps")))
    locale = Marshal.load(Marshal.dump(@service.resources.fetch("betaBuildLocalizations").fetch("locale-unconfigured")))
    prepare("external-testing")
    target = @payload.dig("storePrecondition", "snapshot", "external", "targetLocalizations")
    assert_equal locale.fetch("attributes").slice("locale", "whatsNew"), target.find { |item| item["locale"] == "ja" }
    execute
    assert_equal "submitted-for-review", receipt.fetch("state")
    assert_equal "accepted", receipt.fetch("result")
    assert_equal unrelated, @service.resources.fetch("apps")
    assert_equal locale, @service.resources.fetch("betaBuildLocalizations").fetch("locale-unconfigured")
    refute @service.writes.any? { |_method, path, _body| path.end_with?("/locale-unconfigured") }
    assert_equal 8, @service.writes.length # compliance, notify, private, three locales, review, group
    assert_equal "/v1/betaAppReviewDetails/private-detail-1", @service.writes[2][1]
    assert @service.assigned
  end

  def test_external_recovers_cancellation_after_each_http_mutation_without_repeating_it
    8.times do |boundary|
      # Each matrix row starts from the same independent Store and workspace.
      teardown
      setup
      locale = Marshal.load(Marshal.dump(@service.resources.fetch("betaBuildLocalizations").fetch("locale-unconfigured")))
      prepare("external-testing")
      @service.after_write = lambda do |_method, _path, _body|
        raise Interrupt, "Synthetic cancellation after Store mutation" if @service.writes.length == boundary + 1
      end
      assert_raises(Interrupt) { execute }
      @service.after_write = nil
      recover_external
      assert_equal 8, @service.writes.length, "a completed write was repeated after boundary #{boundary}"
      assert_equal locale, @service.resources.fetch("betaBuildLocalizations").fetch("locale-unconfigured")
      refute @service.writes.any? { |_method, path, _body| path.end_with?("/locale-unconfigured") }
      assert @service.assigned
      assert_equal "submitted-for-review", receipt.fetch("state")
    end
  end

  def test_external_ambiguous_response_is_read_back_not_retried_by_sdk_or_lane
    prepare("external-testing")
    @service.after_write = ->(*) { raise Faraday::TimeoutError, "Synthetic lost response" }
    execute
    assert_equal 8, @service.writes.length
    assert_equal "accepted", receipt.fetch("result")
  end

  def test_external_accepted_but_invisible_create_and_group_assignment_are_not_repeated_on_absence
    {
      "betaBuildLocalizations" => "/v1/betaBuildLocalizations",
      "betaAppReviewSubmissions" => "/v1/betaAppReviewSubmissions",
      "betaGroupRelationships" => "/v1/builds/build-1/relationships/betaGroups",
    }.each do |type, endpoint|
      teardown
      setup
      prepare("external-testing")
      @service.after_write = lambda do |method, path, _body|
        next unless method == :post && path == endpoint
        if type == "betaGroupRelationships"
          @service.hide_assignment = true
        else
          @service.hidden_resources = [[type, @service.resources.fetch(type).keys.last]]
          @service.mask_review_state = true if type == "betaAppReviewSubmissions"
        end
        raise Faraday::TimeoutError, "Accepted synthetic #{type} is not yet visible"
      end
      assert_raises(FastlaneCore::Interface::FastlaneError, type) { execute }
      assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == endpoint }
      @service.after_write = nil
      retry_process
      before = Marshal.load(Marshal.dump(@service.writes))
      error = assert_raises(MobileReleaseKit::ContractError, type) { execute }
      assert_includes error.message, "retry-ios-operation-creates:#{@intent_digest}:"
      assert_equal before, @service.writes
      assert journal.fetch("history").last.fetch("createRetryInventory").fetch("creates").any? { |node| node.fetch("resourceType") == type }
      @service.hidden_resources = []
      @service.mask_review_state = @service.hide_assignment = false
      recover_external
      assert_equal 1, @service.writes.count { |method, path, _body| method == :post && path == endpoint }
      assert @service.assigned
      assert_equal "submitted-for-review", receipt.fetch("state")
    end
  end

  def test_external_late_assignment_visibility_finishes_read_only_without_retry_grant
    prepare("external-testing")
    endpoint = "/v1/builds/build-1/relationships/betaGroups"
    @service.after_write = lambda do |method, path, _body|
      next unless method == :post && path == endpoint
      @service.hide_assignment = true
      raise Faraday::TimeoutError, "Accepted group assignment temporarily invisible"
    end
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    before = Marshal.load(Marshal.dump(@service.writes))
    @service.after_write = nil
    retry_process
    visible_at = @time + 15
    @service.before_read = ->(_path) { @service.hide_assignment = false if @time >= visible_at }
    execute
    assert_equal before, @service.writes
    assert_equal "reconciled", receipt.fetch("result")
    refute receipt.key?("createRetry")
  end

  def test_external_create_retry_token_does_not_replay_after_cancellation_or_attempt_two
    prepare("external-testing")
    @service.before_write = ->(method, _path, _body) { raise Faraday::TimeoutError, "Unknown create outcome" if method == :post }
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    retry_process
    before = Marshal.load(Marshal.dump(@service.writes))
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_equal before, @service.writes
    token = journal.fetch("history").last.fetch("confirmation")
    retry_process(cross_run: true)
    ENV["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = token
    assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    after_retry = Marshal.load(Marshal.dump(@service.writes))
    assert_equal before.length + 1, after_retry.length
    fresh_process
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_equal after_retry, @service.writes
    retry_process
    File.delete(File.join(@root, "journal.json"))
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_equal after_retry, @service.writes
    @service.before_write = nil
    retry_process(cross_run: true)
    execute
    assert_equal "operator_authorized_retry", receipt.fetch("result")
    evidence = receipt.fetch("createRetry")
    assert_equal "operator-authorized-create-retry", evidence.fetch("mode")
    assert_equal @intent_digest, evidence.fetch("inventory").fetch("operationIntentSha256")
    assert_equal @authority, evidence.fetch("executedBy")
    assert_equal 3, evidence.fetch("usedCreates").length
  end

  def test_changed_private_target_and_unrelated_localization_are_rejected_before_mutation
    prepare("external-testing")
    ENV["MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME"] = "Changed"
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_empty @service.writes
    ENV["MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME"] = "Fictional"
    @service.attributes("betaBuildLocalizations", "locale-fr")["whatsNew"] = "Unrelated third value"
    assert_raises(MobileReleaseKit::ContractError) { execute }
    assert_empty @service.writes
  end

  def test_unconfigured_locale_drift_before_or_after_a_partial_write_is_never_repaired
    %i[text removed replaced added].product(%i[before after]).each do |change, boundary|
      teardown
      setup
      prepare("external-testing")
      foreign_state = nil
      drift = lambda do
        locales = @service.resources.fetch("betaBuildLocalizations")
        case change
        when :text
          locales.fetch("locale-unconfigured").fetch("attributes")["whatsNew"] = "Foreign owner edit"
        when :removed
          locales.delete("locale-unconfigured")
        when :replaced
          record = locales.delete("locale-unconfigured")
          record["id"] = "foreign-replacement"
          locales[record.fetch("id")] = record
        when :added
          @service.add("betaBuildLocalizations", "foreign-added", "locale" => "ar", "whatsNew" => "Foreign owner text")
        end
        foreign_state = Marshal.load(Marshal.dump(locales))
      end
      if boundary == :before
        drift.call
      else
        @service.after_write = ->(*) { drift.call; @service.after_write = nil }
      end
      assert_raises(MobileReleaseKit::ContractError, "#{change} #{boundary}") { execute }
      assert_equal(boundary == :before ? 0 : 1, @service.writes.length)
      assert_equal foreign_state, @service.resources.fetch("betaBuildLocalizations")
      refute File.exist?(File.join(@root, "receipt.json"))
    end
  end

  def test_resealed_overbroad_localization_target_is_rejected_before_execution
    prepare("external-testing")
    @payload.dig("storePrecondition", "snapshot", "external", "targetLocalizations").find { |item| item["locale"] == "ja" }["whatsNew"] = "Test the fictional workflow"
    @intent_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(@payload))
    File.write(File.join(@root, "intent.json"), JSON.generate(@payload.merge("integrity" => { "algorithm" => "sha256", "sha256" => @intent_digest })))
    fresh_process
    error = assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
    assert_includes error.message, "configured locale target"
    assert_empty @service.writes
    refute File.exist?(File.join(@root, "receipt.json"))
  end

  def test_raw_metadata_drift_is_rejected_even_when_the_sanitized_target_does_not_change
    ["Test the <fictional workflow", "Test the fictional workflow \n"].product(%i[before after]).each do |changed, boundary|
      teardown
      setup
      path = File.join(@root, "release/store/testflight/what-to-test.txt")
      original = File.read(path)
      assert_equal Pilot::BuildManager.sanitize_changelog(original.strip), Pilot::BuildManager.sanitize_changelog(changed.strip)
      prepare("external-testing")
      if boundary == :before
        File.write(path, changed)
      else
        @service.after_write = ->(*) { File.write(path, changed); @service.after_write = nil }
      end
      assert_raises(FastlaneCore::Interface::FastlaneError) { execute }
      assert_equal(boundary == :before ? 0 : 1, @service.writes.length)
      refute File.exist?(File.join(@root, "receipt.json"))
    end
  end

  def test_what_to_test_is_bounded_valid_utf8_before_any_store_write
    ["\xff".b, " " * (64 * 1024 + 1), "x" * 4_001, " \n\t"].each do |invalid|
      teardown
      setup
      File.binwrite(File.join(@root, "release/store/testflight/what-to-test.txt"), invalid)
      error = assert_raises(FastlaneCore::Interface::FastlaneError) { prepare("external-testing") }
      assert_includes error.message, "bounded UTF-8 text"
      assert_empty @service.writes
      refute File.exist?(File.join(@root, "precondition.json"))
      refute File.exist?(File.join(@root, "receipt.json"))
    end
  end
end
