# frozen_string_literal: true

# Focused LOCAL models: no capture task/native creator is started. The original
# capture boundary and typed observation are real; only its underlying owner
# facts/execution are modeled. These are not process-family/native receipts.
require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "rbconfig"
require_relative "../../fastlane/ios_upload_validation"
require_relative "../../fastlane/android_upload_validation"

class StoreLaneNestedValidationTest < Minitest::Test
  Lifetime = MobileReleaseKit::StoreLaneLifetime
  Native = MobileReleaseKit::NativeUploadValidation
  Session = Native.const_get(:CaptureSession, false)
  Platforms = {
    "ios" => [MobileReleaseKit::IosUploadValidation, "ios_testflight_internal", "ipa"],
    "android" => [MobileReleaseKit::AndroidUploadValidation, "android_internal_upload", "aab"],
  }.freeze

  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-store-nested-model-"))
    original = File.lstat(@root)
    @root_identity = [original.dev, original.ino]
    @config, @intent, @artifact = %w[config.json intent.json artifact.bin].map { |name| File.join(@root, name) }
    File.write(@config, "{}")
    File.write(@intent, "{}")
    File.write(@artifact, "original synthetic artifact")
    @sessions, @requests = [], []
  end

  def teardown
    original = File.lstat(@root)
    assert original.directory? && !original.symlink? && [original.dev, original.ino] == @root_identity
    FileUtils.remove_entry(@root) # All consumers are inert models, never native tasks.
  end

  def invocation(platform = "ios", mode: "execute", deadline: nil)
    Lifetime::Invocation.new(lane: Platforms.fetch(platform)[1], nonce: "n" * 16,
      output: File.join(@root, "receipt.json"), mode: mode,
      run_deadline_ns: deadline || MobileReleaseKit::NativeUploadProcess.monotonic_ns + 60_000_000_000)
  end

  def value(platform)
    suffix = Platforms.fetch(platform)[2]
    result = {"documentType" => "#{platform}-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64, "#{suffix}Sha256" => Digest::SHA256.file(@artifact).hexdigest,
      "#{suffix}Size" => File.size(@artifact)}
    result.merge!("notBefore" => "2020-01-01T00:00:00Z", "notAfter" => "2099-01-01T00:00:00Z") if platform == "ios"
    result
  end

  def validate(platform, record)
    adapter, _lane, suffix = Platforms.fetch(platform)
    Lifetime.stub(:current_invocation, record) do
      adapter.current!(python: RbConfig.ruby, module_root: File.expand_path("../../src", __dir__),
        app_root: @root, config_path: @config, intent_path: @intent, "#{suffix}_path".to_sym => @artifact,
        intent_sha256: "a" * 64, environment: {"DEVELOPER_DIR" => "/model/Xcode", "UNUSED_SECRET" => "not-forwarded"},
        tooling_directory: File.expand_path("../../fastlane", __dir__))
    end
  end

  def modeled_capture(output, failure: nil, constructor_error: nil, returned_copy: false,
                      finality: true, offer: true, phase: :accepted, no_creator: false, cleanup: [])
    original_output = output.dup.freeze
    constructor = lambda do |**request|
      @requests << request
      raise constructor_error if constructor_error
      session = Session.allocate
      session.instance_variable_set(:@store_binding, request.fetch(:store_binding))
      session.instance_variable_set(:@stdout, original_output)
      session.instance_variable_set(:@phase, phase)
      session.define_singleton_method(:execute) do
        raise failure if failure
        returned_copy ? original_output.dup.freeze : original_output
      end
      session.define_singleton_method(:successful_offer?) { offer }
      session.define_singleton_method(:finality_confirmed?) { finality }
      session.define_singleton_method(:no_creator_attempt?) { no_creator }
      session.define_singleton_method(:cleanup_errors) { cleanup }
      @sessions << session
      session
    end
    Session.stub(:new, constructor) { yield }
  end

  def test_both_fixed_platforms_bind_original_capture_and_strict_result_before_continuation
    Platforms.each_key do |platform|
      record, expected = invocation(platform), value(platform)
      result = modeled_capture(JSON.generate(expected)) { validate(platform, record) }
      assert_equal expected, result
      assert result.frozen? && result.values.all?(&:frozen?)
      assert record.require_upload_continuation!
      refute record.uploads_sealed_and_retired?
      assert record.seal_uploads!
      assert record.uploads_sealed_and_retired?
      request = @requests.last
      assert request.fetch(:environment).frozen? && request.fetch(:argv).frozen?
      refute request.fetch(:environment).key?("UNUSED_SECRET")
      assert_equal(platform == "ios" ? "/model/Xcode" : nil, request.fetch(:environment)["DEVELOPER_DIR"])
      refute_nil request.fetch(:store_binding)
      assert_same @sessions.last.instance_variable_get(:@store_observation),
        record.instance_variable_get(:@nested).instance_variable_get(:@observation)
    end
  end

  def test_constructor_and_real_return_predicates_fail_closed_without_registry_inference
    [
      {constructor_error: IOError.new("private constructor detail")},
      {returned_copy: true}, {finality: false}, {offer: false}, {phase: :closed},
    ].each do |fault|
      record = invocation
      modeled_capture(JSON.generate(value("ios")), **fault) do
        assert_raises(MobileReleaseKit::ContractError) { validate("ios", record) }
      end
      assert record.unknown?
      assert_raises(Lifetime::LifetimeError) { record.require_upload_continuation! }
      assert_same fault[:constructor_error], record.first_primary if fault[:constructor_error]
      # Even an empty registry cannot manufacture the missing original result.
      assert_empty Native.send(:unresolved_sessions)
      refute record.uploads_sealed_and_retired?
    end
  end

  def test_original_failure_is_latched_before_redaction_and_interrupt_identity_survives
    [IOError.new("private native failure"), Interrupt.new("original interrupt"), SystemExit.new(23)].each do |primary|
      record = invocation
      secondary = IOError.new("private close failure")
      type = primary.is_a?(IOError) ? MobileReleaseKit::ContractError : primary.class
      observed = modeled_capture(JSON.generate(value("ios")), failure: primary, cleanup: [secondary]) do
        assert_raises(type) { validate("ios", record) }
      end
      assert record.unknown?
      assert_same primary, record.first_primary
      assert_includes record.cleanup_errors, secondary
      if primary.is_a?(IOError)
        refute_includes observed.message, primary.message
        assert_same primary, assert_raises(Lifetime::LifetimeError) { record.require_upload_continuation! }.primary
      else
        assert_same primary, observed
        assert_same primary, assert_raises(primary.class) { record.require_upload_continuation! }
      end
    end
  end

  def test_original_no_creator_proof_is_distinct_from_a_failed_created_validator
    [true, false].each do |no_creator|
      record = invocation
      primary = IOError.new("modeled prelaunch failure")
      modeled_capture("", failure: primary, no_creator: no_creator) do
        assert_raises(MobileReleaseKit::ContractError) { validate("ios", record) }
      end
      assert_equal !no_creator, record.unknown?
      if no_creator
        assert record.require_upload_continuation!
        assert record.seal_uploads!
      else
        assert_raises(Lifetime::LifetimeError) { record.require_upload_continuation! }
      end
      refute record.instance_variable_get(:@nested).instance_variable_get(:@result)
    end
  end

  def test_bound_schema_intent_artifact_and_output_identity_cannot_be_adopted
    Platforms.each_key do |platform|
      suffix = Platforms.fetch(platform)[2]
      [value(platform).merge("operationIntentSha256" => "b" * 64),
       value(platform).merge("#{suffix}Sha256" => "b" * 64),
       value(platform).merge("schemaVersion" => 1.0),
       value(platform).merge("extra" => true)].each do |result|
        record = invocation(platform)
        modeled_capture(JSON.generate(result)) do
          assert_raises(MobileReleaseKit::ContractError) { validate(platform, record) }
        end
        assert record.unknown?
      end
    end
    record = invocation
    adapter = Platforms.fetch("ios")[0]
    original = adapter.method(:capture_validator)
    copied_return = ->(*arguments, **keywords) { original.call(*arguments, **keywords).dup.freeze }
    modeled_capture(JSON.generate(value("ios"))) do
      adapter.stub(:capture_validator, copied_return) do
        assert_raises(Lifetime::LifetimeError) { validate("ios", record) }
      end
    end
    assert record.unknown?
  end

  def test_valid_expired_interval_retires_lifetime_but_malformed_interval_does_not
    expired = value("ios").merge("notAfter" => "2021-01-01T00:00:00Z")
    record = invocation
    modeled_capture(JSON.generate(expired)) do
      error = assert_raises(MobileReleaseKit::ContractError) { validate("ios", record) }
      assert_includes error.message, "eligibility expired"
    end
    refute record.unknown?
    assert record.require_upload_continuation!
    assert record.seal_uploads!
    ["2026-02-30T12:00:00Z", "2019-01-01T00:00:00Z", "2026-09-15T12:00:00+00:00"].each do |invalid|
      record = invocation
      modeled_capture(JSON.generate(value("ios").merge("notAfter" => invalid))) do
        assert_raises(MobileReleaseKit::ContractError) { validate("ios", record) }
      end
      assert record.unknown?
    end
  end

  def test_ios_dispatch_uses_only_original_settled_result_and_original_artifact
    record = invocation
    result = modeled_capture(JSON.generate(value("ios"))) { validate("ios", record) }
    command = record.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: @artifact)
    assert_equal "inert-upload", command
    assert command.frozen?
    assert_same result, record.instance_variable_get(:@nested).instance_variable_get(:@result)
    record.end_ios_transporter_dispatch!
    assert_raises(Lifetime::LifetimeError) do
      record.begin_ios_transporter_dispatch!(command: command, artifact: @artifact)
    end
    assert record.unknown?

    [invocation, invocation("android"), invocation(mode: "prepare"), invocation.tap(&:seal_uploads!)].each do |missing|
      assert_raises(Lifetime::LifetimeError) do
        missing.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: @artifact)
      end
    end
    record = invocation
    modeled_capture(JSON.generate(value("ios"))) { validate("ios", record) }
    assert_raises(Lifetime::LifetimeError) do
      record.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: @artifact + ".replacement")
    end
    assert record.unknown?

    record = invocation
    modeled_capture("", failure: IOError.new("before creator"), no_creator: true) do
      assert_raises(MobileReleaseKit::ContractError) { validate("ios", record) }
    end
    assert record.require_upload_continuation!
    assert_raises(Lifetime::LifetimeError) do
      record.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: @artifact)
    end
  end

  def test_expiry_of_original_result_is_settled_no_send_and_cannot_be_refreshed
    clock = Time.utc(2026, 9, 16, 12)
    record = invocation
    expected = value("ios").merge("notAfter" => (clock + 1).iso8601)
    Time.stub(:now, -> { clock }) do
      result = modeled_capture(JSON.generate(expected)) { validate("ios", record) }
      clock += 1
      error = assert_raises(Lifetime::IosDispatchRefused) do
        record.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: @artifact)
      end
      assert_same error, record.first_primary
      assert_instance_of MobileReleaseKit::ContractError, error.primary
      assert_same result, record.instance_variable_get(:@nested).instance_variable_get(:@result)
      assert_equal 1, @sessions.length
      refute record.unknown?
      assert record.require_upload_continuation!
      record.end_ios_transporter_dispatch!
      assert_same error, assert_raises(Lifetime::IosDispatchRefused) { record.require_ios_dispatch_not_refused! }
      repeated = assert_raises(Lifetime::IosDispatchRefused) do
        record.begin_ios_transporter_dispatch!(command: "replacement-upload", artifact: @artifact)
      end
      assert_same error, repeated
      assert record.seal_uploads!
      assert record.uploads_sealed_and_retired?
      assert_equal 1, @sessions.length
    end
  end

  def test_missing_binding_wrong_platform_prepare_and_sealed_routes_refuse_before_constructor
    record = invocation
    Lifetime.stub(:current_invocation, record) do
      Session.stub(:new, ->(**) { flunk "missing binding reached constructor" }) do
        assert_raises(Lifetime::LifetimeError) do
          Native.capture({}, [], @root, max_seconds: 1, max_output_bytes: 32, label: "model", failure_message: "model")
        end
      end
    end
    assert record.unknown?
    [invocation("android"), invocation(mode: "prepare"), invocation.tap(&:seal_uploads!)].each do |rejected|
      Session.stub(:new, ->(**) { flunk "closed/wrong role reached constructor" }) do
        assert_raises(Lifetime::LifetimeError) { validate("ios", rejected) }
      end
    end
    record = invocation
    environment, argv = {"LANG" => "C"}, [RbConfig.ruby]
    binding = record.reserve_current_validation!(role: "current-ios", adapter: Platforms.fetch("ios")[0],
      environment: environment, argv: argv, tooling_directory: @root, intent_sha256: "a" * 64, artifact: @artifact)
    Lifetime.stub(:current_invocation, record) do
      Session.stub(:new, ->(**) { flunk "changed request reached constructor" }) do
        assert_raises(Lifetime::LifetimeError) do
          Native.capture(environment.merge("LANG" => "changed"), argv, @root,
            max_seconds: 1, max_output_bytes: 32, label: "model", failure_message: "model", store_binding: binding)
        end
      end
    end
    assert record.unknown?
  end

  def test_explicit_activation_cannot_replace_the_original_invocation_or_use_pipe_only_defaults
    refute Lifetime.instance_variable_defined?(:@invocation), "an unrelated invocation is already active"
    acquired = false
    record = invocation
    pipe_only = Lifetime::Invocation.new(lane: "ios_testflight_internal", nonce: "n" * 16, output: File.join(@root, "other.json"))
    assert_raises(Lifetime::LifetimeError) { Lifetime.activate!(pipe_only) }
    Lifetime.activate!(record)
    acquired = true
    assert_same record, Lifetime.current_invocation
    assert_raises(Lifetime::LifetimeError) { Lifetime.activate!(invocation) }
    assert_same record, Lifetime.current_invocation
    assert record.unknown?
  ensure
    if acquired
      assert_same record, Lifetime.instance_variable_get(:@invocation)
      Lifetime.remove_instance_variable(:@invocation) # Only this test's original inert registration.
    end
  end

  def test_one_nested_slot_cannot_be_reused_and_foreign_origin_cannot_mutate_it
    record = invocation
    modeled_capture(JSON.generate(value("ios"))) { validate("ios", record) }
    original_pid = Process.pid
    Process.stub(:pid, original_pid + 1) do
      assert_raises(Lifetime::LifetimeError) { record.require_upload_continuation! }
    end
    refute record.unknown?
    Session.stub(:new, ->(**) { flunk "second slot reached constructor" }) do
      assert_raises(Lifetime::LifetimeError) { validate("ios", record) }
    end
    assert record.unknown?
  end

  def test_nonlocal_capture_unwind_latches_before_any_continuation
    record = invocation
    Session.stub(:new, ->(**) { throw :modeled_lost_return }) do
      catch(:modeled_lost_return) { validate("ios", record) }
    end
    assert record.unknown?
    assert_raises(Lifetime::LifetimeError) { record.require_upload_continuation! }
  end

  def test_actual_constructor_composes_absolute_deadlines_without_starting_a_task
    clock = 100_000_000_000
    MobileReleaseKit::NativeUploadProcess.stub(:monotonic_ns, -> { clock }) do
      record = invocation(deadline: clock + 60_000_000_000)
      environment, argv = {"LANG" => "C"}, [RbConfig.ruby]
      binding = record.reserve_current_validation!(role: "current-ios", adapter: Platforms.fetch("ios")[0],
        environment: environment, argv: argv, tooling_directory: @root, intent_sha256: "a" * 64, artifact: @artifact)
      Lifetime.stub(:current_invocation, record) do
        Lifetime.admit_native_capture!(binding, environment: environment, argv: argv, tooling_directory: @root)
      end
      clock += 10_000_000_000
      session = Session.new(environment: environment, argv: argv, tooling_directory: @root,
        max_seconds: 3_600, max_output_bytes: 64, label: "model", failure_message: "model", store_binding: binding)
      assert_equal 155_000_000_000, session.instance_variable_get(:@run_deadline_ns)
      assert_equal 160_000_000_000, session.instance_variable_get(:@hard_cleanup_deadline_ns)
      refute session.capture_slot.start_attempted?
      session.capture_slot.close_launch! # Retire only this genuinely never-started model slot.
      clock = 155_000_000_000
      assert_raises(MobileReleaseKit::NativeUploadProcess::LifecycleError) do
        Session.new(environment: environment, argv: argv, tooling_directory: @root,
          max_seconds: 3_600, max_output_bytes: 64, label: "model", failure_message: "model", store_binding: binding)
      end
    end
  end
end
