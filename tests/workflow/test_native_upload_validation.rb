# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require_relative "upload_process_fixture"
require_relative "../../fastlane/native_process_spawn"
require_relative "../../fastlane/native_upload_process"
require_relative "../../fastlane/native_upload_validation"

class NativeUploadValidationTest < Minitest::Test
  include UploadProcessFixture::RawCaptureCleanup
  prepend UploadProcessFixture::CaseGuard
  PROOF_FILES = %w[
    tests/workflow/upload_process_fixture.rb
    tests/workflow/upload_process_ownership.rb
    fastlane/native_upload_validation.rb
    fastlane/native_process_spawn.rb
    fastlane/native_upload_process.rb
    fastlane/release_support.rb
    fastlane/store_lane_lifetime.rb
  ].freeze
  IDENTITY_PREDICATE = 'primary.equal?(@injected_error) && '
  UNEXPECTED_PRIMARY_RETHROW = <<~RUBY.lines.map { |line| "      #{line}" }.join.freeze
    unless expected_native_error?(primary)
      raise primary if primary
      raise "native capture did not return the expected first-close failure"
    end
  RUBY
  COLLECTOR_SCRIPTS = {
    "timeout" => "STDOUT.sync = true\nSTDOUT.puts('collector ready')\nsleep 30\n",
    "oversized" => "STDOUT.sync = true\nSTDERR.sync = true\nSTDOUT.write('x' * 32_769)\nSTDERR.puts('collector size control')\n"
  }.freeze
  ISOLATED_COLLECTOR_FLAG = "--mrk-isolated-collector-close"
  ISOLATED_COLLECTOR_MODE = "collector-isolated-close"
  ISOLATED_COLLECTOR_LIMIT = 2 * UploadProcessFixture::DRIVER_LIMIT + 2 * UploadProcessFixture::CLEANUP_LIMIT
  RAW_REPORTING_NS = 2_000_000_000
  ISOLATED_FAILURE_PREFIX = "MRK_ISOLATED_COLLECTOR_FAILURE="
  ISOLATED_FAILURE_STAGES = %w[cli-admission request-contract source-bindings deadline-bound collector-execution
                              capture-contract cleanup-contract reporting-contract custody-contract final-recheck proof-publication
                              capture-primary capture-retained-files capture-retained-lifetime capture-retained-streams
                              capture-record-read capture-record-status capture-record-flags capture-dispatch-contract
                              capture-dispatch-environment capture-source-identities capture-stream-identities capture-child-receipt
                              capture-creator capture-lifetime-endpoints capture-provenance capture-bootstrap-header
                              capture-bootstrap-request capture-bootstrap-sources capture-bootstrap-directory capture-bootstrap-dispatch
                              capture-bootstrap-descriptors capture-bootstrap-configuration capture-bootstrap-ready capture-bootstrap-grant
                              capture-bootstrap-exec capture-bootstrap-directory-finality capture-error-contract capture-readiness
                              capture-transcript capture-termination].freeze
  ISOLATED_FAILURE_CATEGORIES = %w[assertion-error fixture-error native-lifecycle-error io-error os-error interrupt
                                  system-exit json-parser-error key-error no-method-error type-error argument-error runtime-error
                                  standard-error exception unknown].freeze
  NATIVE_PRIMARY_FAILURE_PREFIX = "MRK_NATIVE_PRIMARY_FAILURE="
  NATIVE_PRIMARY_FAILURE_CALLBACK_MODES = {
    "NativeUploadValidationTest#test_unexpected_pre_entry_failures_preserve_original_through_real_cleanup" =>
      %w[publication readiness watchdog].product(%w[standard io interrupt system-exit], %w[none close]).map { |parts| "native-proof-#{parts.join('-')}".freeze }.freeze,
    "NativeUploadValidationTest#test_unexpected_primary_outlives_late_teardown_and_lookalike_diagnostics" =>
      %w[native-proof-late-cleanup native-proof-lookalike].freeze,
    "NativeUploadValidationTest#test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike" =>
      %w[native-proof-entered-io].freeze,
    "NativeUploadValidationTest#test_nested_lifetime_preserves_pre_grant_ioerror_without_native_acquisition" =>
      %w[native-proof-frame-io native-proof-frame-io-close].freeze,
  }.freeze
  NATIVE_PRIMARY_FAILURE_PREDICATES = %w[case proof-failures proof-status result-kind driver-status].freeze
  NATIVE_PRIMARY_PROOF_FAILURES = [
    "actual failed native result", "one real injection/final boundary", "framePublishedBeforeFault",
    "outerPrimarySameObject", "nestedPrimarySameObject", "taskPrimarySameObject", "originalMessagePreserved",
    "originalStatusPreserved", "originalNotIntentional", "actualTaskJoins", "actualDescriptorsClosed",
    "secondary identity", "ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined",
    "handlersRestored", "registryInactive", "no pending cancellation", "unchanged IOError redaction",
    "actual non-IOError return", "native cleanup without fixture fallback", "actual capture finality", "first-close boundary",
  ].freeze
  ORDER_CASES = {
    "native-order-task-before-caller-interrupt" => %w[task-before-caller interrupt],
    "native-order-task-before-caller-system-exit" => %w[task-before-caller system-exit],
    "native-order-caller-before-task-interrupt" => %w[caller-before-task interrupt],
    "native-order-caller-before-task-system-exit" => %w[caller-before-task system-exit],
    "native-order-cleanup-before-caller-interrupt" => %w[cleanup-before-caller interrupt],
    "native-order-cleanup-before-caller-system-exit" => %w[cleanup-before-caller system-exit],
  }.transform_values(&:freeze).freeze
  NATIVE_ORDER_FAILURE_PREFIX = "MRK_NATIVE_ORDER_FAILURE="
  NATIVE_ORDER_FAILURE_CALLBACK_MODES = {
    "NativeUploadValidationTest#test_native_task_error_precedes_later_caller_cancellation_at_the_original_latch" =>
      %w[native-order-task-before-caller-interrupt native-order-task-before-caller-system-exit].freeze,
    "NativeUploadValidationTest#test_native_caller_cancellation_precedes_later_task_ioerror_at_the_original_latch" =>
      %w[native-order-caller-before-task-interrupt native-order-caller-before-task-system-exit].freeze,
    "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown" =>
      %w[native-order-cleanup-before-caller-interrupt].freeze,
    "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown" =>
      %w[native-order-cleanup-before-caller-system-exit].freeze,
  }.freeze
  NATIVE_ORDER_FAILURE_PREDICATES = %w[proof-version proof-kind case source-binding proof-failures proof-status
                                     expected-unknown original-accepted result-kind driver-status].freeze
  NATIVE_ORDER_PROOF_FAILURES = [
    "original failed fixture result", "same first object through original boundaries",
    "unchanged original first message/status", "unchanged original caller message/status",
    "no original upload acceptance", "original shared creator/capture latch", "actual first and later latch returns",
    "actual latch released later fault", "actual caller delivery and rescue", "actual original stdin close",
    "actual capture/creator joins", "actual original native closes", "actual original native EOFs", "actual original C wait",
    "no fixture fallback or pending cancellation", "ownedDescriptorsClosed", "watchdogJoined", "injectorsJoined",
    "handlersRestored", "registryInactive", "no fixture cleanup errors", "observation restored", "unchanged original sources",
    "actual clean body then original cleanup fault", "unknown original task/session retained", "real pre-tail native success not finality",
    "actual body error recorded", "actual settled native cancellation",
  ].freeze

  NATIVE_SETUP_FAILURE_PREFIX = "MRK_NATIVE_SETUP_FAILURE="
  NATIVE_SETUP_FAILURE_CALLBACK = "NativeUploadValidationTest#test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child"
  NATIVE_SETUP_FAILURE_KINDS = %w[pass fixture-cleanup readiness setup-fixture-fault process-observation
                                process-ownership fixture-result unexpected].freeze
  NATIVE_SETUP_FAILURE_CATEGORIES = {
    "UploadProcessFixture::Failure" => "fixture-error", "MobileReleaseKit::ContractError" => "contract-error",
    "MobileReleaseKit::NativeUploadProcess::LifecycleError" => "native-lifecycle-error",
    "IOError" => "io-error", "Interrupt" => "interrupt", "SystemExit" => "system-exit",
  }.freeze
  NATIVE_SETUP_RESULT_CHECKS = %w[ready firstCloseEntered originalCloseCompleted nativeOriginalErrorPreserved watchdogStarted
    watchdogIntervened fallbackUsed deadBeforeFallback ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined
    handlersRestored registryInactive pendingInterrupt cleanupErrorsEmpty].freeze
  NATIVE_SETUP_NATIVE_CHECKS = UploadProcessFixture::ADAPTER_FAILURE_NATIVE_CHECKS
  NATIVE_SETUP_SETTLEMENT_CHECKS = UploadProcessFixture::CaptureObservation::SETTLEMENT_CHECKS

  def setup
    UploadProcessFixture.assert_domain_reusable!
    @root = File.realpath(Dir.mktmpdir("mrk-native-setup-"))
  end

  def teardown
    return unless @root # Refused entry acquired no new case directory.

    if UploadProcessFixture.cleanup_unresolved?(@root)
      warn "Preserve unresolved native fixture evidence: #{@root}"
      unless UploadProcessFixture.expected_unknown_retention?(@root)
        flunk "native fixture retained unexpected process custody"
      end
    elsif @retain_raw_evidence
      warn "Preserve native raw fixture evidence: #{@root}"
    else
      FileUtils.remove_entry(@root)
    end
  end

  def process_case(mode, cleanup_errors: [], order_failure_state: nil)
    UploadProcessFixture.assert_domain_reusable!
    primary_failure_state = {} # Never shared with another mode, raw copy or call.
    optional = order_failure_state.nil? ? {} : {order_failure_state: order_failure_state}
    if mode.instance_of?(String) && UploadProcessFixture::NATIVE_SETUP_FAILURE_MODES.include?(mode)
      setup_failure_state = {} # One ordinary setup case, never another proof's state.
      optional[:setup_failure_state] = setup_failure_state
    end
    value = begin
      UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode,
        primary_failure_state: primary_failure_state, **optional)
    rescue Exception => original
      # run has completed its original lifetime, cleanup and policy restoration.
      # A different failure or partial handoff cannot claim a proof rejection.
      begin
        self.class.report_native_primary_failure(primary_failure_state, original,
          callback: "#{self.class.name}##{name}", mode: mode)
      rescue Exception
        nil # Even optional callback lookup must not replace the actual error.
      end
      if setup_failure_state
        begin
          self.class.report_native_setup_failure(setup_failure_state, original,
            callback: "#{self.class.name}##{name}", mode: mode)
        rescue Exception
          nil # This independent optional projection cannot replace the rejection.
        end
      end
      raise
    end
    assert value.fetch("driverJoined"), value.inspect
    assert value.fetch("knownProcessesDead"), value.inspect
    unless mode.start_with?("kill-")
      %w[watchdogJoined tasksJoined injectorsJoined ownedDescriptorsClosed handlersRestored registryInactive].each do |name|
        assert value.fetch(name), value.inspect
      end
      refute value.fetch("pendingInterrupt"), value.inspect
      if cleanup_errors.empty?
        assert_empty value.fetch("cleanupErrors"), value.inspect
      else
        assert_equal cleanup_errors, value.fetch("cleanupErrors"), value.inspect
      end
    end
    value
  end

  def self.native_primary_failure_line(mode:, proof:, result:, status:)
    return unless mode.instance_of?(String) && UploadProcessFixture::NATIVE_PRIMARY_PROOFS.key?(mode) &&
                  proof.instance_of?(Hash) && %w[case failures driverExitStatus].all? { |key| proof.key?(key) } &&
                  result.instance_of?(Hash) && result.key?("kind")

    failures = proof.fetch("failures")
    inapplicable = UploadProcessFixture::NATIVE_PRIMARY_PROOFS.fetch(mode)[1] == "io" ?
      "actual non-IOError return" : "unchanged IOError redaction"
    allowed = NATIVE_PRIMARY_PROOF_FAILURES.reject { |label| label == inapplicable }
    return unless failures.instance_of?(Array) && failures.length <= 23 &&
                  failures.all? { |label| label.instance_of?(String) && allowed.include?(label) } &&
                  failures == allowed.select { |label| failures.include?(label) }

    # These are observations of the retained original values, not a claim that
    # every comparison ran before the original short-circuit guard rejected.
    passed = [proof["case"] == mode, proof["failures"] == [], proof["driverExitStatus"] == 1,
              result["kind"] != "pass", status.exitstatus == 0]
    rejected = NATIVE_PRIMARY_FAILURE_PREDICATES.each_with_index.filter_map { |label, index| label unless passed[index] }
    return if rejected.empty?

    line = "#{NATIVE_PRIMARY_FAILURE_PREFIX}#{JSON.generate({"schema" => 1, "mode" => mode,
      "failedPredicates" => rejected, "proofFailures" => failures})}\n"
    line.freeze if line.ascii_only? && line.bytesize <= 2048
  end

  def self.report_native_primary_failure(state, original, callback:, mode:)
    return unless state.instance_of?(Hash) && original.instance_of?(UploadProcessFixture::Failure) &&
                  state[:rejection].equal?(original)
    return if state[:report_attempted]

    state[:report_attempted] = true
    return unless callback.instance_of?(String) && mode.instance_of?(String) && state[:mode] == mode &&
                  NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.fetch(callback, []).include?(mode)

    deadline_ns = state.fetch(:deadline_ns)
    return unless deadline_ns.instance_of?(Integer) && deadline_ns.positive? && UploadProcessFixture.clock_ns < deadline_ns

    line = native_primary_failure_line(mode: mode, proof: state.fetch(:proof),
      result: state.fetch(:result), status: state.fetch(:status))
    return unless line && UploadProcessFixture.clock_ns < deadline_ns

    state[:write_attempted] = true # One ordinary captured write, never a retry.
    state[:write_complete] = STDERR.write(line) == line.bytesize
    nil
  rescue Exception => diagnostic_error
    begin
      state[:diagnostic_error] ||= diagnostic_error if state.instance_of?(Hash)
    rescue Exception
      nil # A malformed/frozen optional handoff cannot replace the rejection.
    end
    nil
  end

  def self.native_order_failure_line(mode:, proof:, result:, status:, expected_sources:)
    return unless mode.instance_of?(String) && ORDER_CASES.key?(mode) && proof.instance_of?(Hash) &&
                  %w[version kind case sourceSha256 failures baseDriverReturn expectedUnknown originalAccepted].all? { |key| proof.key?(key) } &&
                  result.instance_of?(Hash) && result.key?("kind") && expected_sources.instance_of?(Hash)

    unknown = ORDER_CASES.fetch(mode).first == "cleanup-before-caller"
    allowed = NATIVE_ORDER_PROOF_FAILURES.first(23) +
      (unknown ? NATIVE_ORDER_PROOF_FAILURES[23, 3] : NATIVE_ORDER_PROOF_FAILURES.last(2))
    failures = proof.fetch("failures")
    return unless failures.instance_of?(Array) && failures.length <= allowed.length &&
                  failures.all? { |label| label.instance_of?(String) && allowed.include?(label) } &&
                  failures == allowed.select { |label| failures.include?(label) }

    # Recheck retained original operands, not an assertion that every term ran
    # before the actual short-circuit rejection. No operand value is published.
    passed = [proof["version"] == 1, proof["kind"] == "native-order-observation", proof["case"] == mode,
      proof["sourceSha256"] == expected_sources, proof["failures"] == [], proof["baseDriverReturn"] == 1,
      proof["expectedUnknown"].equal?(unknown), proof["originalAccepted"].equal?(false),
      result["kind"] == (unknown ? "fixture-cleanup" : "unexpected"), status.exitstatus == 0]
    rejected = NATIVE_ORDER_FAILURE_PREDICATES.each_with_index.filter_map { |label, index| label unless passed[index] }
    return if rejected.empty?

    line = "#{NATIVE_ORDER_FAILURE_PREFIX}#{JSON.generate({"schema" => 1, "mode" => mode,
      "failedPredicates" => rejected, "proofFailures" => failures})}\n"
    line.freeze if line.ascii_only? && line.bytesize <= 2048
  end

  def self.report_native_order_failure(state, original, callback:, mode:)
    return unless state.instance_of?(Hash) && original.instance_of?(UploadProcessFixture::Failure) &&
                  state[:rejection].equal?(original)
    return if state[:report_attempted]

    state[:report_attempted] = true
    return unless callback.instance_of?(String) && mode.instance_of?(String) && state[:mode] == mode &&
                  NATIVE_ORDER_FAILURE_CALLBACK_MODES.fetch(callback, []).include?(mode)

    deadline_ns = state.fetch(:deadline_ns)
    return unless deadline_ns.instance_of?(Integer) && deadline_ns.positive? && UploadProcessFixture.clock_ns < deadline_ns

    line = native_order_failure_line(mode: mode, proof: state.fetch(:proof), result: state.fetch(:result),
      status: state.fetch(:status), expected_sources: state.fetch(:expected_sources))
    return unless line && UploadProcessFixture.clock_ns < deadline_ns

    state[:write_attempted] = true
    state[:write_complete] = STDERR.write(line) == line.bytesize
    nil
  rescue Exception => diagnostic_error
    begin
      state[:diagnostic_error] ||= diagnostic_error if state.instance_of?(Hash)
    rescue Exception
      nil # Optional partial/frozen custody must not replace the actual rejection.
    end
    nil
  end

  def self.native_setup_failure_line(mode:, result:, status:)
    return unless mode.instance_of?(String) && UploadProcessFixture::NATIVE_SETUP_FAILURE_MODES.include?(mode) &&
                  result.instance_of?(Hash)

    code = status.exitstatus
    return unless code.instance_of?(Integer) && code.between?(0, 255)

    # These operands were already read at the original combined rejection.
    # This does not assert that both short-circuit comparisons were evaluated.
    failed = []
    failed << "result-kind" unless result["kind"] == "pass"
    failed << "driver-status" unless code == 0
    return if failed.empty?

    kind = if !result.key?("kind")
      "missing"
    elsif !result["kind"].instance_of?(String)
      "invalid"
    elsif NATIVE_SETUP_FAILURE_KINDS.include?(result["kind"])
      result["kind"]
    else
      "other"
    end
    category = lambda do |key|
      next "missing" unless result.key?(key)
      value = result.fetch(key)
      next "none" if value.nil?
      next "invalid" unless value.instance_of?(String)
      NATIVE_SETUP_FAILURE_CATEGORIES.fetch(value, "other")
    end
    check = lambda do |record, key, absent: false|
      next "missing" if absent
      next "invalid" unless record.instance_of?(Hash)
      next "missing" unless record.key?(key)
      value = record.fetch(key)
      value.equal?(true) || value.equal?(false) ? value : "invalid"
    end
    result_checks = NATIVE_SETUP_RESULT_CHECKS.to_h do |key|
      value = if key == "cleanupErrorsEmpty"
        if !result.key?("cleanupErrors")
          "missing"
        elsif result["cleanupErrors"].instance_of?(Array)
          result["cleanupErrors"].empty?
        else
          "invalid"
        end
      else
        check.call(result, key)
      end
      [key, value]
    end
    projected = UploadProcessFixture.adapter_result_projection(mode: mode, result: result)
    native = result["nativeObservation"]
    settlement_checks = NATIVE_SETUP_SETTLEMENT_CHECKS.to_h do |key|
      value = if !result.key?("nativeObservation") || (native.instance_of?(Hash) && !native.key?("settlementChecks"))
        "missing"
      elsif !native.instance_of?(Hash) || !native["settlementChecks"].instance_of?(Hash)
        "invalid"
      elsif !native["settlementChecks"].key?(key)
        "missing"
      else
        item = native["settlementChecks"].fetch(key)
        item.equal?(true) || item.equal?(false) ||
          (item.instance_of?(String) && %w[missing invalid].include?(item)) ? item : "invalid"
      end
      [key, value]
    end
    line = "#{NATIVE_SETUP_FAILURE_PREFIX}#{JSON.generate({"schema" => 2, "mode" => mode,
      "failedPredicates" => failed, "resultKind" => kind, "driverExitStatus" => code,
      "errorCategory" => category.call("errorClass"), "nativeErrorCategory" => category.call("nativeErrorClass"),
      "resultChecks" => result_checks, "nativeChecks" => projected.fetch("nativeChecks"),
      "settlementChecks" => settlement_checks, "nativeOutcomes" => projected.fetch("nativeOutcomes")})}\n"
    line.freeze if line.ascii_only? && line.bytesize <= 2048
  end

  def self.report_native_setup_failure(state, original, callback:, mode:)
    return unless state.instance_of?(Hash) && original.instance_of?(UploadProcessFixture::Failure) &&
                  state[:rejection].equal?(original)
    return if state[:report_attempted]

    state[:report_attempted] = true
    return unless callback.instance_of?(String) && callback == NATIVE_SETUP_FAILURE_CALLBACK &&
                  mode.instance_of?(String) && state[:mode].instance_of?(String) && state[:mode] == mode &&
                  UploadProcessFixture::NATIVE_SETUP_FAILURE_MODES.include?(mode)

    deadline_ns = state.fetch(:deadline_ns)
    return unless deadline_ns.instance_of?(Integer) && deadline_ns.positive? && UploadProcessFixture.clock_ns < deadline_ns

    line = native_setup_failure_line(mode: mode, result: state.fetch(:result), status: state.fetch(:status))
    return unless line && UploadProcessFixture.clock_ns < deadline_ns

    state[:write_attempted] = true
    state[:write_complete] = STDERR.write(line) == line.bytesize
    nil
  rescue Exception => diagnostic_error
    begin
      state[:diagnostic_error] ||= diagnostic_error if state.instance_of?(Hash)
    rescue Exception
      nil # Optional partial/frozen custody cannot replace the escaping original.
    end
    nil
  end

  def primary_case(mode)
    boundary, kind, secondary = UploadProcessFixture::NATIVE_PRIMARY_PROOFS.fetch(mode)
    cleanup = secondary == "none" ? [] : ["UploadProcessFixture::NativePrimaryProbe::CleanupFailure"]
    value = process_case(mode, cleanup_errors: cleanup)
    proof = value.fetch("primaryProof")
    assert_equal mode, proof.fetch("case")
    assert_equal boundary == "entered" ? "native-setup-io-error" : "native-setup-interrupt", value.fetch("mode")
    assert_empty proof.fetch("failures"), proof.inspect
    assert_equal 1, proof.fetch("driverExitStatus")
    assert_equal 1, proof.fetch("faultCount")
    assert_equal 1, proof.fetch("resultObservations")
    assert value.fetch("harnessPrimaryRetained"), value.inspect
    %w[outerPrimarySameObject nestedPrimarySameObject originalMessagePreserved originalStatusPreserved
       originalNotIntentional framePublishedBeforeFault actualTaskJoins actualDescriptorsClosed].each do |name|
      assert proof.fetch(name), proof.inspect
    end
    assert_equal secondary == "none" ? "unexpected" : "fixture-cleanup", value.fetch("kind")
    assert_equal secondary == "none" ? 0 : 1, proof.fetch("secondaryCount")
    assert proof.fetch("secondaryObjectRecorded"), proof.inspect unless secondary == "none"
    if kind == "io"
      assert_equal "MobileReleaseKit::ContractError", value.fetch("nativeErrorClass")
      assert_equal "Synthetic validator could not be executed safely; no upload is authorized", value.fetch("nativeErrorMessage")
      assert_equal "IOError", value.fetch("errorClass")
    end
    assert_equal 41, value.fetch("nativeExitStatus") if kind == "system-exit"
    observation = value.fetch("nativeObservation")
    assert_native_observation(observation, finality: boundary == "frame" ? :no_producers : :finalized)
    assert_equal boundary != "frame", proof.fetch("actualCustodianReceiptBound")
    assert_equal %w[readiness watchdog entered].include?(boundary), value.fetch("ready")
    assert_equal boundary == "entered", value.fetch("firstCloseEntered")
    assert_equal boundary == "entered", proof.fetch("firstCloseReturned")
    if boundary == "entered"
      %w[firstCloseFromNative originalCloseCompleted].each { |name| assert value.fetch(name), value.inspect }
      assert observation.fetch("stdinCloseReturned"), observation.inspect
      assert_equal 1, value.fetch("injectionCount")
      assert_validator_killed(observation)
      assert proof.fetch("enteredDeathBeforeControlClose"), proof.inspect
    else
      assert_equal 0, value.fetch("injectionCount")
      refute proof.fetch("enteredDeathBeforeControlClose"), proof.inspect
    end
    # C cleanup is no longer an Open3 callback fallback. Even publication and
    # pre-close faults must settle their actual C/K/V obligations themselves.
    refute value.fetch("fallbackUsed"), value.inspect
    refute value.fetch("watchdogIntervened"), value.inspect
    assert_equal boundary == "watchdog" || boundary == "entered", value.fetch("watchdogStarted")
    value
  end

  def test_unexpected_pre_entry_failures_preserve_original_through_real_cleanup
    cases = UploadProcessFixture::NATIVE_PRIMARY_PROOFS.keys.grep(/native-proof-(publication|readiness|watchdog)-/)
    assert_equal %w[publication readiness watchdog].product(%w[standard io interrupt system-exit], %w[none close]).map { |parts| "native-proof-#{parts.join('-')}" }.sort,
                 cases.sort
    cases.each { |mode| primary_case(mode) }
  end

  def test_unexpected_primary_outlives_late_teardown_and_lookalike_diagnostics
    %w[native-proof-late-cleanup native-proof-lookalike].each { |mode| primary_case(mode) }
  end

  def test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike
    primary_case("native-proof-entered-io")
  end

  def test_nested_lifetime_preserves_pre_grant_ioerror_without_native_acquisition
    %w[native-proof-frame-io native-proof-frame-io-close].each { |mode| primary_case(mode) }
  end

  def test_entered_proof_rejects_deleting_only_the_intentional_primary_identity_predicate
    with_proof_copies("identity", IDENTITY_PREDICATE) do |copies|
      copies.each do |label, copy|
        mutant = label == "mutant"
        value, proof, = copied_primary_case(copy, "native-proof-entered-io", mutant: mutant)
        assert_common_raw_proof(value, proof, secondary: false)
        assert_equal "native-setup-io-error", value.fetch("mode")
        %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted].each do |name|
          assert value.fetch(name), name
        end
        assert_equal 1, value.fetch("injectionCount")
        refute value.fetch("fallbackUsed")
        assert_validator_killed(value.fetch("nativeObservation"))
        assert value.fetch("nativeObservation").fetch("stdinCloseReturned")
        assert proof.fetch("firstCloseReturned")
        assert proof.fetch("enteredDeathBeforeControlClose")
        assert_native_io_redaction(value, proof)
        refute value.fetch("nativeOriginalErrorPreserved")
        assert_equal mutant ? 0 : 1, proof.fetch("driverExitStatus") # Method return, not another OS exit.
        assert_equal mutant ? "pass" : "unexpected", value.fetch("kind")
        assert_equal !mutant, proof.fetch("outerPrimarySameObject")
        assert_equal !mutant, proof.fetch("originalMessagePreserved")
        if mutant
          assert_nil value.fetch("errorClass")
          assert_nil value.fetch("error")
          assert_nil value.fetch("harnessPrimaryRetained")
          assert value.fetch("deadBeforeFallback")
          %w[outerPrimarySameObject originalMessagePreserved].each { |name| assert_includes proof.fetch("failures"), name }
          assert_includes proof.fetch("failures"), "actual failed native result"
        else
          assert_equal "IOError", value.fetch("errorClass")
          assert_equal "synthetic private diagnostic", value.fetch("error")
          assert value.fetch("harnessPrimaryRetained")
          assert_empty proof.fetch("failures")
        end
      end
    end
  end

  def test_fresh_lost_primary_mutant_is_rejected_after_real_publication_and_eof_cleanup
    # This is a fresh semantic sensitivity control, NOT a replay of unavailable
    # R5 bytes or its original four external probe scripts.
    with_proof_copies("fresh-swallowed-unexpected-primary", UNEXPECTED_PRIMARY_RETHROW) do |copies|
      %w[standard io].product(%w[none close]).each do |kind, secondary|
        mode = "native-proof-publication-#{kind}-#{secondary}"
        copies.each do |label, copy|
          mutant = label == "mutant"
          has_secondary = secondary == "close"
          value, proof, = copied_primary_case(copy, mode, mutant: mutant)
          assert_common_raw_proof(value, proof, secondary: has_secondary)
          assert_equal "native-setup-interrupt", value.fetch("mode")
          assert_includes [0, 1], proof.fetch("driverExitStatus")
          assert_equal 0, value.fetch("injectionCount")
          refute value.fetch("firstCloseEntered")
          refute proof.fetch("firstCloseReturned")
          refute value.fetch("watchdogStarted")
          refute value.fetch("ready")
          refute value.fetch("fallbackUsed")
          refute proof.fetch("enteredDeathBeforeControlClose")
          assert_native_io_redaction(value, proof) if kind == "io"
          if kind == "standard"
            assert_equal "UploadProcessFixture::NativePrimaryProbe::UnexpectedFailure", value.fetch("nativeErrorClass")
            assert_equal "unexpected synthetic native setup failure", value.fetch("nativeErrorMessage")
          end
          assert_equal !mutant, proof.fetch("outerPrimarySameObject")
          assert_equal !mutant, proof.fetch("originalMessagePreserved")
          if mutant
            %w[outerPrimarySameObject originalMessagePreserved].each { |name| assert_includes proof.fetch("failures"), name }
            refute value.fetch("harnessPrimaryRetained")
            refute_equal "unexpected synthetic native setup failure", value.fetch("error")
          else
            assert_equal 1, proof.fetch("driverExitStatus")
            assert_equal has_secondary ? "fixture-cleanup" : "unexpected", value.fetch("kind")
            assert_empty proof.fetch("failures")
            assert value.fetch("harnessPrimaryRetained")
            assert_equal kind == "io" ? "IOError" : "UploadProcessFixture::NativePrimaryProbe::UnexpectedFailure", value.fetch("errorClass")
            assert_equal "unexpected synthetic native setup failure", value.fetch("error")
          end
        end
      end
    end
  end

  def test_raw_collector_keeps_actual_failed_transcripts_status_and_first_error
    @retain_raw_evidence = true # These expected failures must survive teardown, too.
    invalid = {}
    UploadProcessFixture.lifetime do |scope|
      snapshot = proof_source_snapshot
      copy = make_proof_copy("invalid-driver", snapshot)
      directory = new_raw_case("invalid-driver", "not-a-native-proof")
      scope.active do
        collect_raw_driver(copy, directory, invalid)
        assert_equal 1, invalid.fetch(:status).exitstatus
        assert_equal "", invalid.fetch(:stdout)
        assert_includes invalid.fetch(:stderr), "unknown or mismatched fixture mode/platform/parameters"
        assert_includes invalid.fetch(:stderr), "UploadProcessFixture::Failure"
        error = assert_raises(UploadProcessFixture::Failure) do
          read_raw_primary(directory, invalid, "native-proof-entered-io", expected_exit: 1)
        end
        assert_equal "fixture-result", error.kind
        assert_equal "missing native primary proof", error.message
        %w[owner.json result.json primary-proof.json].each { |name| refute File.exist?(File.join(directory, name)) }
        assert_proof_inventory(copy, snapshot)
        assert_equal snapshot, proof_source_snapshot
      end
    end
    assert_retained_capture(invalid)
    observed = {}
    error = assert_raises(UploadProcessFixture::Failure) do
      UploadProcessFixture.lifetime do |scope|
        directory = new_raw_case("collector-oversized", "collector-oversized")
        scope.active { collect_raw_driver(nil, directory, observed, literal: "oversized") }
      end
    end
    assert_same error, observed.fetch(:primary)
    record = assert_retained_capture(observed)
    assert_equal bounded_error(error), record.fetch("primary")
    assert_equal "diagnostic", error.kind
    assert_equal "oversized raw proof diagnostic", error.message
    assert_operator File.size(File.join(observed.fetch(:directory), "driver.stdout")), :>, UploadProcessFixture::OUTPUT_LIMIT
    status = observed.fetch(:status)
    assert (status.exited? && status.exitstatus == 0) || (status.signaled? && status.termsig == Signal.list.fetch("KILL"))
    # A size-triggered KILL can precede the finite script's stderr write.
    if status.exited?
      assert_equal "collector size control\n", File.binread(File.join(observed.fetch(:directory), "driver.stderr"), UploadProcessFixture::OUTPUT_LIMIT + 1)
    end
    assert_empty observed.fetch(:cleanup_errors)

    # The ambiguous close deliberately poisons its interpreter. It must not
    # share this suite process with another native creation, even after reaping.
    # Parent assertions concern this genuine outer CLI and detached proof only;
    # Exception-object identity is asserted inside that CLI before it exits.
    isolated_directory = new_raw_case("collector-isolated-close", ISOLATED_COLLECTOR_MODE)
    isolated = collect_raw_driver(nil, isolated_directory, {}, isolate_close: true)
    assert_retained_capture(isolated)
    assert_instance_of Process::Status, isolated.fetch(:status)
    assert isolated.fetch(:status).exited?
    assert_isolated_collector_exit(isolated)
    assert_equal "", isolated.fetch(:stdout)
    assert_equal "", isolated.fetch(:stderr)
    assert_empty isolated.fetch(:cleanup_errors)
    proof = read_isolated_json(File.join(isolated_directory, "isolated-control.json"))
    assert_equal %w[argv case childCollector cwd deadlineNs innerState interpreter minitest pid sourceSha256 testSource version], proof.keys.sort
    assert_equal 1, proof.fetch("version")
    assert_equal ISOLATED_COLLECTOR_MODE, proof.fetch("case")
    assert_equal isolated.fetch(:child).pid, proof.fetch("pid")
    assert_equal isolated.fetch(:dispatch).fetch("argv"), proof.fetch("argv")
    assert_equal isolated.fetch(:dispatch).fetch("cwd"), proof.fetch("cwd")
    assert_equal isolated.fetch(:dispatch).fetch("interpreter"), proof.fetch("interpreter")
    assert_equal isolated.fetch(:dispatch).fetch("fixture"), proof.fetch("testSource")
    assert_equal isolated.fetch(:dispatch).fetch("minitest"), proof.fetch("minitest")
    assert_equal isolated.fetch(:isolation_source_hashes), proof.fetch("sourceSha256")
    assert_equal isolated.fetch(:run_deadline_ns), proof.fetch("deadlineNs")
    assert_equal isolated.fetch(:child).creator.run_deadline_ns, proof.fetch("deadlineNs")
    assert_equal isolated.fetch(:isolated_request).fetch("deadlineNs"), proof.fetch("deadlineNs")
    assert_equal({"phase" => "unknown", "stopCompleted" => false, "creatorJoined" => true,
                  "originalWaitBound" => true, "unknownLease" => "out", "retained" => true}, proof.fetch("innerState"))
    inner_record = proof.fetch("childCollector")
    assert_equal "unknown", inner_record.fetch("phase")
    refute inner_record.fetch("stopCompleted")
    assert_equal Signal.list.fetch("KILL"), inner_record.fetch("termSignal")
    assert_equal "driver", inner_record.fetch("primary").fetch("kind")
    assert_equal "raw proof driver deadline expired", inner_record.fetch("primary").fetch("message")
    assert_equal({"observed" => true, "identity" => inner_record.fetch("streamIdentities").first}, inner_record.fetch("literalReadiness"))
    assert_equal proof.fetch("deadlineNs"), inner_record.fetch("enclosingDeadlineNs")
    assert_equal inner_record.fetch("runDeadlineNs") + UploadProcessFixture::CLEANUP_LIMIT * 1_000_000_000,
                 inner_record.fetch("hardDeadlineNs")
    assert_operator inner_record.fetch("hardDeadlineNs"), :<=, proof.fetch("deadlineNs") - RAW_REPORTING_NS
    assert_operator inner_record.fetch("reportingInjectorDeadlineNs"), :<=, proof.fetch("deadlineNs")
    assert_equal isolated.fetch(:isolation_source_hashes), proof_source_snapshot.transform_values { |item| item.fetch("sha256") }
  end

  def self.run_isolated_collector_cli(arguments, failure_state:)
    UploadProcessFixture.assert_domain_reusable!
    unless arguments.length == 2 && arguments.first == ISOLATED_COLLECTOR_FLAG
      raise UploadProcessFixture::Failure.new("fixture-input", "invalid isolated collector command")
    end
    directory = arguments.last
    UploadProcessFixture.owned_fixture_directory(directory)
    control = new("isolated_collector_close")
    control.instance_variable_set(:@root, directory)
    control.__send__(:execute_isolated_collector_close, arguments, failure_state: failure_state)
    0
  end

  def assert_isolated_collector_exit(isolated)
    assert_equal 0, isolated.fetch(:status).exitstatus
  rescue Minitest::Assertion => original
    # There is now an ACTUAL parent failure. Optional diagnostics must not
    # swallow cancellation while merely anticipating a future assertion.
    self.class.report_isolated_capture_failure(isolated, original)
    raise
  end

  def self.isolated_failure_line(stage, error)
    return unless ISOLATED_FAILURE_STAGES.include?(stage)

    category = case error
    when Minitest::Assertion then "assertion-error"
    when UploadProcessFixture::Failure then "fixture-error"
    when MobileReleaseKit::NativeUploadProcess::LifecycleError then "native-lifecycle-error"
    when IOError then "io-error"
    when SystemCallError then "os-error"
    when Interrupt then "interrupt"
    when SystemExit then "system-exit"
    when JSON::ParserError then "json-parser-error"
    when KeyError then "key-error"
    when NoMethodError then "no-method-error"
    when TypeError then "type-error"
    when ArgumentError then "argument-error"
    when RuntimeError then "runtime-error"
    when StandardError then "standard-error"
    when Exception then "exception"
    else "unknown"
    end
    "#{ISOLATED_FAILURE_PREFIX}#{JSON.generate({"schema" => 1, "stage" => stage, "category" => category})}\n".freeze
  end

  def self.parse_isolated_failure(raw, deadline_ns:)
    return unless raw.instance_of?(String) && raw.bytesize <= UploadProcessFixture::OUTPUT_LIMIT &&
                  deadline_ns.instance_of?(Integer) && UploadProcessFixture.clock_ns < deadline_ns

    found, accepted = false, nil
    raw.b.each_line do |line|
      return unless UploadProcessFixture.clock_ns < deadline_ns
      next unless line.start_with?(ISOLATED_FAILURE_PREFIX)
      return if found

      found = true
      return unless line.ascii_only? && line.bytesize <= 256 && line.end_with?("\n")

      payload = line.byteslice(ISOLATED_FAILURE_PREFIX.bytesize, line.bytesize - ISOLATED_FAILURE_PREFIX.bytesize - 1)
      record = JSON.parse(payload, create_additions: false, max_nesting: 4)
      return unless record.instance_of?(Hash) && record.keys == %w[schema stage category] &&
                    record["schema"].instance_of?(Integer) && record["schema"] == 1 &&
                    record["stage"].instance_of?(String) && ISOLATED_FAILURE_STAGES.include?(record["stage"]) &&
                    record["category"].instance_of?(String) && ISOLATED_FAILURE_CATEGORIES.include?(record["category"]) &&
                    JSON.generate(record) == payload

      accepted = "#{ISOLATED_FAILURE_PREFIX}#{JSON.generate(record)}\n".freeze
    end
    return unless UploadProcessFixture.clock_ns < deadline_ns

    accepted
  rescue JSON::ParserError, JSON::NestingError, EncodingError, ArgumentError
    nil
  end

  def self.write_isolated_failure_line(line, state)
    return if state[:write_attempted] || !line
    return unless line.ascii_only? && line.bytesize <= 256 && line.end_with?("\n")
    return if state[:deadline_ns] && UploadProcessFixture.clock_ns >= state.fetch(:deadline_ns)

    state[:write_attempted] = true # BEFORE the one ordinary captured write.
    state[:write_complete] = STDERR.write(line) == line.bytesize
    nil
  end

  def self.report_isolated_cli_failure(state, error)
    state[:primary] ||= error
    state[:failure_stage] ||= state.fetch(:stage)
    return if state[:report_attempted]

    state[:report_attempted] = true
    return if state[:deadline_ns] && UploadProcessFixture.clock_ns >= state.fetch(:deadline_ns)

    # Before request-bound admission, this one finite write still belongs to
    # the original external OwnedChild budget. No new local allowance exists.
    line = isolated_failure_line(state.fetch(:failure_stage), state.fetch(:primary))
    write_isolated_failure_line(line, state)
    nil
  rescue Exception => diagnostic_error
    state[:diagnostic_error] ||= diagnostic_error
    nil # The already latched CLI exception and exit 1 remain authoritative.
  end

  def self.report_isolated_capture_failure(observed, original)
    state = observed[:isolated_failure_report] ||= {primary: original, deadline_ns: observed.fetch(:run_deadline_ns)}
    return if state[:report_attempted]

    state[:report_attempted] = true
    line = parse_isolated_failure(observed.fetch(:stderr), deadline_ns: state.fetch(:deadline_ns))
    write_isolated_failure_line(line, state)
    nil
  rescue Exception => diagnostic_error
    observed[:isolated_failure_report_error] ||= diagnostic_error
    nil # Called ONLY after the actual parent's Minitest::Assertion exists.
  end

  def assert_native_cleanup(value)
    assert_equal 1, value.fetch("injectionCount")
    %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted deadBeforeFallback].each do |name|
      assert value.fetch(name), value.inspect
    end
    refute value.fetch("watchdogIntervened"), value.inspect
    refute value.fetch("fallbackUsed"), value.inspect
    observation = value.fetch("nativeObservation")
    assert_native_observation(observation, finality: :finalized)
    assert observation.fetch("stdinCloseReturned"), observation.inspect
    assert_validator_killed(observation)
  end

  def test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child
    %w[interrupt system-exit io-error].each do |kind|
      value = process_case("native-setup-#{kind}")
      assert_native_cleanup(value)
      if kind == "io-error"
        assert_equal "MobileReleaseKit::ContractError", value.fetch("nativeErrorClass")
        assert_equal "Synthetic validator could not be executed safely; no upload is authorized", value.fetch("nativeErrorMessage")
        refute_includes value.fetch("nativeErrorMessage"), "private diagnostic"
      else
        assert value.fetch("nativeOriginalErrorPreserved"), value.inspect
        assert_equal kind == "interrupt" ? "Interrupt" : "SystemExit", value.fetch("nativeErrorClass")
        assert_equal 23, value.fetch("nativeExitStatus") if kind == "system-exit"
      end
    end
  end

  def test_missing_native_cleanup_requires_eof_and_cannot_pass_the_production_oracle
    # This deliberate missing-cleanup copy is a negative, isolated driver.
    # Actual native tasks/leases may remain UNKNOWN at the original cutoff;
    # the outer driver's own wait cannot turn those facts into finality.
    UploadProcessFixture.assert_domain_reusable!
    sources = proof_source_snapshot
    value = UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: "native-setup-no-cleanup")
    assert value.fetch("driverJoined")
    refute value.key?("knownProcessesDead")
    assert_includes %w[setup-fallback fixture-cleanup], value.fetch("kind")
    assert_equal 1, value.fetch("injectionCount")
    %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted watchdogPreadmitted
       watchdogJoined injectorsJoined handlersRestored registryInactive].each { |name| assert value.fetch(name), name }
    refute value.fetch("pendingInterrupt")
    assert value.fetch("nativeOriginalErrorPreserved"), value.inspect
    assert value.fetch("watchdogIntervened"), value.inspect
    assert value.fetch("fallbackUsed"), value.inspect
    observation = value.fetch("nativeObservation")
    assert_native_observation(observation, finality: :unknown)
    assert_equal "unknown", value.fetch("nativeFinality")
    assert value.fetch("retainedFixture")
    assert value.fetch("domainDisposalRequired")
    assert UploadProcessFixture.expected_unknown_retention?(@root)
    assert UploadProcessFixture.domain_disposal_required?
    if value.fetch("tasksJoined")
      assert observation.fetch("tasks").all? { |task| task["finished"] && task["joined"] && task["actualJoinObserved"] }, observation.inspect
    end
    if value.fetch("ownedDescriptorsClosed")
      assert observation.fetch("leases").all? { |lease| lease["state"] == "closed" && lease["closed"] && lease["actualCloseObserved"] }, observation.inspect
    end
    refute value.key?("deadBeforeFallback"), value.inspect
    proof = value.fetch("missingCleanupProof")
    assert_equal %w[actualValidatorReadNil custodianKillOmitted fifoIdentity helperCopy identities keeperKillOmitted kind mode
                    nativeFinality originalWatchdogWriterClosed reportSha256 sourceSha256 validatorReadNilNs
                    validatorSurvivedUntilFallback version writerCloseEntryNs], proof.keys.sort
    assert_equal [1, "validator-survived-until-fixture-eof", "native-setup-no-cleanup", "unknown"],
                 proof.values_at("version", "kind", "mode", "nativeFinality")
    %w[custodianKillOmitted keeperKillOmitted originalWatchdogWriterClosed actualValidatorReadNil
       validatorSurvivedUntilFallback].each { |name| assert_equal true, proof.fetch(name), name }
    assert_equal sources.transform_values { |item| item.fetch("sha256") }, proof.fetch("sourceSha256")
    dispatch = value.fetch("driverDispatch")
    directory = dispatch.fetch("argv").last
    assert_equal @root, File.dirname(directory)
    assert_equal directory, File.realpath(directory)
    copy = proof.fetch("helperCopy")
    assert_equal %w[label originalPath originalSha256 path sha256], copy.keys.sort
    assert_equal "containment-events", copy.fetch("label")
    assert_equal File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__)), copy.fetch("originalPath")
    assert_equal sources.fetch("fastlane/native_upload_process.rb").fetch("sha256"), copy.fetch("originalSha256")
    assert_equal File.join(directory, "containment-events-helper.rb"), copy.fetch("path")
    assert_equal Digest::SHA256.hexdigest(UploadProcessFixture::OwnedChild.bounded_file(copy.fetch("path"), limit: 1_048_576)), copy.fetch("sha256")
    refute_equal copy.fetch("originalSha256"), copy.fetch("sha256")
    assert_equal copy, value.fetch("helperCopy")
    assert_equal({"version" => 1, "mode" => "native-setup-no-cleanup", "helperCopy" => copy,
                  "sourceSha256" => proof.fetch("sourceSha256")}, value.fetch("containmentSource"))
    graph = proof.fetch("identities")
    assert_equal %w[custodian group keeper sid validator], graph.keys.sort
    graph.each_value { |pid| assert_instance_of Integer, pid; assert_operator pid, :>, 1 }
    assert_equal 3, graph.values_at("custodian", "keeper", "validator").uniq.length
    assert_equal graph.fetch("custodian"), graph.fetch("sid")
    assert_equal graph.fetch("keeper"), graph.fetch("group")
    owner = UploadProcessFixture.read_json(File.join(directory, "owner.json"))
    assert_equal "unknown", owner.fetch("finality")
    assert_equal [{"role" => "custodian", "pid" => graph.fetch("custodian"), "group" => graph.fetch("custodian")},
                  {"role" => "keeper", "pid" => graph.fetch("keeper"), "group" => graph.fetch("custodian")},
                  {"role" => "validator", "pid" => graph.fetch("validator"), "group" => graph.fetch("group")}],
                 owner.fetch("processes").sort_by { |item| item.fetch("role") }
    fifo = proof.fetch("fifoIdentity")
    assert_equal %w[dev gid ino mode nlink rdev type uid], fifo.keys.sort
    assert_equal "fifo", fifo.fetch("type")
    assert_equal Process.uid, fifo.fetch("uid")
    assert_equal 1, fifo.fetch("nlink")
    assert_equal 0o600, fifo.fetch("mode") & 0o7777
    assert_equal UploadProcessFixture::OwnedChild.identity(File.lstat(File.join(directory, "worker-control.fifo"))), fifo
    # Read retained evidence only. No new process observer, task or custody
    # follows UNKNOWN, and a validator read(nil) is not all-role finality.
    hashes = proof.fetch("reportSha256")
    assert_equal %w[containment-custodian-omission.json containment-keeper-omission.json fallback-writer-close.json leader-eof.json], hashes.keys.sort
    entry_bindings = {}
    reports = hashes.to_h do |name, digest|
      path = File.join(directory, name)
      if name.end_with?("-omission.json")
        identity = UploadProcessFixture::OwnedChild.identity(File.lstat(path))
        bytes = UploadProcessFixture::OwnedChild.bounded_file(path, expected: identity, limit: 8192)
        assert_equal identity, UploadProcessFixture::OwnedChild.identity(File.lstat(path))
        entry_bindings[name] = {"identity" => identity, "sha256" => Digest::SHA256.hexdigest(bytes)}
      else
        bytes = UploadProcessFixture::OwnedChild.bounded_file(path)
      end
      assert_equal Digest::SHA256.hexdigest(bytes), digest
      [name, JSON.parse(bytes)]
    end
    close, eof = reports.values_at("fallback-writer-close.json", "leader-eof.json")
    assert_equal close, value.fetch("fallbackWriterClose")
    assert_equal %w[actualOriginalWriterClose closeEntryNs closeReturnNs fifoIdentity identities omissionRecords originalWatchdogThread
                    soleFixtureWriter version watchdogAdmittedBeforeClose watchdogHardDeadlineNs watchdogOwnership
                    watchdogRunDeadlineNs], close.keys.sort
    assert_equal [1, graph, fifo], close.values_at("version", "identities", "fifoIdentity")
    assert_equal entry_bindings, close.fetch("omissionRecords")
    %w[actualOriginalWriterClose soleFixtureWriter originalWatchdogThread watchdogAdmittedBeforeClose].each do |name|
      assert_equal true, close.fetch(name), name
    end
    assert_equal close.fetch("closeEntryNs"), proof.fetch("writerCloseEntryNs")
    assert_equal eof.fetch("readNilNs"), proof.fetch("validatorReadNilNs")
    %w[closeEntryNs closeReturnNs watchdogRunDeadlineNs watchdogHardDeadlineNs].each do |name|
      assert_instance_of Integer, close.fetch(name)
    end
    assert_operator close.fetch("closeEntryNs"), :<=, close.fetch("closeReturnNs")
    custody = close.fetch("watchdogOwnership")
    times = %w[driverDeadlineNs preparedNs prearmDeadlineNs slotCeilingNs startReturnedNs admitReturnedNs
               captureEntryNs armNs fallbackNs effectiveHardDeadlineNs]
    facts = %w[actualDriverCaller actualStartReturned actualAdmitReturned captureCallerIsDriver
               captureFinishedBeforeClose captureJoinedBeforeClose captureThreadExitedBeforeClose]
    assert_equal (times + facts + ["driverPid"]).sort, custody.keys.sort
    times.each { |name| assert_instance_of Integer, custody.fetch(name); assert_operator custody.fetch(name), :>, 0 }
    assert_equal dispatch.fetch("pid"), custody.fetch("driverPid")
    assert_equal dispatch.fetch("deadlineNs"), custody.fetch("driverDeadlineNs")
    (facts - ["captureJoinedBeforeClose"]).each { |name| assert_equal true, custody.fetch(name), name }
    joined = custody.fetch("captureJoinedBeforeClose")
    assert joined.equal?(true) || joined.equal?(false)
    # Native UNKNOWN can lack its original capture join. A completed/exited
    # capture is not a repaired join receipt or native finality.
    if joined
      capture_task = observation.fetch("tasks").find { |task| task.fetch("role") == "capture" }
      assert capture_task.fetch("joined")
      assert capture_task.fetch("actualJoinObserved")
    end
    assert_equal [custody.fetch("preparedNs") + 5_000_000_000, dispatch.fetch("deadlineNs") - 6_300_000_000].min,
                 custody.fetch("prearmDeadlineNs")
    assert_equal custody.fetch("prearmDeadlineNs") + 6_300_000_000, custody.fetch("slotCeilingNs")
    assert_operator custody.fetch("slotCeilingNs"), :<=, dispatch.fetch("deadlineNs")
    %w[preparedNs startReturnedNs admitReturnedNs captureEntryNs armNs].each_cons(2) do |earlier, later|
      assert_operator custody.fetch(earlier), :<=, custody.fetch(later)
    end
    assert_operator custody.fetch("armNs"), :<, custody.fetch("prearmDeadlineNs")
    assert_equal custody.fetch("armNs") + 5_300_000_000, custody.fetch("fallbackNs")
    assert_equal custody.fetch("fallbackNs") + 1_000_000_000, custody.fetch("effectiveHardDeadlineNs")
    assert_operator custody.fetch("effectiveHardDeadlineNs"), :<=, custody.fetch("slotCeilingNs")
    assert_equal [custody.fetch("slotCeilingNs")] * 2, close.values_at("watchdogRunDeadlineNs", "watchdogHardDeadlineNs")
    assert_operator close.fetch("closeEntryNs"), :>=, custody.fetch("fallbackNs")
    assert_operator close.fetch("closeReturnNs"), :<, custody.fetch("effectiveHardDeadlineNs")
    assert_instance_of Integer, eof.fetch("readNilNs")
    # Kernel EOF may reach V before Ruby close returns; the sole SAME writer,
    # actual close and SAME FIFO read(nil), not return-time ordering, bind this.
    assert_operator close.fetch("closeEntryNs"), :<=, eof.fetch("readNilNs")
    assert_equal({"version" => 1, "eof" => true, "controlReadNil" => true, "readNilNs" => eof.fetch("readNilNs"),
                  "pid" => graph.fetch("validator"), "group" => graph.fetch("group"), "sid" => graph.fetch("sid"),
                  "fifoIdentity" => fifo}, eof)
    %w[custodian keeper].each do |role|
      report = reports.fetch("containment-#{role}-omission.json")
      assert_equal %w[entry helperCopy identities kind mode parentPid pid role sourceSha256 version], report.keys.sort
      assert_equal [1, "original-helper-cleanup-omission-entry", "native-setup-no-cleanup", role, graph.fetch(role), graph],
                   report.values_at("version", "kind", "mode", "role", "pid", "identities")
      assert_equal role == "custodian" ? dispatch.fetch("pid") : graph.fetch("custodian"), report.fetch("parentPid")
      assert_equal proof.fetch("sourceSha256"), report.fetch("sourceSha256")
      assert_equal copy, report.fetch("helperCopy")
      omission = report.fetch("entry")
      assert_equal %w[actualOmissionEntry atNs effectiveDeadlineNs group nativeCallOmitted origin originalReservedAuthority route signal], omission.keys.sort
      assert_equal [role == "custodian" ? "custodian-group" : "keeper-group", graph.fetch("group"), "KILL"],
                   omission.values_at("route", "group", "signal")
      %w[actualOmissionEntry nativeCallOmitted originalReservedAuthority].each { |name| assert_equal true, omission.fetch(name), name }
      assert_equal %w[line path], omission.fetch("origin").keys.sort
      assert_equal copy.fetch("path"), omission.fetch("origin").fetch("path")
      origin = role == "custodian" ? MobileReleaseKit::NativeUploadProcess::GroupLease.instance_method(:request) :
                                   MobileReleaseKit::NativeUploadProcess::Keeper.instance_method(:request_group)
      assert_equal origin.source_location.last, omission.fetch("origin").fetch("line")
      %w[atNs effectiveDeadlineNs].each { |key| assert_instance_of Integer, omission.fetch(key) }
      assert_operator custody.fetch("armNs"), :<=, omission.fetch("atNs")
      assert_operator omission.fetch("atNs"), :<, omission.fetch("effectiveDeadlineNs")
      assert_operator omission.fetch("effectiveDeadlineNs"), :<=, dispatch.fetch("deadlineNs")
      assert_operator omission.fetch("atNs"), :<, close.fetch("closeEntryNs")
    end
    driver = value.fetch("driverProvenance")
    assert_equal "reaped", driver.fetch("phase")
    assert driver.fetch("creatorJoined")
    assert driver.fetch("resourcesClosed")
    assert_equal({"pid" => driver.fetch("pid"), "status_kind" => "exit", "status_code" => 1}, driver.fetch("wait"))
    assert_equal({"out" => true, "err" => true}, driver.fetch("ownedStreamEOFs"))
    assert_equal sources, proof_source_snapshot
  end

  def test_partial_pipe_and_pre_entry_faults_close_owned_leases_and_join_actual_tasks
    assert_native_record_publication
    %w[second-pipe owner-failure readiness-failure watchdog-unavailable watchdog-failure].each do |fault|
      value = process_case("native-setup-#{fault}")
      assert_equal fault == "readiness-failure" ? "readiness" : "setup-fixture-fault", value.fetch("kind")
      assert value.fetch("harnessPrimaryRetained"), value.inspect
      assert_equal 0, value.fetch("injectionCount")
      refute value.fetch("firstCloseEntered"), value.inspect
      refute value.fetch("watchdogIntervened"), value.inspect
      assert_equal fault == "watchdog-failure", value.fetch("watchdogStarted")
      if fault == "second-pipe"
        assert_native_observation(value.fetch("nativeObservation"), finality: :no_producers)
        refute value.fetch("fallbackUsed"), value.inspect
      else
        assert_native_observation(value.fetch("nativeObservation"), finality: :finalized)
        refute value.fetch("fallbackUsed"), value.inspect
        assert value.fetch("ready"), value.inspect if fault.start_with?("watchdog-")
      end
    end
  end

  def test_real_post_reap_cancellation_preserves_original_and_closes_only_owned_resources
    value = process_case("native-setup-post-reap-cancel")
    assert_native_cleanup(value)
    assert value.fetch("nativeOriginalErrorPreserved"), value.inspect
    assert_equal "Interrupt", value.fetch("nativeErrorClass")
    assert_equal "synthetic setup cancellation", value.fetch("nativeErrorMessage")
    assert value.fetch("postReapCancellationInjected"), value.inspect
    assert_operator value.fetch("postReapCleanupDepth"), :>, 0
    assert_equal Signal.list.fetch("INT"), value.fetch("selfSignalQueued")
  end

  def test_hard_driver_loss_stops_all_previously_bound_native_roles
    UploadProcessFixture.assert_domain_reusable!
    sources = proof_source_snapshot
    value = UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: "kill-native-setup")
    assert value.fetch("driverJoined")
    assert_equal "driver-terminated", value.fetch("kind")
    assert_equal "kill-native-setup", value.fetch("phase")
    refute value.key?("knownProcessesDead")
    # An independently held ORIGINAL FIFO writer excludes fixture EOF while
    # actual C/K waits, group KILL and absence prove runtime containment. Those
    # events still do not provide the lost driver's original C wait/finality.
    assert_equal Signal.list.fetch("KILL"), value.fetch("driverTermSignal")
    assert_equal "unknown", value.fetch("nativeFinality")
    assert value.fetch("retainedFixture")
    assert value.fetch("domainDisposalRequired")
    assert UploadProcessFixture.expected_unknown_retention?(@root)
    assert UploadProcessFixture.domain_disposal_required?
    proof = value.fetch("containmentProof")
    assert_equal %w[driverKillEntryNs fifoIdentity heldWriterAcquiredNs heldWriterClose heldWriterOpenThroughProof helperCopy
                    helperReportSha256 identities keeperExitStatus kind mode nativeFinality originalCustodianWaitMissing
                    originalKeeperWaitObserved originalValidatorWaitObserved proofCompletedNs releasedAndControlEOFObserved
                    reservedGroupAbsentBeforeFixtureEOF runtimeGroupKillObserved sourceSha256 validatorReceipt version], proof.keys.sort
    assert_equal [1, "runtime-containment-before-fixture-eof", "kill-native-setup", "unknown"],
                 proof.values_at("version", "kind", "mode", "nativeFinality")
    %w[heldWriterOpenThroughProof originalCustodianWaitMissing reservedGroupAbsentBeforeFixtureEOF runtimeGroupKillObserved
       originalKeeperWaitObserved originalValidatorWaitObserved releasedAndControlEOFObserved].each { |name| assert_equal true, proof.fetch(name), name }
    assert_includes [0, 2], proof.fetch("keeperExitStatus")
    assert_equal sources.transform_values { |item| item.fetch("sha256") }, proof.fetch("sourceSha256")
    directory = value.fetch("driverDispatch").fetch("argv").last
    assert_equal @root, File.dirname(directory)
    assert_equal directory, File.realpath(directory)
    copy = proof.fetch("helperCopy")
    assert_equal %w[label originalPath originalSha256 path sha256], copy.keys.sort
    assert_equal "containment-events", copy.fetch("label")
    assert_equal File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__)), copy.fetch("originalPath")
    assert_equal sources.fetch("fastlane/native_upload_process.rb").fetch("sha256"), copy.fetch("originalSha256")
    assert_equal File.join(directory, "containment-events-helper.rb"), copy.fetch("path")
    assert_equal Digest::SHA256.hexdigest(UploadProcessFixture::OwnedChild.bounded_file(copy.fetch("path"), limit: 1_048_576)), copy.fetch("sha256")
    refute_equal copy.fetch("originalSha256"), copy.fetch("sha256")
    graph = proof.fetch("identities")
    assert_equal %w[custodian group keeper sid validator], graph.keys.sort
    graph.each_value { |pid| assert_instance_of Integer, pid; assert_operator pid, :>, 1 }
    assert_equal 3, graph.values_at("custodian", "keeper", "validator").uniq.length
    assert_equal graph.fetch("custodian"), graph.fetch("sid")
    assert_equal graph.fetch("keeper"), graph.fetch("group")
    owner = UploadProcessFixture.read_json(File.join(directory, "owner.json"))
    assert_equal ["kill-native-setup", "active"], owner.values_at("phase", "finality")
    assert_equal [{"role" => "custodian", "pid" => graph.fetch("custodian"), "group" => graph.fetch("custodian")},
                  {"role" => "keeper", "pid" => graph.fetch("keeper"), "group" => graph.fetch("custodian")},
                  {"role" => "validator", "pid" => graph.fetch("validator"), "group" => graph.fetch("group")}],
                 owner.fetch("processes").sort_by { |item| item.fetch("role") }
    assert_equal({"state" => "reaped", "pid" => graph.fetch("validator"), "status_kind" => "signal",
                  "status_code" => Signal.list.fetch("KILL")}, proof.fetch("validatorReceipt"))
    fifo = proof.fetch("fifoIdentity")
    assert_equal %w[dev gid ino mode nlink rdev type uid], fifo.keys.sort
    assert_equal "fifo", fifo.fetch("type")
    assert_equal Process.uid, fifo.fetch("uid")
    assert_equal 1, fifo.fetch("nlink")
    assert_equal 0o600, fifo.fetch("mode") & 0o7777
    assert_equal UploadProcessFixture::OwnedChild.identity(File.lstat(File.join(directory, "worker-control.fifo"))), fifo
    close = proof.fetch("heldWriterClose")
    assert_equal %w[actualCloseReturned closed entryNs returnNs], close.keys.sort
    assert_equal true, close.fetch("actualCloseReturned")
    assert_equal true, close.fetch("closed")
    times = [proof.fetch("heldWriterAcquiredNs"), proof.fetch("driverKillEntryNs"), proof.fetch("proofCompletedNs"),
             close.fetch("entryNs"), close.fetch("returnNs")]
    times.each { |time| assert_instance_of Integer, time; assert_operator time, :>, 0 }
    times.each_cons(2) { |before, after| assert_operator before, :<=, after }
    # These are bounded reads of already retained reports, not new observers.
    # Time fields constrain the proof; actual original call/IO receipts bind it.
    hashes = proof.fetch("helperReportSha256")
    assert_equal %w[containment-custodian.json containment-keeper.json], hashes.keys.sort
    reports = hashes.to_h do |name, digest|
      bytes = UploadProcessFixture::OwnedChild.bounded_file(File.join(directory, name))
      assert_equal Digest::SHA256.hexdigest(bytes), digest
      [name.delete_prefix("containment-").delete_suffix(".json"), JSON.parse(bytes)]
    end
    reports.each do |role, report|
      assert_equal [1, "original-helper-containment-events", "kill-native-setup", role, graph.fetch(role), graph],
                   report.values_at("version", "kind", "mode", "role", "pid", "identities")
      assert_equal proof.fetch("sourceSha256"), report.fetch("sourceSha256")
      assert_equal copy, report.fetch("helperCopy")
      refute report.fetch("terminalAlreadyArmed")
      assert_empty report.fetch("hookRestorationErrors")
      assert_empty report.fetch("omissions")
      child = report.fetch("originalChild")
      assert_equal true, child.fetch("actualOriginalWaitObserved")
      assert_equal true, child.fetch("actualCreatorJoinObserved")
      assert_operator child.fetch("waitNs"), :<=, report.fetch("preArmNs")
      assert_operator proof.fetch("driverKillEntryNs"), :<=, report.fetch("preArmNs")
      assert_operator report.fetch("preArmNs"), :<=, proof.fetch("proofCompletedNs")
    end
    c, k = reports.values_at("custodian", "keeper")
    assert_equal value.fetch("driverProvenance").fetch("pid"), c.fetch("parentPid")
    assert_equal graph.fetch("custodian"), k.fetch("parentPid")
    assert_equal proof.fetch("keeperExitStatus"), k.fetch("originalRunReturn")
    assert_equal({"state" => "reaped", "pid" => graph.fetch("keeper"), "status_kind" => "exit",
                  "status_code" => proof.fetch("keeperExitStatus")}, c.fetch("originalChild").fetch("record"))
    assert_equal proof.fetch("validatorReceipt"), k.fetch("originalChild").fetch("record")
    assert_equal({"v" => 1, "type" => "RELEASED", "validator" => proof.fetch("validatorReceipt")}, k.fetch("releasedFrame"))
    assert_equal true, k.fetch("releasedWritten")
    assert_equal true, k.fetch("actualStatusCloseObserved")
    assert_equal true, c.fetch("acceptedReleased").fetch("actualOriginalAcceptReturned")
    assert_equal k.fetch("releasedFrame"), c.fetch("acceptedReleased").fetch("frame")
    assert_equal true, c.fetch("keeperChannelEOF")
    assert c.fetch("actualEOFs").any? { |event| event.fetch("channel") == "keeper" && event.fetch("actualReadNil").equal?(true) }
    retirement = c.fetch("groupRetirement")
    assert_equal graph.fetch("group"), retirement.fetch("group")
    assert_equal true, retirement.fetch("actualOriginalRetireReturned")
    assert_equal true, retirement.fetch("originalESRCHObserved")
    assert c.fetch("actualAbsences").any? { |event| event.fetch("group") == graph.fetch("group") && event.fetch("actualESRCH").equal?(true) }
    kills = reports.values.flat_map { |report| report.fetch("actualKills") }
    assert_operator kills.length, :>=, 1 # C OR K in this ORIGINAL case, not a forced-C schedule.
    kills.each do |event|
      assert_includes %w[custodian-group keeper-group], event.fetch("route")
      assert_equal [graph.fetch("group"), "KILL", 1, true, true],
                   event.values_at("group", "signal", "returned", "actualSyscallReturned", "originalReservedAuthority")
      assert_equal copy.fetch("path"), event.fetch("origin").fetch("path")
      assert_operator event.fetch("origin").fetch("line"), :>, 0
      assert_operator proof.fetch("driverKillEntryNs"), :<=, event.fetch("atNs")
      assert_operator event.fetch("atNs"), :<=, event.fetch("returnNs")
      assert_operator event.fetch("returnNs"), :<=, proof.fetch("proofCompletedNs")
    end
    driver = value.fetch("driverProvenance")
    assert_equal "reaped", driver.fetch("phase")
    assert driver.fetch("creatorJoined")
    assert driver.fetch("resourcesClosed")
    assert_equal({"pid" => driver.fetch("pid"), "status_kind" => "signal", "status_code" => Signal.list.fetch("KILL")}, driver.fetch("wait"))
    assert_equal({"out" => true, "err" => true}, driver.fetch("ownedStreamEOFs"))
    assert_equal sources, proof_source_snapshot
  end

  def test_native_task_error_precedes_later_caller_cancellation_at_the_original_latch
    %w[interrupt system-exit].each do |caller_kind|
      native_order_case("task-before-caller", caller_kind)
    end
  end

  def test_native_caller_cancellation_precedes_later_task_ioerror_at_the_original_latch
    %w[interrupt system-exit].each do |caller_kind|
      native_order_case("caller-before-task", caller_kind)
    end
  end

  def test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown
    native_order_case("cleanup-before-caller", "interrupt")
  end

  def test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown
    native_order_case("cleanup-before-caller", "system-exit")
  end

  def test_native_platform_modes_and_empty_parameters_are_validated_before_acquisition
    cases = UploadProcessFixture::NATIVE_MODES.flat_map { |mode| %w[ios android].map { |platform| [platform, mode, {}] } }
    cases.concat((UploadProcessFixture::MODES - UploadProcessFixture::NATIVE_MODES).map { |mode| ["native", mode, {}] })
    cases.concat([["native", "missing", {}], ["missing", "native-setup-interrupt", {}],
                  ["native", "native-setup-interrupt", {"python" => "untrusted"}]])
    input_deadline_ns = UploadProcessFixture.clock_ns + UploadProcessFixture::DRIVER_LIMIT * 1_000_000_000
    with_acquisition_veto do
      cases.each do |platform, mode, parameters|
        error = assert_raises(UploadProcessFixture::Failure) do
          UploadProcessFixture.run(platform: platform, root: @root, mode: mode, parameters: parameters)
        end
        assert_equal "fixture-input", error.kind
        assert_equal "unknown or mismatched fixture mode/platform/parameters", error.message
        assert_operator UploadProcessFixture.clock_ns, :<, input_deadline_ns
        UploadProcessFixture.atomic_json(File.join(@root, "input.json"),
          {"platform" => platform, "mode" => mode, "parameters" => parameters, "deadlineNs" => input_deadline_ns})
        error = assert_raises(UploadProcessFixture::Failure) do
          Dir.stub(:tmpdir, @root) { UploadProcessFixture.driver(@root) }
        end
        assert_equal "fixture-input", error.kind
        assert_equal "unknown or mismatched fixture mode/platform/parameters", error.message
        assert_equal ["input.json"], Dir.children(@root)
      end

      # Inert bootstrap diagnostics: no original child, native receipt, actual
      # process operation or new IO is supplied by these doubles. The real stop
      # body sees only an empty acquisition and never an unretired numeric route.
      owner_class = UploadProcessFixture::OwnedChild
      record = {"version" => 1, "stage" => "configuration", "condition" => "directory_identity", "pid" => 701}
      good = JSON.generate(record)
      exercise = lambda do |raw, diagnostic: true, read_error: nil, write_result: :full, cleanup_error: nil, expiry: nil,
                            publication_pending: false|
        now, reads, first = 1, 0, nil
        events, writes, read_observations, report_attempts, removed = Array.new(5) { [] }
        directory = "/inert-mrk-bootstrap"
        owner = owner_class.new(root: @root, deadline_ns: 20, hard_deadline_ns: 30)
        creator, acquisition = Object.new, Object.new
        creator.define_singleton_method(:first_error) { first }
        creator.define_singleton_method(:cancelled?) { !first.nil? }
        creator.define_singleton_method(:cancel!) do |error:, reason_code:|
          first ||= error
          events << :latch
          true
        end
        creator.define_singleton_method(:record_cleanup_error) do |error|
          first ||= error
          events << :cleanup_latch
          nil
        end
        creator.define_singleton_method(:cleanup_deadline_ns) { now = 10 if expiry == :before_read; 10 }
        creator.define_singleton_method(:close_launch!) do
          events << :creator_close
          Kernel.raise cleanup_error if cleanup_error
          nil
        end
        acquisition.define_singleton_method(:close_launch!) { events << :acquisition_close; nil }
        acquisition.define_singleton_method(:resources) { {} }
        acquisition.define_singleton_method(:not_attempted?) { false }
        {creator: creator, acquisition: acquisition, pid: 701, phase: :reaped, creation_finished: true,
         launch_directory: directory, directory_identity: :inert_directory}.each do |name, value|
          owner.instance_variable_set(:"@#{name}", value)
        end
        owner.define_singleton_method(:signal) { |*| Kernel.raise "inert diagnostic attempted numeric signaling" }
        owner.define_singleton_method(:poll_wait) { Kernel.raise "inert diagnostic attempted a process wait" }
        owner.define_singleton_method(:fail_unknown!) do |_error|
          @phase = :unknown
          events << :unknown # No real acquisition exists to poison the case domain.
        end
        original_close = owner.method(:close_resources)
        owner.define_singleton_method(:close_resources) { events << :close_resources; original_close.call }
        reader = lambda do |path, limit:|
          reads += 1
          events << :read
          read_observations << [path, limit, first, owner.instance_variable_get(:@primary), events.dup]
          raise read_error if read_error
          now = 10 if expiry == :after_read
          raw
        end
        sink = lambda do |line|
          events << :write
          writes << line
          report_attempts << owner.instance_variable_get(:@bootstrap_failure_report_attempted)
          raise write_result if write_result.is_a?(Exception)
          write_result == :short ? 1 : line.bytesize
        end
        publication_error = UploadProcessFixture::Failure.new("process-ownership", "bootstrap record publication remains unresolved")
        publication_gate = lambda do |path|
          assert_equal directory, path
          events << :publication_gate
          raise publication_error if publication_pending
          true
        end
        owner_class.stub(:assert_record_publication_final!, publication_gate) do
        File.stub(:exist?, ->(path) { path == File.join(directory, "failure.json") }) do
          owner_class.stub(:bounded_file, reader) do
            owner_class.stub(:directory_identity, ->(path) { assert_equal directory, path; :inert_directory }) do
              UploadProcessFixture.stub(:owned_fixture_directory, ->(*) { Kernel.raise "inert stop bypassed directory identity stub" }) do
                FileUtils.stub(:remove_entry, ->(path) { removed << path; events << :remove_entry }) do
                  UploadProcessFixture.stub(:clock_ns, -> { now }) do
                    STDERR.stub(:write, sink) do
                      original = assert_raises(UploadProcessFixture::Failure) { owner.wait_ready }
                      assert_same first, original
                      assert_equal ["process-ownership", "bootstrap refused admission"], [original.kind, original.message]
                      assert_equal "not_attempted", owner.instance_variable_get(:@go_state)
                      assert_empty writes # wait_ready only snapshots; it never publishes.
                      owner.snapshot_bootstrap_failure
                      assert_equal expiry == :before_read ? 0 : 1, reads
                      # Assert OUTSIDE the no-throw diagnostic callbacks: their
                      # rescue must never swallow this test's own assertions.
                      read_observations.each do |path, limit, latched, primary, sequence|
                        assert_equal File.join(directory, "failure.json"), path
                        assert_equal 1024, limit
                        assert_same original, latched
                        assert_same original, primary
                        assert_equal %i[latch read], sequence
                      end
                      snapshot = diagnostic && !read_error && !%i[before_read after_read].include?(expiry)
                      expected = {"stage" => "configuration", "condition" => "directory_identity"}
                      if snapshot
                        assert_equal expected, owner.instance_variable_get(:@bootstrap_failure_snapshot)
                      else
                        assert_nil owner.instance_variable_get(:@bootstrap_failure_snapshot)
                      end
                      now = 10 if expiry == :before_emit
                      if cleanup_error || publication_pending
                        stopping_error = cleanup_error || publication_error
                        assert_same stopping_error, assert_raises(stopping_error.class) { owner.stop }
                        assert_raises(UploadProcessFixture::Failure) { owner.stop }
                      else
                        assert_equal true, owner.stop
                        assert_equal true, owner.stop
                      end
                      assert_same original, first
                      assert_same original, owner.instance_variable_get(:@primary)
                      assert_equal 10, owner.instance_variable_get(:@bootstrap_failure_cutoff_ns)
                      assert_equal snapshot && expiry != :before_emit ? 1 : 0, writes.length
                      assert_equal [true] * writes.length, report_attempts
                      assert_equal cleanup_error || publication_pending ? [] : [directory], removed
                      assert_includes events, :close_resources
                      if publication_pending
                        assert_operator events.index(:close_resources), :<, events.index(:publication_gate)
                      end
                      unless writes.empty?
                        assert_operator events.index(:close_resources), :<, events.index(:write)
                        assert_operator events.index(:remove_entry), :<, events.index(:write) unless cleanup_error || publication_pending
                      end
                      writes.each do |line|
                        assert_equal "MRK_FIXTURE_BOOTSTRAP_FAILURE=#{JSON.generate({"schema" => 1}.merge(expected))}\n", line
                        assert line.ascii_only?
                        assert_operator line.bytesize, :<=, 256
                        refute_includes line, "pid"
                        refute_includes line, "701"
                        refute_includes line, "private-marker"
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
      exercise.call(good)
      exercise.call(good, publication_pending: true)
      invalid = ["not-json", "[]", "x" * 1025, " #{good}",
        good.sub('"pid":701', '"pid":701,"pid":701'),
        JSON.generate(record.reject { |key, _| key == "condition" }),
        JSON.generate(record.merge("private-marker" => "must not escape")),
        JSON.generate(record.merge("version" => 1.0)), JSON.generate(record.merge("pid" => 702)),
        JSON.generate(record.merge("pid" => 701.0)), JSON.generate(record.merge("stage" => "private-marker")),
        JSON.generate(record.merge("condition" => "setsid"))]
      invalid.each { |bytes| exercise.call(bytes, diagnostic: false) }
      exercise.call(good, read_error: IOError.new("private-marker"))
      %i[before_read after_read before_emit].each { |expiry| exercise.call(good, expiry: expiry) }
      exercise.call(good, write_result: :short)
      exercise.call(good, write_result: IOError.new("private-marker"))
      exercise.call(good, cleanup_error: IOError.new("original cleanup error"), write_result: IOError.new("private-marker"))

      # Exact original endpoints and all reporting seams below are inert. No
      # process/wait receipt is fabricated; the acquisition veto remains live.
      cap = 1_000_000_000_000_000_001 # 1e9 seconds + 1ns loses the 1ns in Float.
      cleanup_ns = UploadProcessFixture::CLEANUP_LIMIT * 1_000_000_000
      candidate_ns = cap + 20_000_000_000
      candidate = Rational(candidate_ns, 1_000_000_000)
      UploadProcessFixture.stub(:clock_ns, cap - 60_000_000_000) do
        refute_equal cap, (cap.fdiv(1_000_000_000).to_r * 1_000_000_000).floor
        assert_equal [cap - cleanup_ns - RAW_REPORTING_NS, cap - RAW_REPORTING_NS, cap],
                     raw_collector_cutoffs(candidate, enclosing_deadline_ns: cap)
        assert_equal [candidate_ns, candidate_ns + cleanup_ns, candidate_ns + cleanup_ns], raw_collector_cutoffs(candidate)
        [false, cap.to_f, "private-marker", 0, MobileReleaseKit::NativeUploadProcess::MAX_TIME + 1].each do |invalid_cap|
          failure = assert_raises(UploadProcessFixture::Failure) { raw_collector_cutoffs(candidate, enclosing_deadline_ns: invalid_cap) }
          assert_equal "fixture-input", failure.kind
        end
        failure = assert_raises(UploadProcessFixture::Failure) do
          raw_collector_cutoffs(candidate, enclosing_deadline_ns: cap - 60_000_000_000 + cleanup_ns + RAW_REPORTING_NS)
        end
        assert_equal "driver", failure.kind
      end
      caps, reporting = [], {}
      frame = Object.new
      UploadProcessFixture.stub(:lifetime, ->(deadline_ns:, &body) { caps << deadline_ns; body.call(frame) }) do
        assert_equal :offered, with_capture_reporting(reporting, nil, enclosing_deadline_ns: cap) { :offered }
      end
      assert_equal [cap], caps
      assert_same frame, reporting.fetch(:reporting_lifetime)

      fixture_class = self.class
      original = Minitest::Assertion.new("private-marker")
      line = fixture_class.isolated_failure_line("capture-contract", original)
      assert_equal "#{ISOLATED_FAILURE_PREFIX}{\"schema\":1,\"stage\":\"capture-contract\",\"category\":\"assertion-error\"}\n", line
      assert_operator line.bytesize, :<=, 256
      assert line.ascii_only?
      category_errors = [original, UploadProcessFixture::Failure.new("private-marker", "private-marker"),
        MobileReleaseKit::NativeUploadProcess::LifecycleError.new, IOError.new("private-marker"), Errno::EIO.new("private-marker"),
        Interrupt.new("private-marker"), SystemExit.new(17, "private-marker"), JSON::ParserError.new("private-marker"),
        KeyError.new("private-marker"), NoMethodError.new("private-marker"), TypeError.new("private-marker"),
        ArgumentError.new("private-marker"), RuntimeError.new("private-marker"), StandardError.new("private-marker"),
        Exception.new("private-marker"), Object.new]
      assert_equal 16, category_errors.length
      assert_equal 16, ISOLATED_FAILURE_CATEGORIES.uniq.length
      category_packets = category_errors.zip(ISOLATED_FAILURE_CATEGORIES).map do |failure, category|
        packet = fixture_class.isolated_failure_line("capture-contract", failure)
        assert_equal category, JSON.parse(packet.delete_prefix(ISOLATED_FAILURE_PREFIX)).fetch("category")
        refute_includes packet, "private-marker"
        packet
      end
      nesting_packet = fixture_class.isolated_failure_line("capture-contract", JSON::NestingError.new("private-marker"))
      assert_equal "json-parser-error", JSON.parse(nesting_packet.delete_prefix(ISOLATED_FAILURE_PREFIX)).fetch("category")
      assert_nil fixture_class.isolated_failure_line("private-marker", original)
      malformed = [line + line, line + "#{ISOLATED_FAILURE_PREFIX}not-json\n", line.delete_suffix("\n"),
        line.sub('"schema":1', '"schema":1,"schema":1'), line.sub('"schema":1', '"schema":true'),
        line.sub('"schema":1', '"schema":1.0'), line.sub('"schema":1', '"schema":2'),
        line.sub('"schema":1', '"schema":1,"pid":701'), line.sub('"schema":1', '"schema":1,"private":"private-marker"'),
        line.sub("capture-contract", "private-marker"), line.sub("assertion-error", "private-marker"),
        line.sub('"stage":"capture-contract"', '"stage":false'), line.sub('"category":"assertion-error"', '"category":[]'),
        line.sub('{"schema":1,', '{ "schema":1,'), line.sub('"schema":1,"stage":"capture-contract"', '"stage":"capture-contract","schema":1'),
        "#{ISOLATED_FAILURE_PREFIX}[]\n", "#{ISOLATED_FAILURE_PREFIX}#{'x' * 256}\n", "#{ISOLATED_FAILURE_PREFIX}\xff\n".b]
      now, clock_sequence, clock_forbidden = 1, nil, false
      inert_clock = lambda do
        raise "early diagnostic manufactured a timer" if clock_forbidden
        clock_sequence ? clock_sequence.shift || now : now
      end
      UploadProcessFixture.stub(:clock_ns, inert_clock) do
        assert_equal 41, ISOLATED_FAILURE_STAGES.uniq.length
        ISOLATED_FAILURE_STAGES.each do |stage|
          packet = fixture_class.isolated_failure_line(stage, original)
          assert_equal({"schema" => 1, "stage" => stage, "category" => "assertion-error"},
                       JSON.parse(packet.delete_prefix(ISOLATED_FAILURE_PREFIX)))
          assert packet.ascii_only?
          assert_operator packet.bytesize, :<=, 256
          assert_equal packet, fixture_class.parse_isolated_failure(packet, deadline_ns: 10)
        end
        (category_packets + [nesting_packet]).each do |packet|
          assert_equal packet, fixture_class.parse_isolated_failure(packet, deadline_ns: 10)
        end
        assert_equal line, fixture_class.parse_isolated_failure("private unrelated transcript\n#{line}", deadline_ns: 10)
        malformed.each { |raw| assert_nil fixture_class.parse_isolated_failure(raw, deadline_ns: 10) }
        assert_nil fixture_class.parse_isolated_failure("x" * (UploadProcessFixture::OUTPUT_LIMIT + 1), deadline_ns: 10)
        now = 10
        assert_nil fixture_class.parse_isolated_failure(line, deadline_ns: 10)
        now = 1
        clock_sequence = [1, 1, 10]
        assert_nil fixture_class.parse_isolated_failure(line, deadline_ns: 10)
        clock_sequence = nil

        [:full, :short, IOError.new("private-marker"), Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |write_result|
          state = {stage: "capture-contract", deadline_ns: 10}
          writes, latched = [], []
          sink = lambda do |packet|
            writes << packet
            latched << [state[:primary], state[:failure_stage], state[:report_attempted], state[:write_attempted]]
            raise write_result if write_result.is_a?(Exception)
            write_result == :short ? 1 : packet.bytesize
          end
          STDERR.stub(:write, sink) do
            fixture_class.report_isolated_cli_failure(state, original)
            state[:stage] = "proof-publication"
            fixture_class.report_isolated_cli_failure(state, IOError.new("later private-marker"))
          end
          assert_equal [line], writes
          assert_equal [[original, "capture-contract", true, true]], latched
          assert_same original, state.fetch(:primary)
          assert_equal "capture-contract", state.fetch(:failure_stage)
          if write_result.is_a?(Exception)
            assert_same write_result, state.fetch(:diagnostic_error)
          else
            assert_equal write_result == :full, state.fetch(:write_complete)
          end

          # Exercise the SAME status-assertion wrapper as the native test, not
          # a copied rescue. This inert status supplies no process authority.
          observed = {status: Struct.new(:exitstatus).new(1), stderr: line, run_deadline_ns: 10}
          parent_writes, parent_latches = [], []
          parent_sink = lambda do |packet|
            parent_writes << packet
            parent_latches << observed.fetch(:isolated_failure_report).fetch(:primary)
            raise write_result if write_result.is_a?(Exception)
            write_result == :short ? 1 : packet.bytesize
          end
          actual = STDERR.stub(:write, parent_sink) do
            assert_raises(Minitest::Assertion) { assert_isolated_collector_exit(observed) }
          end
          assert_equal [line], parent_writes
          assert_equal [actual], parent_latches
          assert_same actual, observed.fetch(:isolated_failure_report).fetch(:primary)
          assert_same write_result, observed.fetch(:isolated_failure_report_error) if write_result.is_a?(Exception)
        end

        writes = []
        STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
          state = {stage: "capture-contract", deadline_ns: 10}
          now = 10
          fixture_class.report_isolated_cli_failure(state, original)
          now = 1
          fixture_class.report_isolated_cli_failure(state, original)
          assert_empty writes # Expiry cannot be retried with a renewed clock.
          assert_same original, state.fetch(:primary)

          early = {stage: "cli-admission", deadline_ns: nil}
          clock_forbidden = true
          fixture_class.report_isolated_cli_failure(early, original)
          clock_forbidden = false
          assert_equal [fixture_class.isolated_failure_line("cli-admission", original)], writes
          assert_nil early.fetch(:deadline_ns)
          writes.clear

          successful = {status: Struct.new(:exitstatus).new(0), stderr: line, run_deadline_ns: 10}
          assert_isolated_collector_exit(successful)
          refute successful.key?(:isolated_failure_report)
          [Interrupt.new("before original assertion"), SystemExit.new(21, "before original assertion")].each do |cancellation|
            status = Object.new
            status.define_singleton_method(:exitstatus) { raise cancellation }
            before_assertion = {status: status, stderr: line, run_deadline_ns: 10}
            assert_same cancellation, assert_raises(cancellation.class) { assert_isolated_collector_exit(before_assertion) }
            refute before_assertion.key?(:isolated_failure_report)
          end
          malformed_capture = {status: Struct.new(:exitstatus).new(1), stderr: line + line, run_deadline_ns: 10}
          actual = assert_raises(Minitest::Assertion) { assert_isolated_collector_exit(malformed_capture) }
          assert_same actual, malformed_capture.fetch(:isolated_failure_report).fetch(:primary)
          assert_empty writes
        end

        # Exercise the actual nested helpers, stopping at deliberate original
        # operands. These partial inputs never reach a Process::Status/receipt
        # assertion or stand in for a successful capture or native provenance.
        checkpoint = lambda do |stage, operand, failure, with_state: true, &body|
          state = {stage: "capture-contract", deadline_ns: 10}
          evaluations = []
          fault = lambda do |seen|
            evaluations << [seen, state.fetch(:stage)]
            raise failure
          end
          keywords = with_state ? {failure_state: state} : {}
          actual = assert_raises(failure.class) { body.call(keywords, fault) }
          assert_same failure, actual
          expected_stage = with_state ? stage : "capture-contract"
          assert_equal [[operand, expected_stage]], evaluations # Checkpoint preceded the operand.
          assert_equal({stage: expected_stage, deadline_ns: 10}, state) # No early primary/report latch.
          if with_state
            writes = []
            STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
              fixture_class.report_isolated_cli_failure(state, actual)
              state[:stage] = "proof-publication"
              fixture_class.report_isolated_cli_failure(state, IOError.new("later private-marker"))
            end
            assert_equal [fixture_class.isolated_failure_line(stage, failure)], writes
            assert_same failure, state.fetch(:primary)
            assert_equal stage, state.fetch(:failure_stage)
          end
        end
        capture_directory = "/inert-mrk-capture"
        capture_observed = {directory: capture_directory, streams_closed: true, stop_completed: false}
        [true, false].each do |with_state|
          checkpoint.call("capture-record-read", File.join(capture_directory, "collector.json"),
                          JSON::ParserError.new("private-marker"), with_state: with_state) do |keywords, fault|
            File.stub(:file?, true) do
              UploadProcessFixture.stub(:read_json, fault) do
                assert_retained_capture(capture_observed, finality: :unknown, **keywords)
              end
            end
          end
        end

        # Only scalar comparisons precede the original :child fetch; no child,
        # acquisition, creator, lifetime or authoritative wait receipt exists.
        capture_status = Struct.new(:exitstatus, :termsig).new(nil, 9)
        capture_fixture = {"path" => File.join(capture_directory, "fixture.rb")}
        capture_environment = UploadProcessFixture::PROCESS_OBSERVER_SELECTION.nil? ? {} :
          {UploadProcessFixture::PROCESS_OBSERVER_KEY => UploadProcessFixture::PROCESS_OBSERVER_SELECTION}
        capture_environment.merge!("TMPDIR" => capture_directory, "TMP" => capture_directory, "TEMP" => capture_directory)
        capture_dispatch = {"isolatedControl" => false, "minitest" => nil, "fixture" => capture_fixture,
          "argv" => [RbConfig.ruby, capture_fixture.fetch("path"), "driver", capture_directory],
          "environment" => capture_environment, "cwd" => Dir.pwd, "interpreter" => :inert_interpreter,
          "options" => {"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
            "stdout" => File.join(capture_directory, "driver.stdout"), "stderr" => File.join(capture_directory, "driver.stderr")}}
        capture_record = {"phase" => "unknown", "exitStatus" => nil, "termSignal" => 9, "streamsClosed" => true,
          "stopCompleted" => false, "inputsRechecked" => true, "dispatch" => capture_dispatch, "streamIdentities" => :inert_streams}
        capture_observed.merge!(status: capture_status, dispatch: capture_dispatch, stream_identities: :inert_streams)
        identity_reads = []
        identity_reader = lambda do |path, limit:|
          identity_reads << [path, limit]
          path == RbConfig.ruby ? :inert_interpreter : capture_fixture
        end
        original_fetch = capture_observed.method(:fetch)
        checkpoint.call("capture-child-receipt", :child, KeyError.new("private-marker")) do |keywords, fault|
          capture_observed.stub(:fetch, ->(key) { key == :child ? fault.call(key) : original_fetch.call(key) }) do
            File.stub(:file?, true) do
              UploadProcessFixture.stub(:read_json, capture_record) do
                stub(:dispatch_file_identity, identity_reader) do
                  assert_retained_capture(capture_observed, finality: :unknown, **keywords)
                end
              end
            end
          end
        end
        assert_equal [[RbConfig.ruby, 32 * 1024 * 1024], [capture_fixture.fetch("path"), 1_048_576]], identity_reads

        [true, false].each do |with_state|
          checkpoint.call("capture-bootstrap-header", "version", NoMethodError.new("private-marker"),
                          with_state: with_state) do |keywords, fault|
            provenance = Object.new
            provenance.define_singleton_method(:fetch, fault)
            assert_raw_bootstrap_provenance(provenance, nil, nil, stream_identities: nil, finality: :unknown, **keywords)
          end
        end
      end

      # Primary-proof diagnostics keep the actual rejection through the real
      # Lifetime implementation. Only the cancellation-policy object and run's
      # native body are inert: no signal policy, child, task or receipt is made.
      primary_mode = "native-proof-readiness-interrupt-none"
      primary_callback = NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.keys.first
      primary_method = primary_callback.split("#", 2).last
      status_class = Struct.new(:exitstatus) # Comparison input, not Process::Status authority.
      primary_status = status_class.new(1)
      primary_proof = {"case" => primary_mode, "failures" => ["first-close boundary"],
        "driverExitStatus" => 1, "nativeErrorMessage" => "private-marker"}
      primary_result = {"kind" => "unexpected", "private" => "private-marker"}
      expected_primary = {"schema" => 1, "mode" => primary_mode,
        "failedPredicates" => %w[proof-failures driver-status], "proofFailures" => ["first-close boundary"]}
      expected_primary_line = "#{NATIVE_PRIMARY_FAILURE_PREFIX}#{JSON.generate(expected_primary)}\n"
      assert_equal [24, 2, 1, 2], NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.values.map(&:length)
      mapped_modes = NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.values.flatten
      assert_equal 29, mapped_modes.uniq.length
      assert_equal UploadProcessFixture::NATIVE_PRIMARY_PROOFS.keys.sort, mapped_modes.sort
      assert_equal 24, NATIVE_PRIMARY_PROOF_FAILURES.uniq.length
      assert_equal expected_primary_line, fixture_class.native_primary_failure_line(mode: primary_mode,
        proof: primary_proof, result: primary_result, status: primary_status)
      empty_proof = primary_proof.merge("case" => "private-marker", "failures" => [], "driverExitStatus" => 0)
      empty_line = fixture_class.native_primary_failure_line(mode: primary_mode, proof: empty_proof,
        result: {"kind" => "pass"}, status: status_class.new(0))
      assert_equal({"schema" => 1, "mode" => primary_mode, "failedPredicates" => %w[case proof-status result-kind],
        "proofFailures" => []}, JSON.parse(empty_line.delete_prefix(NATIVE_PRIMARY_FAILURE_PREFIX)))
      refute_includes empty_line, "private-marker"
      assert_nil fixture_class.native_primary_failure_line(mode: primary_mode,
        proof: primary_proof.merge("failures" => []), result: primary_result, status: status_class.new(0))
      invalid_failures = [nil, "private-marker", ["private-marker"], [:first_close],
        ["first-close boundary", "first-close boundary"], ["first-close boundary", "actual capture finality"],
        ["unchanged IOError redaction"], NATIVE_PRIMARY_PROOF_FAILURES]
      invalid_failures.each do |failures|
        assert_nil fixture_class.native_primary_failure_line(mode: primary_mode,
          proof: primary_proof.merge("failures" => failures), result: primary_result, status: primary_status)
      end
      [primary_mode, "native-proof-entered-io"].each do |mode|
        inapplicable = UploadProcessFixture::NATIVE_PRIMARY_PROOFS.fetch(mode)[1] == "io" ?
          "actual non-IOError return" : "unchanged IOError redaction"
        allowed = NATIVE_PRIMARY_PROOF_FAILURES.reject { |label| label == inapplicable }
        maximum = fixture_class.native_primary_failure_line(mode: mode,
          proof: primary_proof.merge("case" => mode, "failures" => allowed), result: primary_result, status: primary_status)
        assert_equal 23, allowed.length
        assert_equal allowed, JSON.parse(maximum.delete_prefix(NATIVE_PRIMARY_FAILURE_PREFIX)).fetch("proofFailures")
        assert maximum.ascii_only?
        assert maximum.end_with?("\n")
        assert_operator maximum.bytesize, :<=, 2048
        assert_nil fixture_class.native_primary_failure_line(mode: mode,
          proof: primary_proof.merge("case" => mode, "failures" => [inapplicable]), result: primary_result, status: primary_status)
      end

      primary_exercise = lambda do |mutate: nil, write_result: :full, expiry: nil, interrupted: nil, method_name: primary_method|
        now, sequence, depth = 1, nil, 0
        state = run_error = dispatch = nil
        events, writes, observations = [], [], []
        policy = Object.new
        policy.define_singleton_method(:install) { events << :install }
        policy.define_singleton_method(:cleanup_depth) { depth }
        policy.define_singleton_method(:cleanup) do |&body|
          depth += 1
          begin
            body.call
          ensure
            depth -= 1
          end
        end
        policy.define_singleton_method(:restore) { |&body| body.call; events << :restored }
        policy.define_singleton_method(:errors) { [] }
        policy.define_singleton_method(:replay_custom_pending) { events << :replay }
        run = lambda do |**arguments|
          dispatch = arguments
          state = arguments.fetch(:primary_failure_state)
          events << :run_enter
          begin
            UploadProcessFixture.lifetime(deadline_ns: 10) do |frame|
              begin
                frame.active do
                  reject = lambda do
                    UploadProcessFixture.reject_native_primary_proof!(mode: arguments.fetch(:mode), proof: primary_proof,
                      result: primary_result, status: primary_status, deadline_ns: 10, state: state)
                  end
                  if interrupted
                    original_writer = state.method(:[]=)
                    state.stub(:[]=, ->(key, value) { raise interrupted if key == :mode; original_writer.call(key, value) }) { reject.call }
                  else
                    reject.call
                  end
                end
              ensure
                frame.cleanup { events << :cleanup }
              end
            end
          rescue Exception => error
            run_error = error
            raise
          ensure
            mutate.call(state) if mutate
            events << :run_unwound
            now = 10 if expiry == :before_report
            sequence = [1, 10] if expiry == :before_write
          end
        end
        sink = lambda do |packet|
          observations << [state[:rejection], state[:report_attempted], state[:write_attempted], events.dup,
            UploadProcessFixture.instance_variable_get(:@cancellation_scope)]
          events << :write
          writes << packet
          raise write_result if write_result.is_a?(Exception)
          write_result == :short ? 1 : packet.bytesize
        end
        assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
        actual = nil
        UploadProcessFixture::CancellationScope.stub(:new, policy) do
          Thread.current.stub(:pending_interrupt?, false) do
            UploadProcessFixture.stub(:clock_ns, -> { sequence ? sequence.shift || now : now }) do
              UploadProcessFixture.stub(:run, run) do
                stub(:name, method_name) do
                  STDERR.stub(:write, sink) do
                    actual = assert_raises(interrupted ? interrupted.class : UploadProcessFixture::Failure) { process_case(primary_mode) }
                    now, sequence = 1, nil
                    fixture_class.report_native_primary_failure(state, actual,
                      callback: "#{self.class.name}##{method_name}", mode: primary_mode)
                  end
                end
              end
            end
          end
        end
        assert_same run_error, actual
        assert_equal({platform: "native", root: @root, parameters: {}, mode: primary_mode},
          dispatch.reject { |key, _| key == :primary_failure_state })
        assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
        expected_events = %i[run_enter install cleanup restored replay run_unwound]
        assert_equal expected_events, events.take(expected_events.length)
        assert_operator writes.length, :<=, 1
        observations.each do |latched, report_attempted, write_attempted, seen, registry|
          assert_same actual, latched
          assert_equal true, report_attempted
          assert_equal true, write_attempted
          assert_equal expected_events, seen
          assert_nil registry
        end
        writes.each do |packet|
          assert_equal expected_primary_line, packet
          assert packet.ascii_only?
          assert_operator packet.bytesize, :<=, 2048
          refute_includes packet, "private-marker"
        end
        {state: state, original: actual, writes: writes}
      end
      [:full, :short, IOError.new("private-marker"), Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |write_result|
        observed = primary_exercise.call(write_result: write_result)
        assert_equal [expected_primary_line], observed.fetch(:writes)
        state = observed.fetch(:state)
        assert_same observed.fetch(:original), state.fetch(:rejection)
        assert_same primary_proof, state.fetch(:proof)
        assert_same primary_result, state.fetch(:result)
        assert_same primary_status, state.fetch(:status)
        assert_equal 10, state.fetch(:deadline_ns)
        if write_result.is_a?(Exception)
          assert_same write_result, state.fetch(:diagnostic_error)
        else
          assert_equal write_result == :full, state.fetch(:write_complete)
        end
      end
      mutations = [->(state) { state.delete(:status) }, ->(state) { state.delete(:rejection) },
        ->(state) { state[:rejection] = UploadProcessFixture::Failure.new("fixture-result", "private-marker") },
        ->(state) { state[:mode] = "native-proof-frame-io" }, ->(state) { state[:proof] = nil },
        ->(state) { state[:result] = {} }, ->(state) { state[:deadline_ns] = 10.0 },
        ->(state) { state[:proof] = primary_proof.merge("failures" => ["first-close boundary"] * 2) },
        ->(state) { state.freeze }]
      mutations.each { |mutate| assert_empty primary_exercise.call(mutate: mutate).fetch(:writes) }
      %i[before_report before_write].each { |expiry| assert_empty primary_exercise.call(expiry: expiry).fetch(:writes) }
      wrong_method = "test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike"
      assert_empty primary_exercise.call(method_name: wrong_method).fetch(:writes)
      [Interrupt.new("before actual rejection"), SystemExit.new(21, "before actual rejection")].each do |interrupted|
        observed = primary_exercise.call(interrupted: interrupted)
        assert_same interrupted, observed.fetch(:original)
        refute_same interrupted, observed.fetch(:state).fetch(:rejection)
        refute observed.fetch(:state).key?(:proof)
        assert_empty observed.fetch(:writes)
      end

      # The real process_case wrapper must not diagnose a successful run or a
      # later common assertion. These values are inert inputs, not native proof.
      successful = {"driverJoined" => true, "knownProcessesDead" => true, "pendingInterrupt" => false, "cleanupErrors" => []}
      %w[watchdogJoined tasksJoined injectorsJoined ownedDescriptorsClosed handlersRestored registryInactive].each { |key| successful[key] = true }
      writes, handoffs = [], []
      UploadProcessFixture.stub(:run, ->(**arguments) { handoffs << arguments.fetch(:primary_failure_state); successful }) do
        STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
          assert_same successful, process_case(primary_mode)
          successful["driverJoined"] = false
          assert_raises(Minitest::Assertion) { process_case(primary_mode) }
        end
      end
      assert_empty writes
      assert handoffs.all?(&:empty?)
      refute_same(*handoffs)

      assert_native_order_failure_projection
      assert_native_setup_failure_projection
      assert_adapter_fixed_timing_profile
      assert_ownership_family_admission
      assert_adapter_parent_cutoff_composition
      assert_original_capture_settlement_projection
      assert_record_publication_lifecycle
      assert_adapter_failure_projection
      assert_ownership_failure_projection
      assert_native_signal_failure_projection
      assert_missing_cleanup_omission_evidence
      assert_missing_cleanup_watchdog_lifecycle

      # A modeled delivery seam protects the intended callback ordering only;
      # the existing24-mode native test still proves real asynchronous delivery.
      %w[readiness watchdog].each do |boundary|
        driver = UploadProcessFixture::NativePrimaryProbe::Driver.new(@root, [boundary, "interrupt", "none"])
        driver.instance_variable_set(:@observation, Struct.new(:session).new(Struct.new(:capture_slot).new(Object.new)))
        events, masks = [], []
        delivery = lambda do |mask, &body|
          masks << mask
          events << :delivery
          raise driver.original
        end
        actual = driver.stub(:inject, ->(error) { events << [:injected, error] }) do
          Thread.stub(:handle_interrupt, delivery) do
            assert_raises(Interrupt) { driver.fault(boundary); events << :continued }
          end
        end
        assert_same driver.original, actual
        assert_equal [[:injected, actual], :delivery], events
        assert_equal [{Interrupt => :immediate}], masks
        assert_equal 1, driver.fault_count
        assert driver.frame_published
      end
      # Only the actual readiness algorithm runs here. Restoring file/clock/sleep
      # seams supply no child, wait receipt, real IO or native readiness proof.
      readiness_stat_class = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink, :size) do
        def file?
          ftype == "file"
        end
      end
      ready_line = "collector ready\n"
      driver_expiry = ["driver", "raw proof driver deadline expired"]
      readiness_expiry = ["readiness", "literal collector readiness deadline expired"]
      readiness = lambda do |samples, expected:, change: nil, read_error: nil, late_read: false|
        now_ns, run_ns = 0, 40_000_000
        baseline = readiness_stat_class.new(1, 2, 0o100600, 3, 4, 0, "file", 1, 0)
        identity = UploadProcessFixture::OwnedChild.identity(baseline)
        observed = {stream_identities: [identity]}
        writer = Struct.new(:stat).new(baseline)
        opens, limits, naps = [], [], []
        opener = lambda do |path, flags, &body|
          bytes, size = samples.fetch([opens.length, samples.length - 1].min)
          opens << [path, flags, observed.key?(:literal_readiness)]
          before, after, writer.stat = Array.new(3) { baseline.dup }
          before.size = after.size = size
          before.ftype = "directory" if change == :nonregular
          before.ino += 1 if change == :before_identity
          writer.stat.ino += 1 if change == :writer_identity
          after.ino += 1 if change == :after_identity
          stats = [before, after]
          reader = Object.new
          reader.define_singleton_method(:stat) { stats.shift || after }
          reader.define_singleton_method(:read) do |limit|
            limits << limit
            now_ns = run_ns if late_read
            raise read_error if read_error
            bytes
          end
          body.call(reader)
        end
        sleeper = lambda do |seconds|
          naps << [seconds, now_ns, observed.key?(:literal_readiness)]
          raise "inert readiness exceeded fixed sleep bound" if naps.length > 5
          now_ns += (seconds * 1_000_000_000).round
        end
        actual = File.stub(:open, opener) do
          UploadProcessFixture.stub(:clock_ns, -> { now_ns }) do
            stub(:sleep, sleeper) do
              assert_raises(read_error ? read_error.class : UploadProcessFixture::Failure) do
                await_literal_timeout("/inert-readiness", writer, observed, run_ns)
              end
            end
          end
        end
        if read_error
          assert_same read_error, actual
        else
          assert_equal expected, [actual.kind, actual.message]
          assert_equal run_ns, now_ns if %w[driver readiness].include?(actual.kind)
        end
        refute_empty opens
        opens.each do |path, flags, already_ready|
          assert_equal "/inert-readiness/driver.stdout", path
          assert_equal File::RDONLY | File::NOFOLLOW | File::NONBLOCK, flags
          refute already_ready
        end
        assert_equal [UploadProcessFixture::OUTPUT_LIMIT + 1] * limits.length, limits
        naps.each do |seconds, entered_ns, _ready|
          assert_operator seconds, :>=, 0
          assert_operator seconds, :<=, [10_000_000, run_ns - entered_ns].min.fdiv(1_000_000_000)
        end
        if expected == driver_expiry
          assert_equal({"observed" => true, "identity" => identity}, observed.fetch(:literal_readiness))
          assert_equal samples.length, opens.length
          assert_equal [false] * (samples.length - 1) + [true], naps.map(&:last)
        else
          refute observed.key?(:literal_readiness)
        end
        assert_empty naps if late_read
      end
      readiness.call([[nil, 0], ["".b, 0], ["collector ", 10], [ready_line, ready_line.bytesize]], expected: driver_expiry)
      readiness.call([[nil, 0]], expected: readiness_expiry)
      readiness.call([[ready_line, ready_line.bytesize - 1]], expected: readiness_expiry)
      readiness.call([[ready_line, ready_line.bytesize]], expected: readiness_expiry, late_read: true)
      identity_message = "literal collector transcript identity changed"
      bound_message = "literal collector transcript changed or exceeded its bound"
      [[:nonregular, nil, 0, identity_message], [:before_identity, nil, 0, identity_message],
       [:writer_identity, nil, 0, identity_message], [:after_identity, nil, 0, bound_message],
       [nil, "x" * (UploadProcessFixture::OUTPUT_LIMIT + 1), 0, bound_message],
       [nil, nil, UploadProcessFixture::OUTPUT_LIMIT + 1, bound_message],
       [nil, "unexpected", 10, "literal collector readiness bytes were unexpected"],
       [nil, false, 0, bound_message]].each do |change, bytes, size, message|
        readiness.call([[bytes, size]], expected: ["diagnostic", message], change: change)
      end
      readiness.call([[nil, 0]], expected: nil, read_error: IOError.new("original readiness read failure"))
    end
  end

  def test_deadline_and_slow_cleanup_choreography_preserve_original_bounds
    with_acquisition_veto do
      assert_late_final_deadline_choreography
      assert_slow_cleanup_choreography
    end
  end

  def test_observer_terminal_grammar_rejects_contradictory_no_producer_context
    # Inert grammar inputs are never wait receipts, process observations, or
    # permission to signal. All process/task acquisition remains vetoed.
    observer = UploadProcessFixture::CaptureObservation.new(native: MobileReleaseKit::NativeUploadValidation, root: @root)
    observer.instance_variable_set(:@spawn, MobileReleaseKit::NativeProcessSpawn) # Pure declared ABI lookup, no native call.
    context = Struct.new(:reserved, :ready, :custodian_child).new(nil, nil, Struct.new(:pid).new(101))
    observer.instance_variable_set(:@session, context)
    no_keeper = inert_terminal_frame
    reserved = {"v" => 1, "type" => "RESERVED", "keeper_pid" => 102, "group_id" => 102, "session_id" => 101}
    ready = {"v" => 1, "type" => "READY", "validator_pid" => 103, "group_id" => 102, "keeper_pgid" => 101}
    no_validator = no_keeper.merge("keeper" => {"state" => "reaped", "pid" => 102, "status_kind" => "exit", "status_code" => 0},
                                  "group" => {"state" => "retired", "id" => 102, "absent" => true})
    with_acquisition_veto do
      assert observer.terminal_cleanup_confirmed?(no_keeper)
      context.reserved = reserved
      refute observer.terminal_cleanup_confirmed?(no_keeper), "no-K cannot contradict RESERVED"
      context.ready = ready
      refute observer.terminal_cleanup_confirmed?(no_keeper), "no-K cannot contradict READY"
      context.reserved = nil
      refute observer.terminal_cleanup_confirmed?(no_keeper), "READY alone cannot authorize no-K"
      context.reserved, context.ready = reserved, nil
      assert observer.terminal_cleanup_confirmed?(no_validator)
      assert observer.terminal_cleanup_confirmed?(no_validator.merge(
        "keeper" => no_validator.fetch("keeper").merge("status_code" => 2),
      )), "settled K failure is physical finality, not validation success"
      [1, 7].each do |code|
        refute observer.terminal_cleanup_confirmed?(no_validator.merge(
          "keeper" => no_validator.fetch("keeper").merge("status_code" => code),
        )), "default or unassigned K exit cannot confirm cleanup"
      end
      refute observer.terminal_cleanup_confirmed?(no_validator.merge(
        "keeper" => no_validator.fetch("keeper").merge("status_kind" => "signal", "status_code" => Signal.list.fetch("KILL")),
      )), "a K signal receipt cannot confirm its local cleanup"
      context.ready = ready
      refute observer.terminal_cleanup_confirmed?(no_validator), "no-V cannot contradict READY"

      success = no_validator.merge("outcome" => "ok",
                                   "validator" => {"state" => "reaped", "pid" => 103, "status_kind" => "exit", "status_code" => 0})
      assert observer.terminal_cleanup_confirmed?(success)
      invalid = [success.merge("v" => 1.0), success.merge("extra" => true),
                 success.merge("outcome" => "rejected"),
                 success.merge("keeper" => success.fetch("keeper").merge("status_code" => 2)),
                 success.merge("cleanup" => "unknown"),
                 success.merge("group" => success.fetch("group").merge("absent" => false)),
                 success.merge("keeper" => success.fetch("keeper").merge("pid" => 104))]
      invalid << success.merge("outcome" => "failed", "validator" => success.fetch("validator").merge(
        "status_kind" => "signal", "status_code" => MobileReleaseKit::NativeProcessSpawn.nsig,
      ))
      invalid << success.merge("outcome" => "rejected", "validator" => success.fetch("validator").merge(
        "status_kind" => "signal", "status_code" => Signal.list.fetch("KILL"),
      ))
      invalid.each { |frame| refute observer.terminal_cleanup_confirmed?(frame), frame.inspect }
    end
  end

  def test_protocol_rejects_every_unused_late_frame_after_final
    protocol = MobileReleaseKit::NativeUploadProcess::Protocol
    nsig = MobileReleaseKit::NativeProcessSpawn.nsig
    terminal = inert_terminal_frame
    with_acquisition_veto do
      inert_late_frames.each do |late|
        decoder = protocol::Decoder.new(direction: :c_to_o, nsig: nsig)
        bytes = protocol.encode(terminal, direction: :c_to_o, nsig: nsig)
        assert_equal [terminal], decoder.feed(bytes)
        assert_raises(MobileReleaseKit::NativeUploadProcess::ProtocolError) do
          decoder.feed(protocol.encode(late, direction: :c_to_o, nsig: nsig))
        end
        # A failed post-terminal feed is absorbing, not an ignored duplicate.
        assert_raises(MobileReleaseKit::NativeUploadProcess::ProtocolError) { decoder.feed("") }
        assert_raises(MobileReleaseKit::NativeUploadProcess::ProtocolError) { decoder.eof }
      end
    end
  end

  def test_observer_hooks_preserve_original_failures_and_foreign_replacements
    # Only an unreachable toy class is modified. No production method, live
    # task, descriptor, or native acquisition is supplied by these controls.
    # Each model gets an inert diagnostic key, never the real filesystem root.
    # The actual observe arbitration and its UNKNOWN entries remain untouched.
    real_root = @root
    real_root_entries = Dir.children(real_root).sort
    real_root_unresolved = UploadProcessFixture.cleanup_unresolved?(real_root)
    refute real_root_unresolved
    domain_latches = %i[@process_domain_failed @domain_disposal_required].to_h do |name|
      [name, UploadProcessFixture.instance_variable_get(name)]
    end
    prior_unknowns = (UploadProcessFixture.instance_variable_get(:@unresolved_roots) || {}).dup
    @inert_hook_observations = []
    UploadProcessFixture.retain_process_case!(self) # Keep models through Minitest result copying/GC, without latching failure.
    %w[install-before-effect return-publication restore-before-effect foreign-replacement].each do |fault|
      UploadProcessFixture.assert_domain_reusable!
      model_root = Object.new
      target = Class.new do
        def observed = :original
      end
      original = target.instance_method(:observed)
      primary = IOError.new("first toy observation failure: #{fault}")
      secondary = RuntimeError.new("toy restore failed")
      real_define = Module.instance_method(:define_method).bind(target)
      real_lookup = Module.instance_method(:instance_method).bind(target)
      define_calls = lookup_calls = 0
      target.define_singleton_method(:define_method) do |*arguments, &body|
        define_calls += 1
        raise primary if fault == "install-before-effect" && define_calls == 1
        raise secondary if fault == "restore-before-effect" && define_calls == 2
        real_define.call(*arguments, &body)
      end
      target.define_singleton_method(:instance_method) do |name|
        lookup_calls += 1
        raise primary if fault == "return-publication" && lookup_calls == 2
        real_lookup.call(name)
      end
      observer_class = Class.new(UploadProcessFixture::CaptureObservation) do
        define_method(:install) do
          UploadProcessFixture::CaptureObservation.current = self
          @hooks = UploadProcessFixture::CaptureObservation::Hooks.new
          @hooks.wrap(target, :observed) do |saved, _object, arguments, keywords, block|
            [:wrapped, saved.call(*arguments, **keywords, &block)]
          end
        end
      end
      observer = observer_class.new(native: MobileReleaseKit::NativeUploadValidation, root: model_root)
      retained = {fault: fault, root: model_root, observer: observer, target: target,
                  original: original, primary: primary, secondary: secondary}
      @inert_hook_observations << retained
      begin
        with_acquisition_veto do
          error = assert_raises(IOError) do
            observer.observe do
              target.send(:define_method, :observed) { :foreign } if fault == "foreign-replacement"
              raise primary
            end
          end
          assert_same primary, error
          assert_equal "first toy observation failure: #{fault}", error.message
          snapshot = observer.snapshot
          assert_nil observer.session
          assert_nil observer.source_origins
          assert_nil observer.custodian_spec
          assert_empty observer.events
          %i[@slots @attempts @constructed_slots @closed_launches @finished_creations
             @actual_joins @actual_closes @actual_eofs @actual_waits].each do |name|
            assert_empty observer.instance_variable_get(name), name
          end
          refute observer.instance_variable_get(:@creator_gate_entered)
          assert_nil snapshot.fetch("sourceOrigins")
          assert_empty snapshot.fetch("tasks")
          assert_empty snapshot.fetch("leases")
          assert_empty snapshot.fetch("streams")
          if fault == "install-before-effect"
            assert snapshot.fetch("hooksRestored")
            assert_empty snapshot.fetch("observerErrors")
            assert snapshot.fetch("noProducers")
            refute snapshot.fetch("unknown")
            assert_equal :original, target.new.observed
            assert_equal original, real_lookup.call(:observed)
          else
            refute snapshot.fetch("hooksRestored"), fault
            assert snapshot.fetch("unknown"), fault
            refute snapshot.fetch("noProducers"), fault
            refute snapshot.fetch("finalized"), fault
            expected = fault == "restore-before-effect" ? "RuntimeError" : "changed_observation_hook"
            assert_includes snapshot.fetch("observerErrors"), expected
            assert_equal fault == "foreign-replacement" ? :foreign : [:wrapped, :original], target.new.observed
          end
          assert_nil UploadProcessFixture::CaptureObservation.current
          assert_equal fault != "install-before-effect", UploadProcessFixture.cleanup_unresolved?(model_root)
          assert_same real_root, @root
          assert_equal real_root_entries, Dir.children(real_root).sort
          assert_equal real_root_unresolved, UploadProcessFixture.cleanup_unresolved?(real_root)
          domain_latches.each do |name, value|
            assert_same value, UploadProcessFixture.instance_variable_get(name), name
          end
          UploadProcessFixture.assert_domain_reusable!
        end
      ensure
        retained[:hooks] = observer.instance_variable_get(:@hooks)
        retained[:snapshot] = observer.instance_variable_get(:@snapshot) # Original snapshot, not reconstructed evidence.
        # This only discards an inert toy hook. It does not revise the failed
        # observer snapshot or clear any retained model/real UNKNOWN registry.
        real_define.call(:observed, original)
      end
    end
    unknowns = UploadProcessFixture.instance_variable_get(:@unresolved_roots)
    prior_unknowns.each { |key, value| assert_same value, unknowns.fetch(key) }
    assert_equal 4, @inert_hook_observations.map { |entry| entry.fetch(:root) }.uniq.length
    @inert_hook_observations.each do |entry|
      assert_same entry.fetch(:snapshot), entry.fetch(:observer).instance_variable_get(:@snapshot)
      assert_same entry.fetch(:hooks), entry.fetch(:observer).instance_variable_get(:@hooks)
      expected_unknown = entry.fetch(:fault) != "install-before-effect"
      assert_equal expected_unknown, entry.fetch(:snapshot).fetch("unknown")
      assert_equal expected_unknown, unknowns.key?(entry.fetch(:root))
      assert_same true, unknowns.fetch(entry.fetch(:root)) if expected_unknown
    end
  end

  def test_real_observer_finality_requires_exact_wait_join_close_and_eof_witnesses
    # This method CONTAINS a real native capture and is never a fake-only local
    # selector. The following negative variants become inert only after its
    # actual C/K/V/IO/tasks are genuinely finalized.
    @retain_raw_evidence = true
    native = MobileReleaseKit::NativeUploadValidation
    UploadProcessFixture.assert_domain_reusable!
    observer = UploadProcessFixture::CaptureObservation.new(native: native, root: @root)
    output = observer.observe do
      native.capture(
        {"LANG" => "C", "LC_ALL" => "C"},
        [File.realpath(RbConfig.ruby), "--disable=rubyopt,gems", "-e", "STDOUT.write('observed capture')"],
        File.expand_path("../..", __dir__), max_seconds: UploadProcessFixture::READINESS_LIMIT,
        max_output_bytes: 1_024, label: "Synthetic observation", failure_message: "synthetic observation rejected",
      )
    end
    assert_equal "observed capture", output
    baseline = observer.snapshot
    assert_native_observation(baseline, finality: :finalized)
    UploadProcessFixture.atomic_json(File.join(@root, "observation-baseline.json"), baseline)
    session = observer.session
    original_receipt, original_frame = session.custodian_receipt, session.final
    original_frame_bytes = JSON.generate(original_frame)
    assert_instance_of Process::Status, original_receipt.raw_status
    assert_equal original_receipt.pid, original_receipt.raw_status.pid

    witnesses = [["custodian-wait", :@actual_waits, ->(pair) { pair.first.equal?(session.custodian_child) }]]
    [session.capture_slot, session.creator_slot].each_with_index do |slot, index|
      witnesses << ["task-#{index}-join", :@actual_joins, ->(thread) { thread.equal?(slot.thread) }]
    end
    session.leases.each do |role, lease|
      next unless lease.state == :closed
      witnesses << ["#{role}-close", :@actual_closes, ->(actual) { actual.equal?(lease) }]
    end
    %i[stdout_read stderr_read status_read].each do |role|
      io = session.leases.fetch(role).io
      witnesses << ["#{role}-eof", :@actual_eofs, ->(actual) { actual.equal?(io) }]
    end
    with_acquisition_veto do
      # Keep the claimed booleans true: only the independent, actual witness
      # changes. Otherwise a failure could be a vacuous false-flag assertion.
      session.stub(:settled?, true) do
        session.stub(:finality_confirmed?, true) do
          witnesses.each do |label, field, missing|
            original = observer.instance_variable_get(field)
            assert original.any?(&missing), label
            begin
              observer.instance_variable_set(field, original.reject(&missing))
              assert_inert_observer_rejection(observer, label)
            ensure
              observer.instance_variable_set(field, original)
            end
          end
          {custodian_receipt: nil, custodian_child: nil, stdout_eof: false,
           stderr_eof: false, status_eof: false, final: nil, retained_unknown?: true}.each do |method, value|
            session.stub(method, value) { assert_inert_observer_rejection(observer, "fact-#{method.to_s.delete('?')}") }
          end
          [session.capture_slot, session.creator_slot].each_with_index do |slot, index|
            %i[joined? finished? launch_retired?].each do |method|
              slot.stub(method, false) { assert_inert_observer_rejection(observer, "task-#{index}-#{method.to_s.delete('?')}") }
            end
          end
        end
      end
    end
    # Decoder already rejects post-FINAL transport. This separately exercises
    # the owner's absorbing boundary against directly supplied late frames.
    context = [session.hello, session.reserved, session.ready, session.validator_status, session.phase]
    with_acquisition_veto do
      inert_late_frames.each do |late|
        assert_raises(MobileReleaseKit::NativeUploadProcess::ProtocolError) { session.__send__(:receive_frame, late) }
        assert_equal context, [session.hello, session.reserved, session.ready, session.validator_status, session.phase]
        assert_same original_frame, session.final
      end
    end
    assert_same original_receipt, session.custodian_receipt
    assert_same original_frame, session.final
    assert_equal original_frame_bytes, JSON.generate(session.final)
    assert_equal baseline, observer.snapshot
    assert_native_observation(observer.build_snapshot, finality: :finalized)
    assert_nil UploadProcessFixture::CaptureObservation.current
    refute session.retained_unknown?
    @retain_raw_evidence = false
  end

  private

  def assert_native_order_failure_projection
    # Pure projections and original Lifetime unwinds with inert operations. No
    # marker in these controls is a native proof or a process/wait receipt.
    fixture_class = self.class
    predicates = %w[proof-version proof-kind case source-binding proof-failures proof-status
                    expected-unknown original-accepted result-kind driver-status]
    labels = [
      "original failed fixture result", "same first object through original boundaries",
      "unchanged original first message/status", "unchanged original caller message/status",
      "no original upload acceptance", "original shared creator/capture latch", "actual first and later latch returns",
      "actual latch released later fault", "actual caller delivery and rescue", "actual original stdin close",
      "actual capture/creator joins", "actual original native closes", "actual original native EOFs", "actual original C wait",
      "no fixture fallback or pending cancellation", "ownedDescriptorsClosed", "watchdogJoined", "injectorsJoined",
      "handlersRestored", "registryInactive", "no fixture cleanup errors", "observation restored", "unchanged original sources",
      "actual clean body then original cleanup fault", "unknown original task/session retained", "real pre-tail native success not finality",
      "actual body error recorded", "actual settled native cancellation",
    ]
    callbacks = {
      "test_native_task_error_precedes_later_caller_cancellation_at_the_original_latch" =>
        %w[native-order-task-before-caller-interrupt native-order-task-before-caller-system-exit],
      "test_native_caller_cancellation_precedes_later_task_ioerror_at_the_original_latch" =>
        %w[native-order-caller-before-task-interrupt native-order-caller-before-task-system-exit],
      "test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown" => %w[native-order-cleanup-before-caller-interrupt],
      "test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown" => %w[native-order-cleanup-before-caller-system-exit],
    }
    assert_equal predicates, NATIVE_ORDER_FAILURE_PREDICATES
    assert_equal labels, NATIVE_ORDER_PROOF_FAILURES
    assert_equal callbacks.transform_keys { |method| "NativeUploadValidationTest##{method}" }, NATIVE_ORDER_FAILURE_CALLBACK_MODES
    assert_equal ORDER_CASES.keys, callbacks.values.flatten
    sources = {"original-source" => "private-marker"}
    status_class = Struct.new(:exitstatus)
    formatter = fixture_class.method(:native_order_failure_line)
    inputs = lambda do |mode|
      unknown = ORDER_CASES.fetch(mode).first == "cleanup-before-caller"
      {mode: mode, expected_sources: sources, status: status_class.new(0),
       proof: {"version" => 1, "kind" => "native-order-observation", "case" => mode, "sourceSha256" => sources,
               "failures" => [], "baseDriverReturn" => 1, "expectedUnknown" => unknown, "originalAccepted" => false},
       result: {"kind" => unknown ? "fixture-cleanup" : "unexpected"}}
    end
    ORDER_CASES.each do |mode, (family, _kind)|
      value = inputs.call(mode)
      assert_nil formatter.call(**value)
      applicable = labels.first(23) + (family == "cleanup-before-caller" ? labels[23, 3] : labels.last(2))
      value[:proof].merge!("version" => 0, "kind" => "private-marker", "case" => "private-marker", "sourceSha256" => {},
        "failures" => applicable, "baseDriverReturn" => 0, "expectedUnknown" => nil, "originalAccepted" => nil)
      value[:result]["kind"] = "private-marker"
      value[:status].exitstatus = nil
      packet = formatter.call(**value)
      assert_equal "#{NATIVE_ORDER_FAILURE_PREFIX}#{JSON.generate({"schema" => 1, "mode" => mode,
        "failedPredicates" => predicates, "proofFailures" => applicable})}\n", packet
      assert packet.ascii_only?
      assert packet.frozen?
      assert_operator packet.bytesize, :<=, 2048
      refute_includes packet, "private-marker"
      rejected = [labels - applicable, [applicable.last, applicable.first], [applicable.first] * 2,
                  ["private-marker"], [true], nil]
      rejected.each do |failures|
        assert_nil formatter.call(**value.merge(proof: value[:proof].merge("failures" => failures)))
      end
    end
    mode = ORDER_CASES.keys.first
    mutations = [->(v) { v[:proof]["version"] = 2 }, ->(v) { v[:proof]["kind"] = "private-marker" },
      ->(v) { v[:proof]["case"] = "private-marker" }, ->(v) { v[:proof]["sourceSha256"] = {} },
      ->(v) { v[:proof]["failures"] = ["actual body error recorded"] }, ->(v) { v[:proof]["baseDriverReturn"] = 0 },
      ->(v) { v[:proof]["expectedUnknown"] = nil }, ->(v) { v[:proof]["originalAccepted"] = nil },
      ->(v) { v[:result]["kind"] = "pass" }, ->(v) { v[:status].exitstatus = nil }]
    mutations.zip(predicates).each do |mutate, predicate|
      value = inputs.call(mode)
      mutate.call(value)
      record = JSON.parse(formatter.call(**value).delete_prefix(NATIVE_ORDER_FAILURE_PREFIX))
      assert_equal [predicate], record.fetch("failedPredicates")
      assert_equal value[:proof].fetch("failures"), record.fetch("proofFailures")
    end
    invalid_inputs = [->(v) { v[:proof].delete("version") }, ->(v) { v[:proof] = nil },
      ->(v) { v[:result] = {} }, ->(v) { v[:expected_sources] = nil }, ->(v) { v[:mode] = "private-marker" }]
    invalid_inputs.each do |mutate|
      value = inputs.call(mode)
      mutate.call(value)
      assert_nil formatter.call(**value)
    end

    exercise = lambda do |selected: mode, write_result: :full, expiry: nil, mutate: nil,
                            publication_error: nil, projection_error: nil, callback: nil|
      value = inputs.call(selected)
      value[:proof]["failures"] = ["same first object through original boundaries"]
      expected_packet = formatter.call(**value)
      method_name = callback || callbacks.find { |_method, modes| modes.include?(selected) }.first
      now, sequence, depth = 1, nil, 0
      state = escaped = dispatch = nil
      events, writes, observations = [], [], []
      policy = Object.new
      policy.define_singleton_method(:install) { events << :install }
      policy.define_singleton_method(:cleanup_depth) { depth }
      policy.define_singleton_method(:cleanup) do |&body|
        depth += 1
        begin
          body.call
        ensure
          depth -= 1
        end
      end
      policy.define_singleton_method(:restore) { |&body| body.call; events << :restored }
      policy.define_singleton_method(:errors) { [] }
      policy.define_singleton_method(:replay_custom_pending) { events << :replay }
      run = lambda do |**arguments|
        dispatch, state = arguments, arguments.fetch(:order_failure_state)
        events << :run
        begin
          UploadProcessFixture.lifetime(deadline_ns: 10) do |frame|
            begin
              frame.active do
                reject = -> { UploadProcessFixture.reject_native_order_proof!(**value, deadline_ns: 10, state: state) }
                if publication_error
                  original_writer = state.method(:[]=)
                  state.stub(:[]=, ->(key, item) { raise publication_error if key == :mode; original_writer.call(key, item) }) { reject.call }
                else
                  reject.call
                end
              end
            ensure
              frame.cleanup { events << :cleanup }
            end
          end
        rescue Exception => error
          escaped = error
          raise
        ensure
          mutate.call(state) if mutate
          events << :unwound
          now = 10 if expiry == :before_report
          sequence = [1, 10] if expiry == :before_write
        end
      end
      sink = lambda do |packet|
        observations << [state[:rejection], state[:report_attempted], state[:write_attempted], events.dup,
          UploadProcessFixture.instance_variable_get(:@cancellation_scope)]
        writes << packet
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : packet.bytesize
      end
      project = projection_error ? ->(**) { raise projection_error } : formatter
      actual = nil
      UploadProcessFixture::CancellationScope.stub(:new, policy) do
        Thread.current.stub(:pending_interrupt?, false) do
          UploadProcessFixture.stub(:clock_ns, -> { sequence ? sequence.shift || now : now }) do
            UploadProcessFixture.stub(:run, run) do
              stub(:proof_source_snapshot, sources) do
                stub(:name, method_name) do
                  fixture_class.stub(:native_order_failure_line, project) do
                    STDERR.stub(:write, sink) do
                      actual = assert_raises(publication_error ? publication_error.class : UploadProcessFixture::Failure) do
                        native_order_case(*ORDER_CASES.fetch(selected))
                      end
                      now, sequence = 1, nil
                      fixture_class.report_native_order_failure(state, actual,
                        callback: "#{self.class.name}##{method_name}", mode: selected)
                    end
                  end
                end
              end
            end
          end
        end
      end
      assert_same escaped, actual
      assert_equal %i[run install cleanup restored replay unwound], events
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      assert_equal({platform: "native", root: @root, parameters: {}, mode: selected},
        dispatch.reject { |key, _| %i[order_failure_state primary_failure_state].include?(key) })
      assert_equal ORDER_CASES.fetch(selected).first != "cleanup-before-caller", dispatch.key?(:primary_failure_state)
      assert_empty dispatch[:primary_failure_state] if dispatch.key?(:primary_failure_state)
      assert_operator writes.length, :<=, 1
      observations.each do |original, attempted, writing, prior, scope|
        assert_same actual, original
        assert_equal [true, true, events, nil], [attempted, writing, prior, scope]
      end
      writes.each { |packet| assert_equal expected_packet, packet }
      {state: state, original: actual, writes: writes, inputs: value}
    end
    states = [mode, "native-order-cleanup-before-caller-interrupt"].map do |selected|
      outcome = exercise.call(selected: selected)
      state, value = outcome.values_at(:state, :inputs)
      assert_equal 1, outcome.fetch(:writes).length
      %i[proof result status expected_sources].each { |key| assert_same value.fetch(key), state.fetch(key), key }
      assert_same outcome.fetch(:original), state.fetch(:rejection)
      assert_equal ["fixture-result", "native order proof rejected"], [outcome[:original].kind, outcome[:original].message]
      state
    end
    refute_same(*states)
    [:short, IOError.new("private-marker"), Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |write_result|
      outcome = exercise.call(write_result: write_result)
      assert_equal 1, outcome.fetch(:writes).length
      if write_result.is_a?(Exception)
        assert_same write_result, outcome.fetch(:state).fetch(:diagnostic_error)
      else
        assert_equal false, outcome.fetch(:state).fetch(:write_complete)
      end
    end
    %i[before_report before_write].each { |expiry| assert_empty exercise.call(expiry: expiry).fetch(:writes) }
    [->(s) { s.delete(:expected_sources) }, ->(s) { s.delete(:rejection) },
     ->(s) { s[:rejection] = UploadProcessFixture::Failure.new("fixture-result", "private-marker") },
     ->(s) { s[:mode] = ORDER_CASES.keys.last }, ->(s) { s[:proof] = nil }, ->(s) { s.freeze }].each do |mutate|
      assert_empty exercise.call(mutate: mutate).fetch(:writes)
    end
    assert_empty exercise.call(callback: callbacks.keys.last).fetch(:writes)
    interruption = Interrupt.new("private-marker")
    assert_empty exercise.call(projection_error: interruption).fetch(:writes)
    [interruption, SystemExit.new(21, "private-marker")].each do |publication_error|
      outcome = exercise.call(publication_error: publication_error)
      assert_same publication_error, outcome.fetch(:original)
      refute_same publication_error, outcome.fetch(:state).fetch(:rejection)
      assert_empty outcome.fetch(:writes)
    end
    successful = %w[driverJoined knownProcessesDead watchdogJoined tasksJoined injectorsJoined ownedDescriptorsClosed
                     handlersRestored registryInactive].to_h { |key| [key, true] }.merge("pendingInterrupt" => false, "cleanupErrors" => [])
    writes, handoffs = [], []
    UploadProcessFixture.stub(:run, ->(**arguments) { handoffs << arguments.fetch(:order_failure_state); successful }) do
      stub(:proof_source_snapshot, sources) do
        STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
          state = {}
          assert_same successful, process_case(mode, order_failure_state: state)
          assert_empty state
          successful["driverJoined"] = false
          [mode, ORDER_CASES.keys.last].each do |selected|
            assert_raises(Minitest::Assertion) { native_order_case(*ORDER_CASES.fetch(selected)) }
          end
        end
      end
    end
    assert_empty writes
    assert handoffs.all?(&:empty?)
    assert_equal 3, handoffs.map(&:object_id).uniq.length
  end

  def assert_native_setup_failure_projection
    # Only pure data and the original Lifetime/reporting control flow execute.
    # No double here is native custody, a wait receipt, or cleanup authority.
    fixture_class = self.class
    modes = %w[native-setup-interrupt native-setup-system-exit native-setup-io-error]
    callback = "NativeUploadValidationTest#test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child"
    result_keys = %w[ready firstCloseEntered originalCloseCompleted nativeOriginalErrorPreserved watchdogStarted
      watchdogIntervened fallbackUsed deadBeforeFallback ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined
      handlersRestored registryInactive pendingInterrupt cleanupErrorsEmpty]
    native_keys = %w[finalized noProducers settled unknown hooksRestored observerErrorsEmpty productionFinality retainedUnknown
      statusValid statusDecodedEOF cleanupErrorsEmpty originalWaitObserved tasksJoined leasesClosed allActualEOFObserved
      captureSettled captureFinished captureJoined captureActualJoinObserved creatorSettled creatorFinished creatorJoined
      creatorActualJoinObserved stdoutEOF stdoutActualEOFObserved stderrEOF stderrActualEOFObserved statusEOF statusActualEOFObserved groupAbsent]
    settlement_keys = %w[taskCleanupComplete creationSettled custodianWaitBroken acquisitionUnknown]
    outcome_keys = %w[custodian keeper validator finalOutcome finalCleanup groupState captureState creatorState]
    assert_equal modes, UploadProcessFixture::NATIVE_SETUP_FAILURE_MODES
    assert_equal callback, NATIVE_SETUP_FAILURE_CALLBACK
    assert_equal result_keys, NATIVE_SETUP_RESULT_CHECKS
    assert_equal native_keys, NATIVE_SETUP_NATIVE_CHECKS
    assert_equal settlement_keys, NATIVE_SETUP_SETTLEMENT_CHECKS
    status_class = Struct.new(:exitstatus) # Comparison data only.
    status = status_class.new(1)
    raw = result_keys.reject { |key| key == "cleanupErrorsEmpty" }.to_h { |key| [key, true] }
    raw.merge!("kind" => "fixture-cleanup", "errorClass" => "UploadProcessFixture::Failure", "nativeErrorClass" => "Interrupt",
      "cleanupErrors" => ["private-marker"], "error" => "private-marker", "private" => "private-marker",
      "nativeObservation" => native_keys.reject { |key| key == "observerErrorsEmpty" }.to_h { |key| [key, false] }.merge(
        "observerErrors" => [], "private" => "private-marker",
        "settlementChecks" => settlement_keys.zip([true, true, false, false]).to_h,
        "custodian" => {"state" => "reaped", "status_kind" => "exit", "status_code" => 2},
        "final" => {"outcome" => "failed", "cleanup" => "unknown", "group" => {"state" => "retired"},
          "keeper" => {"state" => "reaped", "status_kind" => "exit", "status_code" => 2},
          "validator" => {"state" => "reaped", "status_kind" => "signal", "status_code" => 9}},
        "tasks" => [{"role" => "capture", "state" => "attempted"}, {"role" => "creator", "state" => "not_started"}]))
    formatter = fixture_class.method(:native_setup_failure_line)
    expected = {"schema" => 2, "mode" => modes.first, "failedPredicates" => %w[result-kind driver-status],
      "resultKind" => "fixture-cleanup", "driverExitStatus" => 1, "errorCategory" => "fixture-error", "nativeErrorCategory" => "interrupt",
      "resultChecks" => result_keys.to_h { |key| [key, key != "cleanupErrorsEmpty"] },
      "nativeChecks" => native_keys.to_h { |key| [key, key == "observerErrorsEmpty"] },
      "settlementChecks" => settlement_keys.zip([true, true, false, false]).to_h,
      "nativeOutcomes" => outcome_keys.zip(%w[exit2 exit2 signal failed unknown retired attempted not-started]).to_h}
    modes.each do |mode|
      packet = formatter.call(mode: mode, result: raw, status: status)
      assert_equal "#{NATIVE_SETUP_FAILURE_PREFIX}#{JSON.generate(expected.merge("mode" => mode))}\n", packet
      assert packet.ascii_only?
      assert packet.frozen?
      assert_operator packet.bytesize, :<=, 2048
      refute_includes packet, "private-marker"
    end
    project = lambda do |value, code = 1|
      packet = formatter.call(mode: modes.first, result: value, status: status_class.new(code))
      JSON.parse(packet.delete_prefix(NATIVE_SETUP_FAILURE_PREFIX)) if packet
    end
    assert_nil project.call(raw.merge("kind" => "pass"), 0)
    assert_equal ["result-kind"], project.call(raw, 0).fetch("failedPredicates")
    assert_equal ["driver-status"], project.call(raw.merge("kind" => "pass"), 255).fetch("failedPredicates")
    [nil, true, -1, 256, 1.0].each { |code| assert_nil formatter.call(mode: modes.first, result: raw, status: status_class.new(code)) }
    ["native-setup-no-cleanup", "native-proof-entered-io", nil, :native_setup_interrupt].each do |mode|
      assert_nil formatter.call(mode: mode, result: raw, status: status)
    end
    assert_nil formatter.call(mode: modes.first, result: nil, status: status)
    kinds = %w[pass fixture-cleanup readiness setup-fixture-fault process-observation process-ownership fixture-result unexpected]
    assert_equal kinds, NATIVE_SETUP_FAILURE_KINDS
    (kinds.map { |value| [value, value] } + [["private-marker", "other"], [nil, "invalid"], [true, "invalid"]]).each do |value, label|
      assert_equal label, project.call(raw.merge("kind" => value)).fetch("resultKind")
    end
    categories = {"UploadProcessFixture::Failure" => "fixture-error", "MobileReleaseKit::ContractError" => "contract-error",
      "MobileReleaseKit::NativeUploadProcess::LifecycleError" => "native-lifecycle-error", "IOError" => "io-error",
      "Interrupt" => "interrupt", "SystemExit" => "system-exit"}
    assert_equal categories, NATIVE_SETUP_FAILURE_CATEGORIES
    (categories.to_a + [[nil, "none"], ["private-marker", "other"], [false, "invalid"]]).each do |value, label|
      row = project.call(raw.merge("errorClass" => value, "nativeErrorClass" => value))
      assert_equal [label, label], row.values_at("errorCategory", "nativeErrorCategory")
      refute_includes JSON.generate(row), "private-marker"
    end
    missing = project.call({})
    assert_equal ["missing"] * 3, missing.values_at("resultKind", "errorCategory", "nativeErrorCategory")
    assert_equal({"resultChecks" => result_keys.to_h { |key| [key, "missing"] },
      "nativeChecks" => native_keys.to_h { |key| [key, "missing"] },
      "settlementChecks" => settlement_keys.to_h { |key| [key, "missing"] },
      "nativeOutcomes" => outcome_keys.to_h { |key| [key, "missing"] }},
      missing.slice("resultChecks", "nativeChecks", "settlementChecks", "nativeOutcomes"))
    malformed = result_keys.to_h { |key| [key, "private-marker"] }.merge("cleanupErrors" => nil, "nativeObservation" => nil)
    invalid = project.call(malformed)
    assert_equal ["invalid"], invalid.fetch("resultChecks").values.uniq
    assert_equal ["invalid"], invalid.fetch("nativeChecks").values.uniq
    assert_equal ["invalid"], invalid.fetch("settlementChecks").values.uniq
    assert_equal ["invalid"], invalid.fetch("nativeOutcomes").values.uniq
    assert_equal ["missing"], project.call(raw.merge("nativeObservation" => {})).fetch("nativeChecks").values.uniq
    explicit_false = raw.merge(result_keys.to_h { |key| [key, false] }).merge("cleanupErrors" => [])
    assert_equal result_keys.to_h { |key| [key, key == "cleanupErrorsEmpty"] }, project.call(explicit_false).fetch("resultChecks")
    assert_equal native_keys.to_h { |key| [key, "invalid"] }, project.call(raw.merge(
      "nativeObservation" => native_keys.to_h { |key| [key, 0] }.merge("observerErrors" => 0))).fetch("nativeChecks")
    [nil, false, "private-marker"].each do |record|
      changed = raw.merge("nativeObservation" => raw.fetch("nativeObservation").merge("settlementChecks" => record))
      assert_equal settlement_keys.to_h { |key| [key, "invalid"] }, project.call(changed).fetch("settlementChecks")
    end
    [true, false, "missing", "invalid", nil, 0, "private-marker"].each do |item|
      changed = raw.merge("nativeObservation" => raw.fetch("nativeObservation").merge(
        "settlementChecks" => settlement_keys.to_h { |key| [key, item] }))
      expected_item = [true, false, "missing", "invalid"].include?(item) ? item : "invalid"
      assert_equal settlement_keys.to_h { |key| [key, expected_item] }, project.call(changed).fetch("settlementChecks")
    end
    [{}, {"settlementChecks" => {}}].each do |snapshot|
      assert_equal settlement_keys.to_h { |key| [key, "missing"] }, project.call(raw.merge(
        "nativeObservation" => snapshot)).fetch("settlementChecks")
    end
    # Shared native projection grammar has its own full malformed-input matrix.
    # This integration must keep that original finite projection unchanged.
    shared = UploadProcessFixture.adapter_result_projection(mode: modes.first, result: raw)
    assert_equal shared.slice("nativeChecks", "nativeOutcomes"), project.call(raw).slice("nativeChecks", "nativeOutcomes")
    largest_raw = {"kind" => "setup-fixture-fault", "errorClass" => "MobileReleaseKit::NativeUploadProcess::LifecycleError",
      "nativeErrorClass" => "MobileReleaseKit::NativeUploadProcess::LifecycleError", "nativeObservation" => {
        "custodian" => {"state" => "not_attempted"},
        "final" => {"outcome" => "rejected", "cleanup" => "confirmed", "group" => {"state" => "not_created"},
          "keeper" => {"state" => "not_attempted"}, "validator" => {"state" => "not_attempted"}},
        "tasks" => [{"role" => "capture", "state" => "not_constructed"}, {"role" => "creator", "state" => "not_constructed"}]}}
    largest = formatter.call(mode: modes[1], result: largest_raw, status: status_class.new(255))
    assert_equal 2002, largest.bytesize # 1976 JSON + 25 prefix + LF, under unchanged2048.
    assert_equal 1976, largest.delete_prefix(NATIVE_SETUP_FAILURE_PREFIX).delete_suffix("\n").bytesize
    assert_operator largest.bytesize, :<=, 2048

    exercise = lambda do |selected: modes.first, write_result: :full, expiry: nil, mutate: nil,
                            publication_error: nil, projection_error: nil, callback_name: callback.split("#", 2).last,
                            restoration_error: nil, result: raw|
      now, sequence, depth = 1, nil, 0
      state = escaped = dispatch = nil
      events, writes, projections, observations = [], [], [], []
      policy = Object.new
      policy.define_singleton_method(:install) { events << :install }
      policy.define_singleton_method(:cleanup_depth) { depth }
      policy.define_singleton_method(:cleanup) do |&body|
        depth += 1
        begin
          body.call
        ensure
          depth -= 1
        end
      end
      policy.define_singleton_method(:restore) { |&body| body.call; events << :restored }
      policy.define_singleton_method(:errors) { restoration_error ? [restoration_error] : [] }
      policy.define_singleton_method(:replay_custom_pending) { events << :replay }
      run = lambda do |**arguments|
        dispatch, state = arguments, arguments.fetch(:setup_failure_state)
        events << :run
        begin
          UploadProcessFixture.lifetime(deadline_ns: 10) do |frame|
            begin
              frame.active do
                reject = -> { UploadProcessFixture.reject_native_setup_result!(mode: selected, result: result,
                  status: status, deadline_ns: 10, state: state) }
                if publication_error
                  original_writer = state.method(:[]=)
                  state.stub(:[]=, ->(key, value) { raise publication_error if key == :mode; original_writer.call(key, value) }) { reject.call }
                else
                  reject.call
                end
              end
            ensure
              frame.cleanup { events << :cleanup }
            end
          end
        rescue Exception => error
          escaped = error
          raise
        ensure
          mutate.call(state) if mutate
          events << :unwound
          now = 10 if expiry == :before_report
          sequence = [1, 10] if expiry == :before_write
        end
      end
      sink = lambda do |packet|
        observations << [state[:rejection], state[:report_attempted], state[:write_attempted], events.dup,
          UploadProcessFixture.instance_variable_get(:@cancellation_scope)]
        writes << packet
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : packet.bytesize
      end
      projection = lambda do |**arguments|
        projections << arguments
        raise projection_error if projection_error
        formatter.call(**arguments)
      end
      actual = nil
      UploadProcessFixture::CancellationScope.stub(:new, policy) do
        Thread.current.stub(:pending_interrupt?, false) do
          UploadProcessFixture.stub(:clock_ns, -> { sequence ? sequence.shift || now : now }) do
            UploadProcessFixture.stub(:run, run) do
              stub(:name, callback_name) do
                fixture_class.stub(:native_setup_failure_line, projection) do
                  STDERR.stub(:write, sink) do
                    actual = assert_raises(publication_error ? publication_error.class : UploadProcessFixture::Failure) { process_case(selected) }
                    now, sequence = 1, nil
                    fixture_class.report_native_setup_failure(state, actual,
                      callback: "#{self.class.name}##{callback_name}", mode: selected)
                  end
                end
              end
            end
          end
        end
      end
      assert_same escaped, actual
      assert_equal %i[run install cleanup restored replay unwound], events
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      assert_equal({platform: "native", root: @root, parameters: {}, mode: selected},
        dispatch.reject { |key, _| %i[primary_failure_state setup_failure_state].include?(key) })
      assert_empty dispatch.fetch(:primary_failure_state)
      refute_same state, dispatch.fetch(:primary_failure_state)
      assert_operator writes.length, :<=, 1
      assert_operator projections.length, :<=, 1
      observations.each do |original, attempted, writing, prior, scope|
        assert_same actual, original
        assert_equal [true, true, events, nil], [attempted, writing, prior, scope]
      end
      writes.each { |packet| assert_equal formatter.call(mode: selected, result: result, status: status), packet }
      {state: state, original: actual, writes: writes, projections: projections}
    end
    states = modes.map do |mode|
      outcome = exercise.call(selected: mode)
      state = outcome.fetch(:state)
      assert_equal 1, outcome.fetch(:writes).length
      assert_same raw, state.fetch(:result)
      assert_same status, state.fetch(:status)
      assert_same outcome.fetch(:original), state.fetch(:rejection)
      assert_equal [mode, 10, true], state.values_at(:mode, :deadline_ns, :write_complete)
      assert_equal ["fixture-result", "unexpected fixture result kind/status"], [outcome[:original].kind, outcome[:original].message]
      state
    end
    assert_equal 3, states.map(&:object_id).uniq.length
    [:short, IOError.new("private-marker"), Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |write_result|
      outcome = exercise.call(write_result: write_result)
      assert_equal 1, outcome.fetch(:writes).length
      if write_result.is_a?(Exception)
        assert_same write_result, outcome.fetch(:state).fetch(:diagnostic_error)
      else
        assert_equal false, outcome.fetch(:state).fetch(:write_complete)
      end
    end
    %i[before_report before_write].each do |expiry|
      outcome = exercise.call(expiry: expiry)
      assert_empty outcome.fetch(:writes)
      assert_equal expiry == :before_report ? 0 : 1, outcome.fetch(:projections).length
    end
    [->(s) { s.delete(:status) }, ->(s) { s.delete(:result) }, ->(s) { s.delete(:rejection) },
     ->(s) { s[:rejection] = UploadProcessFixture::Failure.new("fixture-result", "private-marker") },
     ->(s) { s[:mode] = modes.last }, ->(s) { s[:result] = nil }, ->(s) { s[:deadline_ns] = 10.0 },
     ->(s) { s[:result] = raw.merge("kind" => "pass"); s[:status] = status_class.new(0) },
     ->(s) { s.freeze }].each do |mutate|
      assert_empty exercise.call(mutate: mutate).fetch(:writes)
    end
    assert_empty exercise.call(callback_name: "test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike").fetch(:writes)
    interruption = Interrupt.new("private-marker")
    outcome = exercise.call(projection_error: interruption)
    assert_empty outcome.fetch(:writes)
    assert_same interruption, outcome.fetch(:state).fetch(:diagnostic_error)
    assert_equal 1, exercise.call(restoration_error: IOError.new("later private restoration error")).fetch(:writes).length
    [interruption, SystemExit.new(21, "private-marker")].each do |publication_error|
      outcome = exercise.call(publication_error: publication_error)
      assert_same publication_error, outcome.fetch(:original)
      refute_same publication_error, outcome.fetch(:state).fetch(:rejection)
      refute outcome.fetch(:state).key?(:result)
      assert_empty outcome.fetch(:writes)
    end

    # Success and post-run assertions are outside the rejection reporter. Other
    # modes retain their original primary/order keyword shapes with no new state.
    successful = %w[driverJoined knownProcessesDead watchdogJoined tasksJoined injectorsJoined ownedDescriptorsClosed
      handlersRestored registryInactive].to_h { |key| [key, true] }.merge("pendingInterrupt" => false, "cleanupErrors" => [])
    writes, dispatches = [], []
    UploadProcessFixture.stub(:run, ->(**arguments) { dispatches << arguments; successful }) do
      STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
        modes.each { |mode| assert_same successful, process_case(mode) }
        order_state = {}
        assert_same successful, process_case("native-order-task-before-caller-interrupt", order_failure_state: order_state)
        assert_same order_state, dispatches.last.fetch(:order_failure_state)
        assert_same successful, process_case("native-proof-readiness-standard-none")
        successful["driverJoined"] = false
        assert_raises(Minitest::Assertion) { process_case(modes.first) }
      end
    end
    assert_empty writes
    setup_states = dispatches.filter_map { |arguments| arguments[:setup_failure_state] }
    assert_equal 4, setup_states.map(&:object_id).uniq.length
    assert setup_states.all?(&:empty?)
    dispatches.each do |arguments|
      assert_equal modes.include?(arguments.fetch(:mode)), arguments.key?(:setup_failure_state)
      assert_empty arguments.fetch(:primary_failure_state)
    end
  end

  def assert_adapter_fixed_timing_profile
    fixture = UploadProcessFixture
    assert_equal [2, 5, 8, 15, 5, 30, 60], %i[DEADLINE READINESS_LIMIT CAPTURE_LIMIT DRIVER_LIMIT CLEANUP_LIMIT
      WORKER_LIMIT OWNERSHIP_LIMIT].map { |name| fixture.const_get(name) }
    assert_equal [10, 12, 18, 20, 25, 31], %i[ADAPTER_READINESS_LIMIT ADAPTER_RUN_LIMIT ADAPTER_CAPTURE_LIMIT
      ADAPTER_MUTANT_RUN_LIMIT ADAPTER_COMPLETION_LIMIT ADAPTER_DRIVER_LIMIT].map { |name| fixture.const_get(name) }
    assert_equal [15, 31, 31], %w[native ios android].map { |platform| fixture.driver_limit_seconds(platform) }

    # Original initialization and the actual pre-acquisition event are pure
    # here. No execute/task/observer installation or native operation occurs.
    entry = lambda do |mode: "inherited", changes: {}, rejected: nil|
      times = {capture: 5_000_000_000, started: 5_200_000_000, now: 5_300_000_000, outer: 32_000_000_000}.merge(changes)
      driver = fixture::AdapterDriver.new(@root, "ios", mode, {}, deadline_ns: times.fetch(:outer))
      span = mode == "no-deadline" ? fixture::ADAPTER_MUTANT_RUN_LIMIT : fixture::ADAPTER_RUN_LIMIT
      run = times.fetch(:started) + span * 1_000_000_000
      slot = Struct.new(:run_deadline_ns, :hard_cleanup_deadline_ns).new(run, run + 5_000_000_000)
      session = Struct.new(:capture_slot).new(slot)
      driver.instance_variable_set(:@observation, Struct.new(:session).new(session))
      driver.instance_variable_set(:@capture_started_ns, times.fetch(:capture))
      driver.capture_initialized(session, times.fetch(:started))
      assert_equal run, driver.observed.fetch("nativeRunDeadlineNs")
      assert_equal times.fetch(:started) + 10_000_000_000, driver.instance_variable_get(:@readiness_deadline_ns)
      body = []
      enter = -> { driver.native_event(:run_enter, session); body << :original_native_body }
      fixture.stub(:clock_ns, times.fetch(:now)) do
        unless rejected
          enter.call
          assert_equal [:original_native_body], body
          assert_operator times.fetch(:started) + 17_000_000_000, :<, times.fetch(:capture) + 18_000_000_000
          assert_operator times.fetch(:capture) + 18_000_000_000, :<, times.fetch(:started) + 20_000_000_000
          assert_operator times.fetch(:started) + 26_000_000_000, :<, times.fetch(:outer)
        else
          error = assert_raises(fixture::Failure, &enter)
          messages = {
            binding: "adapter entry original session or clocks changed",
            window: "adapter entry missed original one-second window",
            reserve: "adapter entry lacks original completion reserve",
          }
          assert_equal ["setup-fixture-fault", messages.fetch(rejected)], [error.kind, error.message]
          assert_empty body # The original TaskSlot owns the veto before its native body.
        end
      end
      assert_equal [run, run + 5_000_000_000], [slot.run_deadline_ns, slot.hard_cleanup_deadline_ns]
    end
    %w[inherited real-deadline immediate-deadline no-deadline kill-startup kill-descendant].each { |mode| entry.call(mode: mode) }
    entry.call(changes: {now: 5_999_999_999})
    entry.call(changes: {outer: 31_200_000_001}) # More than the whole publication second remains.
    [[{now: 6_000_000_000}, :window], [{now: 6_000_000_001}, :window],
     [{now: 5_199_999_999}, :binding], [{capture: 5_200_000_001}, :binding],
     [{started: 6_000_000_000, now: 6_000_000_000}, :window],
     [{outer: 31_200_000_000}, :reserve], [{outer: 31_199_999_999}, :reserve],
     [{outer: 32_000_000_000.0}, :binding]].each do |changes, reason|
      entry.call(changes: changes, rejected: reason)
    end

    # Read already-retained C/K endpoints and original parent times only. Ties
    # at original start are valid, readiness equality is not. Native hard-loss
    # deliberately has a different RUN and never enters this adapter predicate.
    evidence = fixture::ContainmentEvidence
    custodian = {"runDeadlineNs" => 17_000_000_000, "hardDeadlineNs" => 22_000_000_000}
    keeper = custodian.dup
    prior = {"heldWriterAcquiredNs" => 5_000_000_000, "driverKillEntryNs" => 5_000_000_000}
    %w[kill-startup kill-descendant].each do |mode|
      assert evidence.adapter_hardloss_timely?(mode, custodian, keeper, prior)
      assert evidence.adapter_hardloss_timely?(mode, custodian, keeper, prior.merge("driverKillEntryNs" => 14_999_999_999))
      [prior.merge("heldWriterAcquiredNs" => 4_999_999_999), prior.merge("heldWriterAcquiredNs" => 5_000_000_001),
       prior.merge("driverKillEntryNs" => 15_000_000_000), prior.merge("driverKillEntryNs" => 15_000_000_001),
       prior.merge("driverKillEntryNs" => 5_000_000_000.0), prior.merge("heldWriterAcquiredNs" => true)].each do |bad|
        refute evidence.adapter_hardloss_timely?(mode, custodian, keeper, bad)
      end
      [keeper.merge("runDeadlineNs" => 17_000_000_001), keeper.merge("hardDeadlineNs" => 22_000_000_001),
       keeper.merge("runDeadlineNs" => 17_000_000_000.0), keeper.merge("hardDeadlineNs" => nil)].each do |bad|
        refute evidence.adapter_hardloss_timely?(mode, custodian, bad, prior)
      end
      zero_start = {"runDeadlineNs" => 12_000_000_000, "hardDeadlineNs" => 17_000_000_000}
      refute evidence.adapter_hardloss_timely?(mode, zero_start, zero_start, prior)
      no_grace = custodian.merge("hardDeadlineNs" => 21_000_000_000)
      refute evidence.adapter_hardloss_timely?(mode, no_grace, no_grace, prior)
    end
    assert evidence.adapter_hardloss_timely?("kill-native-setup", {}, {}, {})
    assert_adapter_original_readiness_helpers
  end

  def assert_ownership_family_admission
    fixture, probe_class = UploadProcessFixture, UploadProcessFixture::OwnershipProbe
    ns, now = 1_000_000_000, 100_000_000_000
    start = now
    final, admission = start + 97 * ns, start + 60 * ns
    assert_equal [60, 37, 97], [fixture::OWNERSHIP_LIMIT, fixture::OWNERSHIP_COMPLETION_TAIL, fixture::OWNERSHIP_HEALTHY_LIMIT]
    assert_equal fixture::ADAPTER_DRIVER_LIMIT + fixture::CLEANUP_LIMIT + fixture::ADAPTER_PUBLICATION_LIMIT,
      fixture::OWNERSHIP_COMPLETION_TAIL
    directory = "/inert-original-family"
    stubs = lambda do |bindings, &body|
      if bindings.empty?
        body.call
      else
        target, name, replacement = bindings.first
        target.stub(name, replacement) { stubs.call(bindings.drop(1), &body) }
      end
    end

    # Stop at the actual parent's first lifecycle seam: no directory or native
    # body runs, but its original S/F/A computation and post-return gate do.
    offered, lifetimes = Object.new, []
    stop_before_acquisition = ->(deadline_ns:, &_) { lifetimes << deadline_ns; offered }
    stubs.call([[fixture, :clock_ns, -> { now }], [fixture, :lifetime, stop_before_acquisition]]) do
      fixture::OWNERSHIP_FAILURE_MODES.each_key do |mode|
        [[nil, final], [start + 70 * ns, start + 70 * ns], [start + 120 * ns, final],
         [start + 37 * ns + 1, start + 37 * ns + 1]].each do |parent, expected|
          assert_same offered, fixture.run_ownership_probe(platform: "ios", root: directory, parameters: {}, mode: mode, deadline_ns: parent)
          assert_equal expected, lifetimes.last
        end
        [start + 37 * ns, start + 37 * ns - 1].each do |parent|
          before = lifetimes.length
          assert_raises(fixture::Failure) do
            fixture.run_ownership_probe(platform: "ios", root: directory, parameters: {}, mode: mode, deadline_ns: parent)
          end
          assert_equal before, lifetimes.length
        end
      end
      (%w[ownership-setup ownership-observation] + fixture::OWNERSHIP_UNKNOWN_MODES.keys).each do |mode|
        assert_same offered, fixture.run_ownership_probe(platform: "ios", root: directory, parameters: {}, mode: mode)
        assert_equal start + 60 * ns, lifetimes.last
      end
    end

    input = {"platform" => "ios", "parameters" => {}, "mode" => "ownership-async", "deadlineNs" => final}
    owned_reads = []
    stubs.call([[fixture, :clock_ns, -> { now }], [Dir, :tmpdir, directory],
      [fixture, :owned_fixture_directory, ->(path) { owned_reads << path }]]) do
      fixture::OWNERSHIP_FAILURE_MODES.each_key do |mode|
        value = input.merge("mode" => mode)
        assert_same value, fixture.validate_driver_input!(directory, value, ownership_mode: mode)
        [final + 1, start + 37 * ns, start, final.to_f].each do |bad|
          before = owned_reads.length
          assert_raises(fixture::Failure) { fixture.validate_driver_input!(directory, value.merge("deadlineNs" => bad), ownership_mode: mode) }
          assert_equal before, owned_reads.length
        end
      end
    end

    # Actual initializer/execute/invoke bindings; only selected downstream
    # commands are inert. Their later validation clock cannot renew H.
    fixture.stub(:read_json, ->(*) { input }) do
      probe = probe_class.new(directory, "async")
      assert_equal [final, admission], [probe.deadline_ns, probe.admission_deadline_ns]
      late_probe = probe_class.new(directory, "async")
      fixture.stub(:clock_ns, admission) do
        fixture.stub(:mark_process_domain_failed!, ->(**_) { nil }) do
          error = assert_raises(fixture::Failure) { late_probe.one("capture", "async-spawn") }
          assert_equal "original family admission cutoff expired", error.message
        end
      end
      refute late_probe.instance_variable_defined?(:@case_root)
      refute late_probe.instance_variable_defined?(:@context) # Actual one refused before directory/hooks/traps.
      input = input.merge("mode" => "ownership-signals")
      assert_raises(fixture::Failure) { probe_class.new(directory, "async") }
      input = input.merge("mode" => "ownership-async")
      calls, delayed = [], false
      original_run, original_capture = fixture.method(:run), fixture.method(:capture_command)
      run = lambda do |**keywords|
        calls << [:run, keywords]
        if delayed
          now = keywords.fetch(:deadline_ns)
          original_run.call(**keywords) # Existing stale-input refusal before lifetime.
        else
          :inert_command
        end
      end
      capture = lambda do |argv, **keywords|
        calls << [:capture, keywords]
        if delayed
          now = (keywords.fetch(:deadline) * ns).floor
          original_capture.call(argv, environment: {}, **keywords)
        else
          :inert_command
        end
      end
      bindings = [[fixture, :clock_ns, -> { now }], [File, :realpath, ->(path) { path }],
        [fixture, :run, run], [fixture, :capture_command, capture],
        [fixture, :lifetime, ->(**_keywords, &_body) { flunk "stale H reached lifetime" }],
        [fixture, :command_lifetime, ->(**_keywords, &_body) { flunk "stale H reached command lifetime" }]]
      stubs.call(bindings) do
        %w[capture run].each do |helper|
          {helper: helper, case: "async-reap", case_root: directory}.each { |key, value| probe.instance_variable_set(:"@#{key}", value) }
          now = admission - 1
          assert_equal :inert_command, probe.invoke
          offered_cutoff = helper == "run" ? calls.last.last.fetch(:deadline_ns) : (calls.last.last.fetch(:deadline) * ns).floor
          assert_equal final - ns - 1, offered_cutoff
          assert_equal 2, calls.last.last.fetch(:seconds) if helper == "capture"
          assert_equal [final, admission], [probe.deadline_ns, probe.admission_deadline_ns]
          [admission, admission + 1].each do |expired|
            now = expired
            before = calls.length
            assert_raises(fixture::Failure) { probe.invoke }
            assert_equal before, calls.length
          end
          now, delayed = admission - 1, true
          error = assert_raises(fixture::Failure) { probe.invoke }
          assert_equal(helper == "run" ? "fixture-input" : "process-observation", error.kind)
          actual = helper == "run" ? calls.last.last.fetch(:deadline_ns) : (calls.last.last.fetch(:deadline) * ns).floor
          assert_equal offered_cutoff, actual
          delayed = false
        end
        input = input.merge("mode" => "ownership-unknown-capture-spawn", "deadlineNs" => start + 60 * ns)
        singleton = probe_class.new(directory, "unknown")
        %w[capture run].each do |helper|
          {helper: helper, case: "unknown-spawn", case_root: directory}.each { |key, value| singleton.instance_variable_set(:"@#{key}", value) }
          now = start
          assert_equal :inert_command, singleton.invoke
          actual = helper == "run" ? calls.last.last.fetch(:deadline_ns) : (calls.last.last.fetch(:deadline) * ns).floor
          assert_equal start + 60 * ns, actual
        end
      end
    end
  end

  def assert_adapter_original_readiness_helpers
    fixture = UploadProcessFixture
    start, ready_cutoff, run_cutoff = 1_000_000_000, 11_000_000_000, 13_000_000_000
    driver = fixture::AdapterDriver.new(@root, "ios", "inherited", {}, deadline_ns: 32_000_000_000)
    pipes = [Object.new, Object.new]
    leases = %i[stdout_read stderr_read].zip(pipes).to_h.transform_values { |io| Struct.new(:io).new(io) }
    slot = Struct.new(:run_deadline_ns).new(run_cutoff)
    session = Struct.new(:capture_slot, :leases).new(slot, leases)
    driver.instance_variable_set(:@observation, Struct.new(:session).new(session))
    driver.instance_variable_set(:@native_started_ns, start)
    driver.instance_variable_set(:@readiness_deadline_ns, ready_cutoff)
    now, reads = ready_cutoff - 1, 0
    # Actual record return checks use the selected absolute deadline even if
    # the bounded read itself crosses it. No real path is opened or inspected.
    fixture.stub(:clock_ns, -> { now }) do
      File.stub(:file?, true) do
        reader = lambda do |path|
          assert_equal File.join(@root, "inert.json"), path
          reads += 1
          "{}"
        end
        fixture::OwnedChild.stub(:bounded_file, reader) { assert_equal({}, driver.wait_record("inert.json")) }
        reader = ->(_path) { reads += 1; now = ready_cutoff; "{}" }
        fixture::OwnedChild.stub(:bounded_file, reader) { assert_raises(fixture::Failure) { driver.wait_record("inert.json") } }
        assert_equal 2, reads
        # Readiness is already exhausted, but later STATUS work still uses RUN.
        fixture::OwnedChild.stub(:bounded_file, "{}") do
          assert_equal({}, driver.wait_record("inert.json", kind: "descendant-alive", deadline_ns: run_cutoff))
        end
      end
      %i[readiness status].each do |phase|
        cutoff = phase == :readiness ? ready_cutoff : run_cutoff
        now = cutoff - 20_000_001
        select = lambda do |readers, writers, errors, seconds|
          assert_equal [pipes, nil, nil, 0.02], [readers, writers, errors, seconds]
          now += 20_000_000
          nil
        end
        IO.stub(:select, select) do
          driver.observe_inherited_block!(deadline_ns: cutoff)
          assert driver.observed.fetch("inheritedPipeBlockObserved")
        end
        now = cutoff - 20_000_000
        IO.stub(:select, ->(*) { flunk "pipe observation cannot enter without its complete interval" }) do
          assert_raises(fixture::Failure) { driver.observe_inherited_block!(deadline_ns: cutoff) }
        end
      end
      # The intentional loss wait is still the original RUN, not readiness.
      sleeps = []
      driver.define_singleton_method(:sleep) { |seconds| sleeps << seconds; now = run_cutoff }
      now = ready_cutoff
      error = assert_raises(fixture::Failure) { driver.wait_for_driver_loss }
      assert_equal ["driver", "parent did not stop its actual reserved driver"], [error.kind, error.message]
      assert_equal [0.01], sleeps
      assert_equal run_cutoff, slot.run_deadline_ns
    end

    # Exercise actual watchdog construction/body with an inert TaskSlot double;
    # no thread is started and no join/finality receipt is invented by this model.
    watch = fixture::AdapterDriver.new(@root, "ios", "no-deadline", {}, deadline_ns: 32_000_000_000)
    watch.instance_variable_set(:@capture_started_ns, start)
    requested, body, writes = nil, nil, []
    worker, control = Object.new, Object.new
    worker.define_singleton_method(:start) { |&block| body = block; worker }
    worker.define_singleton_method(:admit!) { true }
    control.define_singleton_method(:close_writer) { writes << :original_writer }
    watch.instance_variable_set(:@control, control)
    now = start + 10_000_000_000
    watch.define_singleton_method(:sleep) { |_seconds| now = start + 18_000_000_000 }
    factory = ->(**keywords) { requested = keywords; worker }
    fixture.stub(:clock_ns, -> { now }) do
      MobileReleaseKit::NativeUploadProcess::TaskSlot.stub(:new, factory) { watch.start_watchdog }
      assert_equal({caller: Thread.current, parent_slot: nil,
        run_deadline_ns: start + 19_000_000_000, hard_cleanup_deadline_ns: start + 19_000_000_000}, requested)
      assert_equal start + 18_000_000_000, watch.observed.fetch("watchdogDeadlineNs")
      assert watch.observed.fetch("watchdogStarted")
      assert_same true, body.call
      assert_equal [:original_writer], writes
      assert watch.observed.fetch("watchdogIntervened")
      assert watch.observed.fetch("fallbackUsed")
    end
  end

  def assert_adapter_parent_cutoff_composition
    # The enclosing selector's acquisition veto stays live. These are actual
    # caller methods and real bound/FailureRecord code, not native receipts.
    fixture, native = UploadProcessFixture, MobileReleaseKit::NativeUploadProcess
    slot_class = native::TaskSlot
    run_ns, hard_ns = 12_000_000_000, 17_000_000_000
    parent = slot_class.new(caller: Thread.current, run_deadline_ns: run_ns, hard_cleanup_deadline_ns: hard_ns)
    session = Struct.new(:capture_slot, :ready, :reserved, :custodian_child).new(parent,
      {"validator_pid" => 103}, {"keeper_pid" => 102}, Struct.new(:pid).new(101))
    marker = {"pid" => 103, "group" => 102}
    frame = {"validator_pid" => 103, "status_kind" => "exit", "status_code" => 0}
    %i[live omission].each do |route|
      %i[accepted not_live late expired].each do |condition|
        readiness_ns = 10_000_000_000
        bound = route == :live ? readiness_ns : run_ns
        now = condition == :expired ? bound : bound - 500_000_000
        calls, actions = [], []
        driver = fixture::AdapterDriver.allocate
        control = Object.new
        control.define_singleton_method(:close_writer) { actions << :writer_closed }
        {observation: Struct.new(:session).new(session), observed: {}, base_mode: "leader-only",
         native_started_ns: 1, readiness_deadline_ns: readiness_ns,
         release_ns: readiness_ns, descendant: marker, control: control}.each do |name, value|
          driver.instance_variable_set(:"@#{name}", value)
        end
        driver.define_singleton_method(:wait_record) do |name, kind:, deadline_ns:|
          raise "unexpected inert omission record" unless name == "omitted-group-kill.json" && kind == "descendant-alive" && deadline_ns == run_ns
          {"version" => 1, "custodian" => 101, "keeper" => 102, "group" => 102, "signal" => "KILL"}
        end
        driver.define_singleton_method(:observe_inherited_block!) do |deadline_ns:|
          raise "later STATUS borrowed readiness cutoff" unless deadline_ns == run_ns
          actions << :blocked
        end
        observe = lambda do |pid, group, **keywords|
          calls << [pid, group, keywords]
          assert_equal [103, 102], [pid, group]
          assert_same parent, keywords.fetch(:parent_slot)
          assert_equal route == :live ? %i[seconds parent_slot run_deadline_ns] : %i[seconds parent_slot], keywords.keys
          assert_equal readiness_ns, keywords.fetch(:run_deadline_ns) if route == :live
          assert_equal condition == :expired ? 0.0 : 0.5, keywords.fetch(:seconds)
          # The real capture_command's zero-seconds rejection is checked below.
          raise fixture::Failure.new("process-observation", "invalid observation deadline") if condition == :expired
          now = bound if condition == :late
          condition != :not_live
        end
        fixture.stub(:clock_ns, -> { now }) do
          fixture.stub(:ready?, observe) do
            invoke = -> { route == :live ? driver.live_marker!(marker, marker.dup, "validator") : driver.status_received(session, frame) }
            if condition == :accepted
              invoke.call
            else
              error = assert_raises(fixture::Failure, &invoke)
              assert_equal condition == :expired && route == :omission ? "process-observation" : "readiness", error.kind
            end
          end
        end
        assert_equal condition == :expired && route == :live ? 0 : 1, calls.length
        assert_equal route == :omission && condition == :accepted ? [:blocked, :writer_closed] : [], actions
        assert_equal route == :omission && condition == :accepted, driver.instance_variable_get(:@omission_observed).equal?(true)
      end
    end

    # command_lifetime is the first pre-acquisition seam. Inspect the supplied
    # block's ACTUAL computed run_ns, and its hard endpoint argument, without
    # invoking its filesystem/child body or reproducing its min computation.
    now, captured, child = 10_000_000_000, nil, nil
    offered = Object.new
    validate = ->(value) { assert_same parent, value; value }
    trace = lambda do |parent_slot:, hard_deadline_ns:, &body|
      captured = [body.binding.local_variable_get(:run_ns), hard_deadline_ns, parent_slot]
      offered
    end
    fixture.stub(:clock_ns, -> { now }) do
      native.stub(:monotonic_ns, -> { now }) do
        fixture.stub(:validate_capture_parent!, validate) do
          fixture.stub(:command_lifetime, trace) do
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 2, parent_slot: parent)
            assert_equal [run_ns, hard_ns, parent], captured
            child = slot_class.new(caller: Thread.current, parent_slot: parent,
              run_deadline_ns: captured[0], hard_cleanup_deadline_ns: captured[1])
            assert_same parent.__send__(:failure_record), child.__send__(:failure_record)
            now = run_ns - 1
            first = IOError.new("original near-run failure")
            child.cancel!(error: first, reason_code: "io")
            assert_same first, parent.first_error
            assert_same first, child.first_error
            assert_equal hard_ns - 1, parent.cleanup_deadline_ns
            assert_operator parent.cleanup_deadline_ns, :>, run_ns
            assert_operator parent.cleanup_deadline_ns, :<=, hard_ns

            # A prior shared failure remains primary and its earlier grace
            # cannot be renewed by another nested task's later error.
            now = 10_000_000_000
            parent = slot_class.new(caller: Thread.current, run_deadline_ns: run_ns, hard_cleanup_deadline_ns: hard_ns)
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 2, parent_slot: parent)
            child = slot_class.new(caller: Thread.current, parent_slot: parent,
              run_deadline_ns: captured[0], hard_cleanup_deadline_ns: captured[1])
            first = Interrupt.new("earlier original failure")
            now = 10_100_000_000
            parent.cancel!(error: first, reason_code: "cancelled")
            earlier_cutoff = parent.cleanup_deadline_ns
            assert_equal 15_100_000_000, earlier_cutoff
            now = run_ns - 1
            child.cancel!(error: IOError.new("later nested failure"), reason_code: "io")
            assert_same first, child.first_error
            assert_equal earlier_cutoff, parent.cleanup_deadline_ns
            assert_equal earlier_cutoff, child.cleanup_deadline_ns

            now = 10_000_000_000
            parent = slot_class.new(caller: Thread.current, run_deadline_ns: run_ns, hard_cleanup_deadline_ns: 14_000_000_000)
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 2, parent_slot: parent)
            assert_equal [run_ns, 14_000_000_000, parent], captured
            child = slot_class.new(caller: Thread.current, parent_slot: parent,
              run_deadline_ns: captured[0], hard_cleanup_deadline_ns: captured[1])
            now = run_ns - 1
            child.cancel!(error: first, reason_code: "cancelled")
            assert_equal 14_000_000_000, parent.cleanup_deadline_ns

            # Shorter requested work and genuine standalone overall deadlines
            # still cap their respective run and cleanup endpoints exactly.
            now = 10_000_000_000
            parent = slot_class.new(caller: Thread.current, run_deadline_ns: run_ns, hard_cleanup_deadline_ns: hard_ns)
            assert_same offered, fixture.capture_command([], environment: {}, seconds: Rational(1, 2), parent_slot: parent)
            assert_equal [10_500_000_000, 15_500_000_000, parent], captured
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 3, deadline: Rational(run_ns, 1_000_000_000))
            assert_equal [run_ns, run_ns, nil], captured
            [Rational(now - 1, 1_000_000_000), Rational(now, 1_000_000_000),
             Rational(2 * now + 1, 2_000_000_000)].each do |expired|
              captured = nil
              invalid = assert_raises(fixture::Failure) { fixture.capture_command([], environment: {}, deadline: expired) }
              assert_equal ["process-observation", "invalid observation deadline"], [invalid.kind, invalid.message]
              assert_nil captured # No command_lifetime, directory or child at stale input entry.
            end
            assert_same offered, fixture.capture_command([], environment: {}, deadline: Rational(now + 1, 1_000_000_000))
            assert_equal [now + 1, now + 1, nil], captured
            assert_same offered, fixture.capture_command([], environment: {}, deadline: nil)
            assert_equal [now + 2_000_000_000, now + 7_000_000_000, nil], captured
            # Absolute readiness caps RUN only, without a resampled relative
            # deadline or converting readiness into the overall cleanup cap.
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 2,
              parent_slot: parent, run_deadline_ns: 10_750_000_000)
            assert_equal [10_750_000_000, 15_750_000_000, parent], captured
            child = slot_class.new(caller: Thread.current, parent_slot: parent,
              run_deadline_ns: captured[0], hard_cleanup_deadline_ns: captured[1])
            assert_same parent.__send__(:failure_record), child.__send__(:failure_record)
            first = IOError.new("original readiness observation failure")
            now = 10_500_000_000
            child.cancel!(error: first, reason_code: "io")
            assert_same first, parent.first_error
            assert_equal 15_500_000_000, child.cleanup_deadline_ns
            now += 1
            child.cancel!(error: Interrupt.new("later readiness cancellation"), reason_code: "cancelled")
            assert_same first, parent.first_error
            assert_equal 15_500_000_000, child.cleanup_deadline_ns
            now = 10_000_000_000
            parent = slot_class.new(caller: Thread.current, run_deadline_ns: run_ns, hard_cleanup_deadline_ns: hard_ns)
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 3,
              parent_slot: parent, run_deadline_ns: 13_000_000_000)
            assert_equal [run_ns, hard_ns, parent], captured
            assert_same offered, fixture.capture_command([], environment: {}, seconds: 2,
              parent_slot: parent, run_deadline_ns: 10_750_000_000, deadline: Rational(11, 1))
            assert_equal [10_750_000_000, 11_000_000_000, parent], captured
            [false, 0, now, now - 1, now.to_f, "11000000000"].each do |bad|
              invalid = assert_raises(fixture::Failure) do
                fixture.capture_command([], environment: {}, seconds: 2, parent_slot: parent, run_deadline_ns: bad)
              end
              assert_equal ["process-observation", "invalid observation deadline"], [invalid.kind, invalid.message]
            end
            invalid = assert_raises(fixture::Failure) { fixture.capture_command([], environment: {}, seconds: 0, parent_slot: parent) }
            assert_equal ["process-observation", "invalid observation deadline"], [invalid.kind, invalid.message]
          end
          late = lambda do |**keywords, &body|
            trace.call(**keywords, &body)
            now = captured.first
            offered
          end
          fixture.stub(:command_lifetime, late) do
            error = assert_raises(fixture::Failure) { fixture.capture_command([], environment: {}, seconds: 2, parent_slot: parent) }
            assert_equal ["process-observation", "process observation result arrived after deadline"], [error.kind, error.message]
            assert_same error, parent.first_error
          end
        end
      end
    end
    [parent, child].each do |slot|
      refute slot.start_attempted?
      assert_nil slot.thread
      refute slot.unresolved?
    end

    # Exercise actual ready? -> state forwarding without a native child. The
    # absent record is inert parser input, not actual process-death evidence.
    fixture.stub(:process_observer_path, "/inert-observer") do
      [nil, 11_000_000_000].each do |bound|
        collector = lambda do |argv, **keywords|
          assert_equal ["/inert-observer", "103"], argv
          expected = {seconds: 2, environment: fixture::PROCESS_OBSERVER_LOCALE, parent_slot: parent}
          expected[:run_deadline_ns] = bound if bound
          assert_equal expected, keywords
          ["MRK_PROCESS_V1 absent 103\n", "", 0]
        end
        fixture.stub(:capture_command, collector) do
          # The parser still requires a nonroot observer identity. Supply inert
          # numeric inputs here instead of depending on the local runner UID.
          Process.stub(:uid, 501) do
            Process.stub(:gid, 20) do
              error = assert_raises(fixture::Failure) do
                fixture.ready?(103, 102, parent_slot: parent, run_deadline_ns: bound)
              end
              assert_equal ["readiness", "fixture stopped before readiness"], [error.kind, error.message]
            end
          end
        end
      end
    end
  end

  def assert_original_capture_settlement_projection
    # Exact admitted Ruby types, deliberately allocated WITHOUT initialization,
    # native creation, a task, a clock, or an IO. Only pure original getters run.
    fixture = UploadProcessFixture
    native = MobileReleaseKit::NativeUploadValidation
    observer_class = fixture::CaptureObservation
    keys = %w[taskCleanupComplete creationSettled custodianWaitBroken acquisitionUnknown]
    assert_equal keys, observer_class::SETTLEMENT_CHECKS
    make = lambda do
      task = lambda do
        value = MobileReleaseKit::NativeUploadProcess::TaskSlot.allocate
        {lock: Mutex.new, launch: :retired, joined: false, start_attempted: false,
         failure: MobileReleaseKit::NativeUploadProcess::TaskSlot.const_get(:FailureRecord, false).new}.each do |key, item|
          value.instance_variable_set(:"@#{key}", item)
        end
        value
      end
      capture, creator = task.call, task.call
      acquisition = MobileReleaseKit::NativeProcessSpawn::Acquisition.allocate
      {lock: Mutex.new, state: :settled, cleanup_errors: [], creator_joined: false,
       creator_absent: true, finished: true, launch: :retired, child_attempted: false}.each do |key, item|
        acquisition.instance_variable_set(:"@#{key}", item)
      end
      session = native.const_get(:CaptureSession, false).allocate
      {capture_slot: capture, creator_slot: creator, acquisition: acquisition, creator_entered: true,
       creation_finish_returned: true, task_cleanup_complete: true, wait_broken: false}.each do |key, item|
        session.instance_variable_set(:"@#{key}", item)
      end
      observer = observer_class.new(native: native, root: Object.new)
      observer.instance_variable_set(:@session, session)
      {observer: observer, session: session, capture: capture, creator: creator, acquisition: acquisition}
    end
    good = keys.zip([true, true, false, false]).to_h
    rig = make.call
    assert_equal good, rig[:observer].settlement_checks
    %i[@task_cleanup_complete @wait_broken].each { |key| rig[:session].remove_instance_variable(key) }
    assert_equal good.merge("taskCleanupComplete" => "missing", "custodianWaitBroken" => "missing"), rig[:observer].settlement_checks
    rig[:session].instance_variable_set(:@task_cleanup_complete, 0)
    rig[:session].instance_variable_set(:@wait_broken, "false")
    assert_equal good.merge("taskCleanupComplete" => "invalid", "custodianWaitBroken" => "invalid"), rig[:observer].settlement_checks
    rig = make.call
    rig[:session].instance_variable_set(:@acquisition, nil)
    rig[:session].instance_variable_set(:@creator_slot, nil)
    rig[:session].instance_variable_set(:@creator_entered, false)
    assert_equal good.merge("acquisitionUnknown" => "missing"), rig[:observer].settlement_checks
    rig[:capture].instance_variable_set(:@launch, :open)
    assert_equal false, rig[:observer].settlement_checks.fetch("creationSettled")
    rig[:session].remove_instance_variable(:@capture_slot)
    assert_equal "missing", rig[:observer].settlement_checks.fetch("creationSettled")
    rig = make.call
    rig[:session].remove_instance_variable(:@creation_finish_returned)
    assert_equal "missing", rig[:observer].settlement_checks.fetch("creationSettled")
    rig[:session].instance_variable_set(:@creation_finish_returned, "true")
    assert_equal "invalid", rig[:observer].settlement_checks.fetch("creationSettled")
    %i[configuring initialized attempting pid_published settled failed unknown].each do |state|
      rig = make.call
      rig[:acquisition].instance_variable_set(:@state, state)
      assert_equal good.merge("creationSettled" => state != :unknown, "acquisitionUnknown" => state == :unknown),
        rig[:observer].settlement_checks
    end
    [nil, "unknown", :other].each do |state|
      rig = make.call
      rig[:acquisition].instance_variable_set(:@state, state)
      assert_equal good.merge("creationSettled" => "invalid", "acquisitionUnknown" => "invalid"), rig[:observer].settlement_checks
    end
    # A lookalike session/task/acquisition/collection is never optional method
    # authority, including a subclass of the otherwise admitted session class.
    calls = []
    replacement = Object.new
    %i[creation_settled? state cleanup_errors not_attempted? joined? start_attempted? launch_retired? empty?].each do |name|
      replacement.define_singleton_method(name) { calls << name; raise "unexpected diagnostic lookalike call" }
    end
    [nil, replacement, Class.new(native.const_get(:CaptureSession, false)).allocate].each do |session|
      rig = make.call
      rig[:observer].instance_variable_set(:@session, session)
      assert_equal keys.to_h { |key| [key, session.nil? ? "missing" : "invalid"] }, rig[:observer].settlement_checks
    end
    %i[@capture_slot @creator_slot @acquisition].each do |variable|
      rig = make.call
      rig[:session].instance_variable_set(variable, replacement)
      checks = rig[:observer].settlement_checks
      assert_equal "invalid", checks.fetch("creationSettled")
      assert_equal variable == :@acquisition ? "invalid" : false, checks.fetch("acquisitionUnknown")
    end
    rig = make.call
    rig[:acquisition].stub(:cleanup_errors, replacement) do
      assert_equal "invalid", rig[:observer].settlement_checks.fetch("creationSettled")
    end
    rig[:creator].stub(:joined?, "true") do
      assert_equal "invalid", rig[:observer].settlement_checks.fetch("creationSettled")
    end
    rig[:creator].stub(:joined?, -> { raise IOError, "optional original getter" }) do
      assert_equal "invalid", rig[:observer].settlement_checks.fetch("creationSettled")
    end
    assert_empty calls
    assert_empty rig[:observer].instance_variable_get(:@observer_errors)

    primary_diagnostic = fixture::OwnershipFailureDiagnostic
    primary_cases = [[nil, %w[none none]], [Interrupt.new("private-marker"), %w[interrupt none]],
      [SignalException.new("TERM"), %w[signal none]], [SystemExit.new(19, "private-marker"), %w[system-exit none]],
      [IOError.new("private-marker"), %w[io-error none]], [Errno::ECHILD.new("private-marker"), %w[os-error echild]],
      [Errno::EPERM.new("private-marker"), %w[os-error other]],
      [MobileReleaseKit::ContractError.new("private-marker"), %w[contract-error none]],
      [fixture::Failure.new(+"process-observation", "private-marker"), %w[fixture-error process-observation]],
      [fixture::Failure.new("private-marker", "private-marker"), %w[fixture-error other]],
      [RuntimeError.new("private-marker"), %w[other none]]]
    primary_cases.concat(MobileReleaseKit::NativeUploadProcess::REASONS.map do |kind|
      [MobileReleaseKit::NativeUploadProcess::LifecycleError.new(kind), ["native-lifecycle-error", kind]]
    end)
    primary_cases.concat(MobileReleaseKit::NativeProcessSpawn::CODES.map do |kind|
      [MobileReleaseKit::NativeProcessSpawn::Error.new(kind), ["native-spawn-error", kind]]
    end)
    primary_calls = []
    primary_cases.each do |error, expected|
      rig = make.call
      record = rig[:capture].instance_variable_get(:@failure)
      record.instance_variable_set(:@first_error, error)
      # Per-object replacement getters are not optional observation authority.
      [[rig[:session], :primary_error], [rig[:capture], :first_error], [record, :first_error],
       [record.instance_variable_get(:@lock), :synchronize]].each do |object, method|
        object.define_singleton_method(method) { primary_calls << method; raise "unexpected primary replacement getter" }
      end
      if error
        %i[kind code message].each do |method|
          error.define_singleton_method(method) { primary_calls << method; raise "unexpected primary error getter" }
        end
      end
      original_kind = error&.instance_variable_get(:@kind)
      kind_frozen = original_kind&.frozen?
      pair = primary_diagnostic.capture_primary(rig[:session])
      assert_equal expected, pair
      assert pair.frozen?
      assert primary_diagnostic.capture_primary_valid?(pair)
      assert_equal kind_frozen, original_kind.frozen? if original_kind
      refute error.frozen? if error
    end
    assert_empty primary_calls
    assert_equal %w[missing missing], primary_diagnostic.capture_primary(nil)
    [Object.new, Class.new(native.const_get(:CaptureSession, false)).allocate].each do |wrong_session|
      assert_equal %w[invalid invalid], primary_diagnostic.capture_primary(wrong_session)
    end
    primary_mutations = [
      ->(value) { value[:session].instance_variable_set(:@capture_slot, Object.new) },
      ->(value) { value[:capture].instance_variable_set(:@failure, Object.new) },
      ->(value) { value[:capture].instance_variable_get(:@failure).instance_variable_set(:@lock, Object.new) },
      ->(value) { value[:capture].instance_variable_get(:@failure).remove_instance_variable(:@first_error) },
      ->(value) { value[:capture].instance_variable_get(:@failure).instance_variable_set(:@first_error, "private-marker") },
      ->(value) { value[:capture].instance_variable_get(:@failure).instance_variable_set(:@first_error,
        fixture::Failure.new(1, "private-marker")) },
    ]
    primary_mutations.each do |mutate|
      rig = make.call
      mutate.call(rig)
      assert_equal %w[invalid invalid], primary_diagnostic.capture_primary(rig[:session])
    end
    rig = make.call
    Mutex.stub(:instance_method, ->(_) { raise IOError, "ordinary original operand read" }) do
      assert_equal %w[invalid invalid], primary_diagnostic.capture_primary(rig[:session])
    end
    original_interrupt = Interrupt.new("original optional interruption")
    Mutex.stub(:instance_method, ->(_) { raise original_interrupt }) do
      assert_same original_interrupt, assert_raises(Interrupt) { primary_diagnostic.capture_primary(rig[:session]) }
    end

    # The real original-return observe path runs with an inert install and base
    # snapshot only. Keep the actual Adapter subclass's slow snapshot additions.
    # Rebind retention to an isolated receiver; remove only this test's inert
    # object-key entry from the shared UNKNOWN diagnostic map in ensure.
    retain_case = fixture.instance_method(:retain_process_case!)
    retain_unknown = fixture.instance_method(:retain_unknown_domain!)
    exercise = lambda do |read_error: nil, primary: nil, session_present: true, snapshot_error: nil,
                          additions_error: nil, stored_primary: nil|
      current = observer_class.current
      assert_nil current
      rig = make.call
      original_record = rig[:capture].instance_variable_get(:@failure)
      original_record.instance_variable_set(:@first_error, stored_primary)
      root, registry = Object.new, Object.new.extend(fixture)
      observer = fixture::AdapterDriver::Observation.new(nil, native: native, root: root)
      observer.instance_variable_set(:@session, rig[:session]) if session_present
      observer.instance_variable_set(:@slow_enabled, true)
      observer.instance_variable_set(:@slow_handoff_performed, false)
      additions = observer.snapshot_additions
      base = {"version" => 1, "finalized" => true, "noProducers" => false,
        "settled" => true, "unknown" => false, "observerErrors" => []}.freeze
      observer.define_singleton_method(:install) do
        @hooks = UploadProcessFixture::CaptureObservation::Hooks.new # No wrapped methods.
        UploadProcessFixture::CaptureObservation.current = self
      end
      observer.define_singleton_method(:build_snapshot) do
        raise snapshot_error if snapshot_error
        @observer_errors.empty? ? base : base.merge("unknown" => true, "finalized" => false, "observerErrors" => @observer_errors.dup)
      end
      observer.define_singleton_method(:snapshot_additions) { raise additions_error } if additions_error
      rig[:acquisition].define_singleton_method(:state) { raise read_error } if read_error
      roots_defined = fixture.instance_variable_defined?(:@unresolved_roots)
      original_roots = fixture.instance_variable_get(:@unresolved_roots)
      prior_roots = (original_roots || {}).dup
      returned = Object.new
      fatal_read = read_error && !read_error.is_a?(StandardError)
      fatal_additions = additions_error && !additions_error.is_a?(StandardError)
      fatal = fatal_read || fatal_additions
      expected_error = primary || (fatal_additions ? additions_error : fatal_read ? read_error : snapshot_error || additions_error)
      invoke = -> { observer.observe { raise primary if primary; returned } }
      begin
        fixture.stub(:retain_process_case!, retain_case.bind(registry)) do
          fixture.stub(:retain_unknown_domain!, retain_unknown.bind(registry)) do
            if expected_error
              error_class = primary || fatal ? expected_error.class : fixture::Failure
              error = assert_raises(error_class, &invoke)
              assert_same expected_error, error if primary || fatal
            else
              assert_same returned, invoke.call
            end
          end
        end
        snapshot = observer.snapshot
        if additions_error
          refute snapshot.key?("slowCleanup")
          refute snapshot.key?("capturePrimary")
          refute snapshot.key?("readinessStage")
        else
          assert_equal additions.fetch("slowCleanup"), snapshot.fetch("slowCleanup")
          assert_equal additions.fetch("capturePrimary"), snapshot.fetch("capturePrimary")
          assert_equal "missing", snapshot.fetch("readinessStage")
        end
        assert_equal keys, snapshot.fetch("settlementChecks").keys
        if fatal || snapshot_error || additions_error
          assert snapshot.fetch("unknown")
          refute snapshot.fetch("finalized")
          refute snapshot.fetch("noProducers")
          assert_includes snapshot.fetch("observerErrors"), (additions_error || (fatal_read ? read_error : snapshot_error)).class.name
          if session_present
            assert registry.__send__(:domain_disposal_required?)
            assert_same observer, registry.instance_variable_get(:@retained_fixture_cases).fetch(observer.object_id)
          else
            refute registry.__send__(:domain_disposal_required?) # No actual install or session in this inert case.
          end
          assert fixture.cleanup_unresolved?(root)
        else
          assert_equal base, snapshot.reject { |key, _| %w[settlementChecks slowCleanup capturePrimary readinessStage].include?(key) }
          expected = session_present ? good : keys.to_h { |key| [key, "missing"] }
          expected = expected.merge("creationSettled" => "invalid", "acquisitionUnknown" => "invalid") if read_error
          assert_equal expected, snapshot.fetch("settlementChecks")
          refute registry.__send__(:domain_disposal_required?)
        end
        assert_equal keys.to_h { |key| [key, "invalid"] }, snapshot.fetch("settlementChecks") if fatal_read
        assert_equal keys.to_h { |key| [key, "missing"] }, snapshot.fetch("settlementChecks") unless session_present
        assert_nil observer.source_origins
        assert_nil observer.custodian_spec
        assert_empty observer.events
        %i[@slots @attempts @constructed_slots @actual_joins @actual_closes @actual_waits].each do |name|
          assert_empty observer.instance_variable_get(name)
        end
        assert_nil observer_class.current
        # Late mutable state cannot repair or resample the original snapshot.
        rig[:session].instance_variable_set(:@task_cleanup_complete, false)
        original_record.instance_variable_set(:@first_error, IOError.new("late primary cannot repair original snapshot"))
        assert_equal snapshot, observer.snapshot
      ensure
        roots = fixture.instance_variable_get(:@unresolved_roots)
        roots.delete(root) if roots # Only the just-created inert object identity.
        assert_equal prior_roots, roots || {}
        if original_roots.nil? && roots && roots.empty?
          roots_defined ? fixture.instance_variable_set(:@unresolved_roots, nil) : fixture.remove_instance_variable(:@unresolved_roots)
        end
        assert_same original_roots, fixture.instance_variable_get(:@unresolved_roots)
        assert_same current, observer_class.current
      end
    end
    exercise.call
    exercise.call(session_present: false)
    exercise.call(read_error: IOError.new("ordinary optional read"))
    exercise.call(read_error: IOError.new("ordinary optional read"), primary: RuntimeError.new("original primary"))
    [Interrupt.new("optional interruption"), SystemExit.new(23, "optional exit")].each do |error|
      exercise.call(read_error: error)
      exercise.call(read_error: error, primary: IOError.new("earlier primary"))
    end
    exercise.call(snapshot_error: IOError.new("original snapshot failed"))
    exercise.call(session_present: false, snapshot_error: IOError.new("no-session snapshot failed"))
    native_primary = MobileReleaseKit::NativeUploadProcess::LifecycleError.new("deadline")
    exercise.call(stored_primary: native_primary, primary: MobileReleaseKit::ContractError.new("redacted outer error"))
    exercise.call(stored_primary: native_primary, snapshot_error: IOError.new("later snapshot read failed"))
    exercise.call(additions_error: IOError.new("ordinary additions failed"))
    [Interrupt.new("additions interruption"), SystemExit.new(23, "additions exit")].each do |error|
      exercise.call(additions_error: error)
      exercise.call(additions_error: error, primary: IOError.new("earlier primary"))
    end
  end

  # The real publisher/ControlLease bodies run, but every filesystem/native
  # effect is replaced. IO.allocate has NO descriptor; all used IO methods are
  # inert singleton methods. Each invocation owns a separate model registry.
  def with_record_publication_model(directory: "/inert-record-parent/child", name: "ready.json",
                                    fault: nil, primary: IOError.new("original inert publication"), secondary: nil, state: {})
    fixture, owner, test = UploadProcessFixture, UploadProcessFixture::OwnedChild, self
    registry = Object.new.extend(fixture)
    registry.singleton_class.send(:public, *fixture.private_instance_methods(false))
    state[:events], state[:open_calls], state[:frames], state[:removed] = [], [], [], []
    state[:opens] ||= []
    state[:directory], state[:final], state[:registry] = directory, File.join(directory, name), registry
    staged = File.join(directory, ".mrk-record-#{name}.stage")
    state[:stage] = staged
    binding = Object.new.freeze # Cannot accidentally invoke a real native function.
    stat_type = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink, :size, :mtime, :ctime) do
      def file? = ftype == "file"
    end
    dir_stat = stat_type.new(1, 2, 0o40700, 3, 4, 0, "directory", 2, 0, 0, 0)
    file_stat = stat_type.new(1, 5, 0o100600, 3, 4, 0, "file", 1, 0, 0, 0)
    directory_io, stage_io = IO.allocate, IO.allocate
    state[:ios] = [directory_io, stage_io]
    [directory_io, stage_io].each_with_index do |io, index|
      io.define_singleton_method(:stat) { (index.zero? ? dir_stat : file_stat).dup }
      io.define_singleton_method(:fileno) { 91 + index }
      io.define_singleton_method(:closed?) { @inert_closed.equal?(true) }
      io.define_singleton_method(:close) do
        label = index.zero? ? :directory_close : :stage_close
        state[:events] << label
        test.refute @inert_closed, "original close must not be retried"
        raise primary if fault == label
        @inert_closed = true
        raise primary if fault == :"#{label}_after"
        raise secondary if index.zero? && secondary
        state[:events] << :"#{label}_returned"
        nil
      end
    end
    stage_io.define_singleton_method(:write) do |bytes|
      state[:events] << :write
      test.refute state[:published]
      raise primary if fault == :write_before
      state[:written] = fault == :short_write ? bytes.byteslice(0, bytes.bytesize - 1) : bytes
      file_stat.size = state[:written].bytesize
      raise primary if fault == :write_after
      fault == :short_write ? bytes.bytesize - 1 : bytes.bytesize
    end
    stage_io.define_singleton_method(:flush) do
      state[:events] << :flush
      test.refute state[:published]
      raise primary if fault == :flush
      self
    end
    original_retain = fixture.instance_method(:retain_process_case!).bind(registry)
    original_release = fixture.instance_method(:release_record_publication!).bind(registry)
    retain = lambda do |frame|
      state[:events] << :register
      state[:frames] << frame
      original_retain.call(frame)
    end
    release = lambda do |frame|
      state[:events] << :release
      assert frame.settled?
      original_release.call(frame)
    end
    opener = lambda do |path, flags, *mode|
      assert_equal 1, state[:frames].length # Custody published BEFORE actual open entry.
      assert registry.record_publication_unresolved?(directory)
      assert registry.cleanup_unresolved?(File.dirname(directory))
      refute registry.cleanup_unresolved?(nil)
      state[:open_calls] << [path, flags, mode]
      refute state[:published]
      if path == directory
        assert_equal File::RDONLY | File::NOFOLLOW | File::NONBLOCK, flags
        assert_empty mode
        state[:events] << :directory_open
        raise primary if fault == :directory_open
        directory_io
      else
        assert_equal staged, path
        assert_equal File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, flags
        assert_equal [0o600], mode
        state[:opens] << state[:final]
        state[:events] << :stage_open
        raise Errno::EEXIST if %i[stage_collision dangling_stage].include?(fault)
        raise primary if fault == :stage_open_after
        file_stat.nlink = 2 if fault == :stage_identity
        stage_io
      end
    end
    rename = lambda do |actual_binding, descriptor, source, destination|
      assert_same binding, actual_binding
      assert_equal [91, File.basename(staged), name], [descriptor, source, destination]
      frame = state[:frames].fetch(0)
      assert_equal :in_flight, frame.rename_state
      assert_equal :closed, frame.leases.last.state
      assert_includes state[:events], :stage_close_returned
      assert registry.record_publication_unresolved?(directory)
      state[:events] << :rename
      case fault
      when :rename_collision then [-1, Errno::EEXIST::Errno]
      when :rename_unavailable then [-1, Errno::ENOSYS::Errno]
      when :bad_return then [1, 0]
      when :bad_errno then [-1, 0]
      else
        state[:published] = state[:written].b
        raise primary if fault == :rename_after
        [0, 0]
      end
    end
    directory_check = lambda do |path|
      assert_equal directory, path
      stat = dir_stat.dup
      # Entry churn is legitimate; it must not be part of the pinned tuple.
      stat.nlink += state[:open_calls].length
      stat.size = stat.mtime = stat.ctime = state[:events].length
      stat.ino += 1 if fault == :directory_identity && state[:events].include?(:stage_open)
      stat
    end
    bindings = [[fixture, :owned_fixture_directory, directory_check],
      [fixture, :retain_process_case!, retain], [fixture, :release_record_publication!, release],
      [fixture, :retain_unknown_domain!, fixture.instance_method(:retain_unknown_domain!).bind(registry)],
      [fixture, :record_publication_unresolved?, fixture.instance_method(:record_publication_unresolved?).bind(registry)],
      [owner, :prepare_record_publication!, -> { state[:events] << :prepare; raise primary if fault == :prepare; binding }],
      [owner, :rename_record_exclusively, rename], [Process, :uid, 3], [File, :open, opener],
      [File, :lstat, ->(path) { assert_equal staged, path; file_stat.dup }],
      [File, :unlink, ->(*) { raise "publisher must not unlink" }],
      [File, :rename, ->(*) { raise "publisher must not use overwriting rename" }],
      [File, :link, ->(*) { raise "publisher must not publish a second link" }],
      [FileUtils, :remove_entry, ->(path) { state[:removed] << path }]]
    with_stubs = lambda do |index = 0, &body|
      if index == bindings.length
        body.call
      else
        receiver, method, replacement = bindings.fetch(index)
        receiver.stub(method, replacement) { with_stubs.call(index + 1, &body) }
      end
    end
    with_stubs.call { yield state }
  end

  def assert_record_publication_lifecycle
    owner, fixture = UploadProcessFixture::OwnedChild, UploadProcessFixture
    payload = {"version" => 1, "value" => "complete \u263a record"}
    with_record_publication_model do |state|
      assert_equal true, owner.write_record(state[:final], payload)
      serialized = JSON.generate(payload)
      assert_equal Encoding::UTF_8, serialized.encoding
      assert_equal Encoding::BINARY, state[:published].encoding
      assert_equal serialized.bytes, state[:published].bytes
      refute_equal serialized, state[:published] # Non-ASCII byte reads have a distinct encoding contract.
      assert_equal serialized.b, state[:published]
      changed = serialized.b
      changed.setbyte(0, changed.getbyte(0) ^ 1)
      refute_equal changed, state[:published]
      assert_equal %i[prepare register directory_open stage_open write flush stage_close stage_close_returned
                      rename directory_close directory_close_returned release], state[:events]
      assert_empty state[:registry].instance_variable_get(:@retained_fixture_cases)
      refute state[:registry].domain_disposal_required?
      refute state[:registry].cleanup_unresolved?(File.dirname(state[:directory]))
    end
    known = {short_write: "bootstrap record write incomplete", rename_collision: "bootstrap record publication refused",
             rename_unavailable: "bootstrap record publication unavailable"}
    known.each do |fault, message|
      with_record_publication_model(fault: fault) do |state|
        error = assert_raises(fixture::Failure) { owner.write_record(state[:final], payload) }
        assert_equal message, error.message
        assert state[:frames].first.settled?
        assert state[:ios].all?(&:closed?) # Only inert observations, never close authority.
        assert_empty state[:registry].instance_variable_get(:@retained_fixture_cases)
        refute state[:registry].domain_disposal_required?
        refute state[:published]
      end
    end
    %i[write_before write_after flush].each do |fault|
      original = IOError.new("original modeled write failure")
      with_record_publication_model(fault: fault, primary: original) do |state|
        assert_same original, assert_raises(IOError) { owner.write_record(state[:final], payload) }
        assert state[:frames].first.settled?
        assert_empty state[:registry].instance_variable_get(:@retained_fixture_cases)
        refute_includes state[:events], :rename
      end
    end
    unknown = %i[directory_open stage_open_after stage_collision dangling_stage stage_identity directory_identity
                 stage_close stage_close_after directory_close directory_close_after rename_after bad_return bad_errno]
    unknown.each do |fault|
      original = Interrupt.new("original modeled publication interruption")
      with_record_publication_model(fault: fault, primary: original) do |state|
        type = %i[stage_collision dangling_stage].include?(fault) ? Errno::EEXIST :
          %i[stage_identity directory_identity bad_return bad_errno].include?(fault) ? fixture::Failure : Interrupt
        error = assert_raises(type) { owner.write_record(state[:final], payload) }
        assert_same original, error if type == Interrupt
        frame = state[:frames].fetch(0)
        assert_same frame, state[:registry].instance_variable_get(:@retained_fixture_cases).fetch(frame.object_id)
        refute frame.settled?
        assert state[:registry].domain_disposal_required?
        assert state[:registry].cleanup_unresolved?(File.dirname(state[:directory]))
        assert state[:registry].cleanup_unresolved?(state[:directory])
        assert state[:registry].record_publication_unresolved?("/")
        refute state[:registry].cleanup_unresolved?("#{state[:directory]}-sibling")
        refute state[:registry].cleanup_unresolved?(nil)
        assert_raises(fixture::Failure) { state[:registry].assert_domain_reusable! }
        error = assert_raises(fixture::Failure) { owner.assert_record_publication_final!(File.dirname(state[:directory])) }
        assert_equal "bootstrap record publication remains unresolved", error.message
        state[:registry].stub(:fixture_entry_names, ->(*) { raise "guard must precede enumeration" }) do
          assert_raises(fixture::Failure) do
            state[:registry].remove_fixture_directory(File.dirname(state[:directory]), root: nil, layout: :joined_case)
          end
        end
        assert_empty state[:removed]
        assert_equal fault != :directory_open, state[:events].include?(:directory_close)
        assert_operator state[:events].count(:stage_close), :<=, 1
        assert_operator state[:events].count(:directory_close), :<=, 1
        assert_operator state[:events].count(:rename), :<=, 1
        # A corrupted enum/tag cannot make an actual retained frame invisible.
        frame.instance_variable_set(:@rename_state, :not_a_real_state)
        assert state[:registry].record_publication_unresolved?(state[:directory])
        if fault == :bad_errno
          [nil, "/owned/../else", "/owned/./child", "/owned//child", "/owned/", "relative", "/owned\0child"].each do |malformed|
            frame.instance_variable_set(:@directory, malformed&.freeze)
            assert state[:registry].record_publication_unresolved?("/unrelated-but-unknown"), malformed.inspect
          end
        end
      end
    end
    primary, secondary = SystemExit.new(19, "original modeled publication"), IOError.new("independent directory close")
    with_record_publication_model(fault: :write_before, primary: primary, secondary: secondary) do |state|
      assert_same primary, assert_raises(SystemExit) { owner.write_record(state[:final], payload) }
      assert_equal [secondary], state[:frames].first.cleanup_errors
      assert state[:registry].domain_disposal_required?
      refute_includes state[:events], :rename
    end
    with_record_publication_model(fault: :prepare, primary: primary) do |state|
      assert_same primary, assert_raises(SystemExit) { owner.write_record(state[:final], payload) }
      assert_empty state[:frames]
      assert_empty state[:open_calls]
    end
    with_record_publication_model do |state|
      [nil, "relative.json", "#{state[:directory]}/../bad.json", "#{state[:directory]}/bad\0.json",
       "#{state[:directory]}/#{'x' * 238}"].each do |path|
        assert_raises(fixture::Failure) { owner.write_record(path, payload) }
      end
      assert_raises(fixture::Failure) { owner.write_record(state[:final], {"x" => "y" * fixture::OUTPUT_LIMIT}) }
      assert_empty state[:events]
      fake_owner = {directory: state[:directory], rename_state: :unknown}
      state[:registry].retain_process_case!(fake_owner)
      refute state[:registry].record_publication_unresolved?(state[:directory])
      state[:registry].retain_unknown_domain!(nil)
      assert state[:registry].cleanup_unresolved?(nil) # Original nil-key semantics remain exact.
    end
    assert_record_publication_collector_guard
  end

  def assert_record_publication_collector_guard
    fixture, owner = UploadProcessFixture, UploadProcessFixture::OwnedChild
    directory = "/inert-record-collector/child"
    scope_type = Struct.new(:cleanup_depth) do
      def cleanup
        self.cleanup_depth += 1
        yield
      ensure
        self.cleanup_depth -= 1
      end
    end
    [nil, File.dirname(directory)].product([false, true]).each do |root, pending|
      registry = Object.new.extend(fixture)
      registry.singleton_class.send(:public, *fixture.private_instance_methods(false))
      if pending
        # An active frame with unattempted IO still excludes namespace disposal.
        frame = owner::RecordPublication.new("#{directory}/nested", {}, "ready.json", "", Object.new)
        registry.retain_process_case!(frame)
      end
      closes, removed, stops = [], [], []
      child = Object.new
      child.define_singleton_method(:stop) { stops << :original_model_stop }
      child.define_singleton_method(:complete?) { true }
      child.define_singleton_method(:streams_complete?) { true }
      scope = fixture::Lifetime.new(scope_type.new(0))
      # Skip the actual native body. These doubles model ONLY the existing
      # cleanup gate; no status/EOF returned here is offered as native evidence.
      scope.define_singleton_method(:active) { ["", "", 0] }
      lifetime = lambda do |**_, &body|
        value = body.call(scope)
        raise scope.primary if scope.primary
        value
      end
      opener = lambda do |path, flags, mode|
        assert_includes %w[stdout stderr].map { |name| File.join(directory, name) }, path
        assert_equal [File::WRONLY | File::CREAT | File::EXCL, 0o600], [flags, mode]
        io = IO.allocate
        io.define_singleton_method(:close) { closes << path }
        io
      end
      bindings = [[registry, :clock_ns, 1], [fixture, :clock_ns, 1], [registry, :command_lifetime, lifetime],
        [fixture, :record_publication_unresolved?, fixture.instance_method(:record_publication_unresolved?).bind(registry)],
        [File, :realpath, directory], [File, :open, opener],
        [owner, :directory_identity, {}], [owner, :new, child],
        [FileUtils, :remove_entry, ->(path) { removed << path }]]
      with_stubs = lambda do |index = 0, &body|
        if index == bindings.length
          body.call
        else
          receiver, method, replacement = bindings.fetch(index)
          receiver.stub(method, replacement) { with_stubs.call(index + 1, &body) }
        end
      end
      # Object#stub uses one alias per method: nesting another mktmpdir stub
      # would destroy the outer acquisition veto's alias during restoration.
      directory_hook = fixture::CaptureObservation::Hooks.new
      begin
        directory_hook.wrap(Dir.singleton_class, :mktmpdir) do |_original, _receiver, arguments, keywords, block|
          assert_equal ["mrk-process-observation-", root], arguments
          assert_empty keywords
          assert_nil block
          directory # Fixed in-memory namespace; never call the original veto or Dir implementation.
        end
        with_stubs.call do
          if pending
            error = assert_raises(fixture::Failure) { registry.capture_command(["inert-never-dispatched"], root: root) }
            assert_equal "bootstrap record publication remains unresolved", error.message
            assert_empty removed
            assert registry.cleanup_unresolved?(root)
          else
            assert_equal ["", "", 0], registry.capture_command(["inert-never-dispatched"], root: root)
            assert_equal [directory], removed
          end
        end
      ensure
        assert_empty directory_hook.restore # Restore the exact pre-existing outer veto, not an alias guess.
      end
      assert_equal %w[stdout stderr].map { |name| File.join(directory, name) }, closes
      assert_equal [:original_model_stop], stops
    end
  end

  def assert_native_record_publication
    owner = UploadProcessFixture::OwnedChild
    directory = File.realpath(Dir.mktmpdir("record-publication-", @root))
    identity = owner.directory_identity(directory)
    payload = {"version" => 1, "value" => "closed complete \u263a bytes"}
    final = File.join(directory, "ready.json")
    captured = []
    original = owner.method(:rename_record_exclusively)
    observe = lambda do |binding, descriptor, staged, name|
      frame = UploadProcessFixture.instance_variable_get(:@retained_fixture_cases).values.find do |candidate|
        candidate.instance_of?(owner::RecordPublication) && candidate.directory == directory
      end
      refute_nil frame
      assert_equal :closed, frame.leases.last.state
      assert frame.leases.last.io.closed? # Observation only; publisher used original ControlLease return.
      assert_equal frame.leases.first.io.fileno, descriptor
      stat = File.lstat(File.join(directory, staged))
      assert_equal [0o600, 1], [stat.mode & 0o7777, stat.nlink]
      assert_equal JSON.generate(payload).b, owner.bounded_file(File.join(directory, staged))
      assert_raises(Errno::ENOENT) { File.lstat(final) } if captured.empty?
      captured << owner.identity(stat)
      original.call(binding, descriptor, staged, name)
    end
    owner.stub(:rename_record_exclusively, observe) do
      assert_equal true, owner.write_record(final, payload)
      assert_equal captured.first, owner.identity(File.lstat(final))
      assert_equal JSON.generate(payload).b, owner.bounded_file(final)
      refute File.exist?(File.join(directory, ".mrk-record-ready.json.stage"))
      refused = assert_raises(UploadProcessFixture::Failure) { owner.write_record(final, payload) }
      assert_equal "bootstrap record publication refused", refused.message
      assert_equal captured.first, owner.identity(File.lstat(final))
      assert_equal JSON.generate(payload).b, owner.bounded_file(final)
      assert_equal captured.last, owner.identity(File.lstat(File.join(directory, ".mrk-record-ready.json.stage")))
      refute UploadProcessFixture.record_publication_unresolved?(directory)
      link = File.join(directory, "dangling.json")
      File.symlink("absent-target", link)
      refused = assert_raises(UploadProcessFixture::Failure) { owner.write_record(link, payload) }
      assert_equal "bootstrap record publication refused", refused.message
      assert File.lstat(link).symlink?
      assert_equal "absent-target", File.readlink(link)
      refute File.exist?(File.join(directory, "absent-target"))
    end
    assert_equal identity, owner.directory_identity(directory)
    owner.assert_record_publication_final!(directory)
    refute UploadProcessFixture.domain_disposal_required?
    FileUtils.remove_entry(directory) # No tasks; all original publication IO/renames have settled.
  end

  def assert_adapter_failure_projection
    # Pure operands and the real shared wrapper/Lifetime only. These anonymous
    # receivers model callback names; no adapter test class or native owner runs.
    callback_modes = {
      "test_deadline_terminates_validator_without_authorizing_upload" => %w[real-deadline],
      "test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits" => %w[inherited],
      "test_descendant_boundary_survives_delayed_start_and_late_parent_record" => %w[delayed-start late-record],
      "test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record" => %w[unready],
      "test_fixture_detects_leader_only_cleanup_and_missing_deadline" => %w[leader-only no-deadline],
      "test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed" => %w[immediate-deadline],
      "test_slow_cleanup_cannot_supply_a_positive_deadline_wait" => %w[real-deadline-slow-cleanup immediate-deadline-slow-cleanup],
    }
    classes = {"ios" => "IosUploadValidationTest", "android" => "AndroidUploadValidationTest"}
    expected_kinds = {"real-deadline" => "pass", "inherited" => "pass", "delayed-start" => "pass", "late-record" => "pass",
      "unready" => "readiness", "leader-only" => "descendant-alive", "no-deadline" => "capture-watchdog",
      "immediate-deadline" => "elapsed-bound", "real-deadline-slow-cleanup" => "pass", "immediate-deadline-slow-cleanup" => "elapsed-bound"}
    fields = %w[schema platform mode expectedKind failedPredicates resultKind driverExitStatus retainedDriverErrorCategory
      retainedDriverErrorCode adapterErrorCategory resultChecks nativeChecks timingChecks nativeOutcomes slowChecks captureDetail readinessStage]
    stages = %w[not-entered native-ready startup-marker validator-marker validator-live dispatch control-admission
      startup-driver-loss descendant-fork descendant-marker descendant-live inherited-pipes descendant-driver-loss
      validator-release owner-publication ready-return]
    result_keys = %w[ready stdinClosedAfterReady deadlinePrimarySameObject deadlineResultSameObject watchdogStarted watchdogIntervened
      fallbackUsed deadBeforeFallback nativeFinalityBeforeFallback adapterRejected adapterCallObserved captureEntered descendantLiveBeforeRelease
      inheritedPipeBlockObserved validatorReapedAfterRelease commitAfterDataEOF ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined
      handlersRestored registryInactive pendingInterrupt cleanupErrorsEmpty]
    native_keys = %w[finalized noProducers settled unknown hooksRestored observerErrorsEmpty productionFinality retainedUnknown
      statusValid statusDecodedEOF cleanupErrorsEmpty originalWaitObserved tasksJoined leasesClosed allActualEOFObserved
      captureSettled captureFinished captureJoined captureActualJoinObserved creatorSettled creatorFinished creatorJoined
      creatorActualJoinObserved stdoutEOF stdoutActualEOFObserved stderrEOF stderrActualEOFObserved statusEOF statusActualEOFObserved groupAbsent]
    timing_keys = %w[runSpanMatchesMode firstTimeoutCutoff selectedTimeoutCutoff blockedDataWaitsPositive firstBlockedDataWithinRun
      captureWithinLimit slowCleanupAtLeastFour captureCoversSlowCleanup slowCleanupWithinOriginalCutoff]
    outcome_keys = %w[custodian keeper validator finalOutcome finalCleanup groupState captureState creatorState]
    slow_keys = %w[handoffPerformed delayEntered delayGuardPassed delayFailed delayFinished originalCleanupCalled originalCleanupFinished]
    assert_equal expected_kinds, UploadProcessFixture::ADAPTER_FAILURE_EXPECTED_KINDS
    assert_equal classes.values.flat_map { |class_name| callback_modes.map { |suffix, modes| ["#{class_name}##{suffix}", modes] } }.to_h,
      UploadProcessFixture::ADAPTER_FAILURE_CALLBACK_MODES
    assert_equal fields, UploadProcessFixture::ADAPTER_FAILURE_FIELDS
    assert_equal stages, UploadProcessFixture::ADAPTER_READINESS_STAGES
    assert UploadProcessFixture::ADAPTER_READINESS_STAGES.all?(&:frozen?)
    assert_equal result_keys, UploadProcessFixture::ADAPTER_FAILURE_RESULT_CHECKS
    assert_equal native_keys, UploadProcessFixture::ADAPTER_FAILURE_NATIVE_CHECKS
    assert_equal timing_keys, UploadProcessFixture::ADAPTER_FAILURE_TIMING_CHECKS
    assert_equal outcome_keys, UploadProcessFixture::ADAPTER_FAILURE_NATIVE_OUTCOMES.keys
    assert_equal slow_keys, UploadProcessFixture::ADAPTER_FAILURE_SLOW_CHECKS
    assert_equal "MRK_ADAPTER_FAILURE=", UploadProcessFixture::ADAPTER_FAILURE_PREFIX
    status_class = Struct.new(:exitstatus) # Already-read comparison data, not a Process::Status receipt.
    status = status_class.new(1)
    start, cutoff = 100, 12_000_000_100
    raw = result_keys.reject { |key| key == "cleanupErrorsEmpty" }.to_h { |key| [key, true] }
    raw.merge!("kind" => "fixture-cleanup", "errorClass" => "UploadProcessFixture::Failure",
      "error" => "actual ready timeout cause was not observed", "adapterErrorClass" => "MobileReleaseKit::ContractError",
      "cleanupErrors" => ["private-marker"], "private" => "private-marker", "pid" => 999_887_766,
      "nativeObservation" => native_keys.reject { |key| key == "observerErrorsEmpty" }.to_h { |key| [key, false] }.merge(
        "observerErrors" => [], "private" => "private-marker",
        "settlementChecks" => {"taskCleanupComplete" => true, "creationSettled" => false, "custodianWaitBroken" => "missing", "acquisitionUnknown" => "invalid"},
        "protocolContext" => {"hello" => {}, "reserved" => nil, "ready" => {}},
        "capturePrimary" => %w[contract-error none], "readinessStage" => "validator-live",
        "custodian" => {"state" => "reaped", "status_kind" => "exit", "status_code" => 2},
        "final" => {"outcome" => "failed", "cleanup" => "confirmed", "group" => {"state" => "retired", "absent" => true},
          "keeper" => {"state" => "reaped", "status_kind" => "exit", "status_code" => 2},
          "validator" => {"state" => "reaped", "status_kind" => "signal", "status_code" => 9}},
        "tasks" => [{"role" => "capture", "state" => "attempted"}, {"role" => "creator", "state" => "not_started"}],
        "slowCleanup" => slow_keys.to_h { |key| [key, key != "delayFailed"] }.merge("slowCleanupSeconds" => 4.0,
          "delayStartedNs" => 2_000_000_000, "delayFinishedNs" => 6_000_000_000,
          "originalCleanupFinishedNs" => 6_000_000_000, "originalCleanupCutoffNs" => 7_000_000_000)),
      "nativeStartedNs" => start, "nativeRunDeadlineNs" => cutoff, "firstTimeoutDecisionNs" => cutoff - 1,
      "selectedTimeoutNs" => cutoff, "blockedDataWaits" => 2, "firstBlockedDataNs" => start + 1,
      "captureSeconds" => 6.0, "slowCleanupSeconds" => 999.0) # Mutable driver data is NOT the slow snapshot authority.
    formatter = UploadProcessFixture.method(:adapter_failure_line)
    expected = {"schema" => 3, "platform" => "ios", "mode" => "real-deadline", "expectedKind" => "pass",
      "failedPredicates" => %w[result-kind driver-status], "resultKind" => "fixture-cleanup", "driverExitStatus" => 1,
      "retainedDriverErrorCategory" => "fixture-error", "retainedDriverErrorCode" => "ready-timeout-unobserved",
      "adapterErrorCategory" => "contract-error", "resultChecks" => result_keys.to_h { |key| [key, key != "cleanupErrorsEmpty"] },
      "nativeChecks" => native_keys.to_h { |key| [key, key == "observerErrorsEmpty"] },
      "timingChecks" => {"runSpanMatchesMode" => true, "firstTimeoutCutoff" => "before-cutoff", "selectedTimeoutCutoff" => "at-or-after-cutoff",
        "blockedDataWaitsPositive" => true, "firstBlockedDataWithinRun" => true, "captureWithinLimit" => true,
        "slowCleanupAtLeastFour" => true, "captureCoversSlowCleanup" => true, "slowCleanupWithinOriginalCutoff" => true},
      "nativeOutcomes" => {"custodian" => "exit2", "keeper" => "exit2", "validator" => "signal", "finalOutcome" => "failed",
        "finalCleanup" => "confirmed", "groupState" => "retired", "captureState" => "attempted", "creatorState" => "not-started"},
      "slowChecks" => slow_keys.to_h { |key| [key, key != "delayFailed"] },
      "captureDetail" => ["contract-error", "1" * 23 + "0", "1ba111111", "10mx", "101", %w[contract-error none]],
      "readinessStage" => "validator-live"}
    classes.each_key do |platform|
      packet = formatter.call(platform: platform, mode: "real-deadline", result: raw, status: status)
      assert_equal "MRK_ADAPTER_FAILURE=#{JSON.generate(expected.merge("platform" => platform))}\n", packet
      assert packet.ascii_only?
      assert packet.frozen?
      assert_operator packet.bytesize, :<=, 4096
      %w[private-marker 999887766 12000000100].each { |private_value| refute_includes packet, private_value }
      refute_includes packet, raw.fetch("error")
    end
    project = lambda do |value, mode: "real-deadline", code: 1|
      packet = formatter.call(platform: "ios", mode: mode, result: value, status: status_class.new(code))
      JSON.parse(packet.delete_prefix("MRK_ADAPTER_FAILURE=")) if packet
    end
    assert_equal UploadProcessFixture::OwnershipFailureDiagnostic.capture_detail(raw,
      projected: UploadProcessFixture.adapter_result_projection(mode: "real-deadline", result: raw)),
      expected.fetch("captureDetail")
    (stages + %w[missing invalid]).each do |stage|
      native = raw.fetch("nativeObservation").merge("readinessStage" => stage.dup)
      assert_equal stage, project.call(raw.merge("nativeObservation" => native)).fetch("readinessStage")
    end
    [nil, true, 1, [], {}, "private-marker"].each do |stage|
      native = raw.fetch("nativeObservation").merge("readinessStage" => stage)
      row = project.call(raw.merge("nativeObservation" => native))
      assert_equal "invalid", row.fetch("readinessStage")
      refute_includes JSON.generate(row), "private-marker"
    end
    assert_equal "missing", project.call(raw.merge("nativeObservation" => {})).fetch("readinessStage")
    expected_kinds.each do |mode, kind|
      accepted_status = kind == "pass" ? 0 : 1
      assert_nil project.call(raw.merge("kind" => kind), mode: mode, code: accepted_status)
      row = project.call(raw.merge("kind" => kind), mode: mode, code: 255)
      assert_equal [kind, ["driver-status"]], row.values_at("expectedKind", "failedPredicates")
    end
    assert_equal ["result-kind"], project.call(raw, code: 0).fetch("failedPredicates")
    assert_equal "other", project.call(raw.merge("kind" => "private-marker")).fetch("resultKind")
    assert_equal "invalid", project.call(raw.merge("kind" => nil)).fetch("resultKind")
    [nil, true, -1, 256, 1.0].each { |code| assert_nil formatter.call(platform: "ios", mode: "real-deadline", result: raw, status: status_class.new(code)) }
    assert_nil formatter.call(platform: "ios", mode: "real-deadline", result: Class.new(Hash).new.merge!(raw), status: status)
    [["native", "real-deadline"], ["ios", "native-setup-interrupt"], ["android", "ownership-async"], ["ios", "kill-startup"]].each do |platform, mode|
      assert_nil formatter.call(platform: platform, mode: mode, result: raw, status: status)
    end

    # The retained driver pair is independent of a cleanup-overridden kind. Only
    # exact persisted literals select codes; private lookalikes remain unquoted.
    [
      ["MobileReleaseKit::NativeUploadProcess::LifecycleError", "native capture deadline failure", "native-lifecycle-error", "native-deadline"],
      ["MobileReleaseKit::NativeUploadProcess::ProtocolError", "native capture protocol failure", "native-protocol-error", "native-protocol"],
      ["MobileReleaseKit::NativeUploadProcess::ProtocolError", "native capture deadline failure", "native-protocol-error", "other"],
      ["MobileReleaseKit::NativeProcessSpawn::Error", "native process close failure", "native-spawn-error", "spawn-close"],
      ["UploadProcessFixture::Failure", "adapter preparation missed original entry budget", "fixture-error", "adapter-entry-budget"],
      ["UploadProcessFixture::Failure", "adapter entry original session or clocks changed", "fixture-error", "adapter-entry-binding"],
      ["UploadProcessFixture::Failure", "adapter entry missed original one-second window", "fixture-error", "adapter-entry-window"],
      ["UploadProcessFixture::Failure", "adapter entry lacks original completion reserve", "fixture-error", "adapter-entry-reserve"],
      ["UploadProcessFixture::Failure", "adapter readiness missed original cutoff", "fixture-error", "adapter-readiness-budget"],
      ["UploadProcessFixture::Failure", "private-marker actual ready timeout cause was not observed", "fixture-error", "other"],
      ["private-marker", "private-marker", "other", "other"],
      [nil, nil, "none", "none"], [nil, "private-marker", "none", "invalid"],
      ["UploadProcessFixture::Failure", nil, "fixture-error", "invalid"], [false, "private-marker", "invalid", "invalid"],
    ].each do |class_name, message, category, code|
      row = project.call(raw.merge("errorClass" => class_name, "error" => message))
      assert_equal [category, code], row.values_at("retainedDriverErrorCategory", "retainedDriverErrorCode")
      refute_includes JSON.generate(row), "private-marker"
    end
    owned_codes = UploadProcessFixture::ADAPTER_FAILURE_OWNED_CODES
    assert_equal 49, owned_codes.length
    assert_equal 49, owned_codes.values.uniq.length
    assert_operator owned_codes.values.map(&:bytesize).max, :<=, 26
    owned_codes.each do |message, code|
      row = project.call(raw.merge("errorClass" => "UploadProcessFixture::Failure", "error" => message))
      assert_equal ["fixture-error", code], row.values_at("retainedDriverErrorCategory", "retainedDriverErrorCode")
      refute_includes JSON.generate(row), message
      row = project.call(raw.merge("errorClass" => "IOError", "error" => message))
      assert_equal ["io-error", "other"], row.values_at("retainedDriverErrorCategory", "retainedDriverErrorCode")
      row = project.call(raw.merge("errorClass" => "UploadProcessFixture::Failure", "error" => "private-marker #{message}"))
      assert_equal "other", row.fetch("retainedDriverErrorCode")
      refute_includes JSON.generate(row), "private-marker"
    end
    missing = project.call({})
    assert_equal ["missing"] * 4, missing.values_at("resultKind", "retainedDriverErrorCategory", "retainedDriverErrorCode", "adapterErrorCategory")
    %w[resultChecks nativeChecks timingChecks nativeOutcomes slowChecks].each { |key| assert_equal ["missing"], missing.fetch(key).values.uniq }
    assert_equal ["missing", "m" * 24, "m" * 9, "m" * 4, "m" * 3, %w[missing missing]], missing.fetch("captureDetail")
    assert_equal "missing", missing.fetch("readinessStage")
    assert_equal "missing", project.call(raw.reject { |key, _| key == "errorClass" }).fetch("retainedDriverErrorCode")
    malformed = raw.merge(result_keys.to_h { |key| [key, "private-marker"] }).merge("cleanupErrors" => nil, "nativeObservation" => nil)
    invalid = project.call(malformed)
    assert_equal ["invalid"], invalid.fetch("resultChecks").values.uniq
    assert_equal ["invalid"], invalid.fetch("nativeChecks").values.uniq
    assert_equal ["invalid"], invalid.fetch("nativeOutcomes").values.uniq
    assert_equal ["invalid"], invalid.fetch("slowChecks").values.uniq
    assert_equal "invalid", invalid.fetch("readinessStage")
    false_checks = raw.merge(result_keys.to_h { |key| [key, false] }).merge("cleanupErrors" => [])
    assert_equal result_keys.to_h { |key| [key, key == "cleanupErrorsEmpty"] }, project.call(false_checks).fetch("resultChecks")

    # Original first construction and selected primary are separate observations.
    # These are scalar vectors; no clock or runtime deadline is changed by them.
    [[start - 1, "before-start"], [start, "before-cutoff"], [cutoff, "at-or-after-cutoff"]].each do |time, relation|
      row = project.call(raw.merge("firstTimeoutDecisionNs" => time)).fetch("timingChecks")
      assert_equal [relation, "at-or-after-cutoff"], row.values_at("firstTimeoutCutoff", "selectedTimeoutCutoff")
    end
    [0, true, start.to_f, 2**63].each do |time|
      assert_equal "invalid", project.call(raw.merge("selectedTimeoutNs" => time)).fetch("timingChecks").fetch("selectedTimeoutCutoff")
    end
    row = project.call(raw.reject { |key, _| key == "firstTimeoutDecisionNs" }.merge("nativeStartedNs" => 0)).fetch("timingChecks")
    assert_equal ["missing", "invalid"], row.values_at("firstTimeoutCutoff", "selectedTimeoutCutoff")
    assert_equal "invalid", project.call(raw.merge("nativeRunDeadlineNs" => start)).fetch("timingChecks").fetch("runSpanMatchesMode")
    assert_equal false, project.call(raw, mode: "no-deadline").fetch("timingChecks").fetch("runSpanMatchesMode")
    assert_equal true, project.call(raw.merge("nativeRunDeadlineNs" => start + 20_000_000_000), mode: "no-deadline").fetch("timingChecks").fetch("runSpanMatchesMode")
    [[0, false], [-1, "invalid"], [1.0, "invalid"]].each do |count, expected_value|
      assert_equal expected_value, project.call(raw.merge("blockedDataWaits" => count)).fetch("timingChecks").fetch("blockedDataWaitsPositive")
    end
    [[start, true], [cutoff, false], [nil, "invalid"]].each do |time, expected_value|
      assert_equal expected_value, project.call(raw.merge("firstBlockedDataNs" => time)).fetch("timingChecks").fetch("firstBlockedDataWithinRun")
    end
    [[18, false], [Float::INFINITY, "invalid"], [Float::NAN, "invalid"], [-1, "invalid"], [nil, "invalid"]].each do |seconds, expected_value|
      assert_equal expected_value, project.call(raw.merge("captureSeconds" => seconds)).fetch("timingChecks").fetch("captureWithinLimit")
    end
    with_slow = lambda do |value|
      raw.merge("nativeObservation" => raw.fetch("nativeObservation").merge("slowCleanup" => value))
    end
    slow_snapshot = raw.fetch("nativeObservation").fetch("slowCleanup")
    row = project.call(with_slow.call(slow_snapshot.merge("slowCleanupSeconds" => 3.5)).merge("captureSeconds" => 3)).fetch("timingChecks")
    assert_equal [false, false], row.values_at("slowCleanupAtLeastFour", "captureCoversSlowCleanup")
    row = project.call(with_slow.call(slow_snapshot.reject { |key, _| key == "slowCleanupSeconds" }).merge("captureSeconds" => nil)).fetch("timingChecks")
    assert_equal ["missing", "missing"], row.values_at("slowCleanupAtLeastFour", "captureCoversSlowCleanup")
    assert_equal expected.fetch("timingChecks"), project.call(raw.merge("slowCleanupSeconds" => -1)).fetch("timingChecks")
    [Float::INFINITY, Float::NAN, nil, -1, true].each do |duration|
      row = project.call(with_slow.call(slow_snapshot.merge("slowCleanupSeconds" => duration))).fetch("timingChecks")
      assert_equal ["invalid", "invalid"], row.values_at("slowCleanupAtLeastFour", "captureCoversSlowCleanup")
    end
    [{"originalCleanupFinishedNs" => 2_000_000_000}, {"delayFinishedNs" => 6_999_999_999}].each do |change|
      row = project.call(with_slow.call(slow_snapshot.merge(change))).fetch("timingChecks")
      assert_equal true, row.fetch("slowCleanupWithinOriginalCutoff")
    end
    [{"originalCleanupFinishedNs" => 1_999_999_999}, {"originalCleanupFinishedNs" => 6_000_000_001},
     {"delayFinishedNs" => 5_999_999_999}, {"delayFinishedNs" => 7_000_000_000},
     {"delayStartedNs" => 6_000_000_001}].each do |change|
      row = project.call(with_slow.call(slow_snapshot.merge(change))).fetch("timingChecks")
      assert_equal false, row.fetch("slowCleanupWithinOriginalCutoff")
    end
    %w[delayStartedNs originalCleanupFinishedNs delayFinishedNs originalCleanupCutoffNs].each do |key|
      row = project.call(with_slow.call(slow_snapshot.reject { |name, _| name == key })).fetch("timingChecks")
      assert_equal "missing", row.fetch("slowCleanupWithinOriginalCutoff")
      [nil, 1.0, true, 0].each do |invalid|
        row = project.call(with_slow.call(slow_snapshot.merge(key => invalid))).fetch("timingChecks")
        assert_equal "invalid", row.fetch("slowCleanupWithinOriginalCutoff")
      end
    end
    slow_keys.each do |key|
      assert_equal false, project.call(with_slow.call(slow_snapshot.merge(key => false))).fetch("slowChecks").fetch(key)
      assert_equal "invalid", project.call(with_slow.call(slow_snapshot.merge(key => nil))).fetch("slowChecks").fetch(key)
      assert_equal "missing", project.call(with_slow.call(slow_snapshot.reject { |name, _| name == key })).fetch("slowChecks").fetch(key)
    end
    child_vectors = [[{}, "missing"], [nil, "invalid"], [{"state" => "unknown"}, "unknown"],
      [{"state" => "not_attempted"}, "not-attempted"], [{"state" => "private-marker"}, "invalid"],
      [{"state" => :unknown}, "invalid"], [{"state" => "reaped", "status_kind" => :exit, "status_code" => 0}, "invalid"]]
    [0, 1, 2, 3, 255, 256, true].each do |code|
      category = code.instance_of?(Integer) && code.between?(0, 255) ? (code <= 2 ? "exit#{code}" : "other-exit") : "invalid"
      child_vectors << [{"state" => "reaped", "status_kind" => "exit", "status_code" => code}, category]
    end
    child_vectors << [{"state" => "reaped", "status_kind" => "signal", "status_code" => 9}, "signal"]
    %w[custodian keeper validator].each do |role|
      child_vectors.each do |record, category|
        native = raw.fetch("nativeObservation").dup
        if role == "custodian"
          native[role] = record
        else
          native["final"] = native.fetch("final").merge(role => record)
        end
        assert_equal category, project.call(raw.merge("nativeObservation" => native)).fetch("nativeOutcomes").fetch(role)
      end
    end
    {"finalOutcome" => ["outcome", %w[ok rejected failed]], "finalCleanup" => ["cleanup", %w[confirmed unknown]]}.each do |key, (field, values)|
      (values + ["private-marker", nil]).each do |value|
        native = raw.fetch("nativeObservation").merge("final" => raw.fetch("nativeObservation").fetch("final").merge(field => value))
        assert_equal values.include?(value) ? value : "invalid", project.call(raw.merge("nativeObservation" => native)).fetch("nativeOutcomes").fetch(key)
      end
    end
    %w[not_created retired unknown].each do |state|
      native = raw.fetch("nativeObservation").merge("final" => raw.fetch("nativeObservation").fetch("final").merge("group" => {"state" => state}))
      assert_equal state.tr("_", "-"), project.call(raw.merge("nativeObservation" => native)).fetch("nativeOutcomes").fetch("groupState")
    end
    %w[capture creator].each do |role|
      %w[unpublished not_constructed not_started attempted].each do |state|
        native = raw.fetch("nativeObservation").merge("tasks" => [{"role" => role, "state" => state}])
        assert_equal state.tr("_", "-"), project.call(raw.merge("nativeObservation" => native)).fetch("nativeOutcomes").fetch("#{role}State")
      end
      [nil, [false], [{"role" => role, "state" => "attempted"}] * 2].each do |records|
        native = raw.fetch("nativeObservation").merge("tasks" => records)
        assert_equal "invalid", project.call(raw.merge("nativeObservation" => native)).fetch("nativeOutcomes").fetch("#{role}State")
      end
    end
    no_final = project.call(raw.merge("nativeObservation" => raw.fetch("nativeObservation").merge("final" => nil))).fetch("nativeOutcomes")
    assert_equal ["missing"] * 5, no_final.values_at("keeper", "validator", "finalOutcome", "finalCleanup", "groupState")

    exercise = lambda do |platform: "ios", selected: "real-deadline", class_name: nil, method_name: nil,
                            write_result: :full, expiry: nil, mutate: nil, publication_error: nil, projection_error: nil,
                            callback_error: nil, cleanup_error: nil, restoration_error: nil, prior_error: nil|
      class_name ||= classes.fetch(platform)
      method_name ||= callback_modes.find { |_suffix, modes| modes.include?(selected) }.first
      callback = "#{class_name}##{method_name}"
      now, sequence, depth = 1, nil, 0
      state = escaped = dispatch = nil
      events, writes, projections, observations, cleanup_messages = [], [], [], [], []
      policy = Object.new
      policy.define_singleton_method(:install) { events << :install }
      policy.define_singleton_method(:cleanup_depth) { depth }
      policy.define_singleton_method(:cleanup) do |&body|
        depth += 1
        begin
          body.call
        ensure
          depth -= 1
        end
      end
      policy.define_singleton_method(:restore) { |&body| body.call; events << :restored }
      policy.define_singleton_method(:errors) { restoration_error ? [restoration_error] : [] }
      policy.define_singleton_method(:replay_custom_pending) { events << :replay }
      receiver = Object.new.extend(UploadProcessFixture::Contracts)
      receiver.define_singleton_method(:name) { events << :callback; raise callback_error if callback_error; method_name }
      run = lambda do |**optional|
        dispatch, state = optional, optional.fetch(:adapter_failure_state)
        events << :run
        begin
          UploadProcessFixture.lifetime(deadline_ns: 10) do |frame|
            # Retain synthetic cleanup diagnostics privately, without an extra
            # real STDERR channel competing with the reporter under test.
            frame.define_singleton_method(:warn) { |message| cleanup_messages << message }
            frame.remember(prior_error) if prior_error
            begin
              frame.active do
                reject = -> { UploadProcessFixture.reject_adapter_result!(platform: platform, mode: selected, result: raw,
                  status: status, deadline_ns: 10, state: state) }
                if publication_error
                  original_writer = state.method(:[]=)
                  state.stub(:[]=, ->(key, value) { raise publication_error if key == :mode; original_writer.call(key, value) }) { reject.call }
                else
                  reject.call
                end
              end
            ensure
              frame.cleanup { events << :cleanup; raise cleanup_error if cleanup_error }
            end
          end
        rescue Exception => error
          escaped = error
          raise
        ensure
          mutate.call(state) if mutate
          events << :unwound
          now = 10 if expiry == :before_report
          sequence = [1, 10] if expiry == :before_write
        end
      end
      sink = lambda do |packet|
        observations << [state[:rejection], state[:report_attempted], state[:write_attempted], events.dup,
          UploadProcessFixture.instance_variable_get(:@cancellation_scope)]
        writes << packet
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : packet.bytesize
      end
      projection = lambda do |**arguments|
        projections << arguments
        raise projection_error if projection_error
        formatter.call(**arguments)
      end
      actual = nil
      expected_error = (prior_error || publication_error)&.class || UploadProcessFixture::Failure
      UploadProcessFixture::CancellationScope.stub(:new, policy) do
        Thread.current.stub(:pending_interrupt?, false) do
          UploadProcessFixture.stub(:clock_ns, -> { sequence ? sequence.shift || now : now }) do
            receiver.stub(:class, Struct.new(:name).new(class_name)) do
              UploadProcessFixture.stub(:adapter_failure_line, projection) do
                STDERR.stub(:write, sink) do
                  actual = assert_raises(expected_error) do
                    receiver.with_adapter_failure_diagnostic(platform: platform, mode: selected) { |optional| run.call(**optional) }
                  end
                  # A renewed test clock cannot reopen an already attempted
                  # optional report, even when the first attempt produced nothing.
                  now, sequence = 1, nil
                  UploadProcessFixture.report_adapter_failure(state, actual, platform: platform, mode: selected, callback: callback)
                end
              end
            end
          end
        end
      end
      assert_same escaped, actual
      assert_equal [:adapter_failure_state], dispatch.keys
      assert_equal %i[run install cleanup restored replay unwound], events.reject { |event| event == :callback }
      assert events.each_index.select { |index| events[index] == :callback }.all? { |index| index > events.index(:unwound) }
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      assert_operator writes.length, :<=, 1
      assert_operator projections.length, :<=, 1
      assert_equal cleanup_error ? 1 : 0, cleanup_messages.length
      observations.each do |original, attempted, writing, prior, scope|
        assert_same actual, original
        assert_equal [true, true, events, nil], [attempted, writing, prior, scope]
      end
      writes.each { |packet| assert_equal formatter.call(platform: platform, mode: selected, result: raw, status: status), packet }
      {state: state, original: actual, writes: writes, projections: projections}
    end
    cases = [exercise.call, exercise.call(platform: "android", selected: "immediate-deadline-slow-cleanup")]
    cases.each do |outcome|
      state = outcome.fetch(:state)
      assert_equal 1, outcome.fetch(:writes).length
      assert_same raw, state.fetch(:result)
      assert_same status, state.fetch(:status)
      assert_same outcome.fetch(:original), state.fetch(:rejection)
      assert_equal [10, true], state.values_at(:deadline_ns, :write_complete)
      assert_equal ["fixture-result", "unexpected fixture result kind/status"], [outcome[:original].kind, outcome[:original].message]
    end
    refute_same(*cases.map { |outcome| outcome.fetch(:state) })
    [:short, IOError.new("private-marker")].each do |write_result|
      outcome = exercise.call(write_result: write_result)
      assert_equal 1, outcome.fetch(:writes).length
      if write_result.is_a?(Exception)
        assert_same write_result, outcome.fetch(:state).fetch(:diagnostic_error)
      else
        assert_equal false, outcome.fetch(:state).fetch(:write_complete)
      end
    end
    %i[before_report before_write].each do |expiry|
      outcome = exercise.call(expiry: expiry)
      assert_empty outcome.fetch(:writes)
      assert_equal expiry == :before_report ? 0 : 1, outcome.fetch(:projections).length
    end
    [->(s) { s.delete(:status) }, ->(s) { s[:status] = nil }, ->(s) { s[:platform] = "android" }, ->(s) { s[:mode] = "inherited" },
     ->(s) { s[:rejection] = UploadProcessFixture::Failure.new("fixture-result", "private-marker") },
     ->(s) { s[:deadline_ns] = 10.0 }, ->(s) { s[:result] = raw.merge("kind" => "pass"); s[:status] = status_class.new(0) },
     ->(s) { s.freeze }].each { |mutate| assert_empty exercise.call(mutate: mutate).fetch(:writes) }
    assert_empty exercise.call(class_name: "NativeUploadValidationTest").fetch(:writes)
    assert_empty exercise.call(method_name: callback_modes.keys.last).fetch(:writes)
    [[:projection_error, Interrupt.new("private-marker")], [:callback_error, SystemExit.new(19, "private-marker")]].each do |key, error|
      outcome = exercise.call(**{key => error})
      assert_empty outcome.fetch(:writes)
      assert_same error, outcome.fetch(:state).fetch(:diagnostic_error)
      assert_equal true, outcome.fetch(:state).fetch(:report_attempted)
    end
    secondary = IOError.new("later private cleanup error")
    assert_equal 1, exercise.call(cleanup_error: secondary, restoration_error: secondary).fetch(:writes).length
    [:publication_error, :prior_error].each do |key|
      original = Interrupt.new("private-marker")
      outcome = exercise.call(**{key => original})
      assert_same original, outcome.fetch(:original)
      refute_same original, outcome.fetch(:state).fetch(:rejection)
      assert_empty outcome.fetch(:writes)
    end

    # Unrelated modes receive no keyword; successful eligible calls use fresh
    # empty states. A later assertion is outside the original guarded run.
    receiver = Object.new.extend(UploadProcessFixture::Contracts)
    receiver.define_singleton_method(:name) { raise "successful wrapper must not inspect a callback" }
    successful, writes, handoffs = Object.new, [], []
    STDERR.stub(:write, ->(packet) { writes << packet; packet.bytesize }) do
      2.times do
        assert_same successful, receiver.with_adapter_failure_diagnostic(platform: "ios", mode: "real-deadline") { |optional| handoffs << optional; successful }
      end
      [["native", "real-deadline"], ["ios", "native-setup-interrupt"], ["ios", "ownership-observation"], ["android", "kill-descendant"]].each do |platform, mode|
        assert_same successful, receiver.with_adapter_failure_diagnostic(platform: platform, mode: mode) { |optional| assert_empty optional; successful }
      end
      assert_raises(Minitest::Assertion) do
        receiver.with_adapter_failure_diagnostic(platform: "android", mode: "real-deadline") { |optional| handoffs << optional; successful }
        flunk "later synthetic assertion"
      end
    end
    assert_empty writes
    assert_equal 3, handoffs.map { |optional| optional.fetch(:adapter_failure_state).object_id }.uniq.length
    assert handoffs.all? { |optional| optional.keys == [:adapter_failure_state] && optional[:adapter_failure_state].empty? }

    # A complete finite upper bound includes the new detail and longest stage;
    # the shared detail's domain controls below already cover its combinations.
    fixture = UploadProcessFixture
    pairs = fixture::ADAPTER_FAILURE_CODES.map { |(name, _message), code| [fixture::ADAPTER_FAILURE_CATEGORIES.fetch(name), code] }
    pairs.concat((fixture::ADAPTER_FAILURE_CATEGORIES.values + %w[other missing invalid none]).product(%w[missing invalid other]))
    category, code = pairs.max_by { |pair| pair.sum(&:bytesize) }
    primary = fixture::OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.flat_map { |kind, values| values.map { |value| [kind, value] } }.
      max_by { |pair| JSON.generate(pair).bytesize }
    maximum_mode, maximum_kind = expected_kinds.max_by { |mode, kind| mode.bytesize + kind.bytesize }
    maximum = expected.merge("platform" => "android", "mode" => maximum_mode, "expectedKind" => maximum_kind,
      "resultKind" => fixture::ADAPTER_FAILURE_KINDS.max_by(&:bytesize), "driverExitStatus" => 255,
      "retainedDriverErrorCategory" => category, "retainedDriverErrorCode" => code,
      "adapterErrorCategory" => fixture::ADAPTER_FAILURE_CATEGORIES.values.max_by(&:bytesize),
      "resultChecks" => result_keys.to_h { |key| [key, "missing"] },
      "nativeChecks" => native_keys.to_h { |key| [key, "missing"] },
      "timingChecks" => timing_keys.to_h { |key| [key, %w[firstTimeoutCutoff selectedTimeoutCutoff].include?(key) ? "at-or-after-cutoff" : "missing"] },
      "nativeOutcomes" => fixture::ADAPTER_FAILURE_NATIVE_OUTCOMES.to_h { |key, values| [key, values.max_by(&:bytesize)] },
      "slowChecks" => slow_keys.to_h { |key| [key, "missing"] },
      "captureDetail" => [fixture::ADAPTER_FAILURE_CATEGORIES.values.max_by(&:bytesize), "m" * 24, "m" * 9, "m" * 4, "m" * 3, primary],
      "readinessStage" => stages.max_by(&:bytesize))
    assert fixture::OwnershipFailureDiagnostic.capture_detail_valid?(maximum.fetch("captureDetail"))
    assert_operator "#{fixture::ADAPTER_FAILURE_PREFIX}#{JSON.generate(maximum)}\n".bytesize, :<=, 4096
    assert_adapter_readiness_stage_choreography
  end

  # Exact native Ruby types, but no native initialization, registered
  # acquisition, Thread, descriptor or filesystem operation. IO.allocate has
  # no FD; every used IO method is an inert singleton seam. The surrounding
  # selector's acquisition veto remains active throughout this model.
  def adapter_output_source_model(mode: "leader-only")
    fixture, spawn, native = UploadProcessFixture, MobileReleaseKit::NativeProcessSpawn, MobileReleaseKit::NativeUploadValidation
    rig = {reads: [], closed: [], stat_errors: {}, admission_errors: {}, admissions: 0, modeled_creates: 0}
    task = lambda do
      value = MobileReleaseKit::NativeUploadProcess::TaskSlot.allocate
      {lock: Mutex.new, thread: Thread.current, caller: Thread.current, joined: false, parent_slot: nil}.each do |name, item|
        value.instance_variable_set(:"@#{name}", item)
      end
      value
    end
    capture, creator = task.call, task.call
    creator.instance_variable_set(:@parent_slot, capture)
    creator.define_singleton_method(:check_creation!) do
      rig[:admissions] += 1
      error = rig[:admission_errors][rig[:admissions]]
      raise error if error
      true
    end
    resources, ios, stats = {}, {}, {}
    acquisition = spawn::Acquisition.allocate
    {lock: Mutex.new, resources: resources, owner_slot: creator, child: nil, child_attempted: false}.each do |name, item|
      acquisition.instance_variable_set(:"@#{name}", item)
    end
    roles = %i[null_stdin null_stdout null_stderr control_read status_write stdin_read stdout_write stderr_write]
    accesses = %i[read write write read write read write write]
    stat_class = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink) do
      def pipe? = ftype == "fifo"
    end
    (roles + %i[stdout_read stderr_read]).each_with_index do |role, index|
      io = IO.allocate
      stats[role] = stat_class.new(1, 101 + index, 0o10600, 3, 4, 0, "fifo".dup, 1)
      io.define_singleton_method(:closed?) { rig[:closed].include?(role) }
      io.define_singleton_method(:stat) do
        raise "inert opposite reader is not a descendant writer" if %i[stdout_read stderr_read].include?(role)
        raise "inert writer resampled after modeled close" if rig[:closed].include?(role)
        rig[:reads] << role
        raise rig[:stat_errors][role] if rig[:stat_errors][role]
        stats.fetch(role)
      end
      lease = spawn::IOLease.allocate
      {lock: Mutex.new, acquisition: acquisition, role: role, access: accesses[index] || :read,
       kind: index < 3 ? :null : :pipe, state: :open, io: io}.each do |name, item|
        lease.instance_variable_set(:"@#{name}", item)
      end
      resources[role], ios[role] = lease, io
    end
    spec = spawn::SpawnSpec.new(executable: "/inert-adapter", argv: ["/inert-adapter"], env: {},
      fd_sources: roles.map { |role| resources.fetch(role) }) # Pure constructor; no native entry.
    session = native.const_get(:CaptureSession, false).allocate
    {capture_slot: capture, creator_slot: creator, acquisition: acquisition, leases: resources,
     custodian_child: nil, ready: nil, reserved: nil}.each { |name, item| session.instance_variable_set(:"@#{name}", item) }
    driver = fixture::AdapterDriver.new(@root, "ios", mode, {}, deadline_ns: 40_000_000_000)
    observation = fixture::AdapterDriver::Observation.new(driver, native: native, root: @root)
    observation.instance_variable_set(:@session, session)
    driver.instance_variable_set(:@observation, observation)
    observation.event(:execute_enter, session)
    observation.remember_custodian_sources(acquisition, spec)
    rig.merge!(driver: driver, observation: observation, session: session, capture: capture, creator: creator,
      acquisition: acquisition, event_acquisition: acquisition, resources: resources, spec: spec, ios: ios, stats: stats)
    rig[:invoke] = lambda do
      observation.event(:custodian_attempt, rig.fetch(:event_acquisition)) # Actual existing event routing/snapshot body.
      rig[:modeled_creates] += 1 # Only a downstream-call counter, NEVER a native creation/settlement receipt.
    end
    rig
  end

  def assert_adapter_output_source_binding
    fixture, spawn = UploadProcessFixture, MobileReleaseKit::NativeProcessSpawn
    writers = %i[stdout_write stderr_write]
    rig = adapter_output_source_model
    binding = rig[:observation].custodian_source_binding
    rig[:observation].remember_custodian_sources(Object.new, Object.new)
    assert_same binding, rig[:observation].custodian_source_binding # First observed original map cannot be replaced.
    rig[:invoke].call
    snapshot = rig[:driver].instance_variable_get(:@output_source_snapshot)
    assert_equal [writers, 2, 1], rig.values_at(:reads, :admissions, :modeled_creates)
    assert_same rig[:session], snapshot.fetch(:session)
    assert_same rig[:acquisition], snapshot.fetch(:acquisition)
    assert_same rig[:spec].fd_sources, snapshot.fetch(:sources)
    assert_same binding, snapshot.fetch(:binding)
    assert snapshot.frozen?
    assert snapshot.fetch(:writers).frozen?
    snapshot.fetch(:writers).zip(writers).each do |entry, role|
      lease, io, identity = entry
      assert entry.frozen?
      assert_same rig[:resources][role], lease
      assert_same rig[:ios][role], io
      assert_equal fixture::OwnedChild.identity(rig[:stats][role]), identity
      assert identity.frozen?
      assert identity.fetch("type").frozen?
      refute_same rig[:stats][role].ftype, identity.fetch("type")
      rig[:stats][role].ino += 10
      rig[:stats][role].ftype.replace("changed-model-stat")
      assert_equal "fifo", identity.fetch("type")
      refute_equal rig[:stats][role].ino, identity.fetch("ino")
    end
    [rig[:session], rig[:acquisition], rig[:capture], rig[:creator], rig[:resources], *rig[:resources].values, *rig[:ios].values].each do |original|
      refute original.frozen?, "snapshot must not freeze native lifecycle custody"
    end
    error = assert_raises(fixture::Failure) { rig[:invoke].call }
    assert_equal ["fixture-source", "adapter output source identity was not bound"], [error.kind, error.message]
    assert_same snapshot, rig[:driver].instance_variable_get(:@output_source_snapshot)
    assert_equal [writers, 2, 1], rig.values_at(:reads, :admissions, :modeled_creates)

    change_sources = lambda do |model, &edit|
      sources = model[:spec].fd_sources.dup
      edit.call(sources)
      spec = spawn::SpawnSpec.allocate # Model malformed maps that the real constructor would already reject.
      spec.instance_variable_set(:@fd_sources, sources.freeze)
      spec.freeze
      model[:observation].instance_variable_set(:@custodian_source_binding, [model[:acquisition], spec].freeze)
    end
    mutations = {
      absent_binding: ->(m) { m[:observation].instance_variable_set(:@custodian_source_binding, nil) },
      missing_writer: ->(m) { m[:resources].delete(:stderr_write) },
      foreign_lease: ->(m) { m[:resources][:stdout_write] = m[:resources][:stdout_write].dup },
      foreign_acquisition: ->(m) { m[:event_acquisition] = spawn::Acquisition.allocate },
      wrong_session: ->(m) { m[:driver].instance_variable_set(:@native_frame, Object.new) },
      resource_copy: ->(m) { m[:session].instance_variable_set(:@leases, m[:resources].dup) },
      swapped_sources: ->(m) { change_sources.call(m) { |sources| sources[6], sources[7] = sources[7], sources[6] } },
      reader_source: ->(m) { change_sources.call(m) { |sources| sources[6] = m[:resources][:stdout_read] } },
      wrong_role: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@role, :stderr_write) },
      wrong_access: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@access, :read) },
      wrong_kind: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@kind, :null) },
      closed_writer: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@state, :closed) },
      closed_io: ->(m) { m[:closed] << :stderr_write },
      missing_io: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@io, nil) },
      shared_writer_io: ->(m) { m[:resources][:stderr_write].instance_variable_set(:@io, m[:ios][:stdout_write]) },
      reader_io: ->(m) { m[:resources][:stdout_write].instance_variable_set(:@io, m[:ios][:stdout_read]) },
      joined_creator: ->(m) { m[:creator].instance_variable_set(:@joined, true) },
      child_attempted: ->(m) { m[:acquisition].instance_variable_set(:@child_attempted, true) },
      child_present: ->(m) { m[:acquisition].instance_variable_set(:@child, Object.new) },
      wrong_owner: ->(m) { m[:acquisition].instance_variable_set(:@owner_slot, m[:capture]) },
      wrong_thread: ->(m) { m[:creator].instance_variable_set(:@thread, nil) },
      wrong_caller: ->(m) { m[:creator].instance_variable_set(:@caller, Object.new) },
    }
    mutations.each do |label, mutate|
      model = adapter_output_source_model
      mutate.call(model)
      error = assert_raises(fixture::Failure, label.to_s) { model[:invoke].call }
      assert_equal ["fixture-source", "adapter output source identity was not bound"], [error.kind, error.message], label.to_s
      assert_equal true, model[:driver].instance_variable_get(:@output_source_attempted)
      assert_nil model[:driver].instance_variable_get(:@output_source_snapshot)
      assert_empty model[:reads]
      assert_equal 0, model[:modeled_creates]
      assert_raises(fixture::Failure) { model[:invoke].call }
      assert_empty model[:reads] # Rejected original opportunity never becomes a later producer.
      assert_equal 0, model[:modeled_creates]
    end
    [[:stat, 1, IOError.new("original second fstat")], [:stat, 1, Interrupt.new("original fstat cancellation")],
     [:admission, 1, MobileReleaseKit::NativeUploadProcess::LifecycleError.new("deadline")],
     [:admission, 2, MobileReleaseKit::NativeUploadProcess::LifecycleError.new("deadline")],
     [:admission, 2, SystemExit.new(23, "original admission exit")]].each do |boundary, admissions, original|
      model = adapter_output_source_model
      if boundary == :stat
        model[:stat_errors][:stderr_write] = original
      else
        model[:admission_errors][admissions] = original
      end
      reads = boundary == :admission && admissions == 1 ? [] : writers
      assert_same original, assert_raises(original.class) { model[:invoke].call }
      assert_equal [reads, admissions, 0], model.values_at(:reads, :admissions, :modeled_creates)
      assert_nil model[:driver].instance_variable_get(:@output_source_snapshot) # First fstat alone never authorizes READY.
      assert_raises(fixture::Failure) { model[:invoke].call }
      assert_equal [reads, admissions, 0], model.values_at(:reads, :admissions, :modeled_creates)
    end
    model = adapter_output_source_model
    model[:stats][:stderr_write].ftype.replace("file")
    error = assert_raises(fixture::Failure) { model[:invoke].call }
    assert_equal ["fixture-source", "adapter output source identity was not bound"], [error.kind, error.message]
    assert_equal [writers, 1, 0], model.values_at(:reads, :admissions, :modeled_creates)
    assert_nil model[:driver].instance_variable_get(:@output_source_snapshot)
    %w[real-deadline immediate-deadline no-deadline kill-startup unready real-deadline-slow-cleanup].each do |mode|
      model = adapter_output_source_model(mode: mode)
      model[:invoke].call
      assert_equal [[], 0, 1], model.values_at(:reads, :admissions, :modeled_creates)
      assert_equal false, model[:driver].instance_variable_get(:@output_source_attempted)
      assert_nil model[:driver].instance_variable_get(:@output_source_snapshot)
    end
  end

  def assert_adapter_readiness_stage_choreography
    fixture = UploadProcessFixture
    assert_adapter_output_source_binding
    full = [["record:leader-ready.json", "validator-marker"], ["live:validator", "validator-live"],
      ["record:adapter-dispatch.json", "dispatch"], ["admission", "control-admission"],
      ["record:fork-return.json", "descendant-fork"], ["record:child-ready.json", "descendant-marker"],
      ["live:descendant", "descendant-live"], ["pipes", "inherited-pipes"],
      ["release", "validator-release"], ["owner:ready", "owner-publication"]]
    # Only fresh private receivers get these seams. Actual ready! executes;
    # every process/file/clock operation below it is inert, not a native receipt.
    readiness_cutoff = 50 + fixture::ADAPTER_READINESS_LIMIT * 1_000_000_000
    exercise = lambda do |mode: "leader-only", stop: nil, error: nil, ready: true,
                         initial_now: 100, advance_at: nil, advanced_now: nil, source_fault: nil, child_mismatch: false|
      now = initial_now
      model = adapter_output_source_model(mode: mode)
      driver, session = model.values_at(:driver, :session)
      model[:invoke].call # Original writer facts exist BEFORE their modeled normal close.
      %i[stdout_write stderr_write].each do |role|
        model[:closed] << role
        model[:resources][role].instance_variable_set(:@state, :closed)
      end
      model[:creator].instance_variable_set(:@joined, true)
      model[:acquisition].instance_variable_set(:@child_attempted, true)
      session.instance_variable_set(:@custodian_child, Struct.new(:pid).new(201))
      session.instance_variable_set(:@ready, ready ? {"validator_pid" => 203, "group_id" => 202} : nil)
      session.instance_variable_set(:@reserved, {})
      case source_fault
      when :absent
        driver.instance_variable_set(:@output_source_snapshot, nil)
      when :binding
        model[:observation].instance_variable_set(:@custodian_source_binding, [model[:acquisition], model[:spec].dup.freeze].freeze)
      when :resource_copy
        session.instance_variable_set(:@leases, model[:resources].dup)
      when :writer_io
        model[:resources][:stdout_write].instance_variable_set(:@io, model[:ios][:stdout_read])
      end
      marker = {"kind" => mode == "kill-startup" ? "startup-wait" : "leader-ready", "pid" => 203, "group" => 202, "sid" => 201}
      fork = {"parent" => 203, "child" => 204, "group" => 202}
      dispatch = {"version" => 1, "pid" => 203, "group" => 202, "sid" => 201,
        "argv" => ["inert-adapter"], "environment" => {}, "cwd" => "inert-cwd", "sourceSha256" => "f" * 64}
      {native_started_ns: 50, readiness_deadline_ns: readiness_cutoff,
        expected_argv: dispatch["argv"], expected_environment: dispatch["environment"], tooling: dispatch["cwd"],
        fake_source_sha: dispatch["sourceSha256"]}.each { |name, value| driver.instance_variable_set(:"@#{name}", value) }
      records = {"leader-ready.json" => marker, "startup-wait.json" => marker, "fork-return.json" => fork,
        "adapter-dispatch.json" => dispatch, "child-ready.json" => marker.merge("kind" => "child-ready", "pid" => 204,
          "stdout" => fixture::OwnedChild.identity(model[:stats][:stdout_write]),
          "stderr" => fixture::OwnedChild.identity(model[:stats][:stderr_write]))}
      if child_mismatch
        records["child-ready.json"]["stdout"] = fixture::OwnedChild.identity(model[:stats][:stdout_read])
      end
      events, returned, escaped, published = [], nil, nil, Object.new
      note = lambda do |name|
        events << [name, driver.instance_variable_get(:@readiness_stage)]
        now = advanced_now if name == advance_at
        raise error if name == stop || name == "driver-loss"
      end
      control = Object.new
      control.define_singleton_method(:admitted!) { note.call("admission") }
      driver.instance_variable_set(:@control, control)
      driver.define_singleton_method(:wait_record) { |name| note.call("record:#{name}"); records.fetch(name) }
      original_live = driver.method(:live_marker!)
      driver.define_singleton_method(:live_marker!) { |value, expected, label| note.call("live:#{label}"); original_live.call(value, expected, label) }
      model[:liveness] = []
      observe = lambda do |pid, group, seconds:, parent_slot:, run_deadline_ns:|
        assert_includes [203, 204], pid
        assert_equal 202, group
        assert_same model[:capture], parent_slot
        assert_equal readiness_cutoff, run_deadline_ns
        assert_operator seconds, :>, 0
        model[:liveness] << pid
        true
      end
      driver.define_singleton_method(:observe_inherited_block!) { note.call("pipes") }
      driver.define_singleton_method(:publish_owner) { |phase| note.call("owner:#{phase}"); published }
      driver.define_singleton_method(:wait_for_driver_loss) { note.call("driver-loss") }
      write = ->(path, value) { note.call("release"); assert_equal File.join(@root, "release-validator.json"), path; assert_equal fork, value; true }
      fixture.stub(:clock_ns, -> { now }) do
        fixture.stub(:ready?, observe) do
          fixture::OwnedChild.stub(:write_record, write) do
            begin
              returned = driver.ready!
            rescue Exception => original
              escaped = original
            end
          end
        end
      end
      [driver, events, returned, escaped, published, model]
    end
    driver, events, returned, escaped, published, model = exercise.call
    assert_nil escaped
    assert_equal full, events
    assert_same published, returned
    assert_equal "ready-return", driver.instance_variable_get(:@readiness_stage)
    assert_equal 50.fdiv(1_000_000_000), driver.observed.fetch("readinessSeconds")
    assert_equal [203, 204], model[:liveness]
    assert_equal %i[stdout_write stderr_write], model[:reads] # No closed-writer resample or opposite-reader stat.
    proof = driver.observed.fetch("descendantProof")
    %w[stdout stderr].each do |stream|
      identity = proof.fetch("#{stream}WriterIdentity")
      assert_equal fixture::OwnedChild.identity(model[:stats][:"#{stream}_write"]), identity
      refute_equal fixture::OwnedChild.identity(model[:stats][:"#{stream}_read"]), identity
    end
    refute_equal proof.fetch("stdoutWriterIdentity"), proof.fetch("stderrWriterIdentity")
    %i[absent binding resource_copy writer_io].each do |source_fault|
      driver, events, returned, escaped, _, model = exercise.call(source_fault: source_fault)
      assert_instance_of fixture::Failure, escaped
      assert_equal ["fixture-source", "adapter output source identity was not bound"], [escaped.kind, escaped.message]
      assert_nil returned
      assert_equal full.take(6), events
      assert_equal [203], model[:liveness] # Reject BEFORE descendant observation or release.
      assert_equal %i[stdout_write stderr_write], model[:reads]
      refute driver.observed.key?("descendantProof")
    end
    driver, events, returned, escaped, _, model = exercise.call(child_mismatch: true)
    assert_instance_of fixture::Failure, escaped
    assert_equal ["readiness", "descendant record is not bound"], [escaped.kind, escaped.message]
    assert_nil returned
    assert_equal full.take(7), events
    assert_equal [203], model[:liveness] # The REAL live_marker! equality guard vetoes the observer.
    refute driver.observed.key?("descendantProof")
    [IOError.new("marker"), Interrupt.new("observation"), StandardError.new("dispatch"), SystemExit.new(23)].each_with_index do |error, index|
      driver, events, returned, escaped = exercise.call(stop: full[index].first, error: error)
      assert_same error, escaped
      assert_nil returned
      assert_equal full.take(index + 1), events # No later operation after this original error.
      assert_equal full[index].last, driver.instance_variable_get(:@readiness_stage)
    end
    driver, events, _, escaped = exercise.call(mode: "unready")
    assert_instance_of fixture::Failure, escaped
    assert_equal "readiness", escaped.kind
    assert_equal "fixture deliberately never became ready", escaped.message
    assert_equal [["record:startup-wait.json", "startup-marker"]], events
    %w[kill-startup kill-descendant].each do |mode|
      error = Interrupt.new("inert driver loss")
      driver, events, returned, escaped = exercise.call(mode: mode, error: error)
      stage = mode == "kill-startup" ? "startup-driver-loss" : "descendant-driver-loss"
      prefix = mode == "kill-startup" ? full.take(4).map { |name, value| [name.sub("leader-ready", "startup-wait"), value] } : full.take(8)
      assert_same error, escaped
      assert_nil returned
      assert_equal prefix + [["owner:#{mode}", stage], ["driver-loss", stage]], events
    end
    _, events, returned, escaped, published = exercise.call(mode: "real-deadline")
    assert_nil escaped
    assert_same published, returned
    assert_equal full.take(4) + [full.last], events
    driver, events, _, escaped = exercise.call(ready: false)
    assert_instance_of fixture::Failure, escaped
    assert_empty events
    assert_equal "native-ready", driver.instance_variable_get(:@readiness_stage)

    driver, events, returned, escaped, published = exercise.call(advance_at: "owner:ready", advanced_now: readiness_cutoff - 1)
    assert_nil escaped
    assert_same published, returned
    assert_equal full, events
    assert_operator driver.observed.fetch("readinessSeconds"), :<, fixture::ADAPTER_READINESS_LIMIT
    # Early ready=true is deliberately not enough. Completion after descendant
    # release or owner publication cannot start the watchdog/actual stdin close.
    [["admission", full.take(4)], ["release", full.take(9)], ["owner:ready", full]].each do |boundary, expected_events|
      [readiness_cutoff, readiness_cutoff + 1].each do |at|
        driver, events, returned, escaped = exercise.call(advance_at: boundary, advanced_now: at)
        assert_instance_of fixture::Failure, escaped
        assert_equal ["readiness", "adapter readiness missed original cutoff"], [escaped.kind, escaped.message]
        assert_nil returned
        assert_equal expected_events, events
        assert_equal boundary != "admission", driver.observed.fetch("ready", false)
        refute driver.observed.key?("readinessSeconds")
        refute_equal "ready-return", driver.instance_variable_get(:@readiness_stage)
      end
    end
    driver, events, _, escaped = exercise.call(initial_now: readiness_cutoff)
    assert_instance_of fixture::Failure, escaped
    assert_empty events
    refute driver.observed.fetch("ready", false)
    driver, events, _, escaped = exercise.call(mode: "unready", advance_at: "record:startup-wait.json", advanced_now: readiness_cutoff)
    assert_instance_of fixture::Failure, escaped
    assert_equal "adapter readiness missed original cutoff", escaped.message
    refute_equal "fixture deliberately never became ready", escaped.message
    %w[kill-startup kill-descendant].each do |mode|
      _, events, returned, escaped = exercise.call(mode: mode, advance_at: "owner:#{mode}", advanced_now: readiness_cutoff)
      assert_instance_of fixture::Failure, escaped
      assert_equal "adapter readiness missed original cutoff", escaped.message
      assert_nil returned
      refute events.any? { |name, _stage| name == "driver-loss" }
    end

    driver = fixture::AdapterDriver.new(@root, "ios", "leader-only", {}, deadline_ns: 40_000_000_000)
    observer = fixture::AdapterDriver::Observation.new(driver, native: nil, root: @root) # No install/session/native entry.
    assert_equal "not-entered", observer.snapshot_additions.fetch("readinessStage")
    raw_stage = "validator-live".dup
    driver.instance_variable_set(:@readiness_stage, raw_stage)
    snapshot = observer.snapshot_additions
    assert snapshot.frozen?
    assert_same fixture::ADAPTER_READINESS_STAGES.find { |stage| stage == raw_stage }, snapshot.fetch("readinessStage")
    refute raw_stage.frozen?
    raw_stage.replace("private-marker")
    driver.instance_variable_set(:@readiness_stage, "ready-return")
    assert_equal "validator-live", snapshot.fetch("readinessStage") # A late producer cannot repair this snapshot.
    driver.remove_instance_variable(:@readiness_stage)
    assert_equal "missing", observer.snapshot_additions.fetch("readinessStage")
    driver.instance_variable_set(:@readiness_stage, nil)
    assert_equal "invalid", observer.snapshot_additions.fetch("readinessStage")
    singleton = driver.singleton_class # Materialize the lookup class before capturing the original Method.
    original_getter = driver.method(:instance_variable_get)
    [IOError.new("optional read"), Interrupt.new("original cancellation")].each do |error|
      refute singleton.instance_methods(false).include?(:instance_variable_get)
      singleton.send(:define_method, :instance_variable_get) { |_name| raise error }
      begin
        if error.is_a?(StandardError)
          assert_equal({"capturePrimary" => %w[missing missing], "readinessStage" => "invalid"}, observer.snapshot_additions)
        else
          assert_same error, assert_raises(Interrupt) { observer.snapshot_additions }
        end
      ensure
        singleton.send(:remove_method, :instance_variable_get) # Restore the exact inherited method, no alias.
      end
      assert_empty observer.instance_variable_get(:@observer_errors)
      assert_equal original_getter, driver.method(:instance_variable_get)
    end
  end

  def assert_ownership_capture_detail_projection(fresh_state, original)
    fixture, diagnostic = UploadProcessFixture, UploadProcessFixture::OwnershipFailureDiagnostic
    assert_equal %w[adapterErrorCategory resultChecks timingChecks settlementChecks protocolContext primary], fixture::OWNERSHIP_CAPTURE_DETAIL_FIELDS
    assert_equal %w[hello reserved ready], fixture::OWNERSHIP_CAPTURE_PROTOCOL_FIELDS
    assert_equal({"contract-error" => %w[none], "missing" => %w[missing], "invalid" => %w[invalid]}, fixture::OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS)
    assert_equal fixture::OWNERSHIP_FAILURE_ERROR_KINDS.merge(fixture::OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS), fixture::OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS
    fixture::OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS.each { |category, kinds| kinds.each { |kind| refute diagnostic.error_pair_valid?(category, kind) } }
    project = lambda do |result|
      diagnostic.capture_detail(result, projected: fixture.adapter_result_projection(mode: "inherited", result: result))
    end
    missing = ["missing", "m" * 24, "m" * 9, "m" * 4, "m" * 3, %w[missing missing]]
    assert_equal missing, project.call({})
    assert_equal missing[0, 2] + ["m" * 6 + "x" * 3, "x" * 4, "x" * 3, %w[invalid invalid]], project.call("nativeObservation" => nil)
    assert_equal missing, project.call("nativeObservation" => {})
    assert_equal "x" * 4, project.call("nativeObservation" => {"settlementChecks" => nil})[3]
    assert_equal "x" * 3, project.call("nativeObservation" => {"protocolContext" => nil})[4]
    assert_equal %w[invalid invalid], project.call("nativeObservation" => {"capturePrimary" => nil})[5]

    # Broadcast every allowed boolean-like state, then a positional pattern;
    # no Cartesian product is needed to prove all24 preserved positions.
    values = [[false, "0"], [true, "1"], [:absent, "m"], [nil, "x"]]
    result_keys = fixture::ADAPTER_FAILURE_RESULT_CHECKS
    encode_result = lambda do |pairs|
      result_keys.zip(pairs).each_with_object({}) do |(key, (value, _code)), raw|
        next if value == :absent
        if key == "cleanupErrorsEmpty"
          raw["cleanupErrors"] = value.equal?(true) ? [] : value.equal?(false) ? ["private-marker"] : nil
        else
          raw[key] = value
        end
      end
    end
    values.each do |pair|
      assert_equal pair.last * 24, project.call(encode_result.call([pair] * 24))[1]
    end
    pattern = Array.new(24) { |index| values[index % values.length] }
    assert_equal pattern.map(&:last).join, project.call(encode_result.call(pattern))[1]
    base_projection = fixture.adapter_result_projection(mode: "inherited", result: {})
    timing_domains = {false => "0", true => "1", "missing" => "m", "invalid" => "x"}
    cutoff_domains = {"before-start" => "s", "before-cutoff" => "b", "at-or-after-cutoff" => "a", "missing" => "m", "invalid" => "x"}
    fixture::ADAPTER_FAILURE_TIMING_CHECKS.each_with_index do |key, index|
      ([1, 2].include?(index) ? cutoff_domains : timing_domains).each do |value, code|
        projection = base_projection.merge("timingChecks" => base_projection.fetch("timingChecks").merge(key => value))
        expected = +("m" * 9)
        expected[index] = code
        detail = diagnostic.capture_detail({}, projected: projection)
        assert_equal expected, detail[2]
        assert diagnostic.capture_detail_valid?(detail)
      end
    end
    fixture::CaptureObservation::SETTLEMENT_CHECKS.each_with_index do |key, index|
      values.each do |value, code|
        checks = value == :absent ? {} : {key => value}
        expected = +("m" * 4)
        expected[index] = code
        assert_equal expected, project.call("nativeObservation" => {"settlementChecks" => checks})[3]
      end
    end
    fixture::OWNERSHIP_CAPTURE_PROTOCOL_FIELDS.each_with_index do |key, index|
      [[nil, "0"], [{"private-marker" => 999_887_766}, "1"], [:absent, "m"], [[], "x"], ["missing", "x"]].each do |value, code|
        context = value == :absent ? {} : {key => value}
        expected = +("m" * 3)
        expected[index] = code
        detail = project.call("nativeObservation" => {"protocolContext" => context})
        assert_equal expected, detail[4]
        refute_includes JSON.generate(detail), "private-marker"
        refute_includes JSON.generate(detail), "999887766"
      end
    end
    ["bad", [], nil].each do |invalid|
      detail = project.call("nativeObservation" => invalid)
      assert_equal ["x" * 4, "x" * 3, %w[invalid invalid]], detail[3, 3]
    end
    fixture::OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.each do |category, kinds|
      kinds.each do |kind|
        pair = [category, kind]
        detail = project.call("nativeObservation" => {"capturePrimary" => pair})
        assert_equal pair, detail.last
        assert diagnostic.capture_detail_valid?(detail)
      end
    end
    [nil, [], {}, %w[missing none], %w[native-spawn-error parent_lost], [false, "none"], ["none", 0],
     ["private-marker", "none"], %w[none none extra]].each do |value|
      refute diagnostic.capture_primary_valid?(value)
      assert_equal %w[invalid invalid], project.call("nativeObservation" => {"capturePrimary" => value}).last
    end
    (fixture::ADAPTER_FAILURE_CATEGORIES.values + %w[none missing invalid other]).uniq.each do |category|
      detail = missing.dup
      detail[0] = category
      assert diagnostic.capture_detail_valid?(detail)
    end
    bad_details = [nil, {}, [], missing[0, 5], missing + ["private-marker"]]
    [[0, false], [0, "private-marker"], [5, %w[none missing]], [5, {"none" => "none"}]].each do |index, value|
      bad_details << missing.dup.tap { |detail| detail[index] = value }
    end
    [24, 9, 4, 3].each_with_index do |length, offset|
      [nil, [], "", "m" * (length - 1), "m" * (length + 1), "m" * (length - 1) + "\n",
       "m" * (length - 1) + "é", "m" * (length - 1) + "z"].each do |value|
        bad_details << missing.dup.tap { |detail| detail[offset + 1] = value }
      end
    end
    ["smmmmmmmm", "m0mmmmmmm", "mm1mmmmmm", "mmmammmmm"].each do |value|
      bad_details << missing.dup.tap { |detail| detail[2] = value }
    end
    state = fresh_state.call(original)
    pair = [+"native-lifecycle-error", +"deadline"]
    state.fetch(:result).fetch("nativeObservation")["capturePrimary"] = pair
    view = diagnostic.run_cleanup(state, operation: original)
    projected_pair = view.fetch("driverResult").fetch("captureDetail").last
    assert_equal pair, projected_pair
    refute_same pair, projected_pair
    pair.zip(projected_pair).each do |raw, projected|
      refute raw.frozen?
      refute_same raw, projected
      assert projected.frozen?
      raw.replace("private-marker")
    end
    assert_equal %w[native-lifecycle-error deadline], projected_pair
    bad_details.each do |detail|
      refute diagnostic.capture_detail_valid?(detail)
      refute diagnostic.run_driver_result_valid?(view.fetch("driverResult").merge("captureDetail" => detail))
    end
    refute diagnostic.run_driver_result_valid?(view.fetch("driverResult").slice(*fixture::OWNERSHIP_RUN_RESULT_FIELDS))
  end

  def assert_ownership_failure_projection
    # Actual projection/caller control flow over source-defined inert objects.
    # No synthetic observation below is a native receipt or cleanup authority.
    fixture, probe_class = UploadProcessFixture, UploadProcessFixture::OwnershipProbe
    diagnostic = UploadProcessFixture::OwnershipFailureDiagnostic
    prefix = "MRK_OWNERSHIP_FAILURE="
    cases = {
      "async" => %w[async-spawn async-reap cleanup-first-async repeated],
      "signals" => %w[INT-spawn TERM-spawn INT-reap TERM-reap cleanup-first-INT cleanup-first-TERM
        install-before-INT install-before-TERM install-buffered-INT install-buffered-TERM install-published-INT
        install-published-TERM restore-before-INT restore-before-TERM restore-after-INT restore-after-TERM],
      "policies" => %w[normal ignored-INT ignored-TERM custom-INT custom-TERM custom-pending-INT
        partial-install changed-handler finalize-report finalize-drain],
    }
    callbacks = {
      "async" => "test_process_ownership_async_through_both_real_fixture_callers",
      "signals" => "test_process_ownership_signals_through_both_real_fixture_callers",
      "policies" => "test_process_ownership_policies_through_both_real_fixture_callers",
    }
    classes = {"ios" => "IosUploadValidationTest", "android" => "AndroidUploadValidationTest"}
    assert_equal cases, fixture::OWNERSHIP_FAILURE_CASES
    assert_equal callbacks, fixture::OWNERSHIP_FAILURE_CALLBACKS
    assert_equal cases.keys.to_h { |family| ["ownership-#{family}", family] }, fixture::OWNERSHIP_FAILURE_MODES
    cases.each do |family, names|
      assert_equal names, probe_class::CASES.fetch(family)
      refute_same probe_class::CASES.fetch(family), fixture::OWNERSHIP_FAILURE_CASES.fetch(family)
      refute probe_class::CASES.fetch(family).frozen?, "diagnostic must not freeze executable case arrays"
    end
    with_stubs = lambda do |bindings, &body|
      if bindings.empty?
        body.call
      else
        receiver, method, replacement = bindings.first
        receiver.stub(method, replacement) { with_stubs.call(bindings.drop(1), &body) }
      end
    end
    # Inert delivery seams at pre-primary bookkeeping. They model an exception
    # arriving there, not a native/signal delivery receipt. Even StandardError
    # may be a caller interruption, so none may be consumed as logging failure.
    [Interrupt.new("private-marker"), SystemExit.new(19, "private-marker"), IOError.new("private-marker")].each do |original|
      probe = probe_class.allocate
      family = Object.new
      family.define_singleton_method(:hash) { raise original }
      probe.instance_variable_set(:@family, family)
      later, failed_domain = [], []
      with_stubs.call([
        [fixture, :assert_domain_reusable!, -> { later << :domain_entry }],
        [fixture, :mark_process_domain_failed!, ->(**_) { failed_domain << :original_rescue }],
      ]) do
        actual = assert_raises(original.class) { probe.one("capture", "async-spawn"); later << :continued }
        assert_same original, actual
      end
      assert_empty later
      assert_equal [:original_rescue], failed_domain
      cases.each_key do |selected_family|
        probe.instance_variable_set(:@family, selected_family)
        diagnostic.stub(:row, ->(**_) { raise original }) do
          actual = assert_raises(original.class) do
            probe.ownership_failure_row({"failures" => ["known case left an unresolved reusable domain"]}, {}, nil)
            later << :continued
          end
          assert_same original, actual
        end
      end
      assert_empty later
    end
    labels = [
      ["numeric requests were vetoed", "numeric-route-veto"],
      ["original handler policy not restored", "handlers-not-restored"],
      ["lifetime registry remains active", "registry-active"],
      ["observation hooks not restored", "hooks-not-restored"],
      ["independent injector cleanup failed", "injector-cleanup"],
      ["original error object/message replaced", "primary-not-preserved"],
      ["original injectors not joined", "injectors-not-joined"],
      ["original injector custody/gate changed", "injector-custody"],
      ["pending cancellation leaked", "pending-interrupt"],
      ["normal/ignored original command did not finalize", "normal-command-not-finalized"],
      ["unsupported policy did not fail closed", "policy-not-fail-closed"],
      ["unsupported policy attempted native creation", "policy-native-creation"],
      ["original custom pending signal lost", "custom-pending-lost"],
      ["intended before-TERM partial installation was not exercised", "partial-install-not-exercised"],
      ["finalization failure skipped original command cleanup", "finalization-cleanup"],
      ["finalization fault missed the original outermost lifetime", "finalization-outer-lifetime"],
      ["cancellation/lost-publication fault not propagated", "cancellation-not-propagated"],
      ["original injection boundary missing", "injection-boundary-missing"],
      ["wrong original cancellation signal", "wrong-signal"],
      ["known cancellation did not finish original ownership", "command-not-finalized"],
      ["native creator published GO before caller cancellation", "pre-go-barrier-missing"],
      ["nested cleanup cancellation not exercised", "nested-cancellation-missing"],
      ["known case left an unresolved reusable domain", "fixture-retained"],
    ]
    assert_equal labels.to_h, fixture::OWNERSHIP_FAILURE_LABEL_CODES
    assert_equal labels.map(&:last) + ["other-failed-check"], fixture::OWNERSHIP_FAILURE_FAILED_CHECKS
    assert_equal MobileReleaseKit::NativeUploadProcess::REASONS + ["other"], fixture::OWNERSHIP_FAILURE_ERROR_KINDS.fetch("native-lifecycle-error")
    assert_equal MobileReleaseKit::NativeProcessSpawn::CODES + ["other"], fixture::OWNERSHIP_FAILURE_ERROR_KINDS.fetch("native-spawn-error")
    first = Interrupt.new("private-marker")
    raw_summary = {"failures" => ["known cancellation did not finish original ownership"], "firstExceptionPreserved" => false,
      "handlersRestored" => true, "pendingInterrupt" => false, "retainedFixture" => true, "private" => "private-marker"}
    raw_snapshot = {"settled" => false, "unknown" => true, "observerErrors" => [], "private" => "private-marker", "pid" => 999_887_766}
    row = diagnostic.row(summary: raw_summary, snapshot: raw_snapshot, owner_phase: :reaped, first: first, operation: first)
    expected = {"schema" => 4, "platform" => "ios", "family" => "async", "helper" => "capture", "case" => "async-spawn",
      "phase" => "row-rejection", "errorCategory" => "fixture-error", "errorKind" => "ownership-probe", "row" => row}
    packet = diagnostic.line(expected)
    assert_equal "#{prefix}#{JSON.generate(expected)}\n", packet
    assert packet.frozen? && packet.ascii_only?
    assert_operator packet.bytesize, :<=, 4096
    assert row.frozen? && row.fetch("failedChecks").frozen? && row.fetch("checks").frozen? && row.fetch("commandChecks").frozen?
    assert_equal "runCleanup", row.keys.last
    assert_equal "missing", row.fetch("runCleanup")
    assert_equal [false, true, "missing", "missing", "missing", false, true], row.fetch("checks").values
    assert_equal [false, "missing", true, "missing", "missing", "missing", "missing", true], row.fetch("commandChecks").values
    refute_includes packet, "private-marker"
    refute_includes packet, "999887766"
    raw_summary.fetch("failures").clear
    raw_summary["firstExceptionPreserved"] = true
    raw_snapshot["settled"] = true
    raw_snapshot.fetch("observerErrors") << "private-marker"
    assert_equal ["command-not-finalized"], row.fetch("failedChecks")
    refute row.fetch("checks").fetch("firstExceptionPreserved")
    refute row.fetch("commandChecks").fetch("settled")
    assert row.fetch("commandChecks").fetch("observerErrorsEmpty")
    constrained = {
      "cancellation-not-propagated" => {"async" => cases.fetch("async"), "signals" => cases.fetch("signals")},
      "injection-boundary-missing" => {"async" => cases.fetch("async"), "signals" => cases.fetch("signals")},
      "wrong-signal" => {"async" => cases.fetch("async"), "signals" => cases.fetch("signals")},
      "command-not-finalized" => {"async" => cases.fetch("async"), "signals" => cases.fetch("signals")},
      "pre-go-barrier-missing" => {"async" => %w[async-spawn], "signals" => %w[INT-spawn TERM-spawn]},
      "nested-cancellation-missing" => {"async" => %w[repeated]},
      "normal-command-not-finalized" => {"policies" => %w[normal ignored-INT ignored-TERM]},
      "policy-not-fail-closed" => {"policies" => %w[custom-INT custom-TERM custom-pending-INT partial-install changed-handler finalize-report finalize-drain]},
      "policy-native-creation" => {"policies" => %w[custom-INT custom-TERM custom-pending-INT partial-install]},
      "custom-pending-lost" => {"policies" => %w[custom-pending-INT]},
      "partial-install-not-exercised" => {"policies" => %w[partial-install]},
      "finalization-cleanup" => {"policies" => %w[finalize-report finalize-drain]},
      "finalization-outer-lifetime" => {"policies" => %w[finalize-report finalize-drain]},
    }
    applicable = lambda do |code, family, helper, name|
      (!constrained.key?(code) || constrained.fetch(code).fetch(family, []).include?(name)) &&
        (code != "nested-cancellation-missing" || helper == "run")
    end
    labels.each do |label, code|
      projected = diagnostic.row(summary: {"failures" => [label]}, snapshot: {}, owner_phase: nil, first: nil, operation: nil)
      assert_equal [code], projected.fetch("failedChecks")
      assert_equal ["missing", "none", "none", "none", "none"], projected.values_at(*fixture::OWNERSHIP_FAILURE_ROW_FIELDS.first(5))
      cases.each do |family, names|
        names.product(%w[capture run]).each do |name, helper|
          value = expected.merge("family" => family, "helper" => helper, "case" => name, "row" => projected)
          assert_equal applicable.call(code, family, helper, name), !!diagnostic.line(value), "#{family}/#{helper}/#{name}/#{code}"
        end
      end
    end
    adverse = diagnostic.row(summary: {"failures" => ["private-marker", nil, Object.new, labels.last.first, labels.first.first, "private-marker"]},
      snapshot: {}, owner_phase: nil, first: nil, operation: nil)
    assert_equal %w[numeric-route-veto fixture-retained other-failed-check], adverse.fetch("failedChecks")
    refute_includes diagnostic.line(expected.merge("row" => adverse)), "private-marker"
    all_codes = labels.map(&:last) + ["other-failed-check"]
    widest = row.merge("ownerPhase" => "unstarted", "firstErrorCategory" => "native-lifecycle-error", "firstErrorKind" => "parent_lost",
      "operationErrorCategory" => "native-lifecycle-error", "operationErrorKind" => "parent_lost",
      "checks" => row.fetch("checks").keys.to_h { |key| [key, "missing"] },
      "commandChecks" => row.fetch("commandChecks").keys.to_h { |key| [key, "missing"] })
    sizes = cases.flat_map do |family, names|
      names.product(%w[capture run]).map do |name, helper|
        value = expected.merge("platform" => "android", "family" => family, "helper" => helper, "case" => name,
          "row" => widest.merge("failedChecks" => all_codes.select { |code| applicable.call(code, family, helper, name) }))
        diagnostic.line(value).bytesize
      end
    end
    assert_equal 1238, sizes.max # Complete prefix + canonical JSON + LF, with runCleanup=missing.
    missing = expected.merge("platform" => "android", "family" => "signals", "helper" => "capture", "case" => "install-published-TERM",
      "phase" => "proof-publication", "errorCategory" => "native-lifecycle-error", "errorKind" => "parent_lost", "row" => "missing")
    assert_equal 237, diagnostic.line(missing).bytesize
    [[nil, "none", "none"], [first, "interrupt", "none"], [SignalException.new("TERM"), "signal", "none"],
     [SystemExit.new(19, "private-marker"), "system-exit", "none"], [IOError.new("private-marker"), "io-error", "none"],
     [fixture::Failure.new("fixture-cleanup", "private-marker"), "fixture-error", "fixture-cleanup"],
     [fixture::Failure.new("private-marker", "private-marker"), "fixture-error", "other"],
     [MobileReleaseKit::NativeUploadProcess::LifecycleError.new("deadline"), "native-lifecycle-error", "deadline"],
     [MobileReleaseKit::NativeProcessSpawn::Error.new("wait"), "native-spawn-error", "wait"],
     [Errno::ECHILD.new("private-marker"), "os-error", "echild"], [RuntimeError.new("private-marker"), "other", "none"]].each do |error, category, kind|
      assert_equal [category, kind], diagnostic.error_pair(error)
    end
    malformed = [expected.merge("schema" => true), expected.merge("schema" => 1), expected.merge("schema" => 2), expected.merge("schema" => 3), expected.merge("platform" => "native"), expected.merge("family" => "signals"),
      expected.merge("helper" => "private-marker"), expected.merge("case" => "normal"), expected.merge("phase" => "snapshot"),
      expected.merge("errorCategory" => "interrupt", "errorKind" => "none"), expected.merge("private" => "private-marker"),
      expected.merge("row" => row.merge("failedChecks" => [])), expected.merge("row" => row.merge("failedChecks" => ["command-not-finalized"] * 2)),
      expected.merge("row" => row.merge("checks" => row.fetch("checks").merge("pendingInterrupt" => 0))),
      expected.merge("row" => row.merge("failedChecks" => ["nested-cancellation-missing"])),
      expected.merge("case" => "repeated", "row" => row.merge("failedChecks" => ["pre-go-barrier-missing"]))]
    malformed.each { |value| assert_nil diagnostic.line(value) }
    fixture.stub(:clock_ns, 1) do
      assert_equal expected, diagnostic.parse("private chatter\n#{packet}", deadline_ns: 10)
      [packet * 2, packet.chomp, packet.sub("\n", "\r\n"), packet.sub('"schema":4', '"schema":4,"schema":4'),
       packet.sub(prefix, "MRK_OWNERSHIP_ASYNC_FAILURE="), packet.sub('{', '{ '), "#{prefix}{bad}\n", "#{prefix}#{'x' * 4096}\n", "#{prefix}é\n"].each do |bytes|
        assert_nil diagnostic.parse(bytes, deadline_ns: 10)
      end
      assert_nil diagnostic.parse(packet, deadline_ns: 1)
    end

    # The bounded run view reads only the original, already-unwound state.
    # Its inner pass/status0 is not eligibility for an adapter failure line.
    run_checks = %w[driverComplete dispatchRequested recoveryEntered recoveryFilesComplete dispatchMatched
      ownerValidated nativeFinal knownDead deathAttempted deathCompleted directoryIdentityMatched layoutAccepted
      removalAttempted removalCompleted]
    run_proof_fields = %w[versionOne ownerFinality custodianMatches keeperMatches validatorMatches groupMatches noProducersMatch]
    run_result_fields = %w[resultKind retainedDriverErrorCategory retainedDriverErrorCode nativeChecks nativeOutcomes]
    run_extended_fields = run_result_fields + ["captureDetail"]
    assert_equal run_checks, fixture::OWNERSHIP_RUN_CHECKS
    assert_equal run_proof_fields, fixture::OWNERSHIP_RUN_NATIVE_PROOF_FIELDS
    assert_equal run_result_fields, fixture::OWNERSHIP_RUN_RESULT_FIELDS
    assert_equal run_extended_fields, fixture::OWNERSHIP_RUN_EXTENDED_RESULT_FIELDS
    clone = ->(value) { JSON.parse(JSON.generate(value)) }
    run_status_type = Struct.new(:exitstatus, :termsig) do
      def exited? = !exitstatus.nil?
      def signaled? = !termsig.nil?
    end
    fresh_run_state = lambda do |original|
      child = {"state" => "reaped", "status_kind" => "exit", "status_code" => 0}
      owner = clone.call({"finality" => "finalized", "custodian" => child, "keeper" => child, "validator" => child,
        "group" => {"state" => "retired"}, "processes" => [], "private" => "private-marker"})
      result = clone.call({"kind" => "pass", "errorClass" => nil, "error" => nil, "private" => "private-marker",
        "nativeObservation" => {"version" => 1, "finalized" => true, "noProducers" => false, "settled" => true,
          "unknown" => false, "hooksRestored" => true, "observerErrors" => [], "custodian" => child,
          "final" => {"keeper" => child, "validator" => child, "group" => {"state" => "retired"}, "outcome" => "ok", "cleanup" => "confirmed"}}})
      frame = fixture::Lifetime.allocate
      frame.instance_variable_set(:@primary, original)
      frame.instance_variable_set(:@cleanup_errors, [fixture::Failure.new("fixture-cleanup", "unresolved observer scratch prevents fixture removal")])
      frame.instance_variable_set(:@cleanup_error_stages, {0 => +"directory-removal"})
      {unwound: true, mode: "inherited", escaped_error: original, record: {"directoryState" => :canonical}, lifetime: frame,
       status: run_status_type.new(0, nil), owner: owner, result: result, result_source: +"recovered",
       checks: run_checks.to_h { |key| [key, !%w[layoutAccepted removalCompleted].include?(key)] }}
    end
    original_state = fresh_run_state.call(first)
    original_errors = original_state.fetch(:lifetime).instance_variable_get(:@cleanup_errors)
    original_stages = original_state.fetch(:lifetime).instance_variable_get(:@cleanup_error_stages)
    assert_nil fixture.adapter_failure_line(platform: "ios", mode: "inherited", result: original_state.fetch(:result), status: original_state.fetch(:status))
    run_view = fixture.stub(:adapter_failure_line, ->(**_) { raise "run view borrowed adapter failure eligibility" }) do
      diagnostic.run_cleanup(original_state, operation: first)
    end
    assert_ownership_capture_detail_projection(fresh_run_state, first)
    assert_equal %w[directoryState driverStatus resultSource checks nativeProof cleanupErrors driverResult], run_view.keys
    assert_equal ["canonical", {"kind" => "exit", "code" => 0}, "recovered"], run_view.values_at("directoryState", "driverStatus", "resultSource")
    assert_equal original_state.fetch(:checks), run_view.fetch("checks")
    assert_equal [true, "finalized", true, true, true, true, false], run_view.fetch("nativeProof").values
    assert_equal [["directory-removal", "fixture-error", "fixture-cleanup", "observer-scratch"]], run_view.fetch("cleanupErrors")
    assert_equal run_extended_fields, run_view.fetch("driverResult").keys
    assert_equal %w[pass none none], run_view.fetch("driverResult").values_at(*run_result_fields.first(3))
    assert_equal fixture.adapter_result_projection(mode: "inherited", result: original_state.fetch(:result)).slice(*run_result_fields),
      run_view.fetch("driverResult").slice(*run_result_fields)
    assert_equal ["missing", "m" * 24, "m" * 9, "m" * 4, "m" * 3, %w[missing missing]], run_view.fetch("driverResult").fetch("captureDetail")
    deeply_frozen = lambda do |value|
      next false unless value.frozen?
      case value
      when Hash then value.all? { |key, item| deeply_frozen.call(key) && deeply_frozen.call(item) }
      when Array then value.all? { |item| deeply_frozen.call(item) }
      else true
      end
    end
    assert deeply_frozen.call(run_view)
    refute original_errors.frozen?
    assert_same first, original_state.fetch(:lifetime).primary
    [original_state, original_state.fetch(:record), original_state.fetch(:checks), original_state.fetch(:owner),
     original_state.fetch(:result), original_state.fetch(:result).fetch("nativeObservation"), original_stages].each { |value| refute value.frozen? }
    [[original_state.fetch(:result).fetch("kind"), run_view.fetch("driverResult").fetch("resultKind")],
     [original_state.fetch(:owner).fetch("finality"), run_view.fetch("nativeProof").fetch("ownerFinality")],
     [original_state.fetch(:result_source), run_view.fetch("resultSource")],
     [original_stages.fetch(0), run_view.fetch("cleanupErrors").first.first]].each do |source, projected|
      refute source.frozen?, "optional run view froze an original operand"
      refute_same source, projected
      source.replace("private-marker")
    end
    assert_equal %w[pass finalized recovered directory-removal], [run_view.dig("driverResult", "resultKind"),
      run_view.dig("nativeProof", "ownerFinality"), run_view.fetch("resultSource"), run_view.fetch("cleanupErrors").first.first]
    refute_includes JSON.generate(run_view), "private-marker"

    # The same secondary raised twice is two original occurrences, with its
    # original per-occurrence stage; optional missing stages never drop it.
    repeated_state = fresh_run_state.call(first)
    secondary = IOError.new("private-marker")
    repeated_errors = [secondary, secondary]
    repeated_frame = repeated_state.fetch(:lifetime)
    repeated_frame.instance_variable_set(:@cleanup_errors, repeated_errors)
    repeated_frame.instance_variable_set(:@cleanup_error_stages, {0 => "child-stop", 1 => "transcript-out-close"})
    assert_equal [["child-stop", "io-error", "none", "other"], ["transcript-out-close", "io-error", "none", "other"]],
      diagnostic.run_cleanup(repeated_state, operation: first).fetch("cleanupErrors")
    assert_same repeated_errors, repeated_frame.instance_variable_get(:@cleanup_errors)
    repeated_errors.each { |error| assert_same secondary, error }
    repeated_frame.instance_variable_set(:@cleanup_error_stages, nil)
    assert_equal [["missing", "io-error", "none", "other"]] * 2, diagnostic.run_cleanup(repeated_state, operation: first).fetch("cleanupErrors")
    repeated_errors.concat([secondary] * 6)
    assert_equal "missing", diagnostic.run_cleanup(repeated_state, operation: first)
    assert_equal 8, repeated_errors.length # Never truncate to the diagnostic ceiling.
    assert_same first, repeated_frame.primary

    conditions = {
      ["fixture-cleanup", "completed driver dispatch changed before cleanup accounting"] => "recovery-dispatch-mismatch",
      ["fixture-result", "invalid native owner observation"] => "owner-shape",
      ["fixture-result", "unbound native process observation"] => "owner-unbound",
      ["fixture-result", "duplicate native observation identity"] => "owner-duplicate",
      ["fixture-result", "native observation graph changed"] => "owner-graph",
      ["fixture-cleanup", "driver directory identity changed"] => "driver-identity-changed",
      ["fixture-cleanup", "fixture directory is not canonical"] => "directory-not-canonical",
      ["fixture-cleanup", "fixture directory is not private and owned"] => "directory-not-private",
      ["fixture-cleanup", "fixture directory changed before enumeration"] => "enumeration-before-identity",
      ["fixture-cleanup", "fixture directory enumeration changed identity"] => "enumeration-open-identity",
      ["fixture-cleanup", "fixture directory listing is oversized or ambiguous"] => "enumeration-listing",
      ["fixture-cleanup", "fixture directory changed during enumeration"] => "enumeration-after-identity",
      ["fixture-cleanup", "fixture directory enumeration failed"] => "enumeration-io",
      ["fixture-cleanup", "unresolved observer scratch prevents fixture removal"] => "observer-scratch",
      ["process-observation", "process observer failed or returned unsupported output"] => "observer-output",
      ["process-observation", "process observer returned malformed or incorrectly scoped metadata"] => "observer-metadata",
      ["fixture-cleanup", "fixture-cleanup deadline expired"] => "death-cutoff",
    }
    assert_equal conditions, fixture::OWNERSHIP_RUN_CONDITION_LITERALS
    assert_equal conditions.to_h { |(kind, _message), code| [code, kind] }, fixture::OWNERSHIP_RUN_CONDITIONS
    conditions.each do |(kind, message), code|
      assert_equal code, diagnostic.run_condition(fixture::Failure.new(kind, message))
      assert_equal "other", diagnostic.run_condition(fixture::Failure.new(kind, "#{message} private-marker"))
      assert_equal "other", diagnostic.run_condition(fixture::Failure.new("other", message))
    end
    unavailable = fixture::Failure.new("fixture-cleanup", "private-marker")
    unavailable.define_singleton_method(:message) { raise IOError, "private-marker" }
    assert_equal "missing", diagnostic.run_condition(unavailable)

    state = fresh_run_state.call(first)
    [nil, {}, state.merge(unwound: false), state.merge(escaped_error: Interrupt.new(first.message)), state.merge(mode: "real-deadline"),
     state.merge(record: nil), state.merge(lifetime: Object.new), state.merge(checks: nil)].each do |unbound|
      assert_equal "missing", diagnostic.run_cleanup(unbound, operation: first)
    end
    assert_equal "missing", diagnostic.run_cleanup(state, operation: nil)
    [[nil, nil, "missing", "missing"], [0, nil, "exit", 0], [255, nil, "exit", 255],
     [nil, 1, "signal", 1], [nil, 255, "signal", 255], [-1, nil, "missing", "missing"],
     [256, nil, "missing", "missing"], [true, nil, "missing", "missing"], [nil, 0, "missing", "missing"]].each do |exit_code, signal_code, kind, code|
      selected = state.merge(status: run_status_type.new(exit_code, signal_code))
      assert_equal({"kind" => kind, "code" => code}, diagnostic.run_cleanup(selected, operation: first).fetch("driverStatus"))
    end
    [["missing", "missing"], ["recovered", "invalid"]].each do |source, expected_result|
      selected = state.merge(owner: nil, result: nil, result_source: source)
      view = diagnostic.run_cleanup(selected, operation: first)
      assert_equal expected_result, view.fetch("driverResult")
      assert_equal ["missing"] * 7, view.fetch("nativeProof").values
    end
    state.fetch(:result).fetch("nativeObservation")["version"] = "1"
    state.fetch(:result).fetch("nativeObservation")["settled"] = 0
    state.fetch(:owner)["keeper"] = {"state" => "unknown"}
    state.fetch(:owner)["finality"] = nil
    view = diagnostic.run_cleanup(state, operation: first)
    assert_equal [false, "invalid", true, false, true, true, false], view.fetch("nativeProof").values
    assert_equal "invalid", view.dig("driverResult", "nativeChecks", "settled")
    assert view.dig("checks", "nativeFinal") # Do not recompute the actual original verdict from optional comparisons.
    no_producers = fresh_run_state.call(first)
    none = {"state" => "not_attempted"}
    no_producers[:owner] = {"finality" => "no_producers", "custodian" => none, "keeper" => none, "validator" => none,
      "group" => {"state" => "not_created"}, "processes" => []}
    no_producers[:result] = {"kind" => "pass", "nativeObservation" => {"version" => 1, "custodian" => none,
      "noProducers" => true, "settled" => true, "unknown" => false, "hooksRestored" => true}}
    no_producers[:checks] = no_producers.fetch(:checks).merge("nativeFinal" => false, "knownDead" => false,
      "deathAttempted" => false, "deathCompleted" => false, "removalAttempted" => false, "removalCompleted" => false)
    view = diagnostic.run_cleanup(no_producers, operation: first)
    assert_equal [true, "no-producers", true, "missing", "missing", "missing", true], view.fetch("nativeProof").values
    assert_equal [false] * 6, view.fetch("checks").values_at("nativeFinal", "knownDead", "deathAttempted", "deathCompleted", "removalAttempted", "removalCompleted")
    [Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |projection_error|
      fixture.stub(:adapter_result_projection, ->(**_) { raise projection_error }) do
        assert_equal "missing", diagnostic.run_cleanup(state, operation: first)
      end
      assert_same first, state.fetch(:lifetime).primary
      assert_same first, state.fetch(:escaped_error)
    end

    run_expected = expected.merge("helper" => "run", "case" => "async-reap", "row" => row.merge("runCleanup" => run_view))
    run_packet = diagnostic.line(run_expected)
    assert_equal "#{prefix}#{JSON.generate(run_expected)}\n", run_packet
    assert_nil diagnostic.line(run_expected.merge("helper" => "capture"))
    assert_nil diagnostic.line(run_expected.merge("row" => run_expected.fetch("row").merge("operationErrorCategory" => "none", "operationErrorKind" => "none")))
    invalid_views = [nil, run_view.merge("private" => "private-marker"), run_view.to_a.reverse.to_h,
      run_view.merge("driverStatus" => {"kind" => "exit", "code" => true}),
      run_view.merge("driverStatus" => {"kind" => "signal", "code" => 256}),
      run_view.merge("checks" => run_view.fetch("checks").merge("nativeFinal" => 0)),
      run_view.merge("nativeProof" => run_view.fetch("nativeProof").merge("ownerFinality" => "no_producers")),
      run_view.merge("cleanupErrors" => [["directory-removal", "fixture-error", "fixture-result", "observer-scratch"]]),
      run_view.merge("cleanupErrors" => [["directory-removal", "none", "none", "other"]]),
      run_view.merge("cleanupErrors" => run_view.fetch("cleanupErrors") * 8),
      run_view.merge("driverResult" => run_view.fetch("driverResult").merge("retainedDriverErrorCode" => "native-deadline")),
      run_view.merge("driverResult" => run_view.fetch("driverResult").merge("nativeChecks" => run_view.dig("driverResult", "nativeChecks").merge("unknown" => nil)))]
    invalid_views.each { |value| assert_nil diagnostic.line(run_expected.merge("row" => run_expected.fetch("row").merge("runCleanup" => value))) }

    # Enumerate the complete finite maximum, not a representative failure.
    # All seven original error occurrences fit; capture cannot carry this view.
    driver_pairs = fixture::ADAPTER_FAILURE_CODES.map { |(name, _message), code| [fixture::ADAPTER_FAILURE_CATEGORIES.fetch(name), code] }
    driver_pairs.concat((fixture::ADAPTER_FAILURE_CATEGORIES.values + %w[other]).product(%w[missing invalid other]))
    driver_pairs.concat([%w[missing missing], %w[none missing], %w[none none], %w[none invalid], %w[invalid missing], %w[invalid invalid]])
    driver_category, driver_code = driver_pairs.max_by { |pair| pair.sum(&:bytesize) }
    primary_pairs = fixture::OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.flat_map { |category, kinds| kinds.map { |kind| [category, kind] } }
    maximum_primary = primary_pairs.max_by { |pair| JSON.generate(pair).bytesize }
    maximum_detail = [(fixture::ADAPTER_FAILURE_CATEGORIES.values + %w[none missing invalid other]).max_by(&:bytesize),
      "x" * 24, "x" * 9, "x" * 4, "x" * 3, maximum_primary]
    assert_equal %w[native-lifecycle-error parent_lost], maximum_primary
    assert_equal 40, JSON.generate(maximum_primary).bytesize
    assert_equal 119, JSON.generate(maximum_detail).bytesize
    assert diagnostic.capture_detail_valid?(maximum_detail)
    maximum_result = {"resultKind" => (fixture::ADAPTER_FAILURE_KINDS + %w[missing invalid other]).max_by(&:bytesize),
      "retainedDriverErrorCategory" => driver_category, "retainedDriverErrorCode" => driver_code,
      "nativeChecks" => fixture::ADAPTER_FAILURE_NATIVE_CHECKS.to_h { |key| [key, "missing"] },
      "nativeOutcomes" => fixture::ADAPTER_FAILURE_NATIVE_OUTCOMES.to_h { |key, values| [key, values.max_by(&:bytesize)] },
      "captureDetail" => maximum_detail}
    error_tuples = fixture::OWNERSHIP_FAILURE_ERROR_KINDS.reject { |category, _| category == "none" }.flat_map do |category, kinds|
      kinds.flat_map do |kind|
        eligible = %w[other missing] + fixture::OWNERSHIP_RUN_CONDITIONS.filter_map { |code, required| code if category == "fixture-error" && kind == required }
        eligible.map { |code| [fixture::OWNERSHIP_RUN_ERROR_STAGES.max_by(&:bytesize), category, kind, code] }
      end
    end
    maximum_error = error_tuples.max_by { |value| JSON.generate(value).bytesize }
    assert_equal %w[transcript-out-close fixture-error fixture-cleanup enumeration-before-identity], maximum_error
    assert_equal 88, JSON.generate(maximum_error).bytesize
    assert_equal 1375, JSON.generate(maximum_result).bytesize
    maximum_view = {"directoryState" => "unattempted", "driverStatus" => {"kind" => "missing", "code" => "missing"}, "resultSource" => "recovered",
      "checks" => run_checks.to_h { |key| [key, "missing"] },
      "nativeProof" => run_proof_fields.to_h { |key| [key, key == "ownerFinality" ? "no-producers" : "missing"] },
      "cleanupErrors" => [maximum_error] * 7, "driverResult" => maximum_result}
    assert_equal 2757, JSON.generate(maximum_view).bytesize
    maximum_lines = cases.flat_map do |family, names|
      names.map do |name|
        value = expected.merge("platform" => "android", "family" => family, "helper" => "run", "case" => name,
          "row" => widest.merge("failedChecks" => all_codes.select { |code| applicable.call(code, family, "run", name) }, "runCleanup" => maximum_view))
        diagnostic.line(value)
      end
    end
    maximum_packet = maximum_lines.max_by(&:bytesize)
    assert_equal 3983, maximum_packet.bytesize
    assert_equal 113, 4096 - maximum_packet.bytesize
    assert_operator maximum_packet.bytesize, :<=, 4096
    fixture.stub(:clock_ns, 1) do
      assert_equal run_expected, diagnostic.parse(run_packet, deadline_ns: 10)
      assert_equal maximum_view, diagnostic.parse(maximum_packet, deadline_ns: 10).fetch("row").fetch("runCleanup")
      assert_nil diagnostic.parse(run_packet.sub('"runCleanup":', '"runCleanup":"missing","runCleanup":'), deadline_ns: 10)
      oversized = maximum_packet.chomp + " " * (4097 - maximum_packet.bytesize) + "\n"
      assert_equal 4097, oversized.bytesize
      JSON.stub(:parse, ->(*_, **_) { flunk "oversized ownership diagnostic reached JSON parsing" }) do
        assert_nil diagnostic.parse(oversized, deadline_ns: 10)
      end
    end

    # The real invoke routing gives run a fresh state, not a prior invocation's
    # error; the capture endpoint never receives this optional run keyword.
    family_final = 97_000_000_001
    family_admission = 60_000_000_001
    row_cutoff = 36_000_000_001
    invoker, invocations = probe_class.allocate, []
    {family: "async", helper: "run", case: "async-reap", case_root: "/inert-run-route", deadline_ns: family_final,
     input: {"platform" => "ios", "parameters" => {}}}.each { |key, value| invoker.instance_variable_set(:"@#{key}", value) }
    fixture.stub(:clock_ns, 1) do
      fixture.stub(:run, ->(**keywords) { invocations << keywords; :inert_run }) do
        2.times { assert_equal :inert_run, invoker.invoke }
      end
    end
    invocations.each do |keywords|
      assert_equal %i[platform root parameters mode deadline_ns run_cleanup_state], keywords.keys
      assert_equal ["ios", "/inert-run-route", {}, "inherited", row_cutoff], keywords.values_at(:platform, :root, :parameters, :mode, :deadline_ns)
      assert_empty keywords.fetch(:run_cleanup_state)
    end
    refute_same(*invocations.map { |keywords| keywords.fetch(:run_cleanup_state) })
    invoker.instance_variable_set(:@helper, "capture")
    with_stubs.call([[fixture, :clock_ns, 1], [File, :realpath, ->(path) { path }], [fixture, :capture_command, ->(argv, **keywords) do
      assert_equal [RbConfig.ruby, "-e", "exit 0"], argv
      assert_equal({seconds: 2, root: "/inert-run-route", deadline: Rational(row_cutoff, 1_000_000_000)}, keywords)
      :inert_capture
    end]]) { assert_equal :inert_capture, invoker.invoke }

    # Run actual one -> execute -> driver-rescue. Directory, proof, observation,
    # trace and signal endpoints are inert; acquisition veto remains outside.
    produce = lambda do |family: "async", helper: "capture", name: nil, platform: "ios", fault: nil, run_fault: nil, timing: nil, write_result: :full|
      name ||= cases.fetch(family).first
      now, constructions, current, lookalike = 1, 0, nil, nil
      events, writes, proofs, rows = [], [], [], []
      run_states, run_projections = [], []
      directory = "/inert-ownership-driver"
      mode = "ownership-#{family}"
      input = {"platform" => platform, "parameters" => {}, "mode" => mode, "deadlineNs" => family_final}
      late = IOError.new("private-marker")
      first_error = Interrupt.new("private-marker")
      handlers = {"INT" => "DEFAULT", "TERM" => "DEFAULT"}
      snapshot = fixture::OWNERSHIP_FAILURE_COMMAND_CHECKS.reject { |key| key == "observerErrorsEmpty" }.to_h { |key| [key, true] }
      snapshot.merge!("noProducers" => false, "unknown" => false, "observerErrors" => [])
      digest = Struct.new(:hexdigest).new("a" * 64)
      trace = Object.new
      trace.define_singleton_method(:enable) { events << :trace_enabled }
      trace.define_singleton_method(:disable) { events << :trace_disabled }
      observation = Object.new
      observation.define_singleton_method(:observe) { |&body| body.call }
      observation.define_singleton_method(:snapshot) do
        events << :snapshot
        raise late if fault == :snapshot && current.instance_variable_get(:@target)
        selected = current.instance_variable_get(:@case)
        no_producers = family == "policies" && (selected.start_with?("custom-") || selected == "partial-install")
        snapshot.merge("settled" => !current.instance_variable_get(:@target), "unknown" => !!current.instance_variable_get(:@target),
          "noProducers" => no_producers && !current.instance_variable_get(:@target))
      end
      fresh = lambda do
        probe = probe_class.allocate
        {directory: directory, family: family, input: input, deadline_ns: family_final, records: []}.each do |key, value|
          probe.instance_variable_set(:"@#{key}", value)
        end
        probe
      end
      driver_probe = fresh.call
      constructor = lambda do |selected_directory, selected_family|
        raise "inert constructor scope changed" unless selected_directory == directory && selected_family == family
        constructions += 1
        driver_probe.instance_variable_set(:@deadline_ns, family_final + 1) if timing == :changed_driver && constructions == 1
        next driver_probe if constructions == 1
        raise late if fault == :next_constructor && constructions == 3
        probe = fresh.call
        probe.instance_variable_set(:@deadline_ns, family_final + 1) if timing == :changed_row && constructions == 3
        original_one = probe.method(:one)
        original_invoke = probe.method(:invoke)
        probe.define_singleton_method(:one) do |selected_helper, selected_name|
          current = self
          @target = selected_helper == helper && selected_name == name && !%i[success next_constructor next_cutoff].include?(fault)
          @case_started = true if @target && fault == :entry
          rows << [selected_helper, selected_name]
          if timing == :near_admission
            now = rows.length == 2 * cases.fetch(family).length ? family_admission - 1 : rows.length * 1_000_000_000
          end
          begin
            value = original_one.call(selected_helper, selected_name, case_root: directory)
            now = family_admission if fault == :next_cutoff
            value
          ensure
            now = family_final if @target && fault == :before_report
            if @target && run_fault == :row_copy && @ownership_run_binding
              bound_row, operation, state = @ownership_run_binding
              @ownership_run_binding = [bound_row.dup.freeze, operation, state].freeze
            end
          end
        end
        probe.define_singleton_method(:install) { now = family_admission if timing == :invoke_expired }
        probe.define_singleton_method(:trap_state) { handlers.dup }
        probe.define_singleton_method(:invoke) do
          if timing == :invoke_expired
            events << :original_invoke
            next original_invoke.call # Actual post-setup admission, not a mocked guard.
          end
          now = family_admission + 1 if timing == :near_admission && rows.length == 2 * cases.fetch(family).length
          @owner = Struct.new(:phase).new(:reaped)
          @owner.define_singleton_method(:complete?) { true }
          # Exercise the REAL policy evaluator, not an async row relabelled
          # as policy. These are inert operation endpoints, never receipts.
          if @family == "policies"
            if @case == "normal" || @case.start_with?("ignored-")
              run_states << (@run_cleanup_state = {}) if @helper == "run" # A successful run has no escaping operation.
              next
            end
            original = @target && @case == "custom-INT" ? first_error : fixture::Failure.new("signal-policy", "private-marker")
            @custom_deliveries << Signal.list.fetch("INT") if @case == "custom-pending-INT" && !@target
            if @case == "partial-install" && !@target
              @partial_install_error = original
              @events << {"boundary" => "before-original-TERM-policy-installation", "intTrapCalls" => 1, "termTrapCalls" => 1}
            end
            handlers["INT"] = @foreign if @case == "changed-handler"
            if @case.start_with?("finalize-") && !@target
              @injected, @outer_lifetime = true, Object.new
              @events << {"boundary" => "finalization-#{@case.delete_prefix('finalize-')}-failure", "originalOutermostLifetime" => true}
            end
          else
            original = @case.include?("TERM") ? SignalException.new("TERM") : @target ? first_error : Interrupt.new("private-marker")
            @events << {"boundary" => "inert-original-cancellation"}
            @pre_go_cancellation = !(@target && @family == "signals")
            @nested_cancelled = true
          end
          @first, @first_message = original, original.message
          if @helper == "run"
            state = fresh_run_state.call(original)
            state[:unwound] = false if @target && run_fault == :unwound
            state[:escaped_error] = Interrupt.new(original.message) if @target && run_fault == :different_error
            @run_cleanup_state = if @target && run_fault == :missing
              nil
            elsif @target && run_fault == :earlier_state
              run_states.last
            else
              state
            end
            run_states << state
          end
          raise(@target && fault == :first_replaced ? Interrupt.new(original.message) : original)
        end
        probe
      end
      environment = {}
      formatter = diagnostic.method(:line)
      run_projector = diagnostic.method(:run_cleanup)
      driver_projector = fixture.method(:adapter_result_projection)
      project_run = lambda do |state, operation:|
        assert_empty environment, "run cleanup projected before complete one.ensure environment restoration"
        assert_equal false, current.instance_variable_get(:@context).fetch(:gate).fetch(:active)
        events << :run_projection
        run_projections << [state, operation]
        run_projector.call(state, operation: operation)
      end
      projection = lambda do |value|
        raise late if fault == :format
        value = formatter.call(value)
        now = family_final if fault == :before_write
        value
      end
      sink = lambda do |bytes|
        events << :write
        writes << bytes
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : bytes.bytesize
      end
      bindings = [
        [fixture, :clock_ns, -> { now }], [fixture, :read_json, input],
        [fixture, :validate_driver_input!, ->(_directory, value, **_) { value }],
        [fixture::OwnedChild, :write_record, ->(*) { events << :dispatch }], [File, :realpath, ->(path) { path }],
        [Digest::SHA256, :file, digest], [probe_class, :new, constructor], [fixture::CommandObservation, :new, observation],
        # Construction registers a callback; a fixed-value Minitest stub would
        # incorrectly invoke it immediately, without an event argument.
        [TracePoint, :new, ->(*) { trace }], [Signal, :trap, ->(key, handler) do
          events << :restore
          now = family_final if timing == :restoration_expired && rows.length == 2 * cases.fetch(family).length
          if current&.instance_variable_get(:@target) && current.instance_variable_get(:@ownership_failure_caught)
            raise late if fault == :restoration
            if fault == :restoration_lookalike
              original = current.instance_variable_get(:@ownership_failure_caught).first
              lookalike ||= fixture::Failure.new(original.kind, original.message)
              raise lookalike
            end
          end
          handlers[key] = handler
        end],
        [ENV, :[], ->(key) { environment[key] }], [ENV, :[]=, ->(key, value) { environment[key] = value }],
        [ENV, :delete, ->(key) { environment.delete(key) }], [ENV, :to_h, {}], [Thread.current, :pending_interrupt?, false],
        [fixture, :cleanup_unresolved?, false], [fixture, :fixture_entry_names, []],
        [fixture, :mark_process_domain_failed!, ->(**_) { events << :failed_domain }],
        [fixture, :atomic_json, ->(_path, value) do
          events << :proof
          raise late if fault == :proof && current.instance_variable_get(:@target)
          proofs << value
          now = family_final if timing == :proof_expired
        end],
        [diagnostic, :line, projection], [diagnostic, :run_cleanup, project_run],
        [fixture, :adapter_result_projection, ->(**keywords) { raise late if run_fault == :projection_error; driver_projector.call(**keywords) }],
        [STDERR, :write, sink],
      ]
      actual = nil
      with_stubs.call(bindings) do
        if fault == :success && (timing.nil? || timing == :near_admission)
          assert_equal "pass", fixture.ownership_driver(directory, mode).fetch("kind")
        else
          actual = assert_raises(fixture::Failure, IOError) { fixture.ownership_driver(directory, mode) }
          driver_probe.report_failure(actual) # A failed or short first write cannot authorize retry.
          driver_probe.report_failure(fixture::Failure.new("ownership-probe", actual.message))
        end
      end
      # A real original ensure stops at the replacement trap error. Reflect
      # that failure honestly; this hash is inert, not the interpreter ENV.
      assert_equal(%i[restoration restoration_lookalike].include?(fault) ?
        %w[TMPDIR TMP TEMP].to_h { |key| [key, directory] } : {}, environment)
      assert_operator writes.length, :<=, 1
      refute_includes writes.join, "private-marker"
      if writes.any?
        assert_operator events.index(:write), :>, events.rindex(:restore) if events.include?(:restore)
      end
      if run_projections.any?
        assert_operator events.index(:run_projection), :>, events.rindex(:restore)
        assert_equal 1, run_projections.length # Same original no-retry/cutoff contract as the outer marker.
      end
      {error: actual, writes: writes, row: writes.empty? ? nil : JSON.parse(writes.first.delete_prefix(prefix)),
       proofs: proofs, rows: rows, late: late, probe: current, driver: driver_probe,
       run_states: run_states, run_projections: run_projections, first_error: first_error, clock: now, events: events}
    end
    completed = produce.call(family: "signals", fault: :success, timing: :near_admission)
    assert_equal %w[capture run].product(cases.fetch("signals")), completed.fetch(:rows)
    assert_equal 32, completed.fetch(:proofs).length
    assert_equal ["run", "restore-after-TERM"], completed.fetch(:rows).last
    assert_operator completed.fetch(:clock), :>, family_admission
    assert_operator completed.fetch(:clock), :<, family_final
    assert_empty completed.fetch(:writes)
    expired = produce.call(fault: :next_cutoff)
    assert_equal [["capture", "async-spawn"]], expired.fetch(:rows)
    assert_equal family_admission, expired.fetch(:clock) # Stop new rows while F is still future.
    {changed_driver: 0, changed_row: 1}.each do |timing, row_count|
      changed = produce.call(fault: :success, timing: timing)
      assert_equal row_count, changed.fetch(:rows).length
      assert_equal "original ownership cutoff changed", changed.fetch(:error).message
    end
    late_entry = produce.call(fault: :success, timing: :invoke_expired)
    assert_includes late_entry.fetch(:events), :original_invoke
    assert_equal "ownership-probe", late_entry.fetch(:error).kind
    %i[proof_expired restoration_expired].each do |timing|
      rejected = produce.call(family: "signals", fault: :success, timing: timing)
      assert_equal "ownership success exceeds original family cutoff", rejected.fetch(:error).message
      assert_equal family_final, rejected.fetch(:clock)
      assert_empty rejected.fetch(:writes)
    end
    original_rejection = produce.call(timing: :proof_expired)
    assert_same original_rejection.fetch(:error), original_rejection.fetch(:probe).instance_variable_get(:@ownership_failure_row).first
    refute_includes JSON.parse(original_rejection.fetch(:error).message).fetch("failures"), "original error object/message replaced"
    fixture::OWNERSHIP_FAILURE_HELPERS.product(cases.fetch("async")).each do |helper, name|
      outcome = produce.call(helper: helper, name: name, platform: helper == "capture" ? "ios" : "android")
      value = outcome.fetch(:row)
      assert_equal [helper, name, "row-rejection", "fixture-error", "ownership-probe"], value.values_at("helper", "case", "phase", "errorCategory", "errorKind")
      assert_equal %w[command-not-finalized fixture-retained], value.fetch("row").fetch("failedChecks")
      assert_equal %w[interrupt none interrupt none], value.fetch("row").values_at("firstErrorCategory", "firstErrorKind", "operationErrorCategory", "operationErrorKind")
      assert value.fetch("row").fetch("checks").fetch("firstExceptionPreserved")
      assert_equal 4, value.fetch("schema")
      assert_equal(helper == "run" ? run_view : "missing", value.fetch("row").fetch("runCleanup"))
      assert_equal "missing", outcome.fetch(:probe).instance_variable_get(:@ownership_failure_row).last.fetch("runCleanup")
      if helper == "run"
        bound_state, operation = outcome.fetch(:run_projections).fetch(0)
        assert_same outcome.fetch(:probe).instance_variable_get(:@run_cleanup_state), bound_state
        assert_same outcome.fetch(:first_error), operation
      else
        assert_empty outcome.fetch(:run_projections)
      end
    end
    %w[INT-spawn TERM-spawn TERM-reap restore-after-TERM].each do |name|
      value = produce.call(family: "signals", name: name, helper: "run", platform: "android").fetch(:row)
      assert_equal ["signals", "run", name], value.values_at("family", "helper", "case")
      assert_equal(name.end_with?("-spawn") ? %w[command-not-finalized pre-go-barrier-missing fixture-retained] :
        %w[command-not-finalized fixture-retained], value.fetch("row").fetch("failedChecks"))
      assert_equal(name.include?("TERM") ? "signal" : "interrupt", value.fetch("row").fetch("operationErrorCategory"))
      assert_equal run_view, value.fetch("row").fetch("runCleanup")
    end
    policy_failures = {
      "normal" => %w[normal-command-not-finalized fixture-retained],
      "ignored-TERM" => %w[normal-command-not-finalized fixture-retained],
      "custom-INT" => %w[policy-not-fail-closed policy-native-creation fixture-retained],
      "custom-TERM" => %w[policy-native-creation fixture-retained],
      "custom-pending-INT" => %w[policy-native-creation custom-pending-lost fixture-retained],
      "partial-install" => %w[policy-native-creation partial-install-not-exercised fixture-retained],
      "changed-handler" => %w[fixture-retained],
      "finalize-report" => %w[finalization-cleanup finalization-outer-lifetime fixture-retained],
      "finalize-drain" => %w[finalization-cleanup finalization-outer-lifetime fixture-retained],
    }
    policy_failures.each do |name, codes|
      value = produce.call(family: "policies", name: name, helper: "run", platform: "android").fetch(:row)
      assert_equal ["policies", "run", name], value.values_at("family", "helper", "case")
      assert_equal codes, value.fetch("row").fetch("failedChecks")
      assert value.fetch("row").fetch("checks").fetch("firstExceptionPreserved")
      assert_equal(name == "normal" || name.start_with?("ignored-") ? "missing" : run_view, value.fetch("row").fetch("runCleanup"))
    end
    %i[missing unwound different_error earlier_state row_copy].each do |run_fault|
      outcome = produce.call(helper: "run", name: "async-reap", run_fault: run_fault)
      assert_equal "missing", outcome.fetch(:row).fetch("row").fetch("runCleanup")
      assert_equal %w[command-not-finalized fixture-retained], outcome.fetch(:row).fetch("row").fetch("failedChecks")
      assert_empty outcome.fetch(:run_projections)
      if run_fault == :earlier_state
        assert_operator outcome.fetch(:proofs).length, :>, 0
        earlier = outcome.fetch(:probe).instance_variable_get(:@run_cleanup_state)
        refute_same outcome.fetch(:first_error), earlier.fetch(:escaped_error)
      end
    end
    outcome = produce.call(helper: "run", run_fault: :projection_error)
    assert_equal "missing", outcome.fetch(:row).fetch("row").fetch("runCleanup")
    assert_equal 1, outcome.fetch(:run_projections).length
    assert_same outcome.fetch(:error), outcome.fetch(:probe).instance_variable_get(:@ownership_failure_row).first
    assert_same outcome.fetch(:first_error), outcome.fetch(:run_states).last.fetch(:lifetime).primary
    outcome = produce.call(helper: "run", fault: :before_report)
    assert_empty outcome.fetch(:writes)
    assert_empty outcome.fetch(:run_projections) # A new optional view cannot renew the original reporting cutoff.
    {"signals" => "TERM-reap", "policies" => "partial-install"}.each do |family, name|
      outcome = produce.call(family: family, name: name, fault: :snapshot)
      assert_operator outcome.fetch(:proofs).length, :>, 0 # Earlier success cannot supply THIS missing row.
      assert_equal [family, name, "snapshot", "missing"], outcome.fetch(:row).values_at("family", "case", "phase", "row")
      assert_same outcome.fetch(:late), outcome.fetch(:error)
      assert_empty produce.call(family: family, fault: :success).fetch(:writes)
    end
    %w[capture run].each do |helper|
      outcome = produce.call(helper: helper, fault: :first_replaced)
      replaced = outcome.fetch(:row).fetch("row")
      assert_equal %w[primary-not-preserved command-not-finalized fixture-retained], replaced.fetch("failedChecks")
      refute replaced.fetch("checks").fetch("firstExceptionPreserved")
      assert_equal "missing", replaced.fetch("runCleanup")
      assert_empty outcome.fetch(:run_projections)
    end
    {entry: "entry", snapshot: "snapshot", proof: "proof-publication", restoration: "restoration"}.each do |fault, phase|
      outcome = produce.call(fault: fault)
      value = outcome.fetch(:row)
      assert_equal [phase, "missing"], value.values_at("phase", "row")
      assert_same outcome.fetch(:late), outcome.fetch(:error) unless fault == :entry
    end
    %w[capture run].each do |helper|
      lookalike = produce.call(helper: helper, fault: :restoration_lookalike)
      assert_equal ["restoration", "fixture-error", "ownership-probe", "missing"], lookalike.fetch(:row).values_at("phase", "errorCategory", "errorKind", "row")
      bound = lookalike.fetch(:probe).instance_variable_get(:@ownership_failure_row).first
      assert_equal bound.message, lookalike.fetch(:error).message
      refute_same bound, lookalike.fetch(:error)
      assert_empty lookalike.fetch(:run_projections)
    end
    %i[next_constructor next_cutoff success format before_report before_write].each { |fault| assert_empty produce.call(fault: fault).fetch(:writes) }
    [:short, IOError.new("private-marker"), Interrupt.new("private-marker"), SystemExit.new(19, "private-marker")].each do |write_result|
      outcome = produce.call(write_result: write_result)
      assert_equal 1, outcome.fetch(:writes).length
      assert_equal "ownership-probe", outcome.fetch(:error).kind
      if write_result.is_a?(Exception)
        assert_same write_result, outcome.fetch(:probe).instance_variable_get(:@ownership_failure_diagnostic_error)
      else
        refute outcome.fetch(:probe).instance_variable_get(:@ownership_failure_write_complete)
      end
    end

    # Original parent custody/request/dispatch checks, optional state transfer,
    # and complete real Lifetime unwind precede the actual Contracts relay.
    relay = lambda do |family: "async", platform: "ios", fault: nil, stderr: packet, write_result: :full|
      now, dispatch, snapshot, state, escaped = 1, nil, nil, nil, nil
      events, writes, supplied_states = [], [], []
      directory, mode = "/inert-ownership-parent", "ownership-#{family}"
      callback = callbacks.fetch(family)
      digest = Struct.new(:hexdigest).new("a" * 64)
      policy = Object.new
      depth = 0
      policy.define_singleton_method(:install) { events << :install }
      policy.define_singleton_method(:cleanup_depth) { depth }
      policy.define_singleton_method(:cleanup) do |&body|
        depth += 1
        begin
          body.call
        ensure
          events << :cleanup
          depth -= 1
        end
      end
      policy.define_singleton_method(:restore) { |&body| body.call; events << :restored }
      policy.define_singleton_method(:errors) { [] }
      policy.define_singleton_method(:replay_custom_pending) { events << :replay }
      observation = Object.new
      observation.define_singleton_method(:observe) { |&body| body.call }
      observation.define_singleton_method(:snapshot) { snapshot }
      capture = lambda do |argv, seconds:, environment:, root:, deadline:|
        raise "inert original cutoff changed" unless deadline == Rational(family_final, 1_000_000_000) && seconds == Rational(family_final - 1, 1_000_000_000) && root == directory
        events << :captured
        dispatch = {"version" => 1, "argv" => argv, "environment" => environment, "cwd" => Dir.pwd,
          "fixtureSha256" => digest.hexdigest, "deadlineNs" => family_final, "pid" => 701}
        requested = {"executable" => argv.first, "argv" => argv, "environment" => environment, "cwd" => Dir.pwd}
        snapshot = {"settled" => true, "actualOwnedControlCloses" => true, "actualTaskJoins" => true,
          "children" => [{"pid" => 701, "finality" => "finalized", "originalWaitObserved" => true, "creatorJoinObserved" => true,
            "actualStreamEOFs" => true, "actualNativeCloses" => true, "provenance" => {"requested" => requested}}]}
        snapshot["settled"] = false if fault == :custody
        requested["cwd"] = "/wrong-inert-request" if fault == :request
        dispatch["pid"] = 702 if fault == :dispatch
        ["not-json-success", stderr, 1] # Failed status must remain a rejection without parsing stdout.
      end
      receiver = Object.new.extend(fixture::Contracts)
      receiver.define_singleton_method(:name) do
        fault == :callback ? "test_other" : fault == :other_family_callback ? callbacks.fetch(family == "async" ? "signals" : "async") : callback
      end
      replacement = IOError.new("private-marker")
      formatter = diagnostic.method(:line)
      projection_count = 0
      project = lambda do |value|
        projection_count += 1
        raise replacement if fault == :format
        value = formatter.call(value)
        now = family_final if fault == :before_write && projection_count == 2
        value
      end
      sink = lambda do |bytes|
        assert_nil fixture.instance_variable_get(:@cancellation_scope)
        assert_equal :unwound, events.last
        writes << bytes
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : bytes.bytesize
      end
      saved = %i[@probe_records @unresolved_roots].to_h do |key|
        [key, [fixture.instance_variable_defined?(key), fixture.instance_variable_get(key)]]
      end
      saved.each_key { |key| fixture.instance_variable_set(key, {}) }
      # Preserve the outer acquisition-veto method without nesting Minitest's
      # same-name alias. This hook returns data only and is restored by identity.
      directory_hook = fixture::CaptureObservation::Hooks.new
      directory_hook.wrap(Dir.singleton_class, :mktmpdir) { |*| directory }
      bindings = [
        [fixture, :clock_ns, -> { now }], [fixture::CancellationScope, :new, policy], [Thread.current, :pending_interrupt?, false],
        [File, :realpath, ->(path) { path }], [fixture::OwnedChild, :directory_identity, :inert_directory],
        [fixture, :atomic_json, ->(*) { events << :input }], [Digest::SHA256, :file, digest],
        [fixture, :driver_environment, {}], [fixture::CommandObservation, :new, observation], [fixture, :capture_command, capture],
        [fixture::OwnedChild, :bounded_file, ->(_path) { JSON.generate(dispatch) }],
        [fixture, :retain_unknown_domain!, ->(*, **) { events << :retained }], [fixture, :warn, ->(*) { nil }],
        [receiver, :class, Struct.new(:name).new(classes.fetch(platform))], [diagnostic, :line, project], [STDERR, :write, sink],
      ]
      actual = nil
      with_stubs.call(bindings) do
        actual = assert_raises(fixture::Failure, IOError) do
          receiver.with_adapter_failure_diagnostic(platform: platform, mode: mode) do |optional|
            supplied_states << optional
            state = optional.fetch(:ownership_failure_state)
            state.freeze if fault == :state
            begin
              fixture.run(platform: platform, root: directory, parameters: {}, mode: mode, deadline_ns: family_final, **optional)
            rescue Exception => original
              escaped = original
              raise
            ensure
              events << :unwound
              now = family_final if fault == :before_report
              state[:rejection] = fixture::Failure.new("ownership-probe", escaped.message) if fault == :same_message
              raise replacement if fault == :outer_replacement
            end
          end
        end
        # A later retry request never rereads/rewrites an already attempted marker.
        fixture.report_ownership_failure(state, actual, platform: platform, mode: mode, callback: "#{classes.fetch(platform)}##{callback}")
      end
      assert_equal [:ownership_failure_state], supplied_states.fetch(0).keys
      assert_nil fixture.instance_variable_get(:@cancellation_scope)
      assert_operator events.index(:unwound), :>, events.index(:replay)
      assert_operator writes.length, :<=, 1
      assert_same(fault == :outer_replacement ? replacement : escaped, actual)
      {state: state, writes: writes, error: actual, replacement: replacement}
    ensure
      saved&.each do |key, (existed, value)|
        existed ? fixture.instance_variable_set(key, value) : fixture.remove_instance_variable(key)
      end
      assert_empty directory_hook.restore if directory_hook
    end
    classes.keys.product(cases.keys).each do |platform, family|
      bytes = diagnostic.line(expected.merge("platform" => platform, "family" => family, "case" => cases.fetch(family).first,
        "row" => row.merge("failedChecks" => ["fixture-retained"])))
      outcome = relay.call(platform: platform, family: family, stderr: bytes)
      assert_equal [bytes], outcome.fetch(:writes)
      assert_same outcome.fetch(:error), outcome.fetch(:state).fetch(:rejection)
      assert_equal [family_final, true], outcome.fetch(:state).values_at(:deadline_ns, :write_complete)
      assert_equal "ownership-probe", outcome.fetch(:error).kind
      assert_empty relay.call(platform: platform, family: family, stderr: bytes, fault: :other_family_callback).fetch(:writes)
      other_family = family == "async" ? "signals" : "async"
      other_bytes = diagnostic.line(expected.merge("platform" => platform, "family" => other_family, "case" => cases.fetch(other_family).first))
      assert_empty relay.call(platform: platform, family: family, stderr: other_bytes).fetch(:writes)
    end
    nested_relay = relay.call(stderr: run_packet)
    assert_equal [run_packet], nested_relay.fetch(:writes)
    assert_same nested_relay.fetch(:error), nested_relay.fetch(:state).fetch(:rejection)
    assert_equal [family_final, true], nested_relay.fetch(:state).values_at(:deadline_ns, :write_complete)
    assert_empty relay.call(stderr: run_packet, fault: :other_family_callback).fetch(:writes)
    %i[custody request dispatch state same_message outer_replacement before_report before_write format callback].each do |fault|
      outcome = relay.call(fault: fault)
      assert_empty outcome.fetch(:writes)
      assert_empty outcome.fetch(:state) if %i[custody request dispatch state].include?(fault)
    end
    [packet * 2, packet.sub('"platform":"ios"', '"platform":"android"'), "#{prefix}{bad}\n"].each do |bytes|
      assert_empty relay.call(stderr: bytes).fetch(:writes)
    end
    [:short, IOError.new("private-marker"), Interrupt.new("private-marker")].each do |write_result|
      outcome = relay.call(write_result: write_result)
      assert_equal [packet], outcome.fetch(:writes)
      assert_equal "ownership-probe", outcome.fetch(:error).kind
      if write_result.is_a?(Exception)
        assert_same write_result, outcome.fetch(:state).fetch(:diagnostic_error)
      else
        refute outcome.fetch(:state).fetch(:write_complete)
      end
    end
    receiver = Object.new.extend(fixture::Contracts)
    receiver.define_singleton_method(:name) { raise "successful call must not inspect callback" }
    handoffs, writes = [], []
    STDERR.stub(:write, ->(bytes) { writes << bytes; bytes.bytesize }) do
      cases.each_key do |family|
        2.times do
          assert_equal :success, receiver.with_adapter_failure_diagnostic(platform: "ios", mode: "ownership-#{family}") { |optional| handoffs << optional; :success }
        end
      end
      %w[ownership-unknown-capture-spawn ownership-setup ownership-observation ownership-private-marker].each do |mode|
        receiver.with_adapter_failure_diagnostic(platform: "ios", mode: mode) { |optional| assert_empty optional }
      end
    end
    assert_empty writes
    assert handoffs.all? { |optional| optional.keys == [:ownership_failure_state] && optional[:ownership_failure_state].empty? }
    assert_equal 6, handoffs.map { |optional| optional.fetch(:ownership_failure_state).object_id }.uniq.length
  end

  def assert_native_signal_failure_projection
    # Only finite in-memory operands and the SAME common wrapper/Lifetime/
    # observer unwind. No native test class, acquisition, proof IO or process
    # operation is loaded/invoked by these controls; the outer veto stays live.
    fixture, diagnostic, probe_class = UploadProcessFixture, UploadProcessFixture::NativeSignalFailureDiagnostic,
      UploadProcessFixture::NativeSignalProbe
    modes, callback = fixture::NATIVE_SIGNAL_FAILURE_MODES, fixture::NATIVE_SIGNAL_FAILURE_CALLBACK
    prefix = "MRK_NATIVE_SIGNAL_FAILURE="
    copy = {"path" => "PRIVATE_SIGNAL_TOKEN", "sha256" => "PRIVATE_SIGNAL_TOKEN"}
    sources = {"PRIVATE_SIGNAL_SOURCE" => "PRIVATE_SIGNAL_TOKEN"}
    clone = ->(value) { JSON.parse(JSON.generate(value)) }
    good = {"kind" => "native-signal-observation", "role" => "driver", "case" => modes.first,
      "sourceSha256" => sources, "hooksRestored" => true, "baseDriverReturn" => 0, "failures" => [],
      "helperCopy" => copy, "actualOriginalPrimary" => true, "actualCustodianReceiptBound" => true,
      "actualNativeDescriptorsClosed" => false, "requests" => [], "private" => "PRIVATE_SIGNAL_TOKEN", "pid" => 999_887_766}
    good["helpers"] = %w[custodian keeper].to_h do |role|
      [role, {"kind" => "native-signal-observation", "role" => "helper", "helperRole" => role,
        "case" => modes.first, "sourceSha256" => sources, "helperCopy" => copy, "helperReturn" => 2,
        "hooksRestored" => true, "originalWaitBound" => true, "creatorJoined" => false,
        "taskJoinsObserved" => true, "failures" => [], "observedHelperReturn" => 2, "requests" => []}]
    end
    raw_result = {"kind" => "pass", "mode" => modes.first, "private" => "PRIVATE_SIGNAL_TOKEN",
      "nativeObservation" => {"custodian" => {"state" => "reaped", "status_kind" => "exit", "status_code" => 1},
        "final" => {"outcome" => "failed", "cleanup" => "confirmed", "group" => {"state" => "retired"}}}}
    project = lambda do |proof = good, mode: modes.first, exit_status: 0, result: raw_result|
      diagnostic.project(mode: mode, proof: proof, result: result,
        status: Struct.new(:exitstatus).new(exit_status), expected_sources: sources)
    end
    assert_equal [50, 9, 20, 6, 9], [fixture::NATIVE_SIGNAL_FAILURE_CHECK_CODES.length,
      fixture::NATIVE_SIGNAL_FAILURE_STAGES.length, fixture::NATIVE_SIGNAL_FAILURE_CATEGORIES.length,
      fixture::NATIVE_SIGNAL_FAILURE_ROUTES.length, fixture::NATIVE_SIGNAL_FAILURE_REFUSALS.length]
    assert_equal probe_class::MODES, modes
    assert_nil project.call # All seven comparisons true is not a failure record.
    faults = [["caseMatches", "case", "PRIVATE_SIGNAL_TOKEN"], ["kindMatches", "kind", nil],
      ["sourceMatches", "sourceSha256", {}], ["failuresEmpty", "failures", ["actual native finality"]],
      ["hooksRestored", "hooksRestored", false], ["baseDriverReturnZero", "baseDriverReturn", 1],
      ["driverExitStatusZero", nil, nil]]
    faults.each do |predicate, key, value|
      proof = key ? good.merge(key => value) : good
      row = project.call(proof, exit_status: key ? 0 : 1)
      assert_equal fixture::NATIVE_SIGNAL_FAILURE_GUARD_FIELDS.to_h { |name| [name, name != predicate] }, row.fetch("guard")
      assert diagnostic.line(row)
      assert_equal 2, row.fetch("schema")
      assert_equal %w[exit1 failed confirmed retired], row.fetch("nativeOutcomes").values
      assert_equal ["not-applicable", 2, 2], row.fetch("rows").map { |item| item.fetch("observedHelperReturn") }
    end
    missing_case = project.call(good.reject { |key, _| key == "case" })
    assert_equal "missing", missing_case.fetch("guard").fetch("caseMatches")
    # Original == semantics are not replaced by normalized return-code types.
    equality = project.call(good.merge("kind" => nil, "baseDriverReturn" => 0.0), exit_status: 0.0)
    assert_equal [true, true], equality.fetch("guard").values_at("baseDriverReturnZero", "driverExitStatusZero")
    assert_equal "missing", equality.fetch("rows").first.fetch("returnCode")
    assert_equal "missing", equality.fetch("result").fetch("driverExitStatus")
    bad = good.merge("failures" => ["actual native finality"])
    packet = diagnostic.line(project.call(bad))
    modes.each do |mode|
      record = project.call(bad.merge("case" => mode), mode: mode)
      assert_equal mode, record.fetch("mode")
      assert_equal %w[driver custodian keeper], record.fetch("rows").map { |row| row.fetch("role") }
      assert_equal [true, false, true], record.fetch("rows")[1].fetch("checks").values_at(
        "hooksRestored", "creatorJoined", "taskJoinsObserved")
      assert_equal 1 << 20, record.fetch("rows").first.fetch("failedCheckMask")
      line = diagnostic.line(record)
      assert line.frozen? && line.ascii_only?
      refute_match(/PRIVATE_SIGNAL|999887766/, line)
    end
    absent = project.call(bad.reject { |key, _| key == "helpers" }).fetch("rows")
    invalid = project.call(bad.merge("helpers" => {"custodian" => nil, "keeper" => []})).fetch("rows")
    [absent, invalid].zip(%w[missing invalid]).each do |rows, state|
      rows.drop(1).each do |row|
        assert_equal [state, "missing", "missing", "missing", 0, false],
          row.values_at("state", "mode", "returnCode", "failuresState", "failedCheckMask", "unknownFailure")
        assert_equal ["missing"], row.fetch("identities").values.uniq
        assert_equal %w[missing not-applicable], row.fetch("checks").values.uniq
        assert_equal [0], (row.fetch("causeMasks") + row.fetch("refusalMasks")).uniq
        assert_equal %w[missing missing], row.values_at("observedHelperReturn", "backendErrorCodes")
      end
    end

    # Exact, non-coercing route/signal/errno packing of ORIGINAL request
    # occurrences. No-error slots and repeated objects keep their positions.
    routes = %w[custodian-group keeper-self-group custodian-direct-keeper fixture self unrecognized]
    signals = %w[0 KILL INT other]
    errnos = %w[ECHILD ESRCH EINTR EBADF EINVAL EIO EPERM EACCES EAGAIN ENOMEM EMFILE ENFILE ENOENT EPIPE other]
    outcome_fields = %w[custodian finalOutcome finalCleanup groupState]
    assert_equal routes, fixture::NATIVE_SIGNAL_FAILURE_ROUTES
    assert_equal signals, fixture::NATIVE_SIGNAL_FAILURE_SIGNALS
    assert_equal errnos, fixture::NATIVE_SIGNAL_FAILURE_ERRNOS
    assert_equal outcome_fields, fixture::NATIVE_SIGNAL_FAILURE_NATIVE_OUTCOME_FIELDS
    assert_equal [64, 360], [fixture::NATIVE_SIGNAL_FAILURE_MAX_REQUESTS, fixture::NATIVE_SIGNAL_FAILURE_MAX_ERROR_CODE]
    packed_requests = routes.product(signals, errnos).map do |route, signal, errno|
      {"route" => route, "signal" => signal, "backendErrorClass" => "Errno::#{errno}"}
    end
    packed = packed_requests.each_slice(64).flat_map { |requests| diagnostic.backend_error_codes("requests" => requests) }
    assert_equal (1..360).to_a, packed
    repeated_request = {"route" => "custodian-group", "signal" => "0", "backendErrorClass" => +"Errno::EPERM",
      "targets" => [999_887_766], "private" => "PRIVATE_SIGNAL_TOKEN"}
    requests = [repeated_request, {}, repeated_request,
      {"route" => "custodian-group", "signal" => "KILL", "backendErrorClass" => "Errno::EINTR"},
      {"route" => "custodian-group", "signal" => 0, "backendErrorClass" => "Errno::EPERM"},
      {"route" => "PRIVATE_SIGNAL_TOKEN", "signal" => "PRIVATE_SIGNAL_TOKEN", "backendErrorClass" => "PRIVATE_SIGNAL_TOKEN"},
      {"backendErrorClass" => nil}]
    detail_proof = clone.call(bad)
    detail_proof.fetch("helpers").fetch("custodian")["requests"] = requests
    detailed = project.call(detail_proof)
    assert_equal [7, 0, 7, 18, 52, 360, 360], detailed.fetch("rows")[1].fetch("backendErrorCodes")
    refute requests.frozen?
    refute repeated_request.frozen?
    repeated_request.fetch("backendErrorClass").replace("PRIVATE_SIGNAL_TOKEN")
    requests.clear
    assert_equal [7, 0, 7, 18, 52, 360, 360], detailed.fetch("rows")[1].fetch("backendErrorCodes")
    assert detailed.fetch("rows")[1].fetch("backendErrorCodes").frozen?
    refute_match(/PRIVATE_SIGNAL|999887766/, diagnostic.line(detailed))
    assert_equal "missing", diagnostic.backend_error_codes({})
    assert_equal [], diagnostic.backend_error_codes("requests" => [])
    assert_equal [0] * 64, diagnostic.backend_error_codes("requests" => [{}] * 64)
    [nil, {}, "PRIVATE_SIGNAL_TOKEN", [nil], [{}] * 65].each do |requests_value|
      assert_equal "invalid", diagnostic.backend_error_codes("requests" => requests_value)
    end
    ["EPERM", "Errno::EPERM PRIVATE_SIGNAL_TOKEN", nil, true, 7].each do |error|
      assert_equal [15], diagnostic.backend_error_codes("requests" => [{"route" => "custodian-group", "signal" => "0", "backendErrorClass" => error}])
    end
    [[0, 0], [2, 2], [255, 255], [-1, "missing"], [256, "missing"], [true, "missing"], [2.0, "missing"], ["2", "missing"]].each do |raw, expected|
      proof = clone.call(bad)
      proof.fetch("helpers").fetch("custodian")["observedHelperReturn"] = raw
      assert_equal expected, project.call(proof).fetch("rows")[1].fetch("observedHelperReturn")
    end
    [[nil, "missing"], [{}, "missing"], [[], "invalid"], [false, "invalid"], [7, "invalid"],
     [{"nativeObservation" => nil}, "invalid"], [{"nativeObservation" => []}, "invalid"]].each do |raw, expected|
      view = project.call(bad, result: raw)
      assert_equal outcome_fields.to_h { |key| [key, expected] }, view.fetch("nativeOutcomes")
    end
    # Native outcomes never borrow the adapter's separate failure-line gate.
    fixture.stub(:adapter_failure_line, ->(**_) { raise "native signal view borrowed adapter failure eligibility" }) do
      expected = fixture.adapter_result_projection(mode: modes.first, result: raw_result).fetch("nativeOutcomes").slice(*outcome_fields)
      assert_equal expected, project.call(bad).fetch("nativeOutcomes")
    end
    labels = fixture::NATIVE_SIGNAL_FAILURE_LABEL_CODES.keys + ["driver proof:IOError", "driver proof:Interrupt",
      "helper proof:PRIVATE_SIGNAL_TOKEN", "hook:entry:IOError", "custodian-group:owner", "custodian-group:source",
      "unrecognized:shape", "PRIVATE_SIGNAL_TOKEN", 123, "PRIVATE_é"]
    mixed_proof = clone.call(bad).merge("failures" => labels)
    mixed = project.call(mixed_proof)
    row = mixed.fetch("rows").first
    assert_equal (1 << 50) - 1, row.fetch("failedCheckMask")
    assert_equal [(1 << 9) | 1, 1 << 19, 1 << 9], row.fetch("causeMasks").values_at(4, 5, 8)
    assert_equal [(1 << 4) | (1 << 5), 1], row.fetch("refusalMasks").values_at(0, 5)
    assert row.fetch("unknownFailure")
    assert row.frozen? && row.fetch("checks").frozen? && row.fetch("causeMasks").frozen?
    mixed_proof.fetch("failures").clear
    mixed_proof.fetch("helpers").clear
    assert_equal "nonempty", row.fetch("failuresState")
    assert_equal "present", mixed.fetch("rows")[1].fetch("state")
    refute_match(/PRIVATE_SIGNAL|PRIVATE_|999887766/, diagnostic.line(mixed))
    [[:absent, "missing", false], [nil, "invalid", true], [[], "empty", false], [[nil], "nonempty", true]].each do |value, state, unknown|
      proof = good.merge("kind" => nil)
      if value == :absent
        proof.delete("failures")
      else
        proof["failures"] = value
      end
      row = project.call(proof).fetch("rows").first
      assert_equal [state, 0, unknown], row.values_at("failuresState", "failedCheckMask", "unknownFailure")
    end
    unavailable = project.call(bad.merge("hooksRestored" => 1, "helpers" => {
      "keeper" => {"role" => "PRIVATE_SIGNAL_TOKEN", "case" => "PRIVATE_SIGNAL_TOKEN", "sourceSha256" => {},
        "helperCopy" => {}, "originalWaitBound" => 1, "failures" => []}}))
    assert_equal false, unavailable.fetch("guard").fetch("hooksRestored")
    assert_equal "missing", unavailable.fetch("rows").first.fetch("checks").fetch("hooksRestored")
    assert_equal [false, false, false], unavailable.fetch("rows").last.fetch("identities").values_at("roleMatches", "sourceMatches", "helperCopyMatches")

    # Full format-level bound includes the prefix and LF, not just JSON bytes.
    largest = clone.call(mixed)
    largest["mode"] = modes.max_by(&:bytesize)
    largest["guard"].transform_values! { "missing" }
    largest["result"] = {"kind" => fixture::ADAPTER_FAILURE_KINDS.max_by(&:bytesize),
      "mode" => largest["mode"], "driverExitStatus" => "missing"}
    largest.fetch("rows").each do |item|
      item.merge!("state" => "present", "mode" => largest["mode"], "returnCode" => "missing", "failuresState" => "nonempty",
        "failedCheckMask" => (1 << 50) - 1, "causeMasks" => Array.new(9, (1 << 20) - 1),
        "refusalMasks" => Array.new(6, 511), "unknownFailure" => false,
        "observedHelperReturn" => item.fetch("role") == "driver" ? "not-applicable" : "missing",
        "backendErrorCodes" => [360] * 64)
      %w[identities checks].each { |key| item[key].transform_values! { |value| value == "not-applicable" ? value : "missing" } }
    end
    largest["nativeOutcomes"] = outcome_fields.to_h { |key| [key, fixture::ADAPTER_FAILURE_NATIVE_OUTCOMES.fetch(key).max_by(&:bytesize)] }
    assert_equal 3641, diagnostic.line(largest).bytesize
    assert_operator diagnostic.line(largest).bytesize, :<=, fixture::NATIVE_SIGNAL_FAILURE_MAX_BYTES
    mutations = [->(value) { value["schema"] = true }, ->(value) { value["schema"] = 1 }, ->(value) { value["guard"].transform_values! { true } },
      ->(value) { value["rows"].reverse! }, ->(value) { value["rows"][0]["failedCheckMask"] = 1 << 50 },
      ->(value) { value["rows"][0]["causeMasks"][0] = true }, ->(value) { value["rows"][0]["refusalMasks"] << 0 },
      ->(value) { value["rows"][0]["identities"]["helperRoleMatches"] = "missing" },
      ->(value) { value["rows"][1]["checks"]["hooksRestored"] = "not-applicable" },
      ->(value) { value["rows"][0]["state"] = "missing" }, ->(value) { value["rows"][0]["failuresState"] = "empty" },
      ->(value) { value["rows"][1]["failuresState"] = "nonempty" },
      ->(value) { value["rows"][0]["checks"] = value["rows"][0]["checks"].to_a.reverse.to_h },
      ->(value) { value["rows"][0]["observedHelperReturn"] = 0 },
      ->(value) { value["rows"][1]["observedHelperReturn"] = true },
      ->(value) { value["rows"][1]["observedHelperReturn"] = 256 },
      ->(value) { value["rows"][1]["observedHelperReturn"] = "not-applicable" },
      ->(value) { value["rows"][1]["backendErrorCodes"] = [true] },
      ->(value) { value["rows"][1]["backendErrorCodes"] = [-1] },
      ->(value) { value["rows"][1]["backendErrorCodes"] = [361] },
      ->(value) { value["rows"][1]["backendErrorCodes"] = [1] * 65 },
      ->(value) { value["rows"][1]["backendErrorCodes"] = nil },
      ->(value) { value["nativeOutcomes"] = value["nativeOutcomes"].to_a.reverse.to_h },
      ->(value) { value["nativeOutcomes"]["custodian"] = "exit3" },
      ->(value) { value["nativeOutcomes"]["finalCleanup"] = true },
      ->(value) { value["nativeOutcomes"]["private"] = "PRIVATE_SIGNAL_TOKEN" },
      ->(value) { value["private"] = "PRIVATE_SIGNAL_TOKEN" }]
    mutations.each do |mutate|
      value = clone.call(project.call(bad))
      mutate.call(value)
      assert_nil diagnostic.line(value)
    end
    %w[observedHelperReturn backendErrorCodes].each do |key|
      value = clone.call(project.call(bad.reject { |name, _| name == "helpers" }))
      value.fetch("rows")[1][key] = key == "observedHelperReturn" ? 2 : []
      assert_nil diagnostic.line(value) # Missing rows cannot borrow partial detail.
    end

    with_stubs = lambda do |bindings, &body|
      if bindings.empty?
        body.call
      else
        receiver, name, replacement = bindings.first
        inherited_query = receiver.equal?(MobileReleaseKit) && name == :const_defined? &&
          !receiver.singleton_class.instance_methods(false).include?(name)
        begin
          receiver.stub(name, replacement) { with_stubs.call(bindings.drop(1), &body) }
        ensure
          # Minitest restores an inherited method as a singleton alias. Remove
          # only this scoped query alias so the original lookup is exact again.
          if inherited_query && receiver.singleton_class.instance_methods(false).include?(name)
            receiver.singleton_class.send(:remove_method, name)
          end
        end
      end
    end
    # Original request/dispatch algorithms over finite data and a saved lambda,
    # NEVER a process syscall. Error origin and identity, not class alone,
    # distinguish handled backend outcomes from broken instrumentation.
    request_rig = lambda do |probe: nil, role: :helper, origin: "native", route: "custodian-group", signal: 0,
                             backend_error: Errno::EPERM.new, phase: nil, observation_error: nil, owner_bound: true|
      probe ||= probe_class.allocate
      requests, calls = [], []
      helper_path = "/inert-native-signal/signal-observed-helper.rb"
      {role: role, requests: requests, paths: {}, helper_path: helper_path, source_hashes: sources}.each do |key, value|
        probe.instance_variable_set(:"@#{key}", value)
      end
      probe.instance_variable_set(:@failures, []) unless probe.instance_variable_defined?(:@failures)
      targets = [route == "custodian-direct-keeper" || origin == "self" ? 701 : -701]
      context = {"origin" => origin, "route" => route, "signal" => signal, "targets" => targets,
        "source" => [helper_path, 101], "state" => origin == "self" ? "self" : "reserved",
        "sourceBound" => true, "ownerBound" => owner_bound, "targetBound" => true,
        "beforeFirstWait" => origin != "self", "numericRetired" => origin == "self",
        "groupRetired" => route == "custodian-direct-keeper", "absent" => false}
      probe.define_singleton_method(:context_for) do |actual_signal, actual_targets, _source|
        raise observation_error if phase == :context
        raise "changed inert syscall operands" unless actual_signal == signal && actual_targets == targets
        context
      end
      probe.define_singleton_method(:refusal) { |_| raise observation_error } if phase == :refusal
      if %i[record result].include?(phase)
        append = requests.method(:<<)
        requests.define_singleton_method(:<<) do |item|
          write = item.method(:[]=)
          key = phase == :result ? "result" : backend_error.is_a?(Errno::ESRCH) ? "absenceObserved" : "backendErrorClass"
          item.define_singleton_method(:[]=) do |name, value|
            raise observation_error if name == key
            write.call(name, value)
          end
          append.call(item)
        end
      end
      if phase == :block
        dispatch = probe.method(:dispatch)
        probe.define_singleton_method(:dispatch) do |value, **keywords, &_handoff|
          dispatch.call(value, **keywords) { |_| raise observation_error }
        end
      end
      backend = lambda do |*arguments|
        calls << arguments
        raise backend_error if backend_error
        1
      end
      {probe: probe, calls: calls, context: context,
       invoke: -> { probe.request(signal, targets, nil, backend) }}
    end
    healthy = request_rig.call(backend_error: nil)
    assert_equal 1, healthy.fetch(:invoke).call
    assert_equal [1, false], healthy.fetch(:probe).requests.fetch(0).values_at("result", "absenceObserved")
    assert_empty healthy.fetch(:probe).failures
    [Errno::EPERM.new, Errno::ESRCH.new].each do |original|
      rig = request_rig.call(backend_error: original)
      assert_same original, assert_raises(original.class, &rig.fetch(:invoke))
      assert_equal [[0, -701]], rig.fetch(:calls)
      probe = rig.fetch(:probe)
      assert_empty probe.failures
      request = probe.requests.fetch(0)
      assert_equal [true, nil, nil, original.is_a?(Errno::ESRCH)],
        request.values_at("forwarded", "rejection", "result", "absenceObserved")
      assert_equal original.is_a?(Errno::ESRCH) ? [0] : [7], diagnostic.backend_error_codes("requests" => probe.requests)
      # Reusing even the SAME exception in the next context cannot borrow the
      # previous invocation's successful backend-error handoff.
      probe.define_singleton_method(:context_for) { |*_| raise original }
      assert_same original, assert_raises(original.class, &rig.fetch(:invoke))
      assert_equal ["request observation:#{original.class.name}"], probe.failures
      assert_equal 1, rig.fetch(:calls).length
    end
    fixture_absence = Errno::ESRCH.new
    rig = request_rig.call(role: :parent, origin: "fixture", route: "fixture", backend_error: fixture_absence)
    assert_same fixture_absence, assert_raises(Errno::ESRCH, &rig.fetch(:invoke))
    assert_empty rig.fetch(:probe).failures # Existing ESRCH is not narrowed to the new EPERM route.
    assert_equal true, rig.fetch(:probe).requests.fetch(0).fetch("absenceObserved")
    [{role: :driver}, {origin: "fixture"}, {route: "keeper-self-group"},
     {route: "custodian-direct-keeper", signal: "KILL"}, {route: "fixture", origin: "fixture"},
     {route: "self", origin: "self", signal: "INT"}, {signal: "KILL"},
     {backend_error: Errno::EACCES.new}].each do |variant|
      original = variant.fetch(:backend_error, Errno::EPERM.new)
      rig = request_rig.call(**variant.merge(backend_error: original))
      assert_same original, assert_raises(original.class, &rig.fetch(:invoke))
      assert_equal ["signal syscall:#{original.class.name}", "request observation:#{original.class.name}"], rig.fetch(:probe).failures
      assert_equal 1, rig.fetch(:calls).length
      assert_equal false, rig.fetch(:probe).requests.fetch(0).fetch("absenceObserved")
    end
    [Errno::EPERM, Errno::ESRCH].product(%i[context refusal record result block]).each do |error_class, phase|
      original, instrumentation = error_class.new, error_class.new
      rig = request_rig.call(backend_error: phase == :result ? nil : original,
        phase: phase, observation_error: instrumentation)
      assert_same instrumentation, assert_raises(error_class, &rig.fetch(:invoke))
      assert_equal ["request observation:#{error_class.name}"], rig.fetch(:probe).failures
      assert_equal %i[context refusal].include?(phase) ? 0 : 1, rig.fetch(:calls).length
    end
    veto = request_rig.call(owner_bound: false)
    assert_equal 0, veto.fetch(:invoke).call
    assert_empty veto.fetch(:calls)
    assert_equal ["custodian-group:owner"], veto.fetch(:probe).failures
    assert_equal [false, "owner", nil, false], veto.fetch(:probe).requests.fetch(0).
      values_at("forwarded", "rejection", "result", "absenceObserved")

    # Execute the REAL helper-entry wrapper and observe unwind over inert
    # method/source/proof endpoints. The original native helper never executes.
    helper_return = lambda do |returned: 2, original_error: nil, observer_failure: false, entry_error: nil,
                              backend_error: nil, backend_handled: false, prepare_error: nil,
                              dependency_error: nil, fresh_helper: false|
      test = self
      events, writes, observed_errors, facts_calls = [], [], [], []
      native, spawn = MobileReleaseKit::NativeUploadProcess, MobileReleaseKit::NativeProcessSpawn
      original_defined, original_native = MobileReleaseKit.method(:const_defined?), native.method(:native)
      native_modules = fixture::OwnedChild.method(:native_modules)
      dependency_loaded = !fresh_helper
      availability = lambda do |name, inherit = true|
        if inherit.equal?(false) && %i[NativeProcessSpawn NativeUploadProcess].include?(name)
          name == :NativeUploadProcess || dependency_loaded
        else
          original_defined.call(name, inherit)
        end
      end
      complete_dependency = lambda do
        events << :native_dependency
        raise dependency_error if dependency_error
        dependency_loaded = true
        spawn
      end
      prepare = lambda do
        events << :publication_prepare
        assert_equal [spawn, native], native_modules.call # Original partial-origin guard, no admission.
        raise prepare_error if prepare_error
        true
      end
      directory = "/inert-native-signal"
      helper_copy = {"path" => "#{directory}/signal-observed-helper.rb", "label" => "signal-observed"}
      entry_block = nil
      entry = Object.new
      entry.define_singleton_method(:wrap) do |receiver, method, &body|
        test.assert_same MobileReleaseKit::NativeUploadProcess.singleton_class, receiver
        test.assert_equal :helper_main, method
        events << :entry_wrap
        entry_block = body
      end
      entry.define_singleton_method(:restore) { events << :entry_restore; raise entry_error if entry_error; [] }
      hooks = Object.new
      hooks.define_singleton_method(:restore) { events << :observer_restore; [] }
      probe = probe_class.allocate
      labels = observer_failure ? ["signal syscall:Errno::EPERM", "request observation:Errno::EPERM"] : []
      {role: :helper, mode: modes.first, root: directory, source_hashes: sources, hooks: hooks,
        records: [], requests: [], failures: labels, control_forwards: 0, hooks_restored: false}.each do |key, value|
        probe.instance_variable_set(:"@#{key}", value)
      end
      probe.define_singleton_method(:install) { probe_class.current = self; events << :observer_install }
      probe.define_singleton_method(:source_snapshot) { events << :source_validation; sources }
      probe.define_singleton_method(:helper_facts) do |result, argv|
        facts_calls << [result, argv]
        {"helperReturn" => result, "helperRole" => argv.first}
      end
      observer = probe.method(:observe)
      probe.define_singleton_method(:observe) do |&body|
        observer.call(&body)
      rescue Exception => error
        observed_errors << error
        raise
      end
      request = request_rig.call(probe: probe, backend_error: backend_error) if backend_error
      body_error = original_error || (backend_error unless backend_handled)
      original = lambda do |argv|
        assert_equal ["custodian"], argv
        events << :original_call
        raise original_error if original_error
        if request
          begin
            request.fetch(:invoke).call
          rescue Exception => error
            assert_same backend_error, error
            raise unless backend_handled # Only the original caller may handle it.
            events << :original_backend_handled
          end
        end
        returned
      end
      normalizer = diagnostic.method(:return_code)
      normalization = lambda do |result|
        assert_equal :entry_restore, events.last
        assert_nil probe_class.current
        events << :return_normalization
        normalizer.call(result)
      end
      previous = [probe_class.current, probe_class.last_parent]
      assert_nil previous.first
      bindings = [[fixture, :owned_fixture_directory, directory], [fixture::OwnedChild, :bounded_file, JSON.generate(helper_copy)],
        [File, :realpath, helper_copy.fetch("path")], [MobileReleaseKit, :const_defined?, availability],
        [native, :native, complete_dependency], [probe_class, :new, ->(*) { events << :probe_construct; probe }],
        [fixture::OwnedChild, :prepare_record_publication!, prepare],
        [fixture::CaptureObservation::Hooks, :new, -> { events << :entry_construct; entry }], [diagnostic, :return_code, normalization],
        [fixture::OwnedChild, :write_record, ->(path, proof) do
          assert_equal "#{directory}/signal-helper-custodian.json", path
          assert_equal :return_normalization, events.last
          events << :helper_proof
          writes << proof
        end]]
      actual = nil
      entry_failure = dependency_error || prepare_error
      with_stubs.call(bindings) do
        if fresh_helper
          rejection = assert_raises(fixture::Failure) { native_modules.call }
          assert_equal ["process-ownership", "partial command runtime would mix source origins"], [rejection.kind, rejection.message]
          assert_empty events
        end
        if entry_failure
          assert_same entry_failure, assert_raises(entry_failure.class) { probe_class.install_helper_observation(directory, modes.first) }
        else
          probe_class.install_helper_observation(directory, modes.first)
          refute_nil entry_block
          invoke = -> { entry_block.call(original, nil, [["custodian"]], {}, nil) }
          if entry_error
            assert_same entry_error, assert_raises(entry_error.class) { invoke.call }
          else
            actual = invoke.call
            assert_same(body_error || observer_failure ? 1 : returned, actual)
          end
        end
      end
      assert_equal original_defined, MobileReleaseKit.method(:const_defined?)
      assert_equal original_native, native.method(:native)
      if entry_failure
        assert_equal dependency_error ? [:native_dependency] : %i[native_dependency publication_prepare], events
        assert_nil entry_block
        assert_empty writes
        assert_empty facts_calls
        assert_equal previous, [probe_class.current, probe_class.last_parent]
        next
      end
      assert_equal %i[native_dependency publication_prepare probe_construct entry_construct entry_wrap], events.take(5)
      assert_operator events.index(:publication_prepare), :<, events.index(:entry_wrap)
      assert_operator events.index(:entry_wrap), :<, events.index(:original_call)
      assert_equal %i[observer_restore source_validation entry_restore], events.select { |event| %i[observer_restore source_validation entry_restore].include?(event) }
      assert_equal [[0, -701]], request.fetch(:calls) if request && !original_error
      assert_nil probe_class.current
      if body_error || observer_failure
        assert_empty facts_calls # Do not collect facts after a failed observation.
        assert_equal 1, observed_errors.length
        body_error ? assert_same(body_error, observed_errors.first) : assert_equal("signal-observation", observed_errors.first.kind)
      else
        assert_equal [[returned, ["custodian"]]], facts_calls
      end
      if entry_error
        assert_empty writes
        refute_includes events, :return_normalization
      else
        assert_equal 1, writes.length
        assert_equal(body_error ? "missing" : normalizer.call(returned), writes.first.fetch("observedHelperReturn"))
        refute writes.first.key?("helperReturn") if body_error || observer_failure
      end
      {returned: actual, proof: writes.first, observer_errors: observed_errors}
    ensure
      probe_class.current, probe_class.last_parent = previous if previous
    end
    retained_return = helper_return.call(observer_failure: true)
    assert_equal 1, retained_return.fetch(:returned)
    assert_equal 2, retained_return.fetch(:proof).fetch("observedHelperReturn")
    helper_view = project.call(bad.merge("helpers" => {"custodian" => retained_return.fetch(:proof)}))
    assert_equal ["missing", 2], helper_view.fetch("rows")[1].values_at("returnCode", "observedHelperReturn")
    assert_equal "exit1", helper_view.fetch("nativeOutcomes").fetch("custodian")
    helper_return.call
    helper_return.call(fresh_helper: true)
    helper_return.call(fresh_helper: true, dependency_error: LoadError.new("original source-bound native dependency"))
    helper_return.call(fresh_helper: true, prepare_error: IOError.new("original publication preparation"))
    helper_return.call(returned: true) # Invalid normalization does not change the original return choice.
    [Interrupt.new("PRIVATE_SIGNAL_TOKEN"), SystemExit.new(19, "PRIVATE_SIGNAL_TOKEN")].each do |original|
      helper_return.call(original_error: original)
    end
    helper_return.call(observer_failure: true, entry_error: IOError.new("PRIVATE_SIGNAL_TOKEN"))
    handled = helper_return.call(backend_error: Errno::EPERM.new, backend_handled: true)
    assert_equal 2, handled.fetch(:returned)
    assert_equal [2, 2], handled.fetch(:proof).values_at("helperReturn", "observedHelperReturn")
    assert_equal [7], diagnostic.backend_error_codes(handled.fetch(:proof))
    assert_empty handled.fetch(:proof).fetch("failures")
    helper_return.call(observer_failure: true, backend_error: Errno::EPERM.new, backend_handled: true)
    escaped = helper_return.call(backend_error: Errno::EPERM.new)
    assert_equal 1, escaped.fetch(:returned)
    assert_equal [7], diagnostic.backend_error_codes(escaped.fetch(:proof))
    assert_equal ["observation body:Errno::EPERM", "helper proof:Errno::EPERM"], escaped.fetch(:proof).fetch("failures")

    exercise = lambda do |mode: modes.first, fault: nil, write_result: :full|
      now, depth, state, selected, escaped = 1, 0, nil, nil, nil
      events, writes, observations, source_reads = [], [], [], []
      later = IOError.new("PRIVATE_SIGNAL_TOKEN")
      earlier = fixture::Failure.new("fixture-result", "PRIVATE_SIGNAL_EARLIER")
      proof = clone.call(bad).merge("case" => mode)
      status = Struct.new(:exitstatus).new(0)
      policy = Object.new
      policy.define_singleton_method(:install) { events << :lifetime_install }
      policy.define_singleton_method(:cleanup_depth) { depth }
      policy.define_singleton_method(:cleanup) do |&body|
        depth += 1
        begin
          body.call
        ensure
          depth -= 1
        end
      end
      policy.define_singleton_method(:restore) do |&body|
        body.call
        events << :lifetime_restore
        raise later if fault == :restoration
      end
      policy.define_singleton_method(:errors) { [] }
      policy.define_singleton_method(:replay_custom_pending) { events << :lifetime_replay }
      hooks = Object.new
      hooks.define_singleton_method(:restore) { events << :observer_restore; raise later if fault == :observer_restore; [] }
      probe = probe_class.allocate
      {role: :parent, mode: mode, root: "/inert-native-signal", source_hashes: sources, hooks: hooks,
        records: [], requests: [], failures: [], control_forwards: 0, hooks_restored: false}.each do |key, value|
        probe.instance_variable_set(:"@#{key}", value)
      end
      probe.define_singleton_method(:install) { probe_class.current = self; events << :observer_install }
      probe.define_singleton_method(:source_hashes) do
        source_reads << probe_class.current.equal?(self)
        raise later if fault == :source_operand
        @source_hashes
      end
      probe.define_singleton_method(:source_snapshot) { events << :source_validation; raise later if fault == :source_validation; sources }
      formatter, projector = diagnostic.method(:line), diagnostic.method(:project)
      projection = lambda do |**arguments|
        raise later if fault == :projection
        projector.call(**arguments)
      end
      formatting = lambda do |value|
        raise later if fault == :format
        line = formatter.call(value)
        now = 10 if fault == :before_write
        line
      end
      sink = lambda do |bytes|
        writes << bytes
        observations << [state[:rejection], state[:report_attempted], state[:write_attempted], events.dup,
          fixture.instance_variable_get(:@cancellation_scope), probe_class.current]
        raise write_result if write_result.is_a?(Exception)
        write_result == :short ? 1 : bytes.bytesize
      end
      previous = [probe_class.current, probe_class.last_parent]
      assert_nil previous.first
      assert_nil fixture.instance_variable_get(:@cancellation_scope)
      bindings = [[fixture, :clock_ns, -> { now }], [fixture::CancellationScope, :new, policy],
        [Thread.current, :pending_interrupt?, false], [probe_class, :new, probe],
        [fixture, :atomic_json, ->(*) { events << :parent_proof; raise later if fault == :parent_proof }],
        [diagnostic, :project, projection], [diagnostic, :line, formatting], [STDERR, :write, sink]]
      actual = nil
      with_stubs.call(bindings) do
        actual = assert_raises(fixture::Failure) do
          fixture.with_native_signal_failure_diagnostic(mode: mode, callback: fault == :callback ? "PRIVATE_SIGNAL_TOKEN" : callback) do |optional|
            state = optional.fetch(:signal_failure_state)
            state.freeze if fault == :state
            begin
              probe_class.observe_parent("/inert-native-signal", mode) do
                fixture.lifetime(deadline_ns: 10) do |frame|
                  frame.define_singleton_method(:report) { events << :lifetime_report } # Keep synthetic diagnostics private.
                  frame.remember(earlier) if fault == :prior
                  begin
                    frame.active do
                      selected = fixture::Failure.new("fixture-result", "native signal proof rejected")
                      begin
                        fixture.remember_native_signal_failure(state, selected, mode: mode, proof: proof, result: raw_result,
                          status: status, expected_sources: probe_class.current.source_hashes, deadline_ns: 10)
                      rescue Exception
                        nil # Same post-selected optional capture seam as the original guard.
                      end
                      raise selected
                    end
                  ensure
                    frame.cleanup do
                      events << :driver_cleanup
                      proof.fetch("failures").clear
                      proof.fetch("helpers").clear
                      raise later if fault == :cleanup
                    end
                  end
                end
              end
            rescue Exception => original
              escaped = original
              raise fixture::Failure.new(original.kind, original.message) if fault == :lookalike
              raise
            ensure
              events << :yield_unwound
              now = 10 if fault == :before_report
            end
          end
        end
        fixture.report_native_signal_failure(state, actual, mode: mode, callback: callback) # Never retry an attempt.
      end
      expected_primary = fault == :prior ? earlier : selected
      assert_same expected_primary, escaped
      fault == :lookalike ? refute_same(expected_primary, actual) : assert_same(expected_primary, actual)
      assert_equal [true], source_reads
      assert_nil fixture.instance_variable_get(:@cancellation_scope)
      assert_nil probe_class.current
      assert_equal [:driver_cleanup, :lifetime_restore, :lifetime_replay, :observer_restore, :parent_proof, :yield_unwound],
        events.select { |event| %i[driver_cleanup lifetime_restore lifetime_replay observer_restore parent_proof yield_unwound].include?(event) }
      observations.each do |original, report_attempted, write_attempted, seen, registry, current|
        assert_same selected, original
        assert report_attempted && write_attempted
        assert_equal :yield_unwound, seen.last
        assert_nil registry
        assert_nil current
      end
      {state: state, original: actual, writes: writes, expected: diagnostic.line(project.call(bad.merge("case" => mode), mode: mode))}
    ensure
      probe_class.current, probe_class.last_parent = previous if previous
    end
    (modes.map { |mode| {mode: mode} } + %i[cleanup restoration observer_restore source_validation parent_proof].map { |fault| {fault: fault} }).each do |options|
      outcome = exercise.call(**options)
      assert_equal [outcome.fetch(:expected)], outcome.fetch(:writes)
      assert_equal [10, true], outcome.fetch(:state).values_at(:deadline_ns, :write_complete)
    end
    %i[state source_operand projection format prior lookalike callback before_report before_write].each do |fault|
      assert_empty exercise.call(fault: fault).fetch(:writes)
    end
    [:short, IOError.new("PRIVATE_SIGNAL_TOKEN"), Interrupt.new("PRIVATE_SIGNAL_TOKEN"), SystemExit.new(19, "PRIVATE_SIGNAL_TOKEN")].each do |result|
      outcome = exercise.call(write_result: result)
      assert_equal [outcome.fetch(:expected)], outcome.fetch(:writes)
      assert_equal "fixture-result", outcome.fetch(:original).kind
      result.is_a?(Exception) ? assert_same(result, outcome.fetch(:state).fetch(:diagnostic_error)) : refute(outcome.fetch(:state).fetch(:write_complete))
    end
    handoffs, writes, continued = [], [], []
    STDERR.stub(:write, ->(bytes) { writes << bytes; bytes.bytesize }) do
      2.times do
        assert_equal :success, fixture.with_native_signal_failure_diagnostic(mode: modes.first, callback: callback) { |optional| handoffs << optional; :success }
      end
      [Interrupt.new("PRIVATE_SIGNAL_TOKEN"), SystemExit.new(19, "PRIVATE_SIGNAL_TOKEN"), IOError.new("PRIVATE_SIGNAL_TOKEN")].each do |original|
        actual = assert_raises(original.class) do
          fixture.with_native_signal_failure_diagnostic(mode: modes.first, callback: callback) { raise original }
          continued << true
        end
        assert_same original, actual
      end
    end
    assert_empty writes
    assert_empty continued
    assert handoffs.all? { |optional| optional.keys == [:signal_failure_state] && optional[:signal_failure_state].empty? }
    refute_same(*handoffs.map { |optional| optional.fetch(:signal_failure_state) })
  end

  def missing_cleanup_omission_sample
    # In-memory inputs shared by entry, reader and watchdog controls. They are
    # never written as native receipts or used to authorize a real operation.
    directory = "/inert-missing-cleanup"
    sources = UploadProcessFixture::ContainmentEvidence::SOURCES.to_h { |name| [name, "a" * 64] }
    original_path = File.realpath(MobileReleaseKit::NativeUploadProcess::GroupLease.instance_method(:request).source_location.first)
    copy = {"label" => "containment-events", "originalPath" => original_path,
      "originalSha256" => "a" * 64, "path" => "#{directory}/containment-events-helper.rb", "sha256" => "b" * 64}
    manifest = {"version" => 1, "mode" => "native-setup-no-cleanup", "helperCopy" => copy, "sourceSha256" => sources}
    graph = {"custodian" => 701, "keeper" => 702, "validator" => 703, "group" => 702, "sid" => 701}
    stat_class = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink)
    records, bytes, stats = {}, {}, {}
    %w[custodian keeper].each_with_index do |role, index|
      name = "containment-#{role}-omission.json"
      origin = role == "custodian" ? MobileReleaseKit::NativeUploadProcess::GroupLease.instance_method(:request) :
                                   MobileReleaseKit::NativeUploadProcess::Keeper.instance_method(:request_group)
      entry = {"route" => "#{role}-group", "group" => 702, "signal" => "KILL", "atNs" => 2_500_000_000,
        "effectiveDeadlineNs" => 7_000_000_000, "originalReservedAuthority" => true,
        "origin" => {"path" => copy.fetch("path"), "line" => origin.source_location.last},
        "actualOmissionEntry" => true, "nativeCallOmitted" => true}
      records[name] = {"version" => 1, "kind" => "original-helper-cleanup-omission-entry", "mode" => manifest.fetch("mode"),
        "sourceSha256" => sources, "helperCopy" => copy, "role" => role, "pid" => graph.fetch(role),
        "parentPid" => role == "custodian" ? 700 : 701, "identities" => graph, "entry" => entry}
      bytes[name] = JSON.generate(records.fetch(name))
      stats[name] = stat_class.new(1, 10 + index, 0o100600, 3, 4, 0, "file", 1)
    end
    {directory: directory, manifest: manifest, graph: graph, records: records, bytes: bytes, stats: stats}
  end

  def assert_missing_cleanup_omission_evidence
    evidence = UploadProcessFixture::ContainmentEvidence
    native = MobileReleaseKit::NativeUploadProcess
    assert_equal 8192, evidence::OMISSION_LIMIT
    assert_equal({"custodian" => "containment-custodian-omission.json", "keeper" => "containment-keeper-omission.json"}, evidence::OMISSION_FILES)
    real_observers = evidence.instance_variable_get(:@helper_observers)
    original_defined, original_native = MobileReleaseKit.method(:const_defined?), native.method(:native)
    spawn, native_modules = MobileReleaseKit::NativeProcessSpawn, UploadProcessFixture::OwnedChild.method(:native_modules)
    with_stubs = lambda do |bindings, &body|
      if bindings.empty?
        body.call
      else
        receiver, name, replacement = bindings.first
        inherited_query = receiver.equal?(MobileReleaseKit) && name == :const_defined? &&
          !receiver.singleton_class.instance_methods(false).include?(name)
        begin
          receiver.stub(name, replacement) { with_stubs.call(bindings.drop(1), &body) }
        ensure
          if inherited_query && receiver.singleton_class.instance_methods(false).include?(name)
            receiver.singleton_class.send(:remove_method, name)
          end
        end
      end
    end
    # A fresh copied helper has only NativeUploadProcess until its ORIGINAL
    # source-bound lazy dependency completes. Model only those two queries;
    # never remove real constants, import a leaf or invoke native admission.
    %i[fresh loaded dependency_failure preparation_failure].each do |scenario|
      sample, events = missing_cleanup_omission_sample, []
      model_class = Class.new(evidence) # Class-local observer storage, never the live helper registry.
      observer = Object.new
      original = scenario == :dependency_failure ? LoadError.new("original source-bound native dependency") :
                                                  IOError.new("original containment publication preparation")
      dependency_loaded = scenario == :loaded
      availability = lambda do |name, inherit = true|
        if inherit.equal?(false) && %i[NativeProcessSpawn NativeUploadProcess].include?(name)
          name == :NativeUploadProcess || dependency_loaded
        else
          original_defined.call(name, inherit)
        end
      end
      complete_dependency = lambda do
        events << :native_dependency
        raise original if scenario == :dependency_failure
        dependency_loaded = true
        spawn
      end
      observer.define_singleton_method(:install) { events << :install }
      prepare = lambda do
        events << :prepare
        assert_equal [spawn, native], native_modules.call
        raise original if scenario == :preparation_failure
        true
      end
      construct = ->(*) { events << :construct; observer }
      bindings = [[UploadProcessFixture, :owned_fixture_directory, ->(*) { events << :directory }],
        [model_class, :source_hashes, {}], [model_class, :manifest!, sample[:manifest]],
        [File, :realpath, sample[:manifest].fetch("helperCopy").fetch("path")],
        [MobileReleaseKit, :const_defined?, availability], [native, :native, complete_dependency],
        [UploadProcessFixture::OwnedChild, :prepare_record_publication!, prepare], [model_class, :new, construct]]
      with_stubs.call(bindings) do
        unless dependency_loaded
          rejection = assert_raises(UploadProcessFixture::Failure) { native_modules.call }
          assert_equal ["process-ownership", "partial command runtime would mix source origins"], [rejection.kind, rejection.message]
          assert_empty events
        end
        invoke = -> { model_class.observe_helper(sample[:directory], "native-setup-no-cleanup", "inert-helper") }
        if %i[dependency_failure preparation_failure].include?(scenario)
          assert_same original, assert_raises(original.class, &invoke)
          assert_nil model_class.instance_variable_get(:@helper_observers)
          expected = scenario == :dependency_failure ? %i[directory native_dependency] : %i[directory native_dependency prepare]
          assert_equal expected, events
        else
          invoke.call
          assert_equal [observer], model_class.instance_variable_get(:@helper_observers)
          assert_equal %i[directory native_dependency prepare construct install], events
        end
      end
      assert_equal original_defined, MobileReleaseKit.method(:const_defined?)
      assert_equal original_native, native.method(:native)
    end
    assert_same real_observers, evidence.instance_variable_get(:@helper_observers)
    make = lambda do |role|
      sample = missing_cleanup_omission_sample
      child_class = Struct.new(:pid, :state, :receipt, :retired) { def numeric_retired? = retired }
      keeper, validator = child_class.new(702, :running, nil, false), child_class.new(703, :pollable, nil, true)
      object = (role == "custodian" ? native::Custodian : native::Keeper).allocate
      {pid: sample[:graph].fetch(role), parent_pid: role == "custodian" ? 700 : 701, session_id: 701,
       inherited_session_id: 701, run_deadline_ns: 7_000_000_000, hard_cleanup_deadline_ns: 7_000_000_000,
       keeper: keeper, validator: validator, group_created: true, self_group_retired: false, self_group_absent: false,
       creator_acquisition: Struct.new(:child).new(role == "custodian" ? keeper : validator),
       moved: {"validator_pid" => 703, "group_id" => 702, "keeper_pgid" => 701},
       moved_frame: {"validator_pid" => 703, "group_id" => 702, "keeper_pgid" => 701}}.each do |key, value|
        object.instance_variable_set(:"@#{key}", value)
      end
      group = native::GroupLease.allocate
      {keeper: keeper, id: 702, session_id: 701, retired: false, absent: false}.each do |key, value|
        group.instance_variable_set(:"@#{key}", value)
      end
      object.instance_variable_set(:@group, group)
      observer = evidence.new(sample[:directory], "native-setup-no-cleanup", sample[:manifest])
      observer.instance_variable_set(:@role, object)
      observer.instance_variable_set(:@origins, sample[:records].values.to_h { |record| [record["entry"]["route"], record["entry"]["origin"]] })
      sample.merge(role: role, object: object, group: group, observer: observer, now: 2_500_000_000,
        target: role == "custodian" ? group : object, route: "#{role}-group", opens: [], delegated: [], written: nil)
    end
    within = lambda do |rig, &body|
      fault = {before: :write_before, short: :short_write, after: :write_after}[rig[:publication]]
      with_record_publication_model(directory: rig[:directory], name: "containment-#{rig[:role]}-omission.json",
                                    fault: fault, primary: rig[:failure], state: rig) do
        Process.stub(:pid, rig[:object].pid) do
          clock = lambda do
            rig[:clock_reads] = rig.fetch(:clock_reads, 0) + 1
            rig[:late_entry] && rig[:clock_reads] > 1 ? 7_000_000_000 : rig[:now]
          end
          UploadProcessFixture.stub(:clock_ns, clock) { body.call }
        end
      end
    end
    invoke = lambda do |rig|
      original = ->(*args, **kwargs) { rig[:delegated] << [args, kwargs]; raise "omission delegated native operation" }
      rig[:observer].group_request(original, rig[:target], ["KILL"], {}, nil, rig[:route])
    end
    %w[custodian keeper].each do |role|
      rig = make.call(role)
      within.call(rig) do
        assert_equal 0, invoke.call(rig) # Integer0 stays truthy; false would manufacture absence.
        assert_equal rig[:records].fetch("containment-#{role}-omission.json"), JSON.parse(rig[:written])
        assert_equal 1, rig[:observer].instance_variable_get(:@omissions).length
        assert_raises(UploadProcessFixture::Failure) { invoke.call(rig) }
        assert_equal 1, rig[:opens].length
        assert_empty rig[:delegated]
      end
      # K's original V is already numerically retired. The valid case above
      # observes only its original identity and never reopens that authority.
      %i[retired wrong_route graph expired].each do |fault|
        candidate = make.call(role)
        case fault
        when :retired
          candidate[:group].instance_variable_set(:@retired, true)
          candidate[:object].instance_variable_set(:@self_group_retired, true)
        when :wrong_route
          candidate[:route] = role == "custodian" ? "keeper-group" : "custodian-group"
          candidate[:target] = role == "custodian" ? candidate[:object] : candidate[:group]
        when :graph then candidate[:object].instance_variable_set(:@session_id, 799)
        when :expired then candidate[:now] = 7_000_000_000
        end
        within.call(candidate) do
          assert_raises(UploadProcessFixture::Failure) { invoke.call(candidate) }
          assert_empty candidate[:opens]
          assert_empty candidate[:delegated]
        end
      end
      %i[before short after].each do |fault|
        candidate = make.call(role)
        candidate[:publication], candidate[:failure] = fault, IOError.new("original inert omission publication")
        within.call(candidate) do
          error = assert_raises(fault == :short ? UploadProcessFixture::Failure : IOError) { invoke.call(candidate) }
          assert_same candidate[:failure], error unless fault == :short
          assert_equal 1, candidate[:observer].instance_variable_get(:@omissions).length
          assert_raises(UploadProcessFixture::Failure) { invoke.call(candidate) }
          assert_equal 1, candidate[:opens].length
          assert_empty candidate[:delegated]
          assert_equal fault != :before, !candidate[:written].nil? # After-effect bytes are not a return receipt.
        end
      end
    end
    %i[oversized late_entry].each do |fault|
      candidate = make.call("custodian")
      if fault == :oversized
        candidate[:manifest]["helperCopy"]["path"] = "x" * 8192
      else
        candidate[:late_entry] = true # Earlier reservation guard passed, actual entry sample did not.
      end
      within.call(candidate) do
        assert_raises(UploadProcessFixture::Failure) { invoke.call(candidate) }
        assert_empty candidate[:opens]
        assert_empty candidate[:delegated]
      end
    end
  end

  def assert_missing_cleanup_watchdog_lifecycle
    # Actual driver/control algorithms; ALL task, thread, lease, clock and output
    # operations are inert. These are not native waits, EOFs or finality receipts.
    klass = UploadProcessFixture::MissingCleanupDriver
    thread_class = Struct.new(:live) do
      def alive? = live
      # The real JSON parser uses Thread.current thread-local storage. Keep
      # those ordinary values isolated on each inert identity, not a real task.
      def [](key) = (@thread_locals ||= {})[key.to_sym]
      def []=(key, value)
        (@thread_locals ||= {})[key.to_sym] = value
      end
    end
    stat_class = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink)
    retain_case = UploadProcessFixture.instance_method(:retain_process_case!)
    retain_unknown = UploadProcessFixture.instance_method(:retain_unknown_domain!)
    registry_names = %i[@retained_fixture_cases @unresolved_roots @expected_unknown_roots @domain_disposal_required @process_domain_failed]
    original_registries = registry_names.to_h do |name|
      value = UploadProcessFixture.instance_variable_get(name)
      [name, [UploadProcessFixture.instance_variable_defined?(name), value, value.is_a?(Hash) ? value.dup : value]]
    end
    make = lambda do |deadline: 20_000_000_000|
      driver = klass.new("/inert-missing-cleanup", "native-setup-no-cleanup", deadline_ns: deadline)
      rig = {driver: driver, now: 1_000_000_000, events: [], writes: [], sleeps: [], factories: [],
             driver_thread: thread_class.new(true), capture_thread: thread_class.new(true), worker_thread: thread_class.new(true),
             flags: {attempted: false, published: true, cancelled: false, retired: false, joined: false, finished: false,
                     unresolved: false, first_error: nil, start_return: :slot, admit_return: true, join_return: true},
             query_hooks: {}, registry: Object.new.extend(UploadProcessFixture), writer_attempts: 0,
             omissions: missing_cleanup_omission_sample, entry_reads: [], stat_reads: Hash.new(0)}
      driver.observed["containmentSource"] = rig[:omissions][:manifest]
      rig[:current] = rig[:driver_thread]
      slot = rig[:slot] = Object.new
      {start_attempted?: :attempted, publication_ready?: :published, cancelled?: :cancelled,
       launch_retired?: :retired, joined?: :joined, finished?: :finished, unresolved?: :unresolved,
       first_error: :first_error}.each do |method, key|
        slot.define_singleton_method(method) do
          rig[:query_hooks].delete(method)&.call(rig)
          item = rig[:flags].fetch(key)
          raise item if item.is_a?(Exception) && method != :first_error
          item
        end
      end
      slot.define_singleton_method(:caller) { rig.fetch(:slot_options).fetch(:caller) }
      slot.define_singleton_method(:thread) { rig[:worker_thread] }
      %i[run_deadline_ns hard_cleanup_deadline_ns].each do |key|
        slot.define_singleton_method(key) { rig.fetch(:slot_options).fetch(key) }
      end
      slot.define_singleton_method(:start) do |&body|
        rig[:flags][:attempted] = true
        rig[:events] << [:start, rig[:current], driver.instance_variable_get(:@watchdog)]
        rig[:worker] = body
        raise rig[:start_error] if rig[:start_error]
        rig[:flags][:start_return] == :slot ? slot : rig[:flags][:start_return]
      end
      slot.define_singleton_method(:admit!) do
        rig[:events] << [:admit, rig[:current], rig[:flags][:published]]
        rig[:now] = rig[:admit_ns] if rig[:admit_ns]
        raise rig[:admit_error] if rig[:admit_error]
        rig[:flags][:admit_return]
      end
      slot.define_singleton_method(:join_until) do |deadline_ns:|
        rig[:events] << [:join, deadline_ns, driver.instance_variable_get(:@watchdog_stopped)]
        raise rig[:join_error] if rig[:join_error]
        if rig[:flags][:join_return].equal?(true)
          rig[:flags][:joined] = rig[:flags][:finished] = true
          rig[:flags][:retired] = true
        end
        rig[:flags][:join_return]
      end
      slot.define_singleton_method(:close_launch!) do
        rig[:events] << [:retire]
        rig[:flags][:retired] = true
        raise rig[:retire_error] if rig[:retire_error]
        rig.fetch(:retire_return, true)
      end
      capture_flags = rig[:capture_flags] = {cancelled: false, retired: false, finished: false, joined: false}
      capture = rig[:capture] = Object.new
      capture.define_singleton_method(:thread) { rig[:capture_thread] }
      capture.define_singleton_method(:caller) { rig.fetch(:capture_caller, rig[:driver_thread]) }
      capture.define_singleton_method(:run_deadline_ns) { 3_000_000_000 }
      capture.define_singleton_method(:hard_cleanup_deadline_ns) { 7_000_000_000 }
      {cancelled?: :cancelled, launch_retired?: :retired, finished?: :finished, joined?: :joined}.each do |method, key|
        capture.define_singleton_method(method) { capture_flags.fetch(key) }
      end
      session = rig[:session] = Struct.new(:capture_slot, :ready, :reserved, :primary_error, :cleanup_errors, :custodian_child, :unknown) do
        def retained_unknown? = unknown
      end.new(capture, {"validator_pid" => 703, "group_id" => 702}, {"keeper_pid" => 702}, nil, [], Struct.new(:pid).new(701), false)
      driver.instance_variable_set(:@observation, Struct.new(:session).new(session))
      driver.observed["ready"] = true
      control = rig[:control] = driver.instance_variable_get(:@control)
      inode = stat_class.new(1, 2, 0o10600, 3, 4, 0, "fifo", 1)
      identity = UploadProcessFixture::OwnedChild.identity(inode)
      control.instance_variable_set(:@identity, identity)
      %i[anchor writer].each do |role|
        state = {value: role == :anchor ? :closed : :open}
        io, lease = Object.new, Object.new
        io.define_singleton_method(:stat) { inode }
        io.define_singleton_method(:close_on_exec?) { true }
        io.define_singleton_method(:closed?) { state[:value] == :closed }
        lease.define_singleton_method(:state) { state[:value] }
        lease.define_singleton_method(:io) { io }
        lease.define_singleton_method(:close_once) do
          raise "inert lease operation under watchdog state lock" if driver.instance_variable_get(:@watchdog_lock).owned?
          rig[:events] << [:lease_close, role]
          if role == :writer && state[:value] != :closed
            rig[:writer_attempts] += 1
            rig[:during_close]&.call(rig)
            raise rig[:writer_error] if rig[:writer_error]
            rig[:now] = rig[:close_return_ns] if rig[:close_return_ns]
          end
          state[:value] = :closed
          true
        end
        control.instance_variable_set(:"@#{role}", lease)
      end
      driver.define_singleton_method(:publish_owner) { |phase| rig[:events] << [:owner, phase]; true }
      rig
    end
    within = lambda do |rig, &body|
      factory = lambda do |**options|
        raise "inert fallback constructed more than once" unless rig[:factories].empty?
        rig[:factories] << options
        rig[:slot_options] = options
        rig[:slot]
      end
      sleeper = lambda do |seconds|
        rig[:sleeps] << seconds
        raise "inert fallback exceeded finite loop allowance" if rig[:sleeps].length > 3
        if rig[:sleep_hook]
          rig[:sleep_hook].call(rig)
        else
          rig[:now] += (seconds * 1_000_000_000).round
        end
      end
      sample = rig[:omissions]
      file_stat = lambda do |path|
        raise "inert omission read under watchdog state lock" if rig[:driver].instance_variable_get(:@watchdog_lock).owned?
        assert_equal sample[:directory], File.dirname(path)
        name = File.basename(path)
        rig[:stat_reads][name] += 1
        raise Errno::ENOENT, "inert missing omission record" unless sample[:stats].key?(name)
        value = sample[:stats].fetch(name)
        value = value.dup.tap { |stat| stat.ino += 1 } if rig[:changed_path] == name && rig[:stat_reads][name].even?
        value
      end
      read = lambda do |path, expected: nil, limit: UploadProcessFixture::OUTPUT_LIMIT|
        raise "inert omission read under watchdog state lock" if rig[:driver].instance_variable_get(:@watchdog_lock).owned?
        assert_equal sample[:directory], File.dirname(path)
        name = File.basename(path)
        if name.end_with?("-omission.json")
          rig[:entry_reads] << name
          assert_equal 8192, limit
          assert_equal UploadProcessFixture::OwnedChild.identity(sample[:stats].fetch(name)), expected
        end
        value = sample[:bytes].fetch(name)
        rig[:after_read]&.call(rig, name)
        value
      end
      manifest = lambda do |directory, mode, sources|
        assert_equal [sample[:directory], "native-setup-no-cleanup", sample[:manifest].fetch("sourceSha256")], [directory, mode, sources]
        rig.fetch(:manifest_read, sample[:manifest])
      end
      # Run the ORIGINAL registry algorithms on a private receiver. No real
      # domain latch/registry is reset or exempted; this proves only their
      # inert retention behavior plus the actual close_control call routing.
      UploadProcessFixture.stub(:retain_process_case!, retain_case.bind(rig[:registry])) do
        UploadProcessFixture.stub(:retain_unknown_domain!, retain_unknown.bind(rig[:registry])) do
          MobileReleaseKit::NativeUploadProcess::TaskSlot.stub(:new, factory) do
            Thread.stub(:main, rig[:driver_thread]) do
              Thread.stub(:current, -> { rig[:current] }) do
                Process.stub(:pid, 700) do
                  UploadProcessFixture.stub(:clock_ns, -> { rig[:now] }) do
                    UploadProcessFixture::OwnedChild.stub(:write_record, ->(path, record) { rig[:writes] << [path, record]; true }) do
                      File.stub(:lstat, file_stat) do
                        File.stub(:file?, ->(path) { sample[:bytes].key?(File.basename(path)) }) do
                          UploadProcessFixture::OwnedChild.stub(:bounded_file, read) do
                            UploadProcessFixture::ContainmentEvidence.stub(:manifest!, manifest) do
                              rig[:driver].stub(:sleep, sleeper) { body.call }
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
      end
    end
    prepare = lambda do |rig|
      assert_equal true, rig[:driver].prepare_watchdog
      assert_same rig[:slot], rig[:driver].instance_variable_get(:@watchdog)
      assert_equal [{caller: rig[:driver_thread], parent_slot: nil, run_deadline_ns: 12_300_000_000,
                     hard_cleanup_deadline_ns: 12_300_000_000}], rig[:factories]
      assert_equal [[:start, rig[:driver_thread], rig[:slot]], [:admit, rig[:driver_thread], true]], rig[:events]
      assert_equal true, rig[:driver].observed.fetch("watchdogPreadmitted")
      refute rig[:driver].observed.fetch("watchdogStarted")
      assert_equal 6_000_000_000, rig[:driver].watchdog_join_deadline_ns
      rig[:driver].native_event(:execute_enter, rig[:session])
      assert_same rig[:session], rig[:driver].instance_variable_get(:@native_frame)
    end
    arm = lambda do |rig|
      rig[:current], rig[:now] = rig[:capture_thread], 2_000_000_000
      assert_equal true, rig[:driver].start_watchdog
      record = rig[:driver].watchdog_arm_record
      assert record.frozen?
      assert_same rig[:session], record.fetch(:session)
      assert_same rig[:capture], record.fetch(:capture)
      assert_same rig[:capture_thread], record.fetch(:thread)
      assert_equal [2_000_000_000, 7_300_000_000, 8_300_000_000], record.values_at(:at_ns, :fallback_ns, :hard_ns)
      assert_equal 8_300_000_000, rig[:driver].watchdog_join_deadline_ns
      assert_equal 1, rig[:factories].length
      record
    end
    ended_capture = lambda do |rig|
      rig[:capture_thread].live = false
      rig[:capture_flags].merge!(finished: true, joined: false, cancelled: true, retired: true)
      rig[:session].unknown = true
      rig[:session].primary_error = Interrupt.new("inert original capture primary")
      rig[:current], rig[:now] = rig[:worker_thread], 7_300_000_000
    end
    retained = lambda do |rig|
      registry, driver = rig.values_at(:registry, :driver)
      assert_same driver, registry.instance_variable_get(:@retained_fixture_cases).fetch(driver.object_id)
      assert_same rig[:control], driver.instance_variable_get(:@control)
      assert_equal({"/inert-missing-cleanup" => true}, registry.instance_variable_get(:@unresolved_roots))
      assert_equal true, registry.instance_variable_get(:@domain_disposal_required)
      assert_nil registry.instance_variable_get(:@expected_unknown_roots)
    end
    parent_proof = lambda do |rig|
      sample = rig[:omissions]
      close = rig[:writes].find { |path, _value| File.basename(path) == "fallback-writer-close.json" }.last
      sample[:bytes]["fallback-writer-close.json"] = JSON.generate(close)
      sample[:bytes]["leader-eof.json"] = JSON.generate({"version" => 1, "eof" => true, "controlReadNil" => true,
        "readNilNs" => close.fetch("closeEntryNs"), "pid" => 703, "group" => 702, "sid" => 701,
        "fifoIdentity" => close.fetch("fifoIdentity")})
      owner = {"version" => 2, "phase" => "native-setup-no-cleanup", "finality" => "unknown",
        "custodian" => {"state" => "unknown"}, "keeper" => {"state" => "unknown"},
        "validator" => {"state" => "unknown"}, "group" => {"state" => "unknown"},
        "processes" => [{"role" => "custodian", "pid" => 701, "group" => 701},
                        {"role" => "keeper", "pid" => 702, "group" => 701},
                        {"role" => "validator", "pid" => 703, "group" => 702}]}
      result = {"containmentSource" => sample[:manifest], "fallbackWriterClose" => close,
        "watchdogPreadmitted" => true, "watchdogJoined" => true}
      UploadProcessFixture::ContainmentEvidence.missing_cleanup!(sample[:directory], owner, result,
        sample[:manifest].fetch("sourceSha256"), deadline_ns: 20_000_000_000,
        driver_dispatch: {"pid" => 700, "deadlineNs" => 20_000_000_000})
    end

    # Driver-side publication/admission, then a distinct capture-side arm.
    rig = make.call
    within.call(rig) do
      prepare.call(rig)
      record = arm.call(rig)
      assert_raises(UploadProcessFixture::Failure) { rig[:driver].start_watchdog }
      assert_same record, rig[:driver].watchdog_arm_record
      ended_capture.call(rig)
      assert_equal true, rig.fetch(:worker).call
      assert_equal 1, rig[:writer_attempts]
      assert_equal 1, rig[:writes].length
      path, report = rig[:writes].first
      assert_equal "/inert-missing-cleanup/fallback-writer-close.json", path
      custody = report.fetch("watchdogOwnership")
      assert_equal [700, 20_000_000_000, 6_000_000_000, 12_300_000_000, 7_300_000_000, 8_300_000_000],
        custody.values_at("driverPid", "driverDeadlineNs", "prearmDeadlineNs", "slotCeilingNs", "fallbackNs", "effectiveHardDeadlineNs")
      assert_equal [true, false, true], custody.values_at("captureFinishedBeforeClose", "captureJoinedBeforeClose", "captureThreadExitedBeforeClose")
      assert_equal true, report.fetch("actualOriginalWriterClose")
      assert_equal rig[:omissions][:records].keys, rig[:entry_reads]
      assert_equal rig[:omissions][:records].keys.to_h { |name| [name,
        {"identity" => UploadProcessFixture::OwnedChild.identity(rig[:omissions][:stats].fetch(name)),
         "sha256" => Digest::SHA256.hexdigest(rig[:omissions][:bytes].fetch(name))}] }, report.fetch("omissionRecords")
      assert_equal true, rig[:session].retained_unknown? # Never repaired by fallback.
      # The real parent binder accepts early entries without either terminal
      # report or callback. These are inert inputs, not native proof receipts.
      proof = parent_proof.call(rig)
      assert_equal "unknown", proof.fetch("nativeFinality")
      assert_equal %w[containment-custodian-omission.json containment-keeper-omission.json fallback-writer-close.json leader-eof.json],
        proof.fetch("reportSha256").keys.sort
      assert_equal proof.fetch("reportSha256").keys.sort, rig[:omissions][:bytes].keys.sort
      assert rig[:session].retained_unknown?
      # Equal parsed JSON is insufficient: the parent's reread must match the
      # exact bytes and original file identity admitted BEFORE the same close.
      name = "containment-keeper-omission.json"
      original_bytes = rig[:omissions][:bytes].fetch(name)
      rig[:omissions][:bytes][name] = original_bytes + " "
      assert_raises(UploadProcessFixture::Failure) { parent_proof.call(rig) }
      rig[:omissions][:bytes][name] = original_bytes
      rig[:omissions][:stats].fetch(name).ino += 1
      assert_raises(UploadProcessFixture::Failure) { parent_proof.call(rig) }
      rig[:omissions][:stats].fetch(name).ino -= 1
      final_reads = 0
      rig[:after_read] = lambda do |c, read_name|
        next unless read_name == "leader-eof.json"
        final_reads += 1
        c[:now] = 20_000_000_000 if final_reads == 2 # Final report hash, after entry admission.
      end
      assert_raises(UploadProcessFixture::Failure) { parent_proof.call(rig) }
      assert_equal 2, final_reads
      assert_equal 20_000_000_000, rig[:now]
      rig[:after_read] = nil
      assert_equal 1, rig[:writer_attempts]
      rig[:now] = 30_000_000_000
      assert_equal 8_300_000_000, rig[:driver].watchdog_join_deadline_ns
      rig[:driver].finish_resources
      assert_includes rig[:events], [:join, 8_300_000_000, true]
      assert_equal 1, rig[:writer_attempts]
    end
    # Only materially different entry/source/file/temporal boundaries. Shared
    # bounded-file permission/size tests and prior watchdog matrices stay reused.
    invalid_entries = {
      "role" => ->(item) { item["role"] = "custodian" },
      "source" => ->(item) { item["sourceSha256"].transform_values! { "c" * 64 } },
      "copy" => ->(item) { item["helperCopy"]["sha256"] = "c" * 64 },
      "graph" => ->(item) { item["identities"]["validator"] = 799 },
      "parent" => ->(item) { item["parentPid"] = 700 },
      "route" => ->(item) { item["entry"]["route"] = "custodian-group" },
      "origin" => ->(item) { item["entry"]["origin"]["line"] += 1 },
      "pre-arm" => ->(item) { item["entry"]["atNs"] = 1_999_999_999 },
      "expired-entry" => ->(item) { item["entry"]["effectiveDeadlineNs"] = item["entry"]["atNs"] },
      "terminal-substitute" => ->(item) { item["kind"] = "original-helper-containment-events" },
    }
    scenarios = invalid_entries.keys + %w[missing-custodian missing-keeper changed-path changed-manifest read-crosses-H]
    scenarios.each do |fault|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        arm.call(candidate)
        ended_capture.call(candidate)
        name = "containment-keeper-omission.json"
        if invalid_entries.key?(fault)
          item = JSON.parse(candidate[:omissions][:bytes].fetch(name))
          invalid_entries.fetch(fault).call(item)
          candidate[:omissions][:bytes][name] = JSON.generate(item)
        elsif fault.start_with?("missing-")
          candidate[:omissions][:stats].delete("containment-#{fault.delete_prefix('missing-')}-omission.json")
        elsif fault == "changed-path"
          candidate[:changed_path] = name
        elsif fault == "changed-manifest"
          candidate[:manifest_read] = JSON.parse(JSON.generate(candidate[:omissions][:manifest]))
          candidate[:manifest_read]["helperCopy"]["sha256"] = "c" * 64
        else
          candidate[:after_read] = ->(c, read_name) { c[:now] = 8_300_000_000 if read_name == name }
        end
        expected = fault.start_with?("missing-") ? Errno::ENOENT : UploadProcessFixture::Failure
        error = assert_raises(expected, fault) { candidate[:control].close_writer }
        assert_same error, candidate[:control].close_error
        assert_nil candidate[:driver].instance_variable_get(:@watchdog_action)
        assert_equal 0, candidate[:writer_attempts], fault
        assert_empty candidate[:writes]
        assert candidate[:session].retained_unknown?
      end
    end
    # Hardloss keeps its stronger terminal requirement; early omissions must
    # not silently replace the original C/K terminal receipt wait in that path.
    candidate = make.call
    within.call(candidate) do
      original = IOError.new("inert hardloss terminal wait")
      wait = lambda do |directory, names, deadline_ns:|
        assert_equal candidate[:omissions][:directory], directory
        assert_equal %w[containment-custodian.json containment-keeper.json], names
        assert_equal 20_000_000_000, deadline_ns
        raise original
      end
      UploadProcessFixture::ContainmentEvidence.stub(:wait_records, wait) do
        caught = assert_raises(IOError) do
          UploadProcessFixture::ContainmentEvidence.hardloss!(candidate[:omissions][:directory], "kill-native-setup",
            {"fifoIdentity" => candidate[:control].instance_variable_get(:@identity)}, candidate[:control].writer,
            deadline_ns: 20_000_000_000)
        end
        assert_same original, caught
        assert_equal 0, candidate[:writer_attempts]
      end
    end
    candidate = make.call
    within.call(candidate) do
      candidate[:now] = 20_000_000_000
      sample = candidate[:omissions]
      assert_raises(UploadProcessFixture::Failure) do
        UploadProcessFixture::ContainmentEvidence.omission_records!(sample[:directory], sample[:manifest], sample[:graph],
          driver_pid: 700, deadline_ns: 20_000_000_000, capture_entry_ns: 1_000_000_000,
          arm_ns: 2_000_000_000, before_ns: 7_300_000_000)
      end
      assert_empty candidate[:entry_reads]
      assert_empty candidate[:stat_reads]
      assert_equal 0, candidate[:writer_attempts]
    end
    # Stop-before-prepare and exhausted original D cannot acquire a new slot.
    [make.call, make.call(deadline: 7_300_000_000), make.call].each_with_index do |candidate, index|
      within.call(candidate) do
        candidate[:driver].stop_watchdog! if index.zero?
        candidate[:current] = candidate[:worker_thread] if index == 2
        assert_raises(UploadProcessFixture::Failure) { candidate[:driver].prepare_watchdog }
        assert_empty candidate[:factories]
      end
    end
    # Late returned publication must never enter even an immediate admit branch.
    %i[publication_query publication_wait admit_return start_return denied_admit start_error admit_error].each do |fault|
      candidate = make.call
      original = IOError.new("inert #{fault}")
      case fault
      when :publication_query then candidate[:query_hooks][:publication_ready?] = ->(c) { c[:now] = 6_000_000_000 }
      when :publication_wait
        candidate[:flags][:published] = false
        candidate[:sleep_hook] = ->(c) { c[:now] = 6_000_000_000; c[:flags][:published] = true }
      when :admit_return then candidate[:admit_ns] = 6_000_000_000
      when :start_return then candidate[:flags][:start_return] = nil
      when :denied_admit then candidate[:flags][:admit_return] = false
      when :start_error then candidate[:start_error] = original
      when :admit_error then candidate[:admit_error] = original
      end
      within.call(candidate) do
        error = assert_raises(%i[start_error admit_error].include?(fault) ? IOError : UploadProcessFixture::Failure) do
          candidate[:driver].prepare_watchdog
        end
        assert_same original, error if %i[start_error admit_error].include?(fault)
        assert_same candidate[:slot], candidate[:driver].instance_variable_get(:@watchdog)
        assert candidate[:flags][:attempted]
        refute candidate[:driver].observed.fetch("watchdogStarted")
        refute candidate[:driver].observed.key?("watchdogPreadmitted")
        assert_empty candidate[:events].select { |row| row.first == :admit } if %i[publication_query publication_wait start_return start_error].include?(fault)
      end
    end
    candidate = make.call
    within.call(candidate) do
      assert_equal true, candidate[:driver].prepare_watchdog
      candidate[:now] = 6_000_000_000
      assert_raises(UploadProcessFixture::Failure) { candidate[:driver].native_event(:execute_enter, candidate[:session]) }
      assert_nil candidate[:driver].instance_variable_get(:@native_frame)
    end
    candidate = make.call
    within.call(candidate) do
      prepare.call(candidate)
      candidate[:current] = candidate[:worker_thread]
      assert_raises(UploadProcessFixture::Failure) { candidate[:driver].claim_watchdog_action!(nil) }
      candidate[:sleep_hook] = ->(c) { c[:now] = 6_000_000_000 }
      assert_raises(UploadProcessFixture::Failure) { candidate.fetch(:worker).call }
      assert_empty candidate[:writes]
      assert_equal 0, candidate[:writer_attempts]
      assert_equal 6_000_000_000, candidate[:driver].watchdog_join_deadline_ns
    end
    # Arm fails before any new authority; action independently rechecks F/H and
    # original worker/caller state, even when native capture has ended UNKNOWN.
    arm_refusals = [->(c) { c[:driver].stop_watchdog! }, ->(c) { c[:now] = 6_000_000_000 },
      ->(c) { c[:current] = c[:driver_thread] }, ->(c) { c[:session].unknown = true },
      ->(c) { c[:capture_flags][:cancelled] = true }]
    arm_refusals.each do |mutate|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        candidate[:current], candidate[:now] = candidate[:capture_thread], 2_000_000_000
        mutate.call(candidate)
        assert_raises(UploadProcessFixture::Failure) { candidate[:driver].start_watchdog }
        assert_nil candidate[:driver].watchdog_arm_record
        refute candidate[:driver].observed.fetch("watchdogStarted")
        assert_equal 1, candidate[:factories].length
      end
    end
    action_refusals = [->(c) { c[:driver].stop_watchdog! }, ->(c) { c[:current] = c[:capture_thread] },
      ->(c) { c[:driver_thread].live = false }, ->(c) { c[:flags][:cancelled] = true },
      ->(c) { c[:flags][:retired] = true }, ->(c) { c[:now] = 7_300_000_000 - 1 }, ->(c) { c[:now] = 8_300_000_000 },
      ->(c) { c[:query_hooks][:launch_retired?] = ->(r) { r[:now] = 8_300_000_000 } }]
    action_refusals.each do |mutate|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        record = arm.call(candidate)
        ended_capture.call(candidate)
        mutate.call(candidate)
        assert_raises(UploadProcessFixture::Failure) { candidate[:driver].claim_watchdog_action!(record) }
        assert_nil candidate[:driver].instance_variable_get(:@watchdog_action)
        assert_equal 0, candidate[:writer_attempts]
      end
    end
    # A failed join forbids BOTH parent lease closes and roots the same driver.
    # The second case stops while the original writer action is already in flight.
    %i[unclaimed inflight join_error].each do |scenario|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        record = arm.call(candidate)
        ended_capture.call(candidate)
        candidate[:flags][:join_return] = false
        candidate[:join_error] = IOError.new("original fallback join failure") if scenario == :join_error
        primary = candidate[:session].primary_error
        cleanup_error = nil
        finish = lambda do |c|
          # Model the parent turn without another real thread or scheduling.
          caller = c[:current]
          c[:current] = c[:driver_thread]
          begin
            before = c[:events].count { |row| row.first == :lease_close }
            cleanup_error = assert_raises(c[:join_error] ? IOError : UploadProcessFixture::Failure) { c[:driver].finish_resources }
            assert_same c[:join_error], cleanup_error if c[:join_error]
            assert_equal before, c[:events].count { |row| row.first == :lease_close }
            assert_same cleanup_error, c[:driver].instance_variable_get(:@cleanup_errors).first
            assert_nil c[:slot].first_error # A native failure is not this independent task's failure.
            assert_same primary, c[:session].primary_error
            assert_includes c[:events], [:owner, "finished"]
            retained.call(c)
          ensure
            c[:current] = caller
          end
        end
        if scenario == :inflight
          candidate[:during_close] = finish
          assert_equal true, candidate.fetch(:worker).call
          claim = candidate[:driver].instance_variable_get(:@watchdog_action)
          assert claim.frozen?
          assert_same record, claim.fetch(:arm)
          assert_equal 7_300_000_000, claim.fetch(:entry_ns)
          assert_equal 1, candidate[:writer_attempts]
          assert_raises(UploadProcessFixture::Failure) { candidate[:driver].claim_watchdog_action!(record) }
          assert_same claim, candidate[:driver].instance_variable_get(:@watchdog_action)
        else
          finish.call(candidate)
          assert_raises(UploadProcessFixture::Failure) { candidate[:control].close_writer }
          assert_nil candidate[:driver].instance_variable_get(:@watchdog_action)
          assert_equal 0, candidate[:writer_attempts]
        end
      end
    end
    # Positive join plus original task failure still closes independent resources
    # and preserves that first error; false/raising custody never closes them.
    candidate = make.call
    within.call(candidate) do
      prepare.call(candidate)
      original = candidate[:flags][:first_error] = IOError.new("original fallback task failure")
      candidate[:flags][:cancelled] = true
      actual = assert_raises(IOError) { candidate[:driver].finish_resources }
      assert_same original, actual
      assert_equal [original], candidate[:driver].instance_variable_get(:@cleanup_errors)
      assert_equal [[:lease_close, :anchor], [:lease_close, :writer]], candidate[:events].select { |row| row.first == :lease_close }
      assert_includes candidate[:events], [:owner, "finished"]
    end
    [{joined: nil}, {joined: true, finished: false}, {joined: true, finished: true, unresolved: true},
     {joined: IOError.new("inert failed original join query")}].each do |flags|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        candidate[:flags].merge!(flags)
        error = assert_raises(flags[:joined].is_a?(Exception) ? IOError : UploadProcessFixture::Failure) { candidate[:driver].close_control }
        assert_same flags[:joined], error if flags[:joined].is_a?(Exception)
        assert_empty candidate[:events].select { |row| row.first == :lease_close }
        retained.call(candidate)
      end
    end
    [true, false].each do |retire_return|
      candidate = make.call
      within.call(candidate) do
        candidate[:driver].instance_variable_set(:@watchdog, candidate[:slot])
        candidate[:retire_return] = retire_return
        if retire_return
          assert_equal true, candidate[:driver].close_control
          assert candidate[:flags][:retired]
        else
          2.times { assert_raises(UploadProcessFixture::Failure) { candidate[:driver].close_control } }
          assert_empty candidate[:events].select { |row| row.first == :lease_close }
          retained.call(candidate)
        end
        assert_equal [[:retire]], candidate[:events].select { |row| row.first == :retire }
      end
    end
    # A real close effect arriving at/after H is retained but never published as
    # timely proof, and neither it nor a close exception authorizes a second call.
    [8_300_000_000, 8_300_000_001, IOError.new("original inert writer close failure")].each do |outcome|
      candidate = make.call
      within.call(candidate) do
        prepare.call(candidate)
        arm.call(candidate)
        ended_capture.call(candidate)
        if outcome.is_a?(Exception)
          candidate[:writer_error] = outcome
        else
          candidate[:close_return_ns] = outcome
        end
        original = assert_raises(outcome.is_a?(Exception) ? IOError : UploadProcessFixture::Failure) { candidate[:control].close_writer }
        assert_same outcome, original if outcome.is_a?(Exception)
        assert_same original, candidate[:control].close_error
        assert_equal true, candidate[:control].close_result unless outcome.is_a?(Exception)
        assert_raises(UploadProcessFixture::Failure) { candidate[:control].close_writer }
        assert_same original, candidate[:control].close_error
        assert_equal 1, candidate[:writer_attempts]
        assert_empty candidate[:writes]
      end
    end
    original_registries.each do |name, (defined, object, contents)|
      assert_equal defined, UploadProcessFixture.instance_variable_defined?(name), name
      assert_same object, UploadProcessFixture.instance_variable_get(name), name
      assert_equal contents, object, name if object.is_a?(Hash)
    end
  end

  def native_order_case(family, caller_kind)
    UploadProcessFixture.assert_domain_reusable!
    assert_equal ORDER_CASES, UploadProcessFixture::NativeOrderProbe::MODES
    mode = "native-order-#{family}-#{caller_kind}"
    assert_equal [family, caller_kind], ORDER_CASES.fetch(mode)
    unknown = family == "cleanup-before-caller"
    caller_first = family == "caller-before-task"
    sources = proof_source_snapshot
    order_failure_state = {} # Each internal mode retains only its own rejection.
    value = begin
      if unknown
        # One original driver in this singleton. Its truthful UNKNOWN is not a
        # successful capture, a ps-repaired receipt, or permission for a next case.
        UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode,
          order_failure_state: order_failure_state)
      else
        process_case(mode, order_failure_state: order_failure_state)
      end
    rescue Exception => original
      begin
        self.class.report_native_order_failure(order_failure_state, original,
          callback: "#{self.class.name}##{name}", mode: mode)
      rescue Exception
        nil # Lookup/report failures cannot replace the original unwound error.
      end
      raise
    end
    assert value.fetch("driverJoined")
    assert_equal unknown ? "fixture-cleanup" : "unexpected", value.fetch("kind")
    proof = value.fetch("nativeOrderProof")
    assert_equal %w[baseDriverReturn bodyError bodyFaults callerDeliveries callerDeliveryReturned callerError callerKind
                    callerRescueObserved captureFinished captureFirstSameObject captureJoined case causalBarrierBound
                    cleanupError cleanupFaults cleanupTailSource creatorFirstSameObject expectedUnknown failures family
                    finiteValidator firstError firstLatch kind laterLatch nativeFirstSameObject ordinaryProductionPass
                    originalAccepted outerFirstSameObject receiptEvents retainedOriginalSession sourceSha256 version], proof.keys.sort
    assert_equal [1, "native-order-observation", mode, family, caller_kind], proof.values_at("version", "kind", "case", "family", "callerKind")
    assert_equal sources.transform_values { |item| item.fetch("sha256") }, proof.fetch("sourceSha256")
    assert_empty proof.fetch("failures"), proof.inspect
    assert_equal 1, proof.fetch("baseDriverReturn") # Original Ruby method return, not the direct driver's OS exit.
    refute proof.fetch("ordinaryProductionPass")
    refute proof.fetch("originalAccepted")
    assert_equal unknown, proof.fetch("expectedUnknown")
    %w[causalBarrierBound callerDeliveryReturned callerRescueObserved outerFirstSameObject nativeFirstSameObject
       captureFirstSameObject creatorFirstSameObject captureJoined].each { |name| assert_equal true, proof.fetch(name), name }
    assert_equal 1, proof.fetch("callerDeliveries")
    assert_equal unknown ? 0 : 1, proof.fetch("bodyFaults")
    assert_equal unknown ? 1 : 0, proof.fetch("cleanupFaults")
    assert_equal !unknown, proof.fetch("captureFinished")
    assert_equal unknown, proof.fetch("retainedOriginalSession")
    caller_error = {"class" => caller_kind == "interrupt" ? "Interrupt" : "SystemExit",
                    "message" => "original native order caller cancellation", "exitStatus" => caller_kind == "interrupt" ? nil : 47}
    body_error = {"class" => caller_first ? "IOError" : "UploadProcessFixture::NativeOrderProbe::BodyFailure",
                  "message" => caller_first ? "later native order body IOError" : "original native order body failure", "exitStatus" => nil}
    cleanup_error = {"class" => "UploadProcessFixture::NativeOrderProbe::CleanupFailure",
                     "message" => "original native order task cleanup failure", "exitStatus" => nil}
    assert_equal caller_error, proof.fetch("callerError")
    assert_equal body_error, proof.fetch("bodyError")
    assert_equal cleanup_error, proof.fetch("cleanupError")
    first_error = unknown ? cleanup_error : caller_first ? caller_error : body_error
    assert_equal first_error, proof.fetch("firstError")
    assert_equal first_error.fetch("class"), value.fetch("nativeErrorClass")
    assert_equal first_error.fetch("message"), value.fetch("nativeErrorMessage")
    assert value.fetch("nativeOriginalErrorPreserved")
    assert_equal 47, value.fetch("nativeExitStatus") if caller_first && caller_kind == "system-exit"
    first, later = proof.values_at("firstLatch", "laterLatch")
    [first, later].each do |receipt|
      assert_equal %w[firstSameObject launchRetired operation originalCallReturned originalSharedRecord originalSlot priorWasFirst priorWasNil thread], receipt.keys.sort
      %w[originalCallReturned originalSharedRecord originalSlot firstSameObject launchRetired].each { |name| assert_equal true, receipt.fetch(name), name }
    end
    assert_equal unknown ? "record_cleanup_error" : "cancel!", first.fetch("operation")
    assert_equal "cancel!", later.fetch("operation")
    assert_equal caller_first ? "caller" : "capture", first.fetch("thread")
    assert_equal caller_first ? "capture" : "caller", later.fetch("thread")
    assert first.fetch("priorWasNil")
    refute first.fetch("priorWasFirst")
    refute later.fetch("priorWasNil")
    assert later.fetch("priorWasFirst")
    # Ordinals are diagnostic only. The driver separately checked the retained
    # original latch-return object which released each actual later exception.
    events = proof.fetch("receiptEvents")
    assert_operator events.length, :<=, 64
    assert_equal (0...events.length).to_a, events.map { |event| event.fetch("ordinal") }
    events.each { |event| assert_includes %w[caller capture], event.fetch("thread") }
    native = value.fetch("nativeObservation")
    assert_native_observation(native, finality: unknown ? :unknown : :finalized)
    if unknown
      assert_equal "unknown", value.fetch("nativeFinality")
      assert value.fetch("retainedFixture")
      assert value.fetch("domainDisposalRequired")
      refute value.key?("knownProcessesDead") # UNKNOWN does not authorize a new process observer or a repaired custody claim.
      assert UploadProcessFixture.expected_unknown_retention?(@root)
      assert UploadProcessFixture.domain_disposal_required?
      refute value.fetch("tasksJoined")
      refute value.fetch("watchdogStarted")
      refute value.key?("deadBeforeFallback")
      assert_equal 0, value.fetch("injectionCount")
      assert_equal %w[capture creator], native.fetch("tasks").map { |task| task.fetch("role") }.sort
      native.fetch("tasks").each do |task|
        %w[startAttempted joined actualJoinObserved actualConstructionObserved launchRetired actualLaunchClosureObserved].each { |name| assert task.fetch(name), task.inspect }
        refute task.fetch("unresolved")
        assert_equal task.fetch("role") == "creator", task.fetch("finished")
      end
      native.fetch("leases").each do |lease|
        assert_equal "closed", lease.fetch("state")
        assert lease.fetch("closed")
        assert lease.fetch("actualCloseObserved")
        assert_nil lease.fetch("closeError")
      end
      assert native.fetch("streams").values.all? { |flag| flag.equal?(true) }
      assert_child_terminal(native.fetch("custodian"), allow_no_attempt: false)
      assert_equal ["exit", 0], native.fetch("custodian").values_at("status_kind", "status_code")
      assert_final_cleanup(native.fetch("final"))
      assert_equal "ok", native.fetch("final").fetch("outcome") # Real pre-tail native success is NOT finality.
      finite = proof.fetch("finiteValidator")
      source = "STDOUT.write(\"native-order-complete\\n\")\n"
      assert_equal({"argv" => [File.realpath(RbConfig.ruby), *MobileReleaseKit::NativeUploadProcess::HELPER_FLAGS, "-e", source],
                    "sha256" => Digest::SHA256.hexdigest(source)}, finite)
      tail = "          begin\n            close_launch!\n            @lock.synchronize { @finished = true }\n          rescue Exception => error\n            record_cleanup_error(error)\n"
      lines = sources.fetch("fastlane/native_upload_process.rb").fetch("bytes").lines
      starts = lines.each_index.select { |index| lines[index, tail.lines.length]&.join == tail }
      assert_equal 1, starts.length
      assert_equal({"path" => File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__)),
                    "line" => starts.first + 2}, proof.fetch("cleanupTailSource"))
    else
      assert_equal "finalized", value.fetch("nativeFinality")
      refute value.fetch("retainedFixture")
      assert_equal 1, value.fetch("injectionCount")
      assert_validator_killed(native)
      assert_nil proof.fetch("cleanupTailSource")
      assert_nil proof.fetch("finiteValidator")
    end
    %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted ownedDescriptorsClosed watchdogJoined
       injectorsJoined handlersRestored registryInactive].each { |name| assert value.fetch(name), name }
    %w[fallbackUsed watchdogIntervened pendingInterrupt].each { |name| refute value.fetch(name), name }
    assert_empty value.fetch("cleanupErrors")
    driver = value.fetch("driverProvenance")
    assert_equal "reaped", driver.fetch("phase")
    assert driver.fetch("creatorJoined")
    assert driver.fetch("resourcesClosed")
    assert_equal({"pid" => driver.fetch("pid"), "status_kind" => "exit", "status_code" => 0}, driver.fetch("wait"))
    assert_equal({"out" => true, "err" => true}, driver.fetch("ownedStreamEOFs"))
    assert_equal sources, proof_source_snapshot
    value
  end

  def execute_isolated_collector_close(arguments, failure_state:)
    UploadProcessFixture.assert_domain_reusable!
    failure_state[:stage] = "request-contract"
    request = read_isolated_json(File.join(@root, "isolated-request.json"))
    assert_equal %w[argv cwd deadlineNs minitest sourceSha256 testSource version], request.keys.sort
    assert_equal 1, request.fetch("version")
    assert_equal({"platform" => "native", "parameters" => {}, "mode" => ISOLATED_COLLECTOR_MODE},
                 read_isolated_json(File.join(@root, "input.json")))
    failure_state[:stage] = "source-bindings"
    minitest = minitest_library_snapshot
    assert_equal minitest, request.fetch("minitest")
    assert_equal isolated_collector_argv(@root, minitest), request.fetch("argv")
    assert_equal Dir.pwd, request.fetch("cwd")
    source_hashes = proof_source_snapshot.transform_values { |item| item.fetch("sha256") }
    assert_equal source_hashes, request.fetch("sourceSha256")
    test_source = dispatch_file_identity(File.realpath(__FILE__), limit: 1_048_576)
    assert_equal test_source, request.fetch("testSource")
    failure_state[:stage] = "deadline-bound"
    deadline_ns = request.fetch("deadlineNs")
    assert_instance_of Integer, deadline_ns
    now_ns = MobileReleaseKit::NativeUploadProcess.monotonic_ns
    assert_operator deadline_ns, :>, now_ns
    assert_operator deadline_ns, :<=, now_ns + ISOLATED_COLLECTOR_LIMIT * 1_000_000_000
    failure_state[:deadline_ns] = deadline_ns

    failure_state[:stage] = "collector-execution"
    observed = {}
    close_fault = IOError.new("synthetic collector close after effect")
    repeat = Interrupt.new("repeat at collector reporting tail")
    error = assert_raises(UploadProcessFixture::Failure) do
      UploadProcessFixture.lifetime(deadline_ns: deadline_ns) do |scope|
        observed[:isolated_lifetime] = scope
        directory = new_raw_case("collector-timeout", "collector-timeout")
        scope.active do
          collect_raw_driver(nil, directory, observed, literal: "timeout", close_fault: close_fault,
                             reporting_repeat: repeat, enclosing_deadline_ns: deadline_ns)
        end
      end
    end
    failure_state[:stage] = "capture-primary"
    assert_same error, observed.fetch(:primary)
    record = assert_retained_capture(observed, finality: :unknown, failure_state: failure_state)
    failure_state[:stage] = "capture-error-contract"
    assert_equal bounded_error(error), record.fetch("primary")
    assert_equal "driver", error.kind
    assert_equal "raw proof driver deadline expired", error.message
    failure_state[:stage] = "capture-readiness"
    assert_equal({"observed" => true, "identity" => observed.fetch(:stream_identities).first}, record.fetch("literalReadiness"))
    failure_state[:stage] = "capture-transcript"
    assert_equal "collector ready\n", File.binread(File.join(observed.fetch(:directory), "driver.stdout"), UploadProcessFixture::OUTPUT_LIMIT + 1)
    failure_state[:stage] = "capture-termination"
    assert_equal Signal.list.fetch("KILL"), observed.fetch(:status).termsig
    failure_state[:stage] = "cleanup-contract"
    assert_equal 2, observed.fetch(:cleanup_errors).length
    assert_same close_fault, observed.fetch(:cleanup_errors).first
    scratch_error = observed.fetch(:cleanup_errors).last
    assert_instance_of UploadProcessFixture::Failure, scratch_error
    assert_equal "fixture-cleanup", scratch_error.kind
    assert_equal "unresolved observer scratch prevents fixture removal", scratch_error.message
    assert_equal ["IOError", "UploadProcessFixture::Failure"], record.fetch("cleanupErrors").map { |entry| entry.fetch("class") }
    assert_equal 1, observed.fetch(:close_fault_calls)
    failure_state[:stage] = "reporting-contract"
    assert observed.fetch(:reporting_repeat_queued)
    assert observed.fetch(:reporting_injector_joined)
    assert observed.fetch(:reporting_injector_admitted)
    %w[reportingRepeatQueued reportingInjectorJoined reportingInjectorAdmitted reportingInjectorFinished].each do |name|
      assert record.fetch(name), name
    end
    slot = observed.fetch(:reporting_injector_slot)
    assert_instance_of MobileReleaseKit::NativeUploadProcess::TaskSlot, slot
    assert_same slot.thread, observed.fetch(:reporting_injector)
    assert slot.joined?
    assert slot.finished?
    assert slot.launch_retired?
    refute slot.unresolved?
    assert_equal true, slot.offer
    assert_nil slot.first_error
    assert_empty slot.cleanup_errors
    refute_same Thread.current, observed.fetch(:reporting_injector)
    refute observed.fetch(:reporting_injector).alive?
    refute observed.fetch(:reporting_injector).report_on_exception
    refute observed.fetch(:reporting_injector).abort_on_exception
    assert_equal observed.fetch(:reporting_thread_defaults), [Thread.report_on_exception, Thread.abort_on_exception]

    failure_state[:stage] = "custody-contract"
    child = observed.fetch(:child)
    assert_equal :unknown, child.phase
    refute child.complete?
    assert_equal :unknown, child.acquisition.state
    assert_equal :reaped, child.child.state
    assert_same child.child, child.acquisition.child
    assert_same child.status, child.child.receipt.raw_status
    assert child.child.numeric_retired?
    assert child.creator.joined?
    assert child.creator.finished?
    refute child.creator.unresolved?
    unknown = child.acquisition.resources.values.select { |lease| lease.state == :unknown }
    assert_equal [:out], unknown.map(&:role)
    assert_same close_fault, unknown.first.close_error
    assert unknown.first.io.closed? # Physical effect is NOT repaired custody.
    assert child.acquisition.resources.values.reject { |lease| lease.equal?(unknown.first) }.all? { |lease| %i[closed not_acquired].include?(lease.state) }
    retained = UploadProcessFixture.instance_variable_get(:@unresolved_children)
    assert_same child, retained.fetch(child.object_id)
    assert UploadProcessFixture.cleanup_unresolved?(observed.fetch(:directory))
    assert File.directory?(child.launch_directory)
    failure_state[:stage] = "final-recheck"
    assert_equal deadline_ns, observed.fetch(:enclosing_deadline_ns)
    assert_equal deadline_ns, observed.fetch(:isolated_lifetime).instance_variable_get(:@drain_deadline_ns).call
    assert_operator child.creator.hard_cleanup_deadline_ns, :<=, deadline_ns - RAW_REPORTING_NS
    assert_operator slot.hard_cleanup_deadline_ns, :<=, deadline_ns
    assert_equal slot.run_deadline_ns, record.fetch("reportingInjectorDeadlineNs")
    assert_equal slot.run_deadline_ns, slot.hard_cleanup_deadline_ns
    assert_equal source_hashes, proof_source_snapshot.transform_values { |item| item.fetch("sha256") }
    assert_equal test_source, dispatch_file_identity(File.realpath(__FILE__), limit: 1_048_576)
    assert_equal minitest, minitest_library_snapshot
    failure_state[:stage] = "proof-publication"
    proof = {"version" => 1, "case" => ISOLATED_COLLECTOR_MODE, "pid" => Process.pid, "deadlineNs" => deadline_ns,
             "argv" => isolated_collector_argv(@root, minitest), "cwd" => Dir.pwd,
             "interpreter" => dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024),
             "testSource" => test_source, "sourceSha256" => source_hashes, "childCollector" => record, "minitest" => minitest,
             "innerState" => {"phase" => "unknown", "stopCompleted" => false, "creatorJoined" => true,
                               "originalWaitBound" => true, "unknownLease" => "out", "retained" => true}}
    raise "oversized isolated collector proof" if JSON.generate(proof).bytesize > UploadProcessFixture::OUTPUT_LIMIT
    UploadProcessFixture.atomic_json(File.join(@root, "isolated-control.json"), proof)
    # The fixed CLI exits immediately. Do not run autorun, another capture,
    # cleanup/reset hooks, or a scratch finalizer in this poisoned interpreter.
  end

  def read_isolated_json(path)
    File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
      before = file.stat
      unless before.file? && before.uid == Process.uid && before.nlink == 1 && (before.mode & 0o7777) == 0o600
        raise UploadProcessFixture::Failure.new("fixture-result", "isolated collector proof identity is invalid")
      end
      bytes = file.read(UploadProcessFixture::OUTPUT_LIMIT + 1)
      identity = ->(stat) { [stat.dev, stat.ino, stat.mode, stat.size, stat.mtime, stat.ctime] }
      unless bytes && bytes.bytesize <= UploadProcessFixture::OUTPUT_LIMIT && bytes.bytesize == before.size &&
             identity.call(before) == identity.call(file.stat)
        raise UploadProcessFixture::Failure.new("fixture-result", "isolated collector proof changed or exceeded its bound")
      end
      value = JSON.parse(bytes)
      raise UploadProcessFixture::Failure.new("fixture-result", "isolated collector proof is not an object") unless value.instance_of?(Hash)
      value
    end
  end

  def isolated_collector_argv(directory, minitest)
    [RbConfig.ruby, *MobileReleaseKit::NativeUploadProcess::HELPER_FLAGS, "-I", minitest.fetch("root"),
     "--", File.realpath(__FILE__), ISOLATED_COLLECTOR_FLAG, directory]
  end

  def minitest_library_snapshot
    raise "isolated collector requires the locked Minitest version" unless Minitest::VERSION == "5.25.5"
    methods = {"Test" => Minitest::Test.instance_method(:run), "Assertions" => Minitest::Assertions.instance_method(:assert),
               "autorun" => Minitest.method(:autorun), "mock" => Object.instance_method(:stub)}
    origins = methods.transform_values do |method|
      path, line = method.source_location
      raise "Minitest origin is not Ruby source" unless path && line
      {"path" => File.realpath(path), "line" => line}
    end
    root = File.dirname(origins.fetch("autorun").fetch("path"))
    expected = {"Test" => "minitest/test.rb", "Assertions" => "minitest/assertions.rb",
                "autorun" => "minitest.rb", "mock" => "minitest/mock.rb"}
    expected.each do |name, relative|
      raise "Minitest origins do not share one exact library" unless origins.fetch(name).fetch("path") == File.join(root, relative)
    end
    # Locked 5.25.5 also ships this inert Hoe plugin source. Account for exactly
    # that file without requiring Hoe or opening any additional loader namespace.
    hoe_root = File.join(root, "hoe")
    raise "unexpected Minitest shadow-loader entry" unless Dir.children(root).sort == %w[hoe minitest minitest.rb]
    pending, files, directories, total = [root], {}, {}, 0
    until pending.empty?
      path = pending.pop
      before = File.lstat(path)
      unless before.directory? && File.realpath(path) == path && (before.mode & 0o022).zero? && directories.length < 16
        raise "Minitest library directory is unsafe or exceeds its bound"
      end
      names = Dir.children(path).sort
      raise "Minitest library directory exceeds its bound" if names.length > 64
      directories[path.delete_prefix("#{root}/")] = [before.dev, before.ino, before.mode, before.uid, before.gid]
      names.each do |name|
        raise "invalid Minitest library name" unless /\A[A-Za-z0-9_.-]+\z/.match?(name) && !%w[. ..].include?(name)
        child = File.join(path, name)
        stat = File.lstat(child)
        if stat.directory?
          unless child == hoe_root || child.start_with?("#{root}/minitest") && child.count("/") - root.count("/") <= 4
            raise "unexpected Minitest namespace"
          end
          pending << child
        else
          unless stat.file? && stat.nlink == 1 && (stat.mode & 0o022).zero? && name.end_with?(".rb") &&
                 File.realpath(child) == child && files.length < 64 && (path != hoe_root || name == "minitest.rb")
            raise "Minitest library contains an unsafe or unexpected loader"
          end
          item = dispatch_file_identity(child, limit: 1_048_576)
          if path == hoe_root && (item.fetch("size") != 544 || item.fetch("sha256") != "66a98ba72d7c7d57c5ea948c9d7ce442567e6c68b22fd34bdd18e4814d1099ef")
            raise "Minitest Hoe source differs from the locked artifact"
          end
          total += item.fetch("size")
          raise "Minitest library byte bound exceeded" if total > 2_097_152
          files[child.delete_prefix("#{root}/")] = item
        end
      end
      identity = ->(stat) { [stat.dev, stat.ino, stat.mode, stat.size, stat.mtime, stat.ctime] }
      raise "Minitest library changed during enumeration" unless identity.call(before) == identity.call(File.lstat(path))
    end
    %w[hoe/minitest.rb minitest.rb minitest/assertions.rb minitest/autorun.rb minitest/mock.rb minitest/test.rb].each do |name|
      raise "Minitest library is incomplete" unless files.key?(name)
    end
    {"root" => root, "version" => Minitest::VERSION, "origins" => origins, "files" => files, "directories" => directories}
  end

  def inert_terminal_frame
    {"v" => 1, "type" => "FINAL", "outcome" => "failed", "cleanup" => "confirmed",
     "keeper" => {"state" => "not_attempted"}, "validator" => {"state" => "not_attempted"},
     "group" => {"state" => "not_created"}}
  end

  def inert_late_frames
    [{"v" => 1, "type" => "HELLO", "pid" => 101, "ppid" => 100, "sid" => 101, "pgid" => 101, "fd_map_version" => 1},
     {"v" => 1, "type" => "RESERVED", "keeper_pid" => 102, "group_id" => 102, "session_id" => 101},
     {"v" => 1, "type" => "READY", "validator_pid" => 103, "group_id" => 102, "keeper_pgid" => 101},
     {"v" => 1, "type" => "STATUS", "validator_pid" => 103, "status_kind" => "exit", "status_code" => 0},
     inert_terminal_frame]
  end

  def assert_inert_observer_rejection(observer, label)
    snapshot = observer.build_snapshot
    refute snapshot.fetch("finalized"), label
    refute snapshot.fetch("noProducers"), label
    assert snapshot.fetch("unknown"), label
    UploadProcessFixture.atomic_json(File.join(@root, "#{label}.inert-observer.json"),
                                     {"inertControl" => true, "case" => label, "snapshot" => snapshot})
  end

  def assert_child_terminal(record, allow_no_attempt: true)
    assert_instance_of Hash, record
    if record.fetch("state") == "not_attempted"
      assert allow_no_attempt
      assert_equal({"state" => "not_attempted"}, record)
      return
    end
    assert_equal %w[pid state status_code status_kind], record.keys.sort
    assert_equal "reaped", record.fetch("state")
    assert_instance_of Integer, record.fetch("pid")
    assert_operator record.fetch("pid"), :>, 1
    assert_operator record.fetch("pid"), :<=, 2_147_483_647
    assert_instance_of Integer, record.fetch("status_code")
    case record.fetch("status_kind")
    when "exit" then assert_includes 0..255, record.fetch("status_code")
    when "signal" then assert_includes 1...MobileReleaseKit::NativeProcessSpawn.nsig, record.fetch("status_code")
    else flunk "invalid genuine child terminal kind: #{record.inspect}"
    end
  end

  def assert_final_cleanup(frame)
    assert_instance_of Hash, frame
    assert_equal %w[cleanup group keeper outcome type v validator], frame.keys.sort
    assert_instance_of Integer, frame.fetch("v")
    assert_equal 1, frame.fetch("v")
    assert_equal "FINAL", frame.fetch("type")
    assert_equal "confirmed", frame.fetch("cleanup")
    assert_includes %w[ok rejected failed], frame.fetch("outcome")
    keeper, validator, group = frame.values_at("keeper", "validator", "group")
    [keeper, validator].each { |record| assert_child_terminal(record) }
    if keeper.fetch("state") == "reaped"
      assert_equal "exit", keeper.fetch("status_kind")
      assert_includes frame.fetch("outcome") == "failed" ? [0, 2] : [0], keeper.fetch("status_code")
    end
    if group.fetch("state") == "not_created"
      assert_equal({"state" => "not_created"}, group)
      assert_equal({"state" => "not_attempted"}, validator)
    else
      assert_equal %w[absent id state], group.keys.sort
      assert_equal "retired", group.fetch("state")
      assert_equal true, group.fetch("absent")
      assert_equal "reaped", keeper.fetch("state")
      assert_equal keeper.fetch("pid"), group.fetch("id")
    end
    if keeper.fetch("state") == "not_attempted"
      assert_equal({"state" => "not_attempted"}, validator)
      assert_equal({"state" => "not_created"}, group)
    end
    if validator.fetch("state") == "not_attempted"
      assert_equal "failed", frame.fetch("outcome")
    elsif frame.fetch("outcome") != "failed"
      assert_equal "retired", group.fetch("state")
      assert_equal ["exit", 0], keeper.values_at("status_kind", "status_code")
      assert_equal "exit", validator.fetch("status_kind")
      if frame.fetch("outcome") == "ok"
        assert_equal 0, validator.fetch("status_code")
      else
        assert_operator validator.fetch("status_code"), :>, 0
      end
    end
  end

  def assert_native_observation(observation, finality:)
    assert_instance_of Hash, observation
    assert_equal 1, observation.fetch("version")
    assert observation.fetch("hooksRestored"), observation.inspect
    assert_empty observation.fetch("observerErrors"), observation.inspect
    assert_equal %w[capture helper spawn], observation.fetch("sourceOrigins").keys.sort
    observation.fetch("sourceOrigins").each_value do |origin|
      assert_equal %w[line path sha256], origin.keys.sort
      assert_equal File.absolute_path(origin.fetch("path")), origin.fetch("path")
      assert_operator origin.fetch("line"), :>, 0
      assert_match(/\A[0-9a-f]{64}\z/, origin.fetch("sha256"))
    end
    assert_equal finality == :finalized, observation.fetch("finalized")
    assert_equal finality == :no_producers, observation.fetch("noProducers")
    assert_equal finality == :unknown, observation.fetch("unknown")
    return if finality == :unknown

    assert observation.fetch("settled"), observation.inspect
    observation.fetch("tasks").each do |task|
      refute task.fetch("unresolved"), task.inspect
      if task.fetch("state") == "not_constructed"
        assert_equal "creator", task.fetch("role")
        refute task.fetch("startAttempted"), task.inspect
        assert task.fetch("creationGateClosed"), task.inspect
        assert task.fetch("actualScopeSettled"), task.inspect
        next
      end
      %w[actualConstructionObserved launchRetired actualLaunchClosureObserved].each do |name|
        assert task.fetch(name), task.inspect
      end
      if task.fetch("startAttempted")
        assert_equal "attempted", task.fetch("state")
        assert_instance_of Integer, task.fetch("thread")
        %w[finished joined actualJoinObserved].each { |name| assert task.fetch(name), task.inspect }
      else
        assert_equal "not_started", task.fetch("state")
        assert_nil task.fetch("thread")
        refute task.fetch("joined"), task.inspect
        refute task.fetch("actualJoinObserved"), task.inspect
      end
    end
    observation.fetch("leases").each do |lease|
      assert_nil lease.fetch("closeError"), lease.inspect
      if lease.fetch("noIOAcquired").equal?(true)
        assert_equal "not_acquired", lease.fetch("state")
        refute lease.fetch("closed"), lease.inspect
        refute lease.fetch("actualCloseObserved"), lease.inspect
      else
        assert_equal "closed", lease.fetch("state")
        assert lease.fetch("closed"), lease.inspect
        assert lease.fetch("actualCloseObserved"), lease.inspect
      end
    end
    if finality == :no_producers
      assert_equal({"state" => "not_attempted"}, observation.fetch("custodian"))
      assert_nil observation.fetch("custodianSpawn")
      assert_nil observation.fetch("final")
    else
      assert_equal %w[capture creator], observation.fetch("tasks").map { |task| task.fetch("role") }.sort
      assert observation.fetch("tasks").all? { |task| task.fetch("startAttempted") }
      %w[productionFinality statusValid statusDecodedEOF cleanupErrorsEmpty originalWaitObserved
        tasksJoined leasesClosed allActualEOFObserved captureSettled captureFinished captureJoined captureActualJoinObserved
        creatorSettled creatorFinished creatorJoined creatorActualJoinObserved stdoutEOF stdoutActualEOFObserved
        stderrEOF stderrActualEOFObserved statusEOF statusActualEOFObserved].each do |key|
        assert_equal true, observation.fetch(key), key
      end
      assert_equal false, observation.fetch("retainedUnknown")
      if observation.fetch("final").fetch("group").fetch("state") == "retired"
        assert_equal true, observation.fetch("groupAbsent")
      else
        refute observation.key?("groupAbsent"), "absence of a group is not a group-absence observation"
      end
      assert_child_terminal(observation.fetch("custodian"), allow_no_attempt: false)
      expected_exit = observation.fetch("final").fetch("outcome") == "failed" ? 2 : 0
      assert_equal ["exit", expected_exit], observation.fetch("custodian").values_at("status_kind", "status_code")
      refute_nil observation.fetch("custodianSpawn")
      %w[stdoutEOF stderrEOF statusEOF actualEOFObserved].each do |name|
        assert_equal true, observation.fetch("streams").fetch(name)
      end
      assert_final_cleanup(observation.fetch("final"))
    end
  end

  def assert_validator_killed(observation)
    validator = observation.fetch("final").fetch("validator")
    assert_child_terminal(validator, allow_no_attempt: false)
    assert_equal ["signal", Signal.list.fetch("KILL")], validator.values_at("status_kind", "status_code")
  end

  def assert_late_final_deadline_choreography
    # Capture the ACTUAL adapter hook registration, but never install a native
    # observer. Only the parent install method has a restoring inert seam. The
    # modeled slot/caller are not tasks, wait receipts or ownership evidence.
    helper = MobileReleaseKit::NativeUploadProcess
    native = MobileReleaseKit::NativeUploadValidation
    parent = UploadProcessFixture::NativeSetupDriver::Observation
    before_install = parent.instance_method(:install)
    before_observer = UploadProcessFixture::CaptureObservation.current
    install_seam = UploadProcessFixture::CaptureObservation::Hooks.new
    begin
      install_seam.wrap(parent, :install) { nil }
      exercise = lambda do |mode: "real-deadline", mutate: nil, finish: :primary, error: IOError.new("genuine caller error"), invalid: false|
        run_cutoff, hard_cutoff = 1_000_000_000, 1_025_000_000
        state = {now: run_cutoff, alive: true, retired: false, unknown: false, cleanup: []}
        record = helper::TaskSlot.const_get(:FailureRecord, false).new
        publish = record.method(:record) # Used only by the modeled original caller, never by the hook.
        record_error = ->(value) { publish.call(error: value, hard_cleanup_deadline_ns: hard_cutoff, cleanup_deadline_ns: nil) }
        caller = Object.new
        caller.define_singleton_method(:alive?) { state.fetch(:alive) }
        slot = Struct.new(:thread, :caller, :run_deadline_ns, :hard_cleanup_deadline_ns).
          new(Thread.current, caller, run_cutoff, hard_cutoff)
        slot.define_singleton_method(:failure_record) { record }
        slot.define_singleton_method(:launch_retired?) { state.fetch(:retired) }
        session = Struct.new(:capture_slot, :ready, :reserved).new(slot, {}, {})
        session.define_singleton_method(:primary_error) { record.first_error }
        session.define_singleton_method(:retained_unknown?) { state.fetch(:unknown) }
        session.define_singleton_method(:cleanup_errors) { state.fetch(:cleanup) }
        deny = ->(*, **) { flunk "late FINAL helper attempted mutation, construction, joining or masking" }
        %i[cancelled? cleanup_deadline_ns cancel! join_until start close_launch! record_cleanup_error].each do |name|
          slot.define_singleton_method(name, &deny)
        end
        %i[timeout_error task_failure caller_failure receive_frame execute].each { |name| session.define_singleton_method(name, &deny) }
        driver = UploadProcessFixture::AdapterDriver.new(@root, "ios", mode, {}, deadline_ns: 40_000_000_000)
        observer = UploadProcessFixture::AdapterDriver::Observation.new(driver, native: native, root: Object.new)
        driver.instance_variable_set(:@observation, observer)
        observer.instance_variable_set(:@session, session)
        driver.observed.merge!("ready" => true, "blockedDataWaits" => 1, "nativeRunDeadlineNs" => run_cutoff)
        registrations = {}
        hooks = Object.new
        hooks.define_singleton_method(:wrap) { |target, name, &body| registrations[[target, name]] = body }
        observer.instance_variable_set(:@hooks, hooks)
        observer.instance_variable_set(:@helper, helper)
        observer.install
        hook = registrations.fetch([native.const_get(:CaptureSession, false), :validate_final])
        frame = {"type" => "FINAL", "outcome" => "failed", "cleanup" => "confirmed"}
        context = {state: state, slot: slot, session: session, observer: observer, driver: driver,
                   frame: frame, publish: record_error, error: error}
        events, sleeps, validated = [], [], []
        result, validation_error = Object.new, helper::ProtocolError.new
        value = nil
        UploadProcessFixture.stub(:clock_ns, -> { state.fetch(:now) }) do
          helper.stub(:monotonic_ns, -> { state.fetch(:now) }) do
            mutate.call(context) if mutate
            original_endpoints = [slot.run_deadline_ns, slot.hard_cleanup_deadline_ns]
            original_frame = frame.dup
            original = lambda do |actual_frame|
              validated << actual_frame
              events << :validation
              raise validation_error if invalid
              result
            end
            actual_helper = driver.method(:after_validated_final)
            after_validation = lambda do |actual_session, actual_frame|
              assert_equal [:validation], events
              assert_same session, actual_session
              assert_same frame, actual_frame
              events << :helper
              actual_helper.call(actual_session, actual_frame)
            end
            pause = lambda do |seconds|
              assert driver.instance_variable_get(:@late_final_yielded), "one-shot must precede yielding"
              assert_operator seconds, :>, 0
              assert_operator seconds, :<=, 0.01
              assert_operator seconds, :<=, (hard_cutoff - state.fetch(:now)) / 1_000_000_000.0
              sleeps << seconds
              assert_operator sleeps.length, :<=, 3 # A renewed cutoff cannot hang this inert regression.
              state[:now] += (seconds * 1_000_000_000).round
              case finish
              when :primary then record_error.call(error)
              when :cancelled then record_error.call(nil)
              when :unknown then state[:unknown] = true
              when :retired then state[:retired] = true
              when :cleanup then state[:cleanup] << error
              when :dead_caller then state[:alive] = false
              when :hard_expiry # Let the original bound expire without publishing an error.
              else flunk "unknown late FINAL test finish"
              end
            end
            record.stub(:record, deny) do
              helper::TaskSlot.stub(:new, deny) do
                helper::LifecycleError.stub(:new, deny) do
                  MobileReleaseKit::ContractError.stub(:new, deny) do
                    Thread.stub(:handle_interrupt, deny) do
                      driver.stub(:sleep, pause) do
                        driver.stub(:after_validated_final, after_validation) do
                          if invalid
                            actual = assert_raises(helper::ProtocolError) { hook.call(original, session, [frame], {}, nil) }
                            assert_same validation_error, actual
                          else
                            value = hook.call(original, session, [frame], {}, nil)
                            assert_same result, value
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
            assert_equal original_endpoints, [slot.run_deadline_ns, slot.hard_cleanup_deadline_ns]
            assert_equal original_frame, frame
          end
        end
        assert_equal [frame], validated
        assert_same frame, validated.first
        assert_equal invalid ? [:validation] : %i[validation helper], events
        {sleeps: sleeps, record: record, driver: driver, error: error}
      end

      %w[real-deadline real-deadline-slow-cleanup].each do |mode|
        [IOError.new("first caller IO error"), Interrupt.new("first caller interruption"), SystemExit.new(23)].each do |error|
          value = exercise.call(mode: mode, error: error)
          assert_equal [0.01], value.fetch(:sleeps)
          assert_same error, value.fetch(:record).first_error # No timeout-type or message matching.
        end
      end
      %i[cancelled unknown retired cleanup dead_caller hard_expiry].each do |finish|
        value = exercise.call(finish: finish)
        assert_equal finish == :hard_expiry ? [0.01, 0.01, 0.005] : [0.01], value.fetch(:sleeps)
        assert_nil value.fetch(:record).first_error
        assert_equal finish == :cancelled, value.fetch(:record).failed?
      end
      assert_empty exercise.call(invalid: true).fetch(:sleeps)
      %w[immediate-deadline immediate-deadline-slow-cleanup no-deadline inherited].each do |mode|
        assert_empty exercise.call(mode: mode).fetch(:sleeps)
      end
      bypasses = [
        ->(c) { c[:state][:now] -= 1 }, ->(c) { c[:state][:now] = c[:slot].hard_cleanup_deadline_ns },
        ->(c) { c[:observer].instance_variable_set(:@session, Object.new) },
        ->(c) { c[:slot].thread = Object.new }, ->(c) { c[:slot].caller = Thread.current },
        ->(c) { c[:state][:alive] = false }, ->(c) { c[:session].ready = nil }, ->(c) { c[:session].reserved = nil },
        ->(c) { c[:driver].observed["ready"] = false }, ->(c) { c[:driver].observed["blockedDataWaits"] = 0 },
        ->(c) { c[:frame]["type"] = "STATUS" }, ->(c) { c[:frame]["outcome"] = "rejected" },
        ->(c) { c[:frame]["cleanup"] = "unknown" }, ->(c) { c[:publish].call(c[:error]) },
        ->(c) { c[:publish].call(nil) }, ->(c) { c[:state][:retired] = true }, ->(c) { c[:state][:unknown] = true },
        ->(c) { c[:state][:cleanup] << c[:error] }, ->(c) { c[:slot].run_deadline_ns = c[:slot].run_deadline_ns.to_f },
        ->(c) { c[:slot].hard_cleanup_deadline_ns = c[:slot].hard_cleanup_deadline_ns.to_f },
        ->(c) { c[:driver].observed["nativeRunDeadlineNs"] -= 1 },
        ->(c) { c[:driver].instance_variable_set(:@late_final_yielded, true) },
      ]
      bypasses.each { |mutate| assert_empty exercise.call(mutate: mutate).fetch(:sleeps) }
    ensure
      assert_empty install_seam.restore
      assert_equal before_install, parent.instance_method(:install)
      assert_same before_observer, UploadProcessFixture::CaptureObservation.current
    end
  end

  def assert_slow_cleanup_choreography
    # Real hook registrations and their ordinary Ruby bodies, but only inert
    # session/task operands. No native observer, thread, IO, signal or wait is
    # installed. The sole parent-install seam is reversed below.
    helper = MobileReleaseKit::NativeUploadProcess
    native = MobileReleaseKit::NativeUploadValidation
    parent = UploadProcessFixture::NativeSetupDriver::Observation
    before_install = parent.instance_method(:install)
    before_observer = UploadProcessFixture::CaptureObservation.current
    install_seam = UploadProcessFixture::CaptureObservation::Hooks.new
    begin
      install_seam.wrap(parent, :install) { nil }
      model = lambda do |mode = "real-deadline-slow-cleanup"|
        primary = MobileReleaseKit::ContractError.new("original modeled timeout")
        state = {now: 2_000_000_000, cutoff: 7_000_000_000, primary: primary}
        slot = Struct.new(:thread, :run_deadline_ns, :hard_cleanup_deadline_ns).
          new(Thread.current, 2_000_000_000, 7_000_000_000)
        session = Struct.new(:capture_slot, :ready, :reserved).new(slot, {}, {})
        session.define_singleton_method(:primary_error) { state.fetch(:primary) }
        session.define_singleton_method(:cleanup_deadline_ns) { state.fetch(:cutoff) }
        driver = UploadProcessFixture::AdapterDriver.new(@root, "ios", mode, {}, deadline_ns: 40_000_000_000)
        observer = UploadProcessFixture::AdapterDriver::Observation.new(driver, native: native, root: Object.new)
        driver.instance_variable_set(:@observation, observer)
        observer.instance_variable_set(:@session, session)
        driver.observed.merge!("ready" => true, "blockedDataWaits" => 1, "nativeRunDeadlineNs" => slot.run_deadline_ns)
        selected = [primary, slot.run_deadline_ns]
        driver.instance_variable_set(:@selected_timeout, selected)
        driver.instance_variable_set(:@timeout_objects, [selected])
        registrations = {}
        hooks = Object.new
        hooks.define_singleton_method(:wrap) { |target, name, &body| registrations[[target, name]] = body }
        observer.instance_variable_set(:@hooks, hooks)
        observer.instance_variable_set(:@helper, helper)
        observer.install
        target = native.const_get(:CaptureSession, false)
        invoke = lambda do |name, &original|
          registrations.fetch([target, name]).call(original, session, [], {}, nil)
        end
        {state: state, slot: slot, session: session, driver: driver, observer: observer, invoke: invoke,
         primary: primary, selected: selected, registrations: registrations}
      end
      observe = ->(m) { m.fetch(:invoke).call(:observe_cancellation) { :observed } }
      run = ->(m, &body) { m.fetch(:invoke).call(:run, &body) }

      m = model.call
      seen = []
      original = -> { seen << :original; :observed }
      run.call(m) do
        hook = m.fetch(:registrations).fetch([native.const_get(:CaptureSession, false), :observe_cancellation])
        actual = assert_raises(MobileReleaseKit::ContractError) { hook.call(original, m.fetch(:session), [], {}, nil) }
        assert_same m.fetch(:primary), actual
        assert_equal [:original], seen
        assert m.fetch(:observer).snapshot_additions.fetch("slowCleanup").fetch("handoffPerformed")
        assert_equal :observed, observe.call(m) # One-shot; no second delivery/construction.
      end
      assert_equal 0, m.fetch(:observer).instance_variable_get(:@slow_body_depth)

      bypasses = [
        ->(c) { c[:observer].instance_variable_set(:@session, Object.new) },
        ->(c) { c[:slot].thread = Object.new }, ->(c) { c[:session].ready = nil }, ->(c) { c[:session].reserved = nil },
        ->(c) { c[:driver].observed["ready"] = false }, ->(c) { c[:driver].observed["blockedDataWaits"] = 0 },
        ->(c) { c[:driver].observed["blockedDataWaits"] = true }, ->(c) { c[:slot].run_deadline_ns = 2.0 },
        ->(c) { c[:driver].observed["nativeRunDeadlineNs"] += 1 }, ->(c) { c[:selected][1] -= 1 },
        ->(c) { c[:selected][1] = 2.0 }, ->(c) { c[:state][:primary] = IOError.new("earlier original error") },
        ->(c) { c[:driver].instance_variable_set(:@selected_timeout, nil) },
        ->(c) { c[:driver].instance_variable_set(:@timeout_objects, [c[:selected].dup]) },
        ->(c) { c[:observer].instance_variable_set(:@slow_cleanup_entered, true) },
      ]
      bypasses.each do |mutate|
        m = model.call
        mutate.call(m)
        run.call(m) { assert_equal :observed, observe.call(m) }
        refute m.fetch(:observer).instance_variable_get(:@slow_handoff_performed)
      end
      %w[real-deadline immediate-deadline immediate-deadline-slow-cleanup no-deadline inherited].each do |mode|
        m = model.call(mode)
        run.call(m) { assert_equal :observed, observe.call(m) }
        refute m.fetch(:observer).instance_variable_get(:@slow_handoff_performed)
        assert_equal({"capturePrimary" => %w[invalid invalid], "readinessStage" => "not-entered"}, m.fetch(:observer).snapshot_additions) unless mode.end_with?("-slow-cleanup")
      end
      m = model.call
      assert_equal :observed, observe.call(m) # Not in the original run-body scope.
      refute m.fetch(:observer).instance_variable_get(:@slow_handoff_performed)
      run.call(m) do
        run.call(m) { assert_equal :observed, observe.call(m) } # Nested run is not the original body.
        assert_same m.fetch(:primary), assert_raises(MobileReleaseKit::ContractError) { observe.call(m) }
      end

      [nil, IOError.new("nested write failure")].each do |write_error|
        m = model.call
        run.call(m) do
          nested = lambda do
            m.fetch(:invoke).call(:write_control) do
              m.fetch(:invoke).call(:write_control) do
                assert_equal :observed, observe.call(m)
                refute m.fetch(:observer).instance_variable_get(:@slow_handoff_performed)
                raise write_error if write_error
              end
            end
          end
          if write_error
            assert_same write_error, assert_raises(IOError) { nested.call }
          else
            nested.call
          end
          assert_equal 0, m.fetch(:observer).instance_variable_get(:@slow_write_depth)
          assert_same m.fetch(:primary), assert_raises(MobileReleaseKit::ContractError) { observe.call(m) }
        end
      end
      m = model.call
      run.call(m) do
        error = IOError.new("original observation failed before handoff")
        actual = assert_raises(IOError) { m.fetch(:invoke).call(:observe_cancellation) { raise error } }
        assert_same error, actual
        refute m.fetch(:observer).instance_variable_get(:@slow_handoff_performed)
        assert_same m.fetch(:primary), assert_raises(MobileReleaseKit::ContractError) { observe.call(m) }
      end

      # Both legitimate real-slow paths reach the ORIGINAL body ensure: the
      # direct handoff above, or natural loop completion after its already
      # recorded timeout, without another direct observation. These inert
      # models retain that timeout; neither creates a replacement or a receipt.
      [false, true].product([10_000_000, 1_500_000_000, 4_000_000_000, 4_400_000_000]).each do |handoff, cleanup_ns|
        m = model.call
        driver, observer, state = m.values_at(:driver, :observer, :state)
        cutoff, primary, selected = state.values_at(:cutoff, :primary) + [m.fetch(:selected)]
        entry_ns = state.fetch(:now)
        remaining_ns = [4_000_000_000 - cleanup_ns, 0].max
        cleanups, sleeps = [], []
        sleeper = lambda do |seconds|
          sleeps << seconds
          assert_equal [:original], cleanups # Native cleanup is never held behind padding.
          assert_equal remaining_ns.fdiv(1_000_000_000), seconds
          state[:now] += remaining_ns
        end
        returned = nil
        UploadProcessFixture.stub(:clock_ns, -> { state.fetch(:now) }) do
          observer.stub(:sleep, sleeper) do
            returned = run.call(m) do
              begin
                if handoff
                  observe.call(m)
                  flunk "eligible original handoff did not transfer its timeout"
                end
                :original_body_returned
              rescue MobileReleaseKit::ContractError => error
                assert handoff
                assert_same primary, error
                :original_timeout_handled
              ensure
                m.fetch(:invoke).call(:finish_task_ownership) do
                  cleanups << :original
                  assert_empty sleeps
                  assert_equal entry_ns, state.fetch(:now)
                  assert_equal :observed, observe.call(m) # Entered cleanup cannot supply a missing handoff.
                  state[:now] += cleanup_ns
                  :cleaned
                end
              end
            end
          end
        end
        assert_equal handoff ? :original_timeout_handled : :original_body_returned, returned
        assert_equal remaining_ns.positive? ? [remaining_ns.fdiv(1_000_000_000)] : [], sleeps
        assert_equal [:original], cleanups
        assert_equal cutoff, state.fetch(:cutoff)
        assert_same primary, state.fetch(:primary)
        assert_same selected, driver.original_timeout_record(m.fetch(:session))
        assert_equal [selected], driver.instance_variable_get(:@timeout_objects)
        assert_equal 0, observer.instance_variable_get(:@slow_body_depth)
        snapshot = observer.snapshot_additions
        slow = snapshot.fetch("slowCleanup")
        assert_equal handoff, slow.fetch("handoffPerformed")
        assert_equal entry_ns, slow.fetch("delayStartedNs")
        assert_equal entry_ns + cleanup_ns, slow.fetch("originalCleanupFinishedNs")
        assert_equal entry_ns + [cleanup_ns, 4_000_000_000].max, slow.fetch("delayFinishedNs")
        assert_equal [cleanup_ns, 4_000_000_000].max.fdiv(1_000_000_000), slow.fetch("slowCleanupSeconds")
        assert_nil driver.validate_slow_cleanup_snapshot!(snapshot)
        next unless cleanup_ns == 10_000_000 # Strict snapshot mutations need no equivalent repeats.
        malformed = [slow.reject { |key, _| key == "handoffPerformed" }]
        [nil, 0, "false"].each { |value| malformed << slow.merge("handoffPerformed" => value) }
        {"delayFailed" => true, "delayFinished" => false, "originalCleanupCalled" => false,
         "slowCleanupSeconds" => 3.99, "originalCleanupFinishedNs" => cutoff, "delayFinishedNs" => cutoff}.each do |key, value|
          malformed << slow.merge(key => value)
        end
        %w[delayStartedNs originalCleanupFinishedNs delayFinishedNs originalCleanupCutoffNs].each do |key|
          malformed << slow.reject { |name, _| name == key }
          [nil, 1.0, true, 0].each { |value| malformed << slow.merge(key => value) }
        end
        malformed.concat([
          slow.merge("originalCleanupFinishedNs" => entry_ns - 1),
          slow.merge("originalCleanupFinishedNs" => slow.fetch("delayFinishedNs") + 1),
          slow.merge("delayFinishedNs" => entry_ns + 3_999_999_999),
          slow.merge("slowCleanupSeconds" => 99),
        ])
        malformed.each do |facts|
          assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!("slowCleanup" => facts) }
        end
        assert_equal handoff, slow.fetch("handoffPerformed") # No domain correction rewrites the original snapshot.
      end

      # Failure while inspecting the context, even a failing recorder, must
      # still call the original cleanup once and preserve known call facts.
      [false, true].each do |recording_fault|
        m = model.call
        driver, observer = m.values_at(:driver, :observer)
        failure, recording_failure = IOError.new("context observation failure"), IOError.new("context recorder failure")
        calls = []
        invoke = lambda do
          observer.stub(:slow_capture_task?, ->(_object) { raise failure }) do
            actual = assert_raises(IOError) do
              m.fetch(:invoke).call(:finish_task_ownership) { calls << :original; :cleaned }
            end
            assert_same recording_fault ? recording_failure : failure, actual
          end
        end
        if recording_fault
          observer.stub(:remember_slow_failure, ->(_error) { raise recording_failure }) { invoke.call }
        else
          invoke.call
        end
        assert_equal [:original], calls
        slow = observer.snapshot_additions.fetch("slowCleanup")
        assert slow.fetch("delayFailed") && slow.fetch("originalCleanupCalled") && slow.fetch("originalCleanupFinished")
        refute slow.fetch("delayEntered")
        refute slow.key?("slowCleanupSeconds")
        assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!(observer.snapshot_additions) }
      end

      # Each mode uses fresh inert state. Clock/sleep failures cannot suppress
      # the original cleanup call, even when the failure recorder itself raises.
      cases = %i[complete guard cleanup_cutoff first_clock cleanup_clock padding_clock record_clock delay_clock
        sleep sleep_after_four short_sleep oversleep late_native late_tail recording recording_late guard_recording
        failure_recording original_cleanup original_cleanup_clock original_cleanup_recording
        original_cleanup_failure_recording nested_entry]
      cases.each do |fault|
        m = model.call("immediate-deadline-slow-cleanup")
        driver, observer, state = m.values_at(:driver, :observer, :state)
        state[:cutoff] = state[:now] + 4_250_000_000 if %i[guard guard_recording].include?(fault)
        original_cutoff = state[:cutoff]
        original_fails = fault.to_s.start_with?("original_cleanup")
        recorder_fails = %i[failure_recording guard_recording original_cleanup_failure_recording].include?(fault)
        clock_calls, sleeps, cleanups = 0, [], []
        failure, recording_failure, cleanup_failure = IOError.new("delay failure"), IOError.new("recording failure"), IOError.new("original cleanup failure")
        m.fetch(:session).define_singleton_method(:cleanup_deadline_ns) { raise failure } if fault == :cleanup_cutoff
        now = lambda do
          clock_calls += 1
          fail_at = {first_clock: 1, cleanup_clock: 2, padding_clock: 3, record_clock: 4, delay_clock: 5,
            original_cleanup_clock: 2, original_cleanup_failure_recording: 2}[fault]
          raise failure if fail_at == clock_calls
          state[:now] = original_cutoff if fault == :late_tail && clock_calls == 5
          state.fetch(:now)
        end
        sleeper = lambda do |seconds|
          sleeps << seconds
          assert_equal [:original], cleanups
          assert_equal 3.99, seconds # Original cleanup has already consumed 10ms.
          raise failure if %i[sleep failure_recording].include?(fault)
          if fault == :nested_entry
            assert_raises(UploadProcessFixture::Failure) do
              m.fetch(:invoke).call(:finish_task_ownership) { cleanups << :unexpected_nested_cleanup }
            end
          end
          state[:now] += if fault == :oversleep then 4_990_000_000
                        elsif fault == :short_sleep then 3_989_999_999
                        else 3_990_000_000
                        end
          raise failure if fault == :sleep_after_four
        end
        original = lambda do
          cleanups << :original
          assert_empty sleeps
          assert observer.instance_variable_get(:@slow_cleanup_entered)
          assert_equal :observed, observe.call(m) # Entered cleanup cannot consume the handoff.
          state[:now] += fault == :late_native ? 5_000_000_000 : 10_000_000
          raise cleanup_failure if original_fails
          :cleaned
        end
        action = -> { run.call(m) { m.fetch(:invoke).call(:finish_task_ownership, &original) } }
        written = driver.observed.method(:[]=)
        writer = lambda do |key, value|
          if key == "cleanupSeconds"
            raise recording_failure if %i[recording original_cleanup_recording].include?(fault)
            state[:now] = original_cutoff if fault == :recording_late
          end
          written.call(key, value)
        end
        perform = lambda do
          if original_fails
            assert_same cleanup_failure, assert_raises(IOError) { action.call }
          elsif recorder_fails
            assert_same recording_failure, assert_raises(IOError) { action.call }
          else
            assert_equal :cleaned, action.call
          end
        end
        UploadProcessFixture.stub(:clock_ns, now) do
          observer.stub(:sleep, sleeper) do
            driver.observed.stub(:[]=, writer) do
              if recorder_fails
                observer.stub(:remember_slow_failure, ->(_error) { raise recording_failure }) { perform.call }
              else
                perform.call
              end
            end
          end
        end
        assert_equal [:original], cleanups
        assert_equal original_cutoff, state.fetch(:cutoff)
        assert_equal 0, observer.instance_variable_get(:@slow_body_depth)
        assert_same m.fetch(:primary), state.fetch(:primary)
        snapshot = observer.snapshot_additions
        slow = snapshot.fetch("slowCleanup")
        assert snapshot.frozen? && slow.frozen?
        assert slow.fetch("delayEntered") && slow.fetch("originalCleanupCalled")
        assert_equal !original_fails, slow.fetch("originalCleanupFinished")
        assert_equal fault != :complete, slow.fetch("delayFailed")
        assert_equal fault == :complete, slow.fetch("delayFinished")
        assert_equal [], sleeps if original_fails || %i[guard guard_recording cleanup_cutoff first_clock cleanup_clock padding_clock late_native].include?(fault)
        refute slow.key?("slowCleanupSeconds") if %i[cleanup_cutoff first_clock delay_clock].include?(fault)
        assert_operator slow.fetch("slowCleanupSeconds"), :>=, 4 if fault == :sleep_after_four
        if fault == :complete
          assert_nil driver.validate_slow_cleanup_snapshot!(snapshot)
          [true, nil, 0, "false"].each do |handoff|
            changed = snapshot.merge("slowCleanup" => slow.merge("handoffPerformed" => handoff))
            assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!(changed) }
          end
          missing = snapshot.merge("slowCleanup" => slow.reject { |key, _| key == "handoffPerformed" })
          assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!(missing) }
        else
          assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!(snapshot) }
        end
        # Later task progress cannot repair the original immutable failure facts.
        old = slow.dup
        observer.instance_variable_set(:@slow_delay_failed, false)
        observer.instance_variable_set(:@slow_delay_finished, true)
        observer.instance_variable_set(:@slow_original_cleanup_finished, true)
        assert_equal old, slow
        assert_raises(UploadProcessFixture::Failure) { driver.validate_slow_cleanup_snapshot!(snapshot) } unless fault == :complete
        # A repeated wrapper call may fail, but cannot repeat the original
        # cleanup or replace the already captured facts above.
        assert_raises(UploadProcessFixture::Failure) do
          m.fetch(:invoke).call(:finish_task_ownership) { cleanups << :unexpected_repeat_cleanup }
        end
        assert_equal [:original], cleanups
        assert_equal old, slow
      end
    ensure
      assert_empty install_seam.restore
      assert_equal before_install, parent.instance_method(:install)
      assert_same before_observer, UploadProcessFixture::CaptureObservation.current
    end
  end

  def with_acquisition_veto
    attempts = {spawn: 0, native_create: 0, task: 0, pipe: 0, directory: 0}
    deny = lambda do |kind|
      lambda do |*, **|
        attempts[kind] += 1
        raise "invalid native fixture attempted #{kind} acquisition"
      end
    end
    # Process.spawn alone no longer intercepts the production creation path.
    # Deny actual native creation and tasks/IO before they can acquire custody.
    Process.stub(:spawn, deny.call(:spawn)) do
      MobileReleaseKit::NativeProcessSpawn.stub(:create, deny.call(:native_create)) do
        Thread.stub(:new, deny.call(:task)) do
          IO.stub(:pipe, deny.call(:pipe)) do
            Dir.stub(:mktmpdir, deny.call(:directory)) { yield }
          end
        end
      end
    end
    assert_equal({spawn: 0, native_create: 0, task: 0, pipe: 0, directory: 0}, attempts)
  end

  def proof_source_snapshot
    root = File.expand_path("../..", __dir__)
    PROOF_FILES.to_h do |name|
      path = File.join(root, name)
      raise "proof source is not a regular file" unless File.lstat(path).file?
      File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
        before = file.stat
        raise "proof source is not a bounded regular file" unless before.file? && before.size <= 1_048_576
        bytes = file.read(1_048_577)
        identity = ->(value) { [value.dev, value.ino, value.mode, value.size, value.mtime, value.ctime] }
        unless bytes && bytes.bytesize <= 1_048_576 && bytes.bytesize == before.size && identity.call(file.stat) == identity.call(before)
          raise "oversized or changed proof source"
        end
        [name, {"bytes" => bytes, "mode" => before.mode & 0o777, "sha256" => Digest::SHA256.hexdigest(bytes)}]
      end
    end
  end

  def assert_proof_inventory(root, snapshot)
    pending, files, directories = [root], [], []
    until pending.empty?
      directory = pending.pop
      Dir.children(directory).sort.each do |name|
        path = File.join(directory, name)
        value = File.lstat(path)
        relative = path.delete_prefix("#{root}/")
        if value.directory?
          directories << relative
          pending << path
        else
          assert value.file?, "proof copy contains a non-regular entry"
          files << relative
          expected = snapshot.fetch(relative)
          assert_equal expected.fetch("mode"), value.mode & 0o777
          assert_equal expected.fetch("bytes").bytesize, value.size
          assert_equal expected.fetch("sha256"), Digest::SHA256.file(path).hexdigest
          assert_equal expected.fetch("bytes"), File.binread(path, expected.fetch("bytes").bytesize + 1)
        end
      end
    end
    assert_equal PROOF_FILES.sort, files.sort
    assert_equal %w[fastlane tests tests/workflow], directories.sort
  end

  def make_proof_copy(label, snapshot)
    UploadProcessFixture.assert_domain_reusable!
    root = Dir.mktmpdir("#{label}-", @root)
    snapshot.each do |name, item|
      path = File.join(root, name)
      FileUtils.mkdir_p(File.dirname(path))
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, item.fetch("mode")) { |file| file.write(item.fetch("bytes")) }
      File.chmod(item.fetch("mode"), path)
    end
    assert_proof_inventory(root, snapshot)
    root
  end

  def with_proof_copies(label, anchor)
    UploadProcessFixture.assert_domain_reusable!
    @retain_raw_evidence = true
    UploadProcessFixture.lifetime do |scope|
      original = proof_source_snapshot
      interpreter = dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024)
      fixture = PROOF_FILES.first
      source = original.fetch(fixture).fetch("bytes")
      assert_equal 1, source.scan(anchor).length, "proof mutation anchor changed"
      changed = source.sub(anchor, "")
      mutant = original.merge(fixture => original.fetch(fixture).merge("bytes" => changed, "sha256" => Digest::SHA256.hexdigest(changed)))
      snapshots = {"pristine" => original, "mutant" => mutant}
      copies = snapshots.to_h { |kind, snapshot| [kind, make_proof_copy("#{label}-#{kind}", snapshot)] }
      manifest = snapshots.transform_values do |snapshot|
        snapshot.transform_values { |item| {"sha256" => item.fetch("sha256"), "mode" => item.fetch("mode"), "size" => item.fetch("bytes").bytesize} }
      end
      UploadProcessFixture.atomic_json(File.join(@root, "source-copies.json"),
                                       {"case" => label, "copies" => manifest, "copyRoots" => copies,
                                        "selectedInterpreter" => RbConfig.ruby, "interpreter" => interpreter})
      scope.active do
        yield copies
        copies.each { |kind, root| assert_proof_inventory(root, snapshots.fetch(kind)) }
        assert_equal original, proof_source_snapshot
        assert_equal interpreter, dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024)
      end
    end
    finish_raw_proof_copies! # Includes successful outer lifetime finalization and no unresolved raw scratch.
  end

  def new_raw_case(label, mode)
    UploadProcessFixture.assert_domain_reusable!
    directory = Dir.mktmpdir("#{label}-", @root)
    UploadProcessFixture.atomic_json(File.join(directory, "input.json"), {"platform" => "native", "parameters" => {}, "mode" => mode})
    directory
  end

  def bounded_error(error)
    return nil unless error
    {"class" => error.class.name, "kind" => error.respond_to?(:kind) ? error.kind : nil,
     "message" => error.message.b.byteslice(0, 512).force_encoding("UTF-8").scrub}
  end

  def dispatch_file_identity(path, limit:)
    raise "raw proof dispatch path is not absolute" unless path == File.absolute_path(path)
    File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
      before = file.stat
      raise "raw proof dispatch input is not a bounded regular file" unless before.file? && before.size <= limit
      identity = ->(value) { [value.dev, value.ino, value.mode, value.size, value.mtime, value.ctime] }
      digest, remaining = Digest::SHA256.new, before.size
      while remaining.positive?
        chunk = file.read([remaining, 65_536].min)
        raise "raw proof dispatch input ended early" unless chunk && !chunk.empty?
        digest.update(chunk)
        remaining -= chunk.bytesize
      end
      raise "raw proof dispatch input changed while read" unless identity.call(before) == identity.call(file.stat)
      {"path" => path, "realpath" => File.realpath(path), "mode" => before.mode & 0o7777,
       "size" => before.size, "sha256" => digest.hexdigest, "device" => before.dev, "inode" => before.ino,
       "mtimeNs" => before.mtime.to_i * 1_000_000_000 + before.mtime.nsec,
       "ctimeNs" => before.ctime.to_i * 1_000_000_000 + before.ctime.nsec}
    end
  end

  def raw_dispatch(copy, directory, fixture, literal, isolate_close: false)
    bootstrap_files = %w[tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb
                         fastlane/native_process_spawn.rb fastlane/native_upload_process.rb]
    source_root = File.expand_path("../..", __dir__)
    minitest = isolate_close ? minitest_library_snapshot : nil
    {"argv" => isolate_close ? isolated_collector_argv(directory, minitest) : [RbConfig.ruby, fixture, "driver", directory], "cwd" => Dir.pwd,
     "environment" => UploadProcessFixture.driver_environment(directory),
     "options" => {"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
                   "stdout" => File.join(directory, "driver.stdout"), "stderr" => File.join(directory, "driver.stderr")},
     "copyRoot" => copy, "literalCase" => literal, "isolatedControl" => isolate_close, "minitest" => minitest,
     "interpreter" => dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024),
     "fixture" => dispatch_file_identity(fixture, limit: 1_048_576),
     "bootstrapSources" => bootstrap_files.to_h { |name| [name, dispatch_file_identity(File.join(source_root, name), limit: 1_048_576)] }}
  end

  def recheck_raw_dispatch(observed)
    dispatch = observed[:dispatch]
    return unless dispatch
    interpreter = dispatch_file_identity(dispatch.fetch("interpreter").fetch("path"), limit: 32 * 1024 * 1024)
    fixture = dispatch_file_identity(dispatch.fetch("fixture").fetch("path"), limit: 1_048_576)
    bootstrap_same = dispatch.fetch("bootstrapSources").values.all? do |source|
      dispatch_file_identity(source.fetch("path"), limit: 1_048_576) == source
    end
    minitest_same = !dispatch.fetch("isolatedControl") || minitest_library_snapshot == dispatch.fetch("minitest")
    unless interpreter == dispatch.fetch("interpreter") && fixture == dispatch.fetch("fixture") && bootstrap_same && minitest_same
      raise UploadProcessFixture::Failure.new("fixture-source", "raw proof dispatch input changed")
    end
    if dispatch.key?("driverInput") # Ordinary copied drivers only; literal/isolated schemas are unchanged.
      input = dispatch.fetch("driverInput")
      directory = observed.fetch(:directory)
      unless UploadProcessFixture.read_json(File.join(directory, "input.json")) == input &&
             observed.fetch(:child).creator&.run_deadline_ns == input.fetch("deadlineNs")
        raise UploadProcessFixture::Failure.new("fixture-source", "raw proof original input/cutoff changed")
      end
      receipt_path = File.join(directory, "driver-dispatch.json")
      if File.file?(receipt_path) # An intentionally invalid mode rejects before publishing this receipt.
        receipt = UploadProcessFixture.read_json(receipt_path)
        unless receipt.fetch("deadlineNs") == input.fetch("deadlineNs") && receipt.fetch("pid") == observed.fetch(:child).pid
          raise UploadProcessFixture::Failure.new("fixture-source", "raw proof dispatch did not echo its original cutoff")
        end
      end
    end
    if dispatch.fetch("isolatedControl")
      request = observed.fetch(:isolated_request)
      binding = dispatch.fetch("isolatedRequest")
      path = File.join(observed.fetch(:directory), "isolated-request.json")
      unless read_isolated_json(path) == request &&
             dispatch_file_identity(path, limit: UploadProcessFixture::OUTPUT_LIMIT) == binding.fetch("identity") &&
             request.fetch("deadlineNs") == binding.fetch("deadlineNs") &&
             request.fetch("deadlineNs") == observed.fetch(:run_deadline_ns) &&
             request.fetch("deadlineNs") == observed.fetch(:child).creator&.run_deadline_ns
        raise UploadProcessFixture::Failure.new("fixture-source", "isolated raw proof original input/cutoff changed")
      end
    end
    observed[:inputs_rechecked] = true
  end

  def write_capture_record(observed)
    child = observed.fetch(:child)
    status = child.status
    record = {"case" => File.basename(observed.fetch(:directory)), "phase" => child.phase.to_s,
              "pid" => child.pid, "exitStatus" => status&.exitstatus, "termSignal" => status&.termsig,
              "stopAttempted" => observed.fetch(:stop_attempted), "stopCompleted" => observed.fetch(:stop_completed),
              "streamsClosed" => observed.fetch(:streams_closed), "nativeObservation" => observed.fetch(:native_observation),
              "ownedChild" => child.provenance, "streamIdentities" => observed[:stream_identities],
              "dispatch" => observed[:dispatch], "inputsRechecked" => observed.fetch(:inputs_rechecked),
              "runDeadlineNs" => observed.fetch(:run_deadline_ns), "hardDeadlineNs" => observed.fetch(:hard_deadline_ns),
              "enclosingDeadlineNs" => observed.fetch(:enclosing_deadline_ns),
              "reportingRepeatQueued" => observed.fetch(:reporting_repeat_queued),
              "reportingInjectorJoined" => observed.fetch(:reporting_injector_joined),
              "reportingInjectorAdmitted" => observed.fetch(:reporting_injector_admitted),
              "reportingInjectorDeadlineNs" => observed[:reporting_injector_deadline_ns],
              "reportingInjectorFinished" => observed[:reporting_injector_slot]&.finished?,
              "literalReadiness" => observed[:literal_readiness],
              "primary" => bounded_error(observed[:primary]), "cleanupErrors" => observed.fetch(:cleanup_errors).map { |error| bounded_error(error) }}
    raise "oversized collector record" if JSON.generate(record).bytesize > UploadProcessFixture::OUTPUT_LIMIT
    UploadProcessFixture.atomic_json(File.join(observed.fetch(:directory), "collector.json"), record)
  end

  def observe_raw_native(directory, observed)
    path = File.join(directory, "owner.json")
    return unless File.file?(path)
    owner = UploadProcessFixture.read_json(path)
    unless owner.is_a?(Hash) && owner.keys.sort == %w[custodian finality group keeper phase processes validator version] &&
           owner["version"].instance_of?(Integer) && owner["version"] == 2 && owner["phase"] == "finished" &&
           %w[finalized no_producers].include?(owner["finality"]) && owner["processes"].is_a?(Array)
      raise UploadProcessFixture::Failure.new("fixture-result", "invalid native proof owner")
    end
    result = UploadProcessFixture.read_json(File.join(directory, "result.json"))
    observation = result.fetch("nativeObservation")
    assert_native_observation(observation, finality: owner.fetch("finality").to_sym)
    assert_owner_observation(owner, observation)
    source_root = observed.fetch(:dispatch).fetch("copyRoot")
    {"capture" => "native_upload_validation.rb", "spawn" => "native_process_spawn.rb",
     "helper" => "native_upload_process.rb"}.each do |role, name|
      origin = observation.fetch("sourceOrigins").fetch(role)
      expected = File.realpath(File.join(source_root, "fastlane", name))
      assert_equal expected, origin.fetch("path")
      assert_equal dispatch_file_identity(expected, limit: 1_048_576).fetch("sha256"), origin.fetch("sha256")
    end
    observed[:native_deadline] ||= UploadProcessFixture.clock + UploadProcessFixture::CLEANUP_LIMIT
    owner.fetch("processes").each do |process|
      # These exact role/group observations never grant a signal or wait route.
      # In particular, K has moved away from its original reserved group G.
      UploadProcessFixture.dead!(process.fetch("pid"), process.fetch("group"), deadline: observed.fetch(:native_deadline))
    end
    observed[:native_observation] = "observed-stopped"
  end

  def assert_owner_observation(owner, observation)
    assert_equal observation.fetch("custodian"), owner.fetch("custodian")
    if owner.fetch("finality") == "no_producers"
      %w[keeper validator].each { |role| assert_equal({"state" => "not_attempted"}, owner.fetch(role)) }
      assert_equal({"state" => "not_created"}, owner.fetch("group"))
      assert_empty owner.fetch("processes")
      return
    end
    %w[keeper validator group].each do |role|
      assert_equal observation.fetch("final").fetch(role), owner.fetch(role)
    end
    processes = owner.fetch("processes")
    assert_equal processes.map { |process| process.fetch("role") }.uniq.length, processes.length
    processes.each do |process|
      assert_equal %w[group pid role], process.keys.sort
      assert_includes %w[custodian keeper validator], process.fetch("role")
      %w[pid group].each do |name|
        assert_instance_of Integer, process.fetch(name)
        assert_includes 2..2_147_483_647, process.fetch(name)
      end
      terminal = owner.fetch(process.fetch("role"))
      assert_equal "reaped", terminal.fetch("state")
      assert_equal terminal.fetch("pid"), process.fetch("pid")
    end
    # Only independently accepted role bindings can populate the read-only
    # observation list. A terminal PID by itself is never an adopted target.
    context = observation.fetch("protocolContext")
    expected = []
    if (hello = context.fetch("hello"))
      expected << {"role" => "custodian", "pid" => hello.fetch("pid"), "group" => hello.fetch("pgid")}
    end
    if context.fetch("reserved") && (ready = context.fetch("ready"))
      expected << {"role" => "keeper", "pid" => context.fetch("reserved").fetch("keeper_pid"), "group" => ready.fetch("keeper_pgid")}
      expected << {"role" => "validator", "pid" => ready.fetch("validator_pid"), "group" => ready.fetch("group_id")}
    end
    assert_equal expected.sort_by { |entry| entry.fetch("role") }, processes.sort_by { |entry| entry.fetch("role") }
  end

  # The entire reporting tail stays inside this additional, deferred lifetime.
  # Its authoritative first error outlives publication failures AND a queued
  # repeat at the point which used to be outside the inner collection lifetime.
  def remember_reporting_cleanup(observed, scope, error, slot: nil)
    observed[:cleanup_errors] << error
    scope.remember(error)
    return unless slot

    begin
      slot.cancel!(error: error, reason_code: "cancelled")
    rescue Exception => cancellation_error
      observed[:cleanup_errors] << cancellation_error
      scope.remember(cancellation_error)
    end
  end

  def with_capture_reporting(observed, repeat, enclosing_deadline_ns:)
    UploadProcessFixture.lifetime(deadline_ns: enclosing_deadline_ns) do |report_scope|
      observed[:reporting_lifetime] = report_scope
      begin
        yield
      rescue Exception => error
        report_scope.remember(error)
        observed[:primary] ||= report_scope.primary
        begin
          if repeat
            target = Thread.current
            now_ns = MobileReleaseKit::NativeUploadProcess.monotonic_ns
            deadline_ns = [now_ns + RAW_REPORTING_NS, enclosing_deadline_ns].min
            unless deadline_ns > now_ns
              raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting deadline expired")
            end
            observed[:reporting_injector_deadline_ns] = deadline_ns
            observed[:reporting_thread_defaults] = [Thread.report_on_exception, Thread.abort_on_exception]
            injector = MobileReleaseKit::NativeUploadProcess::TaskSlot.new(
              caller: target, run_deadline_ns: deadline_ns, hard_cleanup_deadline_ns: deadline_ns,
            )
            # Publish custody before Thread.new. The task cannot deliver a
            # repeat until its actual self-published/returned identities agree.
            observed[:reporting_injector_slot] = injector
            injector.start do |_owned_slot|
              target.raise(repeat)
              true
            end
            unless injector.admit!
              raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector was not admitted")
            end
            observed[:reporting_injector_admitted] = true
            observed[:reporting_injector] = injector.thread
            unless injector.join_until(deadline_ns: deadline_ns)
              raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector did not join")
            end
            raise injector.first_error if injector.first_error
            unless injector.offer.equal?(true)
              raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector did not deliver its repeat")
            end
            observed[:reporting_repeat_queued] = Thread.current.pending_interrupt?
          end
        rescue Exception => secondary
          remember_reporting_cleanup(observed, report_scope, secondary, slot: observed[:reporting_injector_slot])
        ensure
          report_scope.cleanup do
            if (injector = observed[:reporting_injector_slot])
              begin
                injector.close_launch!
                unless injector.join_until(deadline_ns: observed.fetch(:reporting_injector_deadline_ns))
                  raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector did not finish")
                end
                observed[:reporting_injector] = injector.thread
                observed[:reporting_injector_joined] = injector.joined? && injector.finished? && !injector.unresolved?
              rescue Exception => secondary
                remember_reporting_cleanup(observed, report_scope, secondary, slot: injector)
              end
            end
            begin
              write_capture_record(observed)
            rescue Exception => publication_error
              observed[:cleanup_errors] << publication_error
              report_scope.remember(publication_error)
            end
          end
        end
        raise report_scope.primary
      end
    end
  end

  def raw_collector_cutoffs(deadline, enclosing_deadline_ns: nil)
    run_ns = (deadline.to_r * 1_000_000_000).floor # Original conversion, never another clock sample.
    cleanup_ns = UploadProcessFixture::CLEANUP_LIMIT * 1_000_000_000
    maximum = MobileReleaseKit::NativeUploadProcess::MAX_TIME
    unless run_ns.between?(1, maximum - cleanup_ns) &&
           (enclosing_deadline_ns.nil? || enclosing_deadline_ns.instance_of?(Integer) && enclosing_deadline_ns.between?(1, maximum))
      raise UploadProcessFixture::Failure.new("fixture-input", "invalid raw collector deadline")
    end
    if enclosing_deadline_ns
      # Inner run, original cleanup and reporting all fit INSIDE the original
      # enclosing endpoint, without converting its absolute value to Float.
      run_ns = [run_ns, enclosing_deadline_ns - cleanup_ns - RAW_REPORTING_NS].min
    end
    unless run_ns > UploadProcessFixture.clock_ns
      raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired")
    end
    hard_ns = run_ns + cleanup_ns
    [run_ns, hard_ns, enclosing_deadline_ns || hard_ns]
  end

  def collect_raw_driver(copy, directory, observed, literal: nil, close_fault: nil, reporting_repeat: nil,
                         isolate_close: false, enclosing_deadline_ns: nil)
    UploadProcessFixture.assert_domain_reusable!
    @retain_raw_evidence = true
    raise "invalid fixed collector isolation" unless [true, false].include?(isolate_close) && (!isolate_close || (!copy && !literal && !close_fault && !reporting_repeat))
    deadline = UploadProcessFixture.clock + (isolate_close ? ISOLATED_COLLECTOR_LIMIT : UploadProcessFixture::DRIVER_LIMIT)
    run_ns, hard_ns, enclosing_ns = raw_collector_cutoffs(deadline, enclosing_deadline_ns: enclosing_deadline_ns)
    child = UploadProcessFixture::OwnedChild.new(root: directory, deadline_ns: run_ns, hard_deadline_ns: hard_ns)
    output = errors = nil
    observed.merge!(directory: directory, child: child, status: nil, primary: nil, cleanup_errors: [],
                    run_deadline_ns: run_ns, hard_deadline_ns: hard_ns, enclosing_deadline_ns: enclosing_ns,
                    stop_attempted: false, stop_completed: false, streams_closed: false,
                    native_observation: literal || isolate_close ? "literal-has-no-native-capture" : "pending", close_fault_calls: 0,
                    inputs_rechecked: false, reporting_repeat_queued: false, reporting_injector_joined: nil,
                    reporting_injector_admitted: false, reporting_injector_slot: nil)
    with_capture_reporting(observed, reporting_repeat, enclosing_deadline_ns: enclosing_ns) do
      UploadProcessFixture.lifetime(deadline_ns: hard_ns) do |scope|
        observed[:collector_lifetime] = scope
        begin
          write_capture_record(observed) # Truthful pending state before acquisition.
          fixture = if isolate_close
            File.realpath(__FILE__)
          elsif literal
            path = File.join(directory, "collector-control.rb")
            bytes = COLLECTOR_SCRIPTS.fetch(literal)
            File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(bytes) }
            actual = dispatch_file_identity(path, limit: 1_048_576)
            unless actual.fetch("sha256") == Digest::SHA256.hexdigest(bytes) && actual.fetch("size") == bytes.bytesize
              raise "literal collector fixture bytes changed"
            end
            UploadProcessFixture.atomic_json(File.join(directory, "literal-source.json"),
                                             {"case" => literal, "identity" => actual})
            path
          else
            File.join(copy, PROOF_FILES.first)
          end
          observed[:dispatch] = raw_dispatch(copy, directory, fixture, literal, isolate_close: isolate_close)
          unless literal || isolate_close
            input_path = File.join(directory, "input.json")
            input = UploadProcessFixture.read_json(input_path)
            unless input.instance_of?(Hash) && input.keys.sort == %w[mode parameters platform]
              raise UploadProcessFixture::Failure.new("fixture-input", "unexpected raw copied-driver input envelope")
            end
            # Publish the original collector cutoff BEFORE child.start. This
            # consumes the same run budget and never rewrites a live input.
            input = input.merge("deadlineNs" => run_ns)
            UploadProcessFixture.atomic_json(input_path, input)
            observed[:dispatch]["driverInput"] = input
          end
          if isolate_close
            observed[:isolation_source_hashes] = proof_source_snapshot.transform_values { |item| item.fetch("sha256") }
            request = {"version" => 1, "argv" => observed.fetch(:dispatch).fetch("argv"),
                       "cwd" => observed.fetch(:dispatch).fetch("cwd"), "deadlineNs" => run_ns,
                       "minitest" => observed.fetch(:dispatch).fetch("minitest"),
                       "sourceSha256" => observed.fetch(:isolation_source_hashes),
                       "testSource" => observed.fetch(:dispatch).fetch("fixture")}
            # Keep the full envelope privately in memory; dispatch already has
            # Minitest's complete inventory and must not serialize it twice.
            observed[:isolated_request] = request
            request_path = File.join(directory, "isolated-request.json")
            UploadProcessFixture.atomic_json(request_path, request)
            observed.fetch(:dispatch)["isolatedRequest"] = {
              "deadlineNs" => run_ns, "identity" => dispatch_file_identity(request_path, limit: UploadProcessFixture::OUTPUT_LIMIT)}
          end
          write_capture_record(observed)
          output = File.open(File.join(directory, "driver.stdout"), File::WRONLY | File::CREAT | File::EXCL, 0o600)
          errors = File.open(File.join(directory, "driver.stderr"), File::WRONLY | File::CREAT | File::EXCL, 0o600)
          observed[:stream_identities] = [output, errors].map { |file| UploadProcessFixture::OwnedChild.identity(file.stat) }
          if close_fault
            original_close = output.method(:close)
            output.define_singleton_method(:close) do
              observed[:close_fault_calls] += 1
              original_close.call
              raise close_fault
            end
          end
          scope.active do
            dispatch = observed.fetch(:dispatch)
            child.start(dispatch.fetch("environment"), *dispatch.fetch("argv"), chdir: dispatch.fetch("cwd"),
                        in: File::NULL, out: output, err: errors,
                        unsetenv_others: true, pgroup: true)
            if literal == "timeout"
              # This one fixed control intentionally outlives the original run
              # cutoff. Its real ready bytes let us stop acquiring read-only ps
              # children, whose own startup deadline must not replace this
              # intended error. It retains the genuine pre-wait signal route.
              await_literal_timeout(directory, output, observed, run_ns)
            end
            loop do
              if [output, errors].any? { |file| file.stat.size > UploadProcessFixture::OUTPUT_LIMIT }
                raise UploadProcessFixture::Failure.new("diagnostic", "oversized raw proof diagnostic")
              end
              remaining = run_ns - UploadProcessFixture.clock_ns
              raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired") unless remaining.positive?

              if child.phase == :reserved
                # This is a non-consuming observation of the actual reserved
                # driver, not a wait receipt or authority from owner.json.
                # Keep the pre-wait stop route until completion is observed.
                stopped = UploadProcessFixture.state(child.pid, child.pid,
                  seconds: [remaining, 2_000_000_000].min.fdiv(1_000_000_000),
                  deadline: Rational(run_ns, 1_000_000_000)) == :stopped
                child.retire_numeric! if stopped
              end
              remaining = run_ns - UploadProcessFixture.clock_ns
              raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired") unless remaining.positive?
              # Retirement is permanent even if a genuine first WNOHANG wait
              # returns nil. No later observation or timeout reopens a numeric
              # signal route; stop may only finish this wait or retain UNKNOWN.
              child.poll_wait if child.phase == :waiting
              unless %i[reserved waiting reaped].include?(child.phase)
                raise UploadProcessFixture::Failure.new("process-ownership", "raw proof driver wait authority is unknown")
              end
              remaining = run_ns - UploadProcessFixture.clock_ns
              raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired") unless remaining.positive?
              break if child.status
              sleep [remaining, 10_000_000].min.fdiv(1_000_000_000)
            end
            stdout, stderr = [[output, "driver.stdout"], [errors, "driver.stderr"]].map do |writer, name|
              read_raw_transcript(File.join(directory, name), writer, deadline_ns: run_ns)
            end
            if [stdout, stderr].any? { |value| value.bytesize > UploadProcessFixture::OUTPUT_LIMIT }
              raise UploadProcessFixture::Failure.new("diagnostic", "oversized raw proof diagnostic")
            end
            observed.merge!(stdout: stdout, stderr: stderr, status: child.status)
          end
        rescue Exception => error
          observed[:primary] ||= error
          scope.remember(error)
          raise
        ensure
          scope.cleanup do
            attempt = lambda do |&operation|
              operation.call
            rescue Exception => error
              observed[:cleanup_errors] << error
              observed[:primary] ||= error
              scope.remember(error)
            end
            attempt.call do
              observed[:stop_attempted] = true
              # KILL is permitted only before the first consuming wait. The
              # owned API never revives a retired route, even on a nil wait.
              child.stop
              observed[:stop_completed] = child.complete?
            end
            observed[:status] = child.status
            [output, errors].compact.each { |file| attempt.call { close_raw_writer(child, file) } }
            observed[:streams_closed] = output && errors && [output, errors].all?(&:closed?)
            attempt.call { observe_raw_native(directory, observed) } unless literal || isolate_close
            attempt.call { check_raw_capture_scratch!(directory) }
            attempt.call { recheck_raw_dispatch(observed) }
            attempt.call { write_capture_record(observed) }
          end
        end
      end
    end
    observed
  end

  def await_literal_timeout(directory, writer, observed, run_ns)
    expected = "collector ready\n"
    identity = observed.fetch(:stream_identities).first
    loop do
      remaining = run_ns - UploadProcessFixture.clock_ns
      unless remaining.positive?
        raise UploadProcessFixture::Failure.new("readiness", "literal collector readiness deadline expired")
      end
      bytes, size = File.open(File.join(directory, "driver.stdout"), File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |reader|
        before = reader.stat
        unless before.file? && UploadProcessFixture::OwnedChild.identity(before) == identity &&
               UploadProcessFixture::OwnedChild.identity(writer.stat) == identity
          raise UploadProcessFixture::Failure.new("diagnostic", "literal collector transcript identity changed")
        end
        value = reader.read(UploadProcessFixture::OUTPUT_LIMIT + 1)
        # Initial regular-file EOF can precede application output after GO.
        value = "".b if value.nil?
        after = reader.stat
        unless UploadProcessFixture::OwnedChild.identity(after) == identity && value &&
               value.bytesize <= UploadProcessFixture::OUTPUT_LIMIT && after.size <= UploadProcessFixture::OUTPUT_LIMIT
          raise UploadProcessFixture::Failure.new("diagnostic", "literal collector transcript changed or exceeded its bound")
        end
        [value, after.size]
      end
      # The still-running literal can publish a prefix concurrently. Only its
      # actual COMPLETE fixed bytes authorize readiness, never size/EOF alone.
      unless expected.start_with?(bytes) && size <= expected.bytesize
        raise UploadProcessFixture::Failure.new("diagnostic", "literal collector readiness bytes were unexpected")
      end
      if bytes == expected && size == expected.bytesize
        unless UploadProcessFixture.clock_ns < run_ns
          raise UploadProcessFixture::Failure.new("readiness", "literal collector readiness deadline expired")
        end
        observed[:literal_readiness] = {"observed" => true, "identity" => identity}
        break
      end
      sleep [10_000_000, [run_ns - UploadProcessFixture.clock_ns, 0].max].min.fdiv(1_000_000_000)
    end
    while (remaining = run_ns - UploadProcessFixture.clock_ns).positive?
      sleep [remaining, 10_000_000].min.fdiv(1_000_000_000)
    end
    raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired")
  end

  def close_raw_writer(child, file)
    lease = child.acquisition&.resources&.values&.find { |candidate| candidate.io.equal?(file) }
    if lease
      # The actual native lease, not the retained File object, owns this close.
      # In particular UNKNOWN never retries even when File#closed? is true.
      if lease.state == :open
        if child.creator&.start_attempted? && !child.creator.joined?
          raise UploadProcessFixture::Failure.new("fixture-cleanup", "raw output creator is not joined")
        end
        lease.close_once
      end
      return
    end
    if child.acquisition&.state == :unknown || (child.creator&.start_attempted? && !child.creator.joined?)
      raise UploadProcessFixture::Failure.new("fixture-cleanup", "raw output custody remains unpublished")
    end
    file.close unless file.closed?
  end

  def read_raw_transcript(path, writer, deadline_ns:)
    # Native maps grant stdout/stderr WRITE only. Read the real saved transcript
    # through a separate no-follow reader after the genuine driver wait, while
    # the original write-only object still binds the exact task-owned inode.
    unless UploadProcessFixture.clock_ns < deadline_ns
      raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired")
    end
    File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |reader|
      before, owned = reader.stat, writer.stat
      unless before.file? && before.dev == owned.dev && before.ino == owned.ino
        raise UploadProcessFixture::Failure.new("diagnostic", "raw proof transcript identity changed")
      end
      unless UploadProcessFixture.clock_ns < deadline_ns
        raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired")
      end
      bytes = reader.read(UploadProcessFixture::OUTPUT_LIMIT + 1) || ""
      identity = ->(value) { [value.dev, value.ino, value.mode, value.size, value.mtime, value.ctime] }
      unless identity.call(before) == identity.call(reader.stat)
        raise UploadProcessFixture::Failure.new("diagnostic", "raw proof transcript changed while read")
      end
      unless UploadProcessFixture.clock_ns < deadline_ns
        raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired")
      end
      bytes
    end
  end

  def read_raw_primary(directory, observed, mode, expected_exit:)
    status = observed.fetch(:status)
    unless status&.exited? && status.exitstatus == expected_exit
      raise UploadProcessFixture::Failure.new("fixture-result", "unexpected native proof CLI status")
    end
    unless %w[owner.json result.json primary-proof.json].all? { |name| File.file?(File.join(directory, name)) }
      raise UploadProcessFixture::Failure.new("fixture-result", "missing native primary proof")
    end
    owner, result, proof = %w[owner.json result.json primary-proof.json].map { |name| UploadProcessFixture.read_json(File.join(directory, name)) }
    assert_equal "finished", owner.fetch("phase")
    assert_equal "observed-stopped", observed.fetch(:native_observation)
    assert_equal mode, proof.fetch("case")
    assert_equal "", observed.fetch(:stdout)
    assert result.is_a?(Hash)
    assert proof.is_a?(Hash)
    assert_equal "finalized", owner.fetch("finality")
    assert_owner_observation(owner, result.fetch("nativeObservation"))
    [result, proof, owner]
  end

  def copied_primary_case(copy, mode, mutant:)
    directory = new_raw_case("#{mutant ? 'mutant' : 'pristine'}-proof", mode)
    observed = collect_raw_driver(copy, directory, {})
    read_raw_primary(directory, observed, mode, expected_exit: mutant ? 1 : 0)
  end

  def assert_common_raw_proof(value, proof, secondary:)
    assert_native_observation(value.fetch("nativeObservation"), finality: :finalized)
    %w[ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined handlersRestored registryInactive].each do |name|
      assert value.fetch(name), name
    end
    refute value.fetch("pendingInterrupt")
    refute value.fetch("watchdogIntervened")
    assert_equal secondary ? ["UploadProcessFixture::NativePrimaryProbe::CleanupFailure"] : [], value.fetch("cleanupErrors")
    %w[faultCount resultObservations].each { |name| assert_equal 1, proof.fetch(name), name }
    %w[framePublishedBeforeFault nestedPrimarySameObject originalNotIntentional originalStatusPreserved
       actualCustodianReceiptBound actualTaskJoins actualDescriptorsClosed].each do |name|
      assert proof.fetch(name), name
    end
    assert_equal secondary ? 1 : 0, proof.fetch("secondaryCount")
    assert_equal secondary, proof.fetch("secondaryObjectRecorded")
  end

  def assert_native_io_redaction(value, _proof)
    assert_equal "MobileReleaseKit::ContractError", value.fetch("nativeErrorClass")
    assert_equal "Synthetic validator could not be executed safely; no upload is authorized", value.fetch("nativeErrorMessage")
  end

  def assert_retained_capture(observed, finality: :finalized, failure_state: nil)
    failure_state[:stage] = "capture-retained-files" if failure_state
    assert_includes %i[finalized unknown], finality
    directory = observed.fetch(:directory)
    %w[input.json driver.stdout driver.stderr collector.json].each { |name| assert File.file?(File.join(directory, name)), name }
    failure_state[:stage] = "capture-retained-lifetime" if failure_state
    assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
    refute Thread.current.pending_interrupt?
    failure_state[:stage] = "capture-retained-streams" if failure_state
    assert observed.fetch(:streams_closed)
    assert_equal finality == :finalized, observed.fetch(:stop_completed)
    failure_state[:stage] = "capture-record-read" if failure_state
    record = UploadProcessFixture.read_json(File.join(directory, "collector.json"))
    failure_state[:stage] = "capture-record-status" if failure_state
    assert_equal finality == :finalized ? "reaped" : "unknown", record.fetch("phase")
    exit_status = observed.fetch(:status).exitstatus
    recorded_exit_status = record.fetch("exitStatus")
    exit_status.nil? ? assert_nil(recorded_exit_status) : assert_equal(exit_status, recorded_exit_status)
    term_signal = observed.fetch(:status).termsig
    recorded_term_signal = record.fetch("termSignal")
    term_signal.nil? ? assert_nil(recorded_term_signal) : assert_equal(term_signal, recorded_term_signal)
    failure_state[:stage] = "capture-record-flags" if failure_state
    assert record.fetch("streamsClosed")
    assert_equal finality == :finalized, record.fetch("stopCompleted")
    assert record.fetch("inputsRechecked")
    failure_state[:stage] = "capture-dispatch-contract" if failure_state
    assert_equal observed.fetch(:dispatch), record.fetch("dispatch")
    dispatch = record.fetch("dispatch")
    if dispatch.fetch("isolatedControl")
      assert_equal minitest_library_snapshot, dispatch.fetch("minitest")
      assert_equal isolated_collector_argv(directory, dispatch.fetch("minitest")), dispatch.fetch("argv")
      assert_equal File.realpath(__FILE__), dispatch.fetch("fixture").fetch("path")
    else
      assert_nil dispatch.fetch("minitest")
      assert_equal [RbConfig.ruby, dispatch.fetch("fixture").fetch("path"), "driver", directory], dispatch.fetch("argv")
    end
    failure_state[:stage] = "capture-dispatch-environment" if failure_state
    expected_environment = UploadProcessFixture::PROCESS_OBSERVER_SELECTION.nil? ? {} :
      {UploadProcessFixture::PROCESS_OBSERVER_KEY => UploadProcessFixture::PROCESS_OBSERVER_SELECTION}
    expected_environment.merge!("TMPDIR" => directory, "TMP" => directory, "TEMP" => directory)
    assert_equal expected_environment, dispatch.fetch("environment")
    assert_equal Dir.pwd, dispatch.fetch("cwd")
    assert_equal({"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
                  "stdout" => File.join(directory, "driver.stdout"), "stderr" => File.join(directory, "driver.stderr")}, dispatch.fetch("options"))
    failure_state[:stage] = "capture-source-identities" if failure_state
    assert_equal dispatch.fetch("interpreter"), dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024)
    assert_equal dispatch.fetch("fixture"), dispatch_file_identity(dispatch.fetch("fixture").fetch("path"), limit: 1_048_576)
    failure_state[:stage] = "capture-stream-identities" if failure_state
    assert_equal observed.fetch(:stream_identities), record.fetch("streamIdentities")
    failure_state[:stage] = "capture-child-receipt" if failure_state
    child = observed.fetch(:child)
    assert_same observed.fetch(:status), child.status
    assert_instance_of Process::Status, child.status
    assert_same child.child, child.acquisition.child
    assert_same child.status, child.child.receipt.raw_status
    assert_equal child.pid, child.status.pid
    failure_state[:stage] = "capture-creator" if failure_state
    assert child.creator.joined?
    assert child.creator.finished?
    refute child.creator.unresolved?
    failure_state[:stage] = "capture-lifetime-endpoints" if failure_state
    assert_equal observed.fetch(:run_deadline_ns), child.creator.run_deadline_ns
    assert_equal observed.fetch(:hard_deadline_ns), child.creator.hard_cleanup_deadline_ns
    assert_equal observed.fetch(:run_deadline_ns), record.fetch("runDeadlineNs")
    assert_equal observed.fetch(:hard_deadline_ns), record.fetch("hardDeadlineNs")
    assert_equal observed.fetch(:enclosing_deadline_ns), record.fetch("enclosingDeadlineNs")
    assert_equal observed.fetch(:hard_deadline_ns), observed.fetch(:collector_lifetime).instance_variable_get(:@drain_deadline_ns).call
    assert_equal observed.fetch(:enclosing_deadline_ns), observed.fetch(:reporting_lifetime).instance_variable_get(:@drain_deadline_ns).call
    failure_state[:stage] = "capture-provenance" if failure_state
    assert_equal child.provenance, record.fetch("ownedChild")
    assert_raw_bootstrap_provenance(record.fetch("ownedChild"), dispatch, child.status,
                                    stream_identities: record.fetch("streamIdentities"), finality: finality, failure_state: failure_state)
    record
  end

  def assert_raw_bootstrap_provenance(provenance, dispatch, status, stream_identities:, finality:, failure_state: nil)
    failure_state[:stage] = "capture-bootstrap-header" if failure_state
    assert_equal 1, provenance.fetch("version")
    assert_equal status.pid, provenance.fetch("pid")
    assert_equal finality == :finalized ? "reaped" : "unknown", provenance.fetch("phase")
    assert provenance.fetch("numericRetired")
    assert provenance.fetch("creatorJoined")
    assert_equal finality == :finalized, provenance.fetch("resourcesClosed")
    assert_equal({"pid" => status.pid, "status_kind" => status.exited? ? "exit" : "signal",
                  "status_code" => status.exited? ? status.exitstatus : status.termsig}, provenance.fetch("wait"))
    failure_state[:stage] = "capture-bootstrap-request" if failure_state
    assert_equal({"executable" => dispatch.fetch("argv").first, "argv" => dispatch.fetch("argv"),
                  "environment" => dispatch.fetch("environment"), "cwd" => dispatch.fetch("cwd")}, provenance.fetch("requested"))
    failure_state[:stage] = "capture-bootstrap-sources" if failure_state
    bootstrap = provenance.fetch("nativeBootstrap")
    assert_equal %w[argv creatorCwd environment executable fdSources fixtureSha256], bootstrap.keys.sort
    sources = dispatch.fetch("bootstrapSources")
    assert_equal %w[fastlane/native_process_spawn.rb fastlane/native_upload_process.rb tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb], sources.keys.sort
    sources.each_value do |source|
      assert_equal source, dispatch_file_identity(source.fetch("path"), limit: 1_048_576)
    end
    fixture = sources.fetch("tests/workflow/upload_process_fixture.rb")
    failure_state[:stage] = "capture-bootstrap-directory" if failure_state
    launch = provenance.fetch("launchDirectory")
    assert_equal %w[dev gid ino mode rdev type uid], launch.fetch("identity").keys.sort
    assert_equal File.dirname(dispatch.fetch("options").fetch("stdout")), File.dirname(launch.fetch("path"))
    assert_match(/\Amrk-owned-launch-/, File.basename(launch.fetch("path")))
    assert_equal "directory", launch.fetch("identity").fetch("type")
    assert_equal Process.uid, launch.fetch("identity").fetch("uid")
    assert_equal 0o700, launch.fetch("identity").fetch("mode") & 0o7777
    failure_state[:stage] = "capture-bootstrap-dispatch" if failure_state
    assert_equal File.realpath(RbConfig.ruby), bootstrap.fetch("executable")
    assert_equal [File.realpath(RbConfig.ruby), *MobileReleaseKit::NativeUploadProcess::HELPER_FLAGS, "--",
                  fixture.fetch("realpath"), "owned-child", launch.fetch("path")], bootstrap.fetch("argv")
    assert_equal MobileReleaseKit::NativeUploadProcess.helper_environment, bootstrap.fetch("environment")
    assert_equal dispatch.fetch("cwd"), bootstrap.fetch("creatorCwd")
    assert_equal fixture.fetch("sha256"), bootstrap.fetch("fixtureSha256")
    failure_state[:stage] = "capture-bootstrap-descriptors" if failure_state
    descriptors = bootstrap.fetch("fdSources")
    assert_equal %w[in out err], descriptors.map { |entry| entry.fetch("role") }
    assert_equal UploadProcessFixture::OwnedChild.identity(File.stat(File::NULL)), descriptors.first.fetch("identity")
    assert_equal stream_identities, descriptors.drop(1).map { |entry| entry.fetch("identity") }

    failure_state[:stage] = "capture-bootstrap-configuration" if failure_state
    config = provenance.fetch("configuration")
    assert_equal %w[bytes identity path sha256], config.keys.sort
    assert_equal File.join(launch.fetch("path"), "configuration.json"), config.fetch("path")
    assert_equal "file", config.fetch("identity").fetch("type")
    assert_equal Process.uid, config.fetch("identity").fetch("uid")
    assert_equal 0o600, config.fetch("identity").fetch("mode") & 0o7777
    assert_includes 1..UploadProcessFixture::OUTPUT_LIMIT, config.fetch("bytes")
    assert_match(/\A[0-9a-f]{64}\z/, config.fetch("sha256"))
    failure_state[:stage] = "capture-bootstrap-ready" if failure_state
    assert_equal({"version" => 1, "pid" => status.pid, "pgid" => status.pid, "sid" => status.pid,
                  "configurationSha256" => config.fetch("sha256"), "cwd" => dispatch.fetch("cwd")}, provenance.fetch("ready"))
    failure_state[:stage] = "capture-bootstrap-grant" if failure_state
    assert_equal({"state" => "granted", "bytesWritten" => 3}, provenance.fetch("grant"))
    failure_state[:stage] = "capture-bootstrap-exec" if failure_state
    assert_equal({"version" => 1, "pid" => status.pid, "configurationSha256" => config.fetch("sha256"),
                  "argvSha256" => Digest::SHA256.hexdigest(JSON.generate(dispatch.fetch("argv"))),
                  "cwd" => dispatch.fetch("cwd")}, provenance.fetch("execAttempt"))
    failure_state[:stage] = "capture-bootstrap-directory-finality" if failure_state
    if finality == :finalized
      refute File.exist?(launch.fetch("path"))
    else
      assert_equal launch.fetch("identity"), UploadProcessFixture::OwnedChild.directory_identity(launch.fetch("path"))
    end
  end
end

if $PROGRAM_NAME == __FILE__ && ARGV.first.to_s.start_with?("--mrk-isolated-")
  isolated_failure = {stage: "cli-admission", deadline_ns: nil}
  begin
    File.umask(0o077)
    Process.exit!(NativeUploadValidationTest.run_isolated_collector_cli(ARGV, failure_state: isolated_failure))
  rescue Exception => error
    NativeUploadValidationTest.report_isolated_cli_failure(isolated_failure, error)
    Process.exit!(1)
  end
end
