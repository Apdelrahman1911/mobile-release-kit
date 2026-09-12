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
                              capture-contract cleanup-contract reporting-contract custody-contract final-recheck proof-publication].freeze
  ISOLATED_FAILURE_CATEGORIES = %w[assertion-error fixture-error native-lifecycle-error io-error os-error interrupt
                                  system-exit standard-error exception unknown].freeze
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

  def process_case(mode, cleanup_errors: [])
    UploadProcessFixture.assert_domain_reusable!
    primary_failure_state = {} # Never shared with another mode, raw copy or call.
    value = begin
      UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode,
        primary_failure_state: primary_failure_state)
    rescue Exception => original
      # run has completed its original lifetime, cleanup and policy restoration.
      # A different failure or partial handoff cannot claim a proof rejection.
      begin
        self.class.report_native_primary_failure(primary_failure_state, original,
          callback: "#{self.class.name}##{name}", mode: mode)
      rescue Exception
        nil # Even optional callback lookup must not replace the actual error.
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
    %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted
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
    assert_equal %w[containment-custodian.json containment-keeper.json fallback-writer-close.json leader-eof.json], hashes.keys.sort
    reports = hashes.to_h do |name, digest|
      bytes = UploadProcessFixture::OwnedChild.bounded_file(File.join(directory, name))
      assert_equal Digest::SHA256.hexdigest(bytes), digest
      [name, JSON.parse(bytes)]
    end
    close, eof = reports.values_at("fallback-writer-close.json", "leader-eof.json")
    assert_equal close, value.fetch("fallbackWriterClose")
    assert_equal [1, graph, fifo], close.values_at("version", "identities", "fifoIdentity")
    %w[actualOriginalWriterClose soleFixtureWriter originalWatchdogThread watchdogAdmittedBeforeClose].each do |name|
      assert_equal true, close.fetch(name), name
    end
    assert_equal close.fetch("closeEntryNs"), proof.fetch("writerCloseEntryNs")
    assert_equal eof.fetch("readNilNs"), proof.fetch("validatorReadNilNs")
    %w[closeEntryNs closeReturnNs watchdogRunDeadlineNs watchdogHardDeadlineNs].each do |name|
      assert_instance_of Integer, close.fetch(name)
    end
    assert_operator close.fetch("closeEntryNs"), :<=, close.fetch("closeReturnNs")
    assert_instance_of Integer, eof.fetch("readNilNs")
    # Kernel EOF may reach V before Ruby close returns; the sole SAME writer,
    # actual close and SAME FIFO read(nil), not return-time ordering, bind this.
    assert_operator close.fetch("closeEntryNs"), :<=, eof.fetch("readNilNs")
    assert_equal({"version" => 1, "eof" => true, "controlReadNil" => true, "readNilNs" => eof.fetch("readNilNs"),
                  "pid" => graph.fetch("validator"), "group" => graph.fetch("group"), "sid" => graph.fetch("sid"),
                  "fifoIdentity" => fifo}, eof)
    %w[custodian keeper].each do |role|
      report = reports.fetch("containment-#{role}.json")
      assert_equal [1, "original-helper-containment-events", "native-setup-no-cleanup", role, graph.fetch(role), graph],
                   report.values_at("version", "kind", "mode", "role", "pid", "identities")
      assert_equal proof.fetch("sourceSha256"), report.fetch("sourceSha256")
      assert_equal copy, report.fetch("helperCopy")
      refute report.fetch("terminalAlreadyArmed")
      assert_empty report.fetch("hookRestorationErrors")
      assert_empty report.fetch("actualKills")
      assert_equal 1, report.fetch("omissions").length
      omission = report.fetch("omissions").first
      assert_equal [role == "custodian" ? "custodian-group" : "keeper-group", graph.fetch("group"), "KILL"],
                   omission.values_at("route", "group", "signal")
      %w[actualOmissionEntry nativeCallOmitted originalReservedAuthority].each { |name| assert_equal true, omission.fetch(name), name }
      assert_equal copy.fetch("path"), omission.fetch("origin").fetch("path")
      assert_operator omission.fetch("origin").fetch("line"), :>, 0
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
      exercise = lambda do |raw, diagnostic: true, read_error: nil, write_result: :full, cleanup_error: nil, expiry: nil|
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
                      if cleanup_error
                        assert_same cleanup_error, assert_raises(IOError) { owner.stop }
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
                      assert_equal cleanup_error ? [] : [directory], removed
                      assert_includes events, :close_resources
                      unless writes.empty?
                        assert_operator events.index(:close_resources), :<, events.index(:write)
                        assert_operator events.index(:remove_entry), :<, events.index(:write) unless cleanup_error
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
      exercise.call(good)
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
        Interrupt.new("private-marker"), SystemExit.new(17, "private-marker"), RuntimeError.new("private-marker"),
        Exception.new("private-marker"), Object.new]
      category_errors.zip(ISOLATED_FAILURE_CATEGORIES).each do |failure, category|
        packet = fixture_class.isolated_failure_line("capture-contract", failure)
        assert_equal category, JSON.parse(packet.delete_prefix(ISOLATED_FAILURE_PREFIX)).fetch("category")
        refute_includes packet, "private-marker"
      end
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
      assert_late_final_deadline_choreography
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

  def native_order_case(family, caller_kind)
    UploadProcessFixture.assert_domain_reusable!
    assert_equal ORDER_CASES, UploadProcessFixture::NativeOrderProbe::MODES
    mode = "native-order-#{family}-#{caller_kind}"
    assert_equal [family, caller_kind], ORDER_CASES.fetch(mode)
    unknown = family == "cleanup-before-caller"
    caller_first = family == "caller-before-task"
    sources = proof_source_snapshot
    value = if unknown
      # One original driver in this singleton. Its truthful UNKNOWN is not a
      # successful capture, a ps-repaired receipt, or permission for a next case.
      UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode)
    else
      process_case(mode)
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
    failure_state[:stage] = "capture-contract"
    assert_same error, observed.fetch(:primary)
    record = assert_retained_capture(observed, finality: :unknown)
    assert_equal bounded_error(error), record.fetch("primary")
    assert_equal "driver", error.kind
    assert_equal "raw proof driver deadline expired", error.message
    assert_equal({"observed" => true, "identity" => observed.fetch(:stream_identities).first}, record.fetch("literalReadiness"))
    assert_equal "collector ready\n", File.binread(File.join(observed.fetch(:directory), "driver.stdout"), UploadProcessFixture::OUTPUT_LIMIT + 1)
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
        driver = UploadProcessFixture::AdapterDriver.new(@root, "ios", mode, {})
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

  def assert_retained_capture(observed, finality: :finalized)
    assert_includes %i[finalized unknown], finality
    directory = observed.fetch(:directory)
    %w[input.json driver.stdout driver.stderr collector.json].each { |name| assert File.file?(File.join(directory, name)), name }
    assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
    refute Thread.current.pending_interrupt?
    assert observed.fetch(:streams_closed)
    assert_equal finality == :finalized, observed.fetch(:stop_completed)
    record = UploadProcessFixture.read_json(File.join(directory, "collector.json"))
    assert_equal finality == :finalized ? "reaped" : "unknown", record.fetch("phase")
    assert_equal observed.fetch(:status).exitstatus, record.fetch("exitStatus")
    assert_equal observed.fetch(:status).termsig, record.fetch("termSignal")
    assert record.fetch("streamsClosed")
    assert_equal finality == :finalized, record.fetch("stopCompleted")
    assert record.fetch("inputsRechecked")
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
    expected_environment = UploadProcessFixture::PROCESS_OBSERVER_SELECTION.nil? ? {} :
      {UploadProcessFixture::PROCESS_OBSERVER_KEY => UploadProcessFixture::PROCESS_OBSERVER_SELECTION}
    expected_environment.merge!("TMPDIR" => directory, "TMP" => directory, "TEMP" => directory)
    assert_equal expected_environment, dispatch.fetch("environment")
    assert_equal Dir.pwd, dispatch.fetch("cwd")
    assert_equal({"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
                  "stdout" => File.join(directory, "driver.stdout"), "stderr" => File.join(directory, "driver.stderr")}, dispatch.fetch("options"))
    assert_equal dispatch.fetch("interpreter"), dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024)
    assert_equal dispatch.fetch("fixture"), dispatch_file_identity(dispatch.fetch("fixture").fetch("path"), limit: 1_048_576)
    assert_equal observed.fetch(:stream_identities), record.fetch("streamIdentities")
    child = observed.fetch(:child)
    assert_same observed.fetch(:status), child.status
    assert_instance_of Process::Status, child.status
    assert_same child.child, child.acquisition.child
    assert_same child.status, child.child.receipt.raw_status
    assert_equal child.pid, child.status.pid
    assert child.creator.joined?
    assert child.creator.finished?
    refute child.creator.unresolved?
    assert_equal observed.fetch(:run_deadline_ns), child.creator.run_deadline_ns
    assert_equal observed.fetch(:hard_deadline_ns), child.creator.hard_cleanup_deadline_ns
    assert_equal observed.fetch(:run_deadline_ns), record.fetch("runDeadlineNs")
    assert_equal observed.fetch(:hard_deadline_ns), record.fetch("hardDeadlineNs")
    assert_equal observed.fetch(:enclosing_deadline_ns), record.fetch("enclosingDeadlineNs")
    assert_equal observed.fetch(:hard_deadline_ns), observed.fetch(:collector_lifetime).instance_variable_get(:@drain_deadline_ns).call
    assert_equal observed.fetch(:enclosing_deadline_ns), observed.fetch(:reporting_lifetime).instance_variable_get(:@drain_deadline_ns).call
    assert_equal child.provenance, record.fetch("ownedChild")
    assert_raw_bootstrap_provenance(record.fetch("ownedChild"), dispatch, child.status,
                                    stream_identities: record.fetch("streamIdentities"), finality: finality)
    record
  end

  def assert_raw_bootstrap_provenance(provenance, dispatch, status, stream_identities:, finality:)
    assert_equal 1, provenance.fetch("version")
    assert_equal status.pid, provenance.fetch("pid")
    assert_equal finality == :finalized ? "reaped" : "unknown", provenance.fetch("phase")
    assert provenance.fetch("numericRetired")
    assert provenance.fetch("creatorJoined")
    assert_equal finality == :finalized, provenance.fetch("resourcesClosed")
    assert_equal({"pid" => status.pid, "status_kind" => status.exited? ? "exit" : "signal",
                  "status_code" => status.exited? ? status.exitstatus : status.termsig}, provenance.fetch("wait"))
    assert_equal({"executable" => dispatch.fetch("argv").first, "argv" => dispatch.fetch("argv"),
                  "environment" => dispatch.fetch("environment"), "cwd" => dispatch.fetch("cwd")}, provenance.fetch("requested"))
    bootstrap = provenance.fetch("nativeBootstrap")
    assert_equal %w[argv creatorCwd environment executable fdSources fixtureSha256], bootstrap.keys.sort
    sources = dispatch.fetch("bootstrapSources")
    assert_equal %w[fastlane/native_process_spawn.rb fastlane/native_upload_process.rb tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb], sources.keys.sort
    sources.each_value do |source|
      assert_equal source, dispatch_file_identity(source.fetch("path"), limit: 1_048_576)
    end
    fixture = sources.fetch("tests/workflow/upload_process_fixture.rb")
    launch = provenance.fetch("launchDirectory")
    assert_equal %w[dev gid ino mode rdev type uid], launch.fetch("identity").keys.sort
    assert_equal File.dirname(dispatch.fetch("options").fetch("stdout")), File.dirname(launch.fetch("path"))
    assert_match(/\Amrk-owned-launch-/, File.basename(launch.fetch("path")))
    assert_equal "directory", launch.fetch("identity").fetch("type")
    assert_equal Process.uid, launch.fetch("identity").fetch("uid")
    assert_equal 0o700, launch.fetch("identity").fetch("mode") & 0o7777
    assert_equal File.realpath(RbConfig.ruby), bootstrap.fetch("executable")
    assert_equal [File.realpath(RbConfig.ruby), *MobileReleaseKit::NativeUploadProcess::HELPER_FLAGS, "--",
                  fixture.fetch("realpath"), "owned-child", launch.fetch("path")], bootstrap.fetch("argv")
    assert_equal MobileReleaseKit::NativeUploadProcess.helper_environment, bootstrap.fetch("environment")
    assert_equal dispatch.fetch("cwd"), bootstrap.fetch("creatorCwd")
    assert_equal fixture.fetch("sha256"), bootstrap.fetch("fixtureSha256")
    descriptors = bootstrap.fetch("fdSources")
    assert_equal %w[in out err], descriptors.map { |entry| entry.fetch("role") }
    assert_equal UploadProcessFixture::OwnedChild.identity(File.stat(File::NULL)), descriptors.first.fetch("identity")
    assert_equal stream_identities, descriptors.drop(1).map { |entry| entry.fetch("identity") }

    config = provenance.fetch("configuration")
    assert_equal %w[bytes identity path sha256], config.keys.sort
    assert_equal File.join(launch.fetch("path"), "configuration.json"), config.fetch("path")
    assert_equal "file", config.fetch("identity").fetch("type")
    assert_equal Process.uid, config.fetch("identity").fetch("uid")
    assert_equal 0o600, config.fetch("identity").fetch("mode") & 0o7777
    assert_includes 1..UploadProcessFixture::OUTPUT_LIMIT, config.fetch("bytes")
    assert_match(/\A[0-9a-f]{64}\z/, config.fetch("sha256"))
    assert_equal({"version" => 1, "pid" => status.pid, "pgid" => status.pid, "sid" => status.pid,
                  "configurationSha256" => config.fetch("sha256"), "cwd" => dispatch.fetch("cwd")}, provenance.fetch("ready"))
    assert_equal({"state" => "granted", "bytesWritten" => 3}, provenance.fetch("grant"))
    assert_equal({"version" => 1, "pid" => status.pid, "configurationSha256" => config.fetch("sha256"),
                  "argvSha256" => Digest::SHA256.hexdigest(JSON.generate(dispatch.fetch("argv"))),
                  "cwd" => dispatch.fetch("cwd")}, provenance.fetch("execAttempt"))
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
