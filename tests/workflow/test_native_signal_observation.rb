# frozen_string_literal: true

# Intentionally separate from the ordinary native suite. This instrumented
# proof runs only under the reviewed disposable native owner; a safe veto never
# substitutes for successful unmodified production cleanup.
require "minitest/autorun"
require "minitest/mock"
require_relative "upload_process_fixture"
require_relative "../../fastlane/native_process_spawn"
require_relative "../../fastlane/native_upload_process"

class NativeSignalObservationTest < Minitest::Test
  prepend UploadProcessFixture::CaseGuard
  SOURCE_FILES = %w[
    tests/workflow/upload_process_fixture.rb
    tests/workflow/upload_process_ownership.rb
    fastlane/native_upload_validation.rb
    fastlane/native_process_spawn.rb
    fastlane/native_upload_process.rb
    fastlane/release_support.rb
  ].freeze
  EXPECTED_MODES = %w[native-setup-interrupt native-setup-system-exit native-setup-io-error
                      native-setup-post-reap-cancel].freeze
  EXPECTED_ROUTES = %w[custodian-group keeper-self-group custodian-direct-keeper fixture].freeze
  EXPECTED_CONTROL_STATES = %w[reserved unknown retired-before-first-nil-wait reaped].freeze

  def setup
    UploadProcessFixture.assert_domain_reusable!
    @root = File.realpath(Dir.mktmpdir("mrk-native-signal-proof-"))
    @retain = true
  end

  def teardown
    return unless @root # Refused entry acquired no new fixture directory.

    probe = UploadProcessFixture::NativeSignalProbe
    if @retain || probe.current || UploadProcessFixture.cleanup_unresolved?(@root)
      warn "Preserve failed native signal observation: #{@root}"
      if probe.current || UploadProcessFixture.cleanup_unresolved?(@root)
        flunk "native signal observation retained unexpected process custody"
      end
    else
      probe.last_parent = nil # Clear only positively retired successful control metadata.
      FileUtils.remove_entry(@root)
    end
  end

  def test_native_first_close_and_post_reap_signals_with_safe_veto_controls
    assert_flag_admission
    assert_equal EXPECTED_MODES, UploadProcessFixture::NativeSignalProbe::MODES
    assert_equal EXPECTED_ROUTES, UploadProcessFixture::NativeSignalProbe::ROUTES
    assert_equal EXPECTED_CONTROL_STATES, UploadProcessFixture::NativeSignalProbe::CONTROL_STATES
    source_hashes = source_snapshot
    summaries, last_helpers = [], nil
    EXPECTED_MODES.each do |mode|
      UploadProcessFixture.assert_domain_reusable!
      value = UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode, observe_signals: true)
      assert_equal "pass", value.fetch("kind")
      assert_equal 0, value.fetch("observedDriverExitStatus") # Actual direct-child OS status.
      assert value.fetch("driverJoined")
      assert value.fetch("knownProcessesDead")
      native = value.fetch("nativeSignalProof")
      parent = value.fetch("parentSignalProof")
      helpers = native.fetch("helpers")
      assert_equal %w[custodian keeper], helpers.keys.sort
      copy = native.fetch("helperCopy")
      assert_helper_copy(copy, source_hashes)
      assert_signal_proof(native, role: "driver", mode: mode, source_hashes: source_hashes)
      assert_signal_proof(parent, role: "parent", mode: mode, source_hashes: source_hashes)
      helpers.each do |role, proof|
        assert_signal_proof(proof, role: "helper", mode: mode, source_hashes: source_hashes)
        assert_equal role, proof.fetch("helperRole")
        assert_equal copy, proof.fetch("helperCopy")
        assert_helper_resources(proof)
      end
      assert_equal parent.fetch("sourceSha256"), native.fetch("sourceSha256")
      assert_equal 0, native.fetch("baseDriverReturn") # A Ruby method return, not another OS exit.
      assert native.fetch("actualOriginalPrimary")
      assert native.fetch("actualCustodianReceiptBound")
      assert native.fetch("actualNativeDescriptorsClosed")
      observation = value.fetch("nativeObservation")
      assert_native_finality(observation, helpers, copy, source_hashes)
      driver_pid = helpers.fetch("custodian").fetch("parentPid")
      driver_records = parent.fetch("fixtureReservations").select { |record| record.fetch("pid") == driver_pid }
      assert_equal 1, driver_records.length # The original fixture wait, not a helper's PID claim alone.
      assert_equal 0, driver_records.first.fetch("exitStatus")
      [parent, native, *helpers.values].each do |proof|
        proof.fetch("requests").each do |request|
          assert_actual_request(request, proof: proof, copy: copy, helpers: helpers, driver_pid: driver_pid, source_hashes: source_hashes)
        end
      end
      production = helpers.values.flat_map { |proof| proof.fetch("requests") }
      group_requests = production.select { |request| %w[custodian-group keeper-self-group].include?(request.fetch("route")) }
      kills = group_requests.select { |request| request.fetch("signal") == "KILL" && request.fetch("result") == 1 && !request.fetch("absenceObserved") }
      # C and K legitimately race. Each ORIGINAL case needs a real authorized
      # reserved-G KILL, not an exact C call count or pooled cross-case total.
      assert_operator kills.length, :>=, 1, mode
      assert_equal kills.length, native.fetch("successfulGroupKILLs")
      # Preserve the original C-owned pinned lease route independently of the
      # C/K KILL race. A genuine C signal0 ESRCH still witnesses that request.
      assert group_requests.any? { |request| request.fetch("route") == "custodian-group" && request.fetch("signal") == "0" }, mode
      self_signals = native.fetch("requests").select { |request| request.fetch("origin") == "self" }
      assert_equal mode == EXPECTED_MODES.last ? 1 : 0, self_signals.length
      if mode == EXPECTED_MODES.last
        assert value.fetch("postReapCancellationInjected")
        assert_operator value.fetch("postReapCleanupDepth"), :>, 0
        assert_equal Signal.list.fetch("INT"), value.fetch("selfSignalQueued")
      end
      parent.fetch("requests").each { |request| assert_equal "fixture", request.fetch("origin") }
      %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted
         ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined handlersRestored registryInactive deadBeforeFallback].each do |name|
        assert value.fetch(name), name
      end
      assert_equal 1, value.fetch("injectionCount")
      if mode == "native-setup-io-error"
        assert_equal "MobileReleaseKit::ContractError", value.fetch("nativeErrorClass")
        assert_equal "Synthetic validator could not be executed safely; no upload is authorized", value.fetch("nativeErrorMessage")
      else
        assert value.fetch("nativeOriginalErrorPreserved")
        assert_equal 23, value.fetch("nativeExitStatus") if mode == "native-setup-system-exit"
      end
      refute value.fetch("pendingInterrupt")
      refute value.fetch("fallbackUsed")
      refute value.fetch("watchdogIntervened")
      refute value.key?("workerControlEOF")
      assert_empty value.fetch("cleanupErrors")
      assert_nil UploadProcessFixture::NativeSignalProbe.current
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      summaries << {"case" => mode, "driverOSExit" => value.fetch("observedDriverExitStatus"),
                    "custodianOSExit" => observation.fetch("custodian").fetch("status_code"),
                    "validatorTermSignal" => helpers.fetch("keeper").fetch("child").fetch("status_code"),
                    "successfulReservedGroupKILLs" => kills.length, "selfINTs" => self_signals.length,
                    "nativeRequestsByRoute" => production.group_by { |request| request.fetch("route") }.transform_values(&:length),
                    "fixtureReservationsReaped" => [parent, native].sum { |proof| proof.fetch("fixtureReservations").length },
                    "vetoes" => 0, "sourceSha256" => native.fetch("sourceSha256")}
      last_helpers = helpers
    end
    retired = UploadProcessFixture::NativeSignalProbe.last_parent.records.find { |record| record[:private_group] && record[:state] == :reaped }
    refute_nil retired
    controls = exercise_inert_controls(retired, last_helpers)
    assert_equal 32, controls.length
    assert_equal 7, controls.sum { |control| control.fetch("controlForwards") } # direct-K signal0 is never valid.
    assert_nil UploadProcessFixture::NativeSignalProbe.current
    assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
    refute Thread.current.pending_interrupt?
    assert_equal source_hashes, source_snapshot
    # Instrumented native facts and inert guard sensitivity remain separate;
    # neither substitutes for successful unmodified production cleanup.
    control_summary = controls.group_by { |control| [control.fetch("routeVariant"), control.fetch("signalVariant")] }.map do |(route, signal), proofs|
      {"route" => route, "signal" => signal, "states" => proofs.map { |proof| proof.fetch("stateVariant") },
       "inertForwards" => proofs.map { |proof| proof.fetch("controlForwards") }}
    end
    warn "NATIVE_SIGNAL_OBSERVATION=#{JSON.generate('instrumentedCases' => summaries, 'inertControls' => control_summary)}"
    @retain = false
  end

  private

  def source_path(name)
    File.realpath(File.join(File.expand_path("../..", __dir__), name))
  end

  def source_contents(name)
    File.open(source_path(name), File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
      before = file.stat
      raise "signal proof source is not a bounded regular file" unless before.file? && before.size <= 1_048_576
      bytes = file.read(1_048_577)
      identity = ->(value) { [value.dev, value.ino, value.mode, value.size, value.mtime, value.ctime] }
      unless bytes && bytes.bytesize == before.size && identity.call(file.stat) == identity.call(before)
        raise "signal proof source changed while read"
      end
      bytes
    end
  end

  def source_snapshot
    SOURCE_FILES.to_h { |name| [name, Digest::SHA256.hexdigest(source_contents(name))] }
  end

  def source_line(name, prefix)
    lines = source_contents(name).lines
    matches = lines.each_index.select { |index| lines[index].strip.start_with?(prefix) }
    assert_equal 1, matches.length, "ambiguous source seam: #{name} #{prefix}"
    matches.first + 1
  end

  def assert_signal_proof(proof, role:, mode:, source_hashes:)
    assert_equal mode, proof.fetch("case")
    assert_equal role, proof.fetch("role")
    assert_equal "native-signal-observation", proof.fetch("kind")
    assert_equal source_hashes, proof.fetch("sourceSha256")
    assert_empty proof.fetch("failures"), proof.inspect
    assert_equal true, proof.fetch("hooksRestored")
    assert_equal 0, proof.fetch("controlForwards")
    assert_operator JSON.generate(proof).bytesize, :<=, UploadProcessFixture::OUTPUT_LIMIT
    records = proof.fetch("fixtureReservations")
    if role == "helper"
      assert_empty records
    else
      refute_empty records # Original driver/read-only observation children really ran.
      records.each do |record|
        assert_equal "reaped", record.fetch("phase")
        assert_equal "reaped", record.fetch("ownerPhase")
        %w[privateGroup complete originalWaitBound creatorJoinObserved].each { |name| assert_equal true, record.fetch(name), record.inspect }
        # A real Linux ps returns1 for absence; neither result is synthesized.
        assert_includes [0, 1], record.fetch("exitStatus")
        assert_nil record.fetch("termSignal")
      end
    end
  end

  def assert_helper_copy(copy, source_hashes)
    assert_equal %w[label originalPath originalSha256 path sha256], copy.keys.sort
    assert_equal "signal-observed", copy.fetch("label")
    assert_equal source_path("fastlane/native_upload_process.rb"), copy.fetch("originalPath")
    assert_equal source_hashes.fetch("fastlane/native_upload_process.rb"), copy.fetch("originalSha256")
    assert_equal File.absolute_path(copy.fetch("path")), copy.fetch("path")
    assert copy.fetch("path").start_with?(@root + "/"), copy.inspect
    assert_equal "signal-observed-helper.rb", File.basename(copy.fetch("path"))
    assert_match(/\A[0-9a-f]{64}\z/, copy.fetch("sha256"))
    refute_equal copy.fetch("originalSha256"), copy.fetch("sha256")
    # The exact helper copy was rehashed by its real executing observer before
    # exit. Its directory can now be removed; a pathname is not live custody.
  end

  def assert_helper_resources(proof)
    %w[originalWaitBound creatorJoined taskJoinsObserved].each { |name| assert_equal true, proof.fetch(name), proof.inspect }
    origin = proof.fetch("helperMainOrigin")
    assert_equal proof.fetch("helperCopy").fetch("path"), origin.fetch("path")
    assert_equal source_line("fastlane/native_upload_process.rb", "def self.helper_main(argv)"), origin.fetch("line")
    leases = proof.fetch("leases")
    refute_empty leases
    assert_equal leases.length, leases.map { |lease| lease.values_at("acquisition", "role") }.uniq.length
    nulls = leases.select { |lease| lease.fetch("processLifetime") }
    assert_equal %w[null_stderr null_stdin null_stdout], nulls.map { |lease| lease.fetch("role") }.sort
    leases.each do |lease|
      assert_includes %w[bootstrap creator], lease.fetch("acquisition")
      refute lease.fetch("noIOAcquired"), lease.inspect # Genuine READY used these acquired roles.
      if lease.fetch("processLifetime")
        assert_equal "bootstrap", lease.fetch("acquisition")
        assert_equal "null", lease.fetch("kind")
        assert_equal "open", lease.fetch("state")
        assert_equal lease.fetch("role") == "null_stdin" ? "read" : "write", lease.fetch("access")
        refute lease.fetch("closed")
        refute lease.fetch("actualCloseObserved")
      else
        assert_equal "closed", lease.fetch("state")
        assert lease.fetch("closed")
        assert lease.fetch("actualCloseObserved")
      end
    end
    if proof.fetch("helperRole") == "custodian"
      assert_equal true, proof.fetch("keeperWaitAfterRetirement")
    else
      assert_nil proof.fetch("keeperWaitAfterRetirement")
    end
  end

  def assert_native_finality(observation, helpers, copy, source_hashes)
    assert_equal 1, observation.fetch("version")
    %w[hooksRestored settled finalized stdinCloseReturned].each { |name| assert_equal true, observation.fetch(name), observation.inspect }
    refute observation.fetch("noProducers")
    refute observation.fetch("unknown")
    assert_empty observation.fetch("observerErrors")
    origins = {"capture" => "fastlane/native_upload_validation.rb", "helper" => "fastlane/native_upload_process.rb",
               "spawn" => "fastlane/native_process_spawn.rb"}
    assert_equal origins.keys.sort, observation.fetch("sourceOrigins").keys.sort
    origins.each do |role, name|
      origin = observation.fetch("sourceOrigins").fetch(role)
      assert_equal source_path(name), origin.fetch("path")
      assert_equal source_hashes.fetch(name), origin.fetch("sha256")
      assert_operator origin.fetch("line"), :>, 0
    end
    assert_equal %w[capture creator], observation.fetch("tasks").map { |task| task.fetch("role") }.sort
    observation.fetch("tasks").each do |task|
      %w[actualConstructionObserved actualLaunchClosureObserved launchRetired startAttempted finished joined actualJoinObserved].each do |name|
        assert_equal true, task.fetch(name), task.inspect
      end
      assert_instance_of Integer, task.fetch("thread")
      refute task.fetch("unresolved")
    end
    refute_empty observation.fetch("leases")
    observation.fetch("leases").each do |lease|
      assert_equal "closed", lease.fetch("state")
      assert_equal true, lease.fetch("closed")
      assert_equal true, lease.fetch("actualCloseObserved")
      refute lease.fetch("noIOAcquired")
      assert_nil lease.fetch("closeError")
    end
    %w[stdoutEOF stderrEOF statusEOF actualEOFObserved].each do |name|
      assert_equal true, observation.fetch("streams").fetch(name)
    end
    custodian, keeper = helpers.values_at("custodian", "keeper")
    receipt = observation.fetch("custodian")
    assert_equal({"state" => "reaped", "pid" => custodian.fetch("pid"), "status_kind" => "exit", "status_code" => 2}, receipt)
    assert_equal 2, custodian.fetch("helperReturn")
    assert_equal custodian.fetch("pid"), custodian.fetch("sessionId")
    assert_equal custodian.fetch("pid"), keeper.fetch("parentPid")
    assert_equal custodian.fetch("pid"), keeper.fetch("sessionId")
    frame = observation.fetch("final")
    assert_equal %w[cleanup group keeper outcome type v validator], frame.keys.sort
    assert_equal [1, "FINAL", "failed", "confirmed"], frame.values_at("v", "type", "outcome", "cleanup")
    assert_equal frame.fetch("keeper"), custodian.fetch("child")
    assert_equal({"state" => "reaped", "pid" => keeper.fetch("pid"), "status_kind" => "exit", "status_code" => keeper.fetch("helperReturn")}, custodian.fetch("child"))
    assert_includes [0, 2], keeper.fetch("helperReturn") # Default1/tail failure is UNKNOWN, never finality.
    assert_equal frame.fetch("validator"), keeper.fetch("child")
    assert_equal ["reaped", "signal", Signal.list.fetch("KILL")], keeper.fetch("child").values_at("state", "status_kind", "status_code")
    assert_equal({"state" => "retired", "id" => keeper.fetch("pid"), "absent" => true}, frame.fetch("group"))
    assert_equal frame.fetch("group"), custodian.fetch("group")
    assert_equal ["retired", keeper.fetch("pid")], keeper.fetch("group").values_at("state", "id")
    context = observation.fetch("protocolContext")
    assert_equal custodian.fetch("pid"), context.fetch("hello").fetch("pid")
    assert_equal [keeper.fetch("pid"), keeper.fetch("pid"), custodian.fetch("pid")], context.fetch("reserved").values_at("keeper_pid", "group_id", "session_id")
    assert_equal [keeper.fetch("child").fetch("pid"), keeper.fetch("pid"), custodian.fetch("pid")], context.fetch("ready").values_at("validator_pid", "group_id", "keeper_pgid")
    spawn = observation.fetch("custodianSpawn")
    argv = spawn.fetch("argv")
    assert_equal File.realpath(RbConfig.ruby), spawn.fetch("executable")
    assert_equal MobileReleaseKit::NativeUploadProcess.helper_environment, spawn.fetch("environment")
    flags = MobileReleaseKit::NativeUploadProcess::HELPER_FLAGS
    assert_equal [File.realpath(RbConfig.ruby), *flags, "--", copy.fetch("path")], argv.first(flags.length + 3)
    assert_equal ["custodian", custodian.fetch("parentPid").to_s, custodian.fetch("parentPid").to_s], argv[flags.length + 3, 3]
    assert_equal flags.length + 8, argv.length
    assert argv.last(2).all? { |time| time.match?(/\A[1-9][0-9]*\z/) }
  end

  def assert_actual_request(request, proof:, copy:, helpers:, driver_pid:, source_hashes:)
    assert_nil request.fetch("rejection"), request.inspect
    assert_equal true, request.fetch("forwarded")
    %w[sourceBound ownerBound targetBound].each { |name| assert_equal true, request.fetch(name), request.inspect }
    refute request.key?("backendErrorClass")
    if request.fetch("absenceObserved")
      assert_nil request.fetch("result") # A genuine ESRCH is not a successful KILL.
    else
      assert_equal false, request.fetch("absenceObserved")
      assert_equal 1, request.fetch("result")
    end
    route = request.fetch("route")
    keeper_pid = helpers.fetch("keeper").fetch("pid")
    prefix = case route
    when "custodian-group" then 'result = Process.kill(signal, -@id)'
    when "keeper-self-group" then 'result = Process.kill(signal, -@pid)'
    when "custodian-direct-keeper" then 'result = Process.kill("KILL", @keeper.pid)'
    when "fixture" then 'Process.kill(signal, group ? -@pid : @pid)'
    when "self" then 'Process.kill("INT", Process.pid)'
    else flunk "unrecognized actual signal route: #{request.inspect}"
    end
    if %w[custodian-group keeper-self-group custodian-direct-keeper].include?(route)
      assert_equal "helper", proof.fetch("role")
      assert_equal route == "keeper-self-group" ? "keeper" : "custodian", proof.fetch("helperRole")
      assert_equal "native", request.fetch("origin")
      assert_equal keeper_pid, request.fetch("holderPid")
      assert_equal [route == "custodian-direct-keeper" ? keeper_pid : -keeper_pid], request.fetch("targets")
      assert_equal route == "custodian-direct-keeper", request.fetch("groupRetired")
      assert_equal false, request.fetch("absent") unless route == "custodian-direct-keeper"
      name, executed_path, sha = "fastlane/native_upload_process.rb", copy.fetch("path"), copy.fetch("sha256")
    elsif route == "fixture"
      assert_includes %w[parent driver], proof.fetch("role")
      assert_equal "fixture", request.fetch("origin")
      record = proof.fetch("fixtureReservations").find { |entry| entry.fetch("pid") == request.fetch("holderPid") }
      refute_nil record, request.inspect
      assert_includes [[record.fetch("pid")], [-record.fetch("pid")]], request.fetch("targets")
      assert_equal false, request.fetch("groupRetired")
      name = "tests/workflow/upload_process_ownership.rb"
      executed_path, sha = source_path(name), source_hashes.fetch(name)
    else
      assert_equal "driver", proof.fetch("role")
      assert_equal EXPECTED_MODES.last, proof.fetch("case")
      assert_equal "self", request.fetch("origin")
      assert_equal driver_pid, request.fetch("holderPid")
      assert_equal [driver_pid], request.fetch("targets")
      assert_equal "INT", request.fetch("signal")
      refute request.fetch("absenceObserved")
      name = "tests/workflow/upload_process_fixture.rb"
      executed_path, sha = source_path(name), source_hashes.fetch(name)
    end
    if route == "self"
      assert_equal "self", request.fetch("state")
      assert_equal false, request.fetch("beforeFirstWait")
      assert_equal true, request.fetch("numericRetired")
    else
      assert_equal "reserved", request.fetch("state")
      assert_equal true, request.fetch("beforeFirstWait")
      assert_equal false, request.fetch("numericRetired")
      assert_includes route == "custodian-direct-keeper" ? ["KILL"] : %w[0 KILL], request.fetch("signal")
    end
    # The copied helper only changes one require line and appends instrumentation
    # before its footer, so these earlier direct syscall lines stay identical.
    assert_equal({"path" => name, "executedPath" => executed_path, "line" => source_line(name, prefix), "sha256" => sha}, request.fetch("source"))
  end

  def assert_flag_admission
    cases = [nil, 0, 1, "true", [], {}].map { |flag| ["native", "native-setup-interrupt", flag] }
    cases.concat([["native", "native-setup-no-cleanup", true], ["native", "native-setup-second-pipe", true],
                  ["ios", "real-deadline", true], ["android", "real-deadline", true]])
    input_deadline_ns = UploadProcessFixture.clock_ns + UploadProcessFixture::DRIVER_LIMIT * 1_000_000_000
    with_acquisition_veto do
      cases.each do |platform, mode, flag|
        error = assert_raises(UploadProcessFixture::Failure) do
          UploadProcessFixture.run(platform: platform, root: @root, parameters: {}, mode: mode, observe_signals: flag)
        end
        assert_equal "fixture-input", error.kind
        assert_equal "invalid native signal observation request", error.message
        assert_operator UploadProcessFixture.clock_ns, :<, input_deadline_ns
        UploadProcessFixture.atomic_json(File.join(@root, "input.json"),
          {"platform" => platform, "parameters" => {}, "mode" => mode, "observeSignals" => flag, "deadlineNs" => input_deadline_ns})
        error = assert_raises(UploadProcessFixture::Failure) do
          Dir.stub(:tmpdir, @root) { UploadProcessFixture.driver(@root) }
        end
        assert_equal "fixture-input", error.kind
        assert_equal "invalid native signal observation request", error.message
        assert_equal ["input.json"], Dir.children(@root)
      end
    end
    File.unlink(File.join(@root, "input.json"))
  end

  def with_acquisition_veto
    attempts = {spawn: 0, native_create: 0, task: 0, pipe: 0, directory: 0}
    deny = lambda do |kind|
      lambda do |*, **|
        attempts[kind] += 1
        raise "invalid signal proof attempted #{kind} acquisition"
      end
    end
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

  def exercise_inert_controls(retired, helpers)
    evidence = []
    with_acquisition_veto do
      EXPECTED_ROUTES.product([0, "KILL"]).each do |route, signal|
        contexts = []
        EXPECTED_CONTROL_STATES.each do |state|
          UploadProcessFixture.assert_domain_reusable!
          observer = UploadProcessFixture::NativeSignalProbe.new(:control, EXPECTED_MODES.last)
          context = observer.control_context(route == "fixture" ? retired : helpers, route, state, signal)
          contexts << context.reject { |key, _| key == "state" }
          reason = {"reserved" => route == "custodian-direct-keeper" && signal == 0 ? "signal" : nil,
                    "unknown" => "unknown", "retired-before-first-nil-wait" => "post-retirement", "reaped" => "post-reap"}.fetch(state)
          if reason.nil?
            assert_equal 1, observer.observe { observer.dispatch(context) }
          else
            original = RuntimeError.new("first inert signal-control failure")
            secondary, returned = nil, nil
            error = assert_raises(RuntimeError) do
              UploadProcessFixture.lifetime do |frame|
                begin
                  frame.active { raise original }
                ensure
                  frame.cleanup do
                    begin
                      observer.observe { returned = observer.dispatch(context) }
                    rescue Exception => cleanup_error
                      secondary = cleanup_error
                      raise
                    end
                  end
                end
              end
            end
            assert_same original, error
            assert_equal "first inert signal-control failure", error.message
            assert_instance_of UploadProcessFixture::Failure, secondary
            assert_equal "signal-observation", secondary.kind
            assert_equal 0, returned
          end
          assert observer.hooks_restored
          assert_nil UploadProcessFixture::NativeSignalProbe.current
          assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
          refute Thread.current.pending_interrupt?
          assert_empty observer.records # No child, pipe, TaskSlot, or wait receipt was acquired or fabricated.
          assert_equal 1, observer.requests.length
          request = observer.requests.first
          assert_equal reason, request.fetch("rejection")
          assert_equal reason.nil?, request.fetch("forwarded")
          assert_equal reason.nil? ? 1 : nil, request.fetch("result")
          refute request.fetch("absenceObserved") # These controls never call a real syscall.
          assert_equal reason.nil? ? [] : ["#{route}:#{reason}"], observer.failures
          proof = observer.evidence.merge("syntheticControl" => true, "stateVariant" => state,
                                          "routeVariant" => route, "signalVariant" => signal.to_s)
          assert_equal reason.nil? ? 1 : 0, proof.fetch("controlForwards")
          UploadProcessFixture.atomic_json(File.join(@root, "#{route}-#{signal}-#{state}.inert-signal-control.json"), proof)
          evidence << proof
        end
        assert_equal [contexts.first] * EXPECTED_CONTROL_STATES.length, contexts # State alone varies within this route/signal template.
      end
    end
    evidence
  end
end
