# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require_relative "upload_process_fixture"

class NativeUploadValidationTest < Minitest::Test
  PROOF_FILES = %w[
    tests/workflow/upload_process_fixture.rb
    tests/workflow/upload_process_ownership.rb
    fastlane/native_upload_validation.rb
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

  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-native-setup-"))
  end

  def teardown
    if @retain_raw_evidence || UploadProcessFixture.cleanup_unresolved?(@root)
      warn "Preserve unresolved native fixture evidence: #{@root}"
    else
      FileUtils.remove_entry(@root)
    end
  end

  def process_case(mode, cleanup_errors: [])
    value = UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode)
    assert value.fetch("driverJoined"), value.inspect
    assert value.fetch("knownProcessesDead"), value.inspect
    unless mode.start_with?("kill-")
      %w[watchdogJoined waiterJoined injectorsJoined ownedDescriptorsClosed handlersRestored registryInactive].each do |name|
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
       originalNotIntentional framePublishedBeforeFault actualWaiterMatchesDriver actualDescriptorsClosed].each do |name|
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
    if boundary == "frame"
      assert_equal 0, proof.fetch("backendEntries")
      assert_equal 0, proof.fetch("callbackEntries")
      assert_equal 0, value.fetch("nativeSpawnAttempts")
      assert_equal 4, value.fetch("ownedDescriptorCount")
      assert proof.fetch("callbackAbsent"), proof.inspect
      refute proof.fetch("actualWaiterReaped"), proof.inspect
      refute value.fetch("fallbackUsed"), value.inspect
      refute value.key?("workerControlEOF"), value.inspect
    else
      assert_equal 1, proof.fetch("backendEntries")
      assert_equal 1, proof.fetch("callbackEntries")
      assert_equal 7, value.fetch("ownedDescriptorCount")
      assert proof.fetch("callbackPrimarySameObject"), proof.inspect
      assert proof.fetch("actualWaiterReaped"), proof.inspect
      refute proof.fetch("callbackAbsent"), proof.inspect
      if boundary == "entered"
        %w[captureEntered firstCloseFromNative originalCloseCompleted].each { |name| assert value.fetch(name), value.inspect }
        assert_equal 1, value.fetch("injectionCount")
        assert_equal Signal.list.fetch("KILL"), proof.fetch("actualWorkerTermSignal")
        assert_nil proof.fetch("actualWorkerExitStatus")
        assert proof.fetch("enteredDeathBeforeControlClose"), proof.inspect
        refute value.fetch("fallbackUsed"), value.inspect
        refute value.key?("workerControlEOF"), value.inspect
        assert_equal 1, proof.fetch("signalRequests").length
        assert proof.fetch("signalRequests").first.fetch("forwarded"), proof.inspect
      else
        assert value.fetch("fallbackUsed"), value.inspect
        assert value.fetch("workerControlEOF"), value.inspect
        assert_equal 0, proof.fetch("actualWorkerExitStatus")
        assert_nil proof.fetch("actualWorkerTermSignal")
      end
    end
    unless boundary == "entered"
      refute value.fetch("captureEntered"), value.inspect
      refute value.key?("firstCloseFromNative"), value.inspect
      assert_equal 0, value.fetch("injectionCount")
      assert_empty proof.fetch("signalRequests"), proof.inspect
    end
    refute value.fetch("watchdogIntervened"), value.inspect
    assert_equal boundary == "watchdog" || boundary == "entered", value.fetch("watchdogStarted")
    value
  end

  def test_unexpected_pre_entry_failures_preserve_original_through_real_cleanup
    cases = UploadProcessFixture::NATIVE_PRIMARY_PROOFS.keys.grep(/native-proof-(publication|readiness|watchdog)-/)
    assert_equal 24, cases.length
    cases.each { |mode| primary_case(mode) }
  end

  def test_unexpected_primary_outlives_late_teardown_and_lookalike_diagnostics
    %w[native-proof-late-cleanup native-proof-lookalike].each { |mode| primary_case(mode) }
  end

  def test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike
    primary_case("native-proof-entered-io")
  end

  def test_nested_lifetime_preserves_pre_callback_ioerror_without_acquiring_native_child
    %w[native-proof-frame-io native-proof-frame-io-close].each { |mode| primary_case(mode) }
  end

  def test_entered_proof_rejects_deleting_only_the_intentional_primary_identity_predicate
    with_proof_copies("identity", IDENTITY_PREDICATE) do |copies|
      copies.each do |label, copy|
        mutant = label == "mutant"
        value, proof, owner = copied_primary_case(copy, "native-proof-entered-io", mutant: mutant)
        assert_common_raw_proof(value, proof, secondary: false)
        assert_equal "native-setup-io-error", value.fetch("mode")
        %w[ready captureEntered firstCloseFromNative originalCloseCompleted watchdogStarted].each do |name|
          assert value.fetch(name), name
        end
        assert_equal 1, value.fetch("injectionCount")
        refute value.fetch("fallbackUsed")
        refute value.key?("workerControlEOF")
        assert_nil value.fetch("workerExitStatus")
        assert_equal Signal.list.fetch("KILL"), value.fetch("workerTermSignal")
        assert_nil proof.fetch("actualWorkerExitStatus")
        assert_equal Signal.list.fetch("KILL"), proof.fetch("actualWorkerTermSignal")
        assert proof.fetch("enteredDeathBeforeControlClose")
        assert_equal [{"signal" => "KILL", "target" => -owner.fetch("leader"), "forwarded" => true, "result" => 1}],
                     proof.fetch("signalRequests")
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
          assert_equal ["actual failed native result", "outerPrimarySameObject", "originalMessagePreserved"], proof.fetch("failures")
        else
          assert_equal "IOError", value.fetch("errorClass")
          assert_equal "synthetic private diagnostic", value.fetch("error")
          assert value.fetch("harnessPrimaryRetained")
          refute value.key?("deadBeforeFallback")
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
          assert_equal 1, proof.fetch("driverExitStatus")
          assert_equal 0, value.fetch("injectionCount")
          refute value.fetch("captureEntered")
          refute value.key?("firstCloseFromNative")
          refute value.fetch("watchdogStarted")
          assert value.fetch("fallbackUsed")
          assert value.fetch("workerControlEOF")
          assert_equal 0, value.fetch("workerExitStatus")
          assert_nil value.fetch("workerTermSignal")
          assert_equal 0, proof.fetch("actualWorkerExitStatus")
          assert_nil proof.fetch("actualWorkerTermSignal")
          refute proof.fetch("enteredDeathBeforeControlClose")
          assert_empty proof.fetch("signalRequests")
          assert_equal has_secondary ? "fixture-cleanup" : "unexpected", value.fetch("kind")
          assert_native_io_redaction(value, proof) if kind == "io"
          if kind == "standard"
            assert_equal "UploadProcessFixture::NativePrimaryProbe::UnexpectedFailure", value.fetch("nativeErrorClass")
            assert_equal "unexpected synthetic native setup failure", value.fetch("nativeErrorMessage")
          end
          assert_equal !mutant, proof.fetch("outerPrimarySameObject")
          assert_equal !mutant, proof.fetch("originalMessagePreserved")
          if mutant
            assert_equal ["outerPrimarySameObject", "originalMessagePreserved"], proof.fetch("failures")
            assert_equal has_secondary ? "UploadProcessFixture::NativePrimaryProbe::CleanupFailure" : "RuntimeError", value.fetch("errorClass")
            assert_equal has_secondary ? "secondary synthetic native cleanup failure" : "native cleanup did not SIGKILL the actual worker", value.fetch("error")
          else
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
    COLLECTOR_SCRIPTS.each_key do |fault|
      observed = {}
      close_fault = fault == "timeout" ? IOError.new("synthetic collector close after effect") : nil
      repeat = fault == "timeout" ? Interrupt.new("repeat at collector reporting tail") : nil
      error = assert_raises(UploadProcessFixture::Failure) do
        UploadProcessFixture.lifetime do |scope|
          directory = new_raw_case("collector-#{fault}", "collector-#{fault}")
          scope.active { collect_raw_driver(nil, directory, observed, literal: fault, close_fault: close_fault, reporting_repeat: repeat) }
        end
      end
      assert_same error, observed.fetch(:primary)
      record = assert_retained_capture(observed)
      assert_equal error.class.name, record.fetch("primary").fetch("class")
      assert_equal error.kind, record.fetch("primary").fetch("kind")
      assert_equal error.message, record.fetch("primary").fetch("message")
      if fault == "timeout"
        assert_equal "driver", error.kind
        assert_equal "raw proof driver deadline expired", error.message
        assert_equal "collector ready\n", File.binread(File.join(observed.fetch(:directory), "driver.stdout"), UploadProcessFixture::OUTPUT_LIMIT + 1)
        assert_equal Signal.list.fetch("KILL"), observed.fetch(:status).termsig
        assert_equal [close_fault], observed.fetch(:cleanup_errors)
        assert_equal ["IOError"], record.fetch("cleanupErrors").map { |entry| entry.fetch("class") }
        assert_equal 1, observed.fetch(:close_fault_calls)
        assert observed.fetch(:reporting_repeat_queued)
        assert observed.fetch(:reporting_injector_joined)
        assert record.fetch("reportingRepeatQueued")
        assert record.fetch("reportingInjectorJoined")
        refute_same Thread.current, observed.fetch(:reporting_injector)
        refute observed.fetch(:reporting_injector).alive?
      else
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
      end
    end
  end

  def assert_native_cleanup(value)
    assert_equal 1, value.fetch("nativeSpawnAttempts")
    assert_equal 1, value.fetch("injectionCount")
    %w[ready captureEntered firstCloseFromNative originalCloseCompleted watchdogStarted deadBeforeFallback].each do |name|
      assert value.fetch(name), value.inspect
    end
    refute value.fetch("watchdogIntervened"), value.inspect
    refute value.fetch("fallbackUsed"), value.inspect
    refute value.key?("workerControlEOF"), value.inspect
    assert_nil value.fetch("workerExitStatus")
    assert_equal Signal.list.fetch("KILL"), value.fetch("workerTermSignal")
    assert_equal 7, value.fetch("ownedDescriptorCount")
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
    value = process_case("native-setup-no-cleanup")
    assert_equal "setup-fallback", value.fetch("kind")
    assert_equal 1, value.fetch("injectionCount")
    assert value.fetch("nativeOriginalErrorPreserved"), value.inspect
    assert value.fetch("watchdogIntervened"), value.inspect
    assert value.fetch("fallbackUsed"), value.inspect
    assert value.fetch("workerControlEOF"), value.inspect
    assert_equal 0, value.fetch("workerExitStatus")
    assert_nil value.fetch("workerTermSignal")
    refute value.key?("deadBeforeFallback"), value.inspect
    assert_match(/\A[0-9a-f]{64}\z/, value.fetch("mutationSourceSha256"))
    assert_match(/\A[0-9a-f]{64}\z/, value.fetch("mutationSha256"))
    refute_equal value.fetch("mutationSourceSha256"), value.fetch("mutationSha256")
  end

  def test_partial_pipe_and_pre_entry_faults_close_actual_resources_before_implicit_join
    %w[second-pipe owner-failure readiness-failure watchdog-unavailable watchdog-failure].each do |fault|
      value = process_case("native-setup-#{fault}")
      assert_equal fault == "readiness-failure" ? "readiness" : "setup-fixture-fault", value.fetch("kind")
      assert value.fetch("harnessPrimaryRetained"), value.inspect
      assert_equal 0, value.fetch("injectionCount")
      refute value.fetch("captureEntered"), value.inspect
      refute value.key?("firstCloseFromNative"), value.inspect
      refute value.key?("deadBeforeFallback"), value.inspect
      refute value.fetch("watchdogIntervened"), value.inspect
      assert_equal fault == "watchdog-failure", value.fetch("watchdogStarted")
      if fault == "second-pipe"
        assert_equal 0, value.fetch("nativeSpawnAttempts")
        assert_equal 2, value.fetch("ownedDescriptorCount")
        refute value.fetch("fallbackUsed"), value.inspect
        refute value.key?("workerExitStatus"), value.inspect
      else
        assert_equal 1, value.fetch("nativeSpawnAttempts")
        assert_equal 7, value.fetch("ownedDescriptorCount")
        assert value.fetch("fallbackUsed"), value.inspect
        assert value.fetch("workerControlEOF"), value.inspect
        assert_equal 0, value.fetch("workerExitStatus")
        assert_nil value.fetch("workerTermSignal")
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

  def test_hard_driver_loss_stops_native_leader_via_the_sole_control_writer
    value = process_case("kill-native-setup")
    assert_equal "driver-terminated", value.fetch("kind")
    assert_equal "kill-native-setup", value.fetch("phase")
    assert value.fetch("eofAfterDriverDeath"), value.inspect
  end

  def test_native_platform_modes_and_empty_parameters_are_validated_before_acquisition
    cases = UploadProcessFixture::NATIVE_MODES.flat_map { |mode| %w[ios android].map { |platform| [platform, mode, {}] } }
    cases.concat((UploadProcessFixture::MODES - UploadProcessFixture::NATIVE_MODES).map { |mode| ["native", mode, {}] })
    cases.concat([["native", "missing", {}], ["missing", "native-setup-interrupt", {}],
                  ["native", "native-setup-interrupt", {"python" => "untrusted"}]])
    starts = 0
    Process.stub(:spawn, lambda { |*| starts += 1; raise "invalid fixture spawned a child" }) do
      cases.each do |platform, mode, parameters|
        error = assert_raises(UploadProcessFixture::Failure) do
          UploadProcessFixture.run(platform: platform, root: @root, mode: mode, parameters: parameters)
        end
        assert_equal "fixture-input", error.kind
        UploadProcessFixture.atomic_json(File.join(@root, "input.json"), {"platform" => platform, "mode" => mode, "parameters" => parameters})
        error = assert_raises(UploadProcessFixture::Failure) { UploadProcessFixture.driver(@root) }
        assert_equal "fixture-input", error.kind
        assert_equal ["input.json"], Dir.children(@root)
      end
    end
    assert_equal 0, starts
  end

  private

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
    @retain_raw_evidence = false # Includes successful outer lifetime finalization.
  end

  def new_raw_case(label, mode)
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

  def raw_dispatch(copy, directory, fixture, literal)
    {"argv" => [RbConfig.ruby, fixture, "driver", directory], "cwd" => Dir.pwd, "environment" => {},
     "options" => {"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
                   "stdout" => File.join(directory, "driver.stdout"), "stderr" => File.join(directory, "driver.stderr")},
     "copyRoot" => copy, "literalCase" => literal,
     "interpreter" => dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024),
     "fixture" => dispatch_file_identity(fixture, limit: 1_048_576)}
  end

  def recheck_raw_dispatch(observed)
    dispatch = observed[:dispatch]
    return unless dispatch
    interpreter = dispatch_file_identity(dispatch.fetch("argv").first, limit: 32 * 1024 * 1024)
    fixture = dispatch_file_identity(dispatch.fetch("argv")[1], limit: 1_048_576)
    unless interpreter == dispatch.fetch("interpreter") && fixture == dispatch.fetch("fixture")
      raise UploadProcessFixture::Failure.new("fixture-source", "raw proof dispatch input changed")
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
              "dispatch" => observed[:dispatch], "inputsRechecked" => observed.fetch(:inputs_rechecked),
              "reportingRepeatQueued" => observed.fetch(:reporting_repeat_queued),
              "reportingInjectorJoined" => observed.fetch(:reporting_injector_joined),
              "primary" => bounded_error(observed[:primary]), "cleanupErrors" => observed.fetch(:cleanup_errors).map { |error| bounded_error(error) }}
    raise "oversized collector record" if JSON.generate(record).bytesize > UploadProcessFixture::OUTPUT_LIMIT
    UploadProcessFixture.atomic_json(File.join(observed.fetch(:directory), "collector.json"), record)
  end

  def observe_raw_native(directory, observed)
    path = File.join(directory, "owner.json")
    return unless File.file?(path)
    owner = UploadProcessFixture.read_json(path)
    unless owner.is_a?(Hash) && owner.keys.sort == %w[group leader phase] && owner["leader"].is_a?(Integer) &&
           owner["leader"] > 1 && owner["group"] == owner["leader"] && %w[launched finished].include?(owner["phase"])
      raise UploadProcessFixture::Failure.new("fixture-result", "invalid native proof owner")
    end
    observed[:native_deadline] ||= UploadProcessFixture.clock + UploadProcessFixture::CLEANUP_LIMIT
    UploadProcessFixture.dead!(owner.fetch("leader"), owner.fetch("group"), deadline: observed.fetch(:native_deadline))
    observed[:native_observation] = "observed-stopped"
  end

  # The entire reporting tail stays inside this additional, deferred lifetime.
  # Its authoritative first error outlives publication failures AND a queued
  # repeat at the point which used to be outside the inner collection lifetime.
  def with_capture_reporting(observed, repeat)
    UploadProcessFixture.lifetime do |report_scope|
      begin
        yield
      rescue Exception => error
        report_scope.remember(error)
        observed[:primary] ||= report_scope.primary
        begin
          if repeat
            target = Thread.current
            observed[:reporting_injector] = Thread.new { target.raise(repeat) }
            unless observed.fetch(:reporting_injector).join(2)
              raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector did not join")
            end
            observed[:reporting_repeat_queued] = Thread.current.pending_interrupt?
          end
        rescue Exception => secondary
          observed[:cleanup_errors] << secondary
          report_scope.remember(secondary)
        ensure
          report_scope.cleanup do
            if (injector = observed[:reporting_injector])
              begin
                unless injector.join(2)
                  raise UploadProcessFixture::Failure.new("fixture-cleanup", "collector reporting injector did not finish")
                end
                observed[:reporting_injector_joined] = !injector.alive?
              rescue Exception => secondary
                observed[:cleanup_errors] << secondary
                report_scope.remember(secondary)
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

  def collect_raw_driver(copy, directory, observed, literal: nil, close_fault: nil, reporting_repeat: nil)
    @retain_raw_evidence = true
    child = UploadProcessFixture::OwnedChild.new
    output = errors = nil
    observed.merge!(directory: directory, child: child, status: nil, primary: nil, cleanup_errors: [],
                    stop_attempted: false, stop_completed: false, streams_closed: false,
                    native_observation: literal ? "literal-has-no-native-child" : "pending", close_fault_calls: 0,
                    inputs_rechecked: false, reporting_repeat_queued: false, reporting_injector_joined: nil)
    with_capture_reporting(observed, reporting_repeat) do
      UploadProcessFixture.lifetime do |scope|
        begin
          write_capture_record(observed) # Truthful pending state before acquisition.
          fixture = if literal
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
          observed[:dispatch] = raw_dispatch(copy, directory, fixture, literal)
          write_capture_record(observed)
          output = File.open(File.join(directory, "driver.stdout"), File::RDWR | File::CREAT | File::EXCL, 0o600)
          errors = File.open(File.join(directory, "driver.stderr"), File::RDWR | File::CREAT | File::EXCL, 0o600)
          if close_fault
            original_close = output.method(:close)
            output.define_singleton_method(:close) do
              observed[:close_fault_calls] += 1
              original_close.call
              raise close_fault
            end
          end
          scope.active do
            deadline = UploadProcessFixture.clock + UploadProcessFixture::DRIVER_LIMIT
            dispatch = observed.fetch(:dispatch)
            child.start(dispatch.fetch("environment"), *dispatch.fetch("argv"), chdir: dispatch.fetch("cwd"),
                        in: File::NULL, out: output, err: errors,
                        unsetenv_others: true, pgroup: true)
            loop do
              child.poll
              if [output, errors].any? { |file| file.stat.size > UploadProcessFixture::OUTPUT_LIMIT }
                raise UploadProcessFixture::Failure.new("diagnostic", "oversized raw proof diagnostic")
              end
              remaining = deadline - UploadProcessFixture.clock
              raise UploadProcessFixture::Failure.new("driver", "raw proof driver deadline expired") unless remaining.positive?
              break if child.status
              sleep [remaining, 0.01].min
            end
            stdout, stderr = [output, errors].map do |file|
              file.rewind
              file.read(UploadProcessFixture::OUTPUT_LIMIT + 1) || ""
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
              child.stop # Only the still-owned direct reservation; never marker PIDs.
              observed[:stop_completed] = child.complete?
            end
            observed[:status] = child.status
            [output, errors].compact.each { |file| attempt.call { file.close unless file.closed? } }
            observed[:streams_closed] = output && errors && [output, errors].all?(&:closed?)
            attempt.call { observe_raw_native(directory, observed) } unless literal
            attempt.call { recheck_raw_dispatch(observed) }
            attempt.call { write_capture_record(observed) }
          end
        end
      end
    end
    observed
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
    if mode == "native-proof-entered-io"
      refute File.exist?(File.join(directory, "leader-eof.json"))
    else
      assert_equal({"eof" => true}, UploadProcessFixture.read_json(File.join(directory, "leader-eof.json")))
    end
    [result, proof, owner]
  end

  def copied_primary_case(copy, mode, mutant:)
    directory = new_raw_case("#{mutant ? 'mutant' : 'pristine'}-proof", mode)
    observed = collect_raw_driver(copy, directory, {})
    read_raw_primary(directory, observed, mode, expected_exit: mutant ? 1 : 0)
  end

  def assert_common_raw_proof(value, proof, secondary:)
    assert_equal 1, value.fetch("nativeSpawnAttempts")
    assert_equal 7, value.fetch("ownedDescriptorCount")
    %w[ownedDescriptorsClosed watchdogJoined waiterJoined injectorsJoined handlersRestored registryInactive].each do |name|
      assert value.fetch(name), name
    end
    refute value.fetch("pendingInterrupt")
    refute value.fetch("watchdogIntervened")
    assert_equal secondary ? ["UploadProcessFixture::NativePrimaryProbe::CleanupFailure"] : [], value.fetch("cleanupErrors")
    %w[faultCount resultObservations backendEntries callbackEntries].each { |name| assert_equal 1, proof.fetch(name), name }
    %w[framePublishedBeforeFault nestedPrimarySameObject callbackPrimarySameObject originalNotIntentional
       originalStatusPreserved actualWaiterMatchesDriver actualWaiterReaped actualDescriptorsClosed].each do |name|
      assert proof.fetch(name), name
    end
    refute proof.fetch("callbackAbsent")
    assert_equal secondary ? 1 : 0, proof.fetch("secondaryCount")
    secondary ? assert(proof.fetch("secondaryObjectRecorded")) : assert_nil(proof.fetch("secondaryObjectRecorded"))
  end

  def assert_native_io_redaction(value, proof)
    assert_equal "MobileReleaseKit::ContractError", value.fetch("nativeErrorClass")
    assert_equal "Synthetic validator could not be executed safely; no upload is authorized", value.fetch("nativeErrorMessage")
    assert_equal value.fetch("nativeErrorClass"), proof.fetch("nativeErrorClass")
    assert_equal value.fetch("nativeErrorMessage"), proof.fetch("nativeErrorMessage")
  end

  def assert_retained_capture(observed)
    directory = observed.fetch(:directory)
    %w[input.json driver.stdout driver.stderr collector.json].each { |name| assert File.file?(File.join(directory, name)), name }
    assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
    refute Thread.current.pending_interrupt?
    assert observed.fetch(:streams_closed)
    assert observed.fetch(:stop_completed)
    record = UploadProcessFixture.read_json(File.join(directory, "collector.json"))
    assert_equal "reaped", record.fetch("phase")
    assert_equal observed.fetch(:status).exitstatus, record.fetch("exitStatus")
    assert_equal observed.fetch(:status).termsig, record.fetch("termSignal")
    assert record.fetch("streamsClosed")
    assert record.fetch("stopCompleted")
    assert record.fetch("inputsRechecked")
    assert_equal observed.fetch(:dispatch), record.fetch("dispatch")
    dispatch = record.fetch("dispatch")
    assert_equal [RbConfig.ruby, dispatch.fetch("fixture").fetch("path"), "driver", directory], dispatch.fetch("argv")
    assert_equal({}, dispatch.fetch("environment"))
    assert_equal Dir.pwd, dispatch.fetch("cwd")
    assert_equal({"unsetenv_others" => true, "pgroup" => true, "stdin" => File::NULL,
                  "stdout" => File.join(directory, "driver.stdout"), "stderr" => File.join(directory, "driver.stderr")}, dispatch.fetch("options"))
    assert_equal dispatch.fetch("interpreter"), dispatch_file_identity(RbConfig.ruby, limit: 32 * 1024 * 1024)
    assert_equal dispatch.fetch("fixture"), dispatch_file_identity(dispatch.fetch("argv")[1], limit: 1_048_576)
    record
  end
end
