# frozen_string_literal: true

# Intentionally a separate invocation from the ordinary native13 suite. This
# entered, instrumented proof is hosted-only until the QA-007 runtime fix lands.
require "minitest/autorun"
require "minitest/mock"
require_relative "upload_process_fixture"

class NativeSignalObservationTest < Minitest::Test
  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-native-signal-proof-"))
    @retain = true
  end

  def teardown
    probe = UploadProcessFixture::NativeSignalProbe
    probe.last_parent = nil # Retired in-process control metadata, never live custody.
    if @retain || probe.current || UploadProcessFixture.cleanup_unresolved?(@root)
      warn "Preserve failed native signal observation: #{@root}"
    else
      FileUtils.remove_entry(@root)
    end
  end

  def test_native_first_close_and_post_reap_signals_with_safe_veto_controls
    assert_flag_admission
    summaries = []
    UploadProcessFixture::NativeSignalProbe::MODES.each do |mode|
      value = UploadProcessFixture.run(platform: "native", root: @root, parameters: {}, mode: mode, observe_signals: true)
      assert_equal "pass", value.fetch("kind")
      assert_equal 0, value.fetch("observedDriverExitStatus") # Actual direct-child OS status.
      assert value.fetch("driverJoined")
      assert value.fetch("knownProcessesDead")
      native = value.fetch("nativeSignalProof")
      parent = value.fetch("parentSignalProof")
      [native, parent].each do |proof|
        assert_equal mode, proof.fetch("case")
        assert_equal "native-signal-observation", proof.fetch("kind")
        assert_empty proof.fetch("failures"), proof.inspect
        assert proof.fetch("hooksRestored"), proof.inspect
        assert_equal 0, proof.fetch("controlForwards")
        refute_empty proof.fetch("fixtureReservations"), proof.inspect
        proof.fetch("fixtureReservations").each do |record|
          assert_equal "reaped", record.fetch("phase")
          assert_equal "reaped", record.fetch("ownerPhase")
          assert record.fetch("privateGroup")
          # The real read-only ps command returns1 for an absent native process.
          assert_includes [0, 1], record.fetch("exitStatus")
          assert_nil record.fetch("termSignal")
        end
        proof.fetch("requests").each do |request|
          assert_nil request.fetch("rejection"), request.inspect
          assert request.fetch("forwarded"), request.inspect
          assert_equal 1, request.fetch("result")
          assert_equal "live", request.fetch("state") unless request.fetch("origin") == "self"
        end
      end
      assert_equal parent.fetch("sourceSha256"), native.fetch("sourceSha256")
      assert_equal 0, native.fetch("baseDriverReturn") # A Ruby method return, not another OS exit.
      assert_equal 1, native.fetch("backendEntries")
      assert_equal 1, native.fetch("callbackEntries")
      assert_equal Signal.list.fetch("KILL"), native.fetch("actualWorkerTermSignal")
      assert_nil native.fetch("actualWorkerExitStatus")
      assert native.fetch("actualOriginalPrimary")
      assert native.fetch("actualNativeDescriptorsClosed")
      production = native.fetch("requests").select { |request| request.fetch("origin") == "native" }
      assert_equal 1, production.length
      assert_equal "KILL", production.first.fetch("signal")
      assert_equal [-native.fetch("actualWaiterPid")], production.first.fetch("targets")
      assert_equal "fastlane/native_upload_validation.rb", production.first.fetch("source").fetch("path")
      self_signals = native.fetch("requests").select { |request| request.fetch("origin") == "self" }
      assert_equal mode == UploadProcessFixture::NativeSignalProbe::MODES.last ? 1 : 0, self_signals.length
      parent.fetch("requests").each { |request| assert_equal "fixture", request.fetch("origin") }
      %w[ownedDescriptorsClosed watchdogJoined waiterJoined injectorsJoined handlersRestored registryInactive deadBeforeFallback].each do |name|
        assert value.fetch(name), name
      end
      refute value.fetch("pendingInterrupt")
      refute value.fetch("fallbackUsed")
      refute value.fetch("watchdogIntervened")
      refute value.key?("workerControlEOF")
      assert_empty value.fetch("cleanupErrors")
      assert_nil UploadProcessFixture::NativeSignalProbe.current
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      summaries << {"case" => mode, "driverOSExit" => value.fetch("observedDriverExitStatus"),
                    "nativeWorkerTermSignal" => native.fetch("actualWorkerTermSignal"),
                    "productionKILLs" => production.length, "selfINTs" => self_signals.length,
                    "fixtureReservationsReaped" => [parent, native].sum { |proof| proof.fetch("fixtureReservations").length },
                    "vetoes" => 0, "sourceSha256" => native.fetch("sourceSha256")}
    end
    retired = UploadProcessFixture::NativeSignalProbe.last_parent.records.find { |record| record[:private_group] && record[:state] == :reaped }
    refute_nil retired
    controls = exercise_inert_controls(retired)
    assert_equal [1, 0, 0], controls.map { |control| control.fetch("controlForwards") }
    assert_equal [[], ["fixture:unknown"], ["fixture:post-reap"]], controls.map { |control| control.fetch("failures") }
    assert_nil UploadProcessFixture::NativeSignalProbe.current
    assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
    refute Thread.current.pending_interrupt?
    # Bounded synthetic/source-only summary; never mix an inert control with a
    # real production call or label this invocation an unmodified-suite pass.
    warn "NATIVE_SIGNAL_OBSERVATION=#{JSON.generate('instrumentedCases' => summaries, 'inertControlForwards' => [1, 0, 0])}"
    @retain = false
  end

  private

  def assert_flag_admission
    cases = [nil, 0, 1, "true", [], {}].map { |flag| ["native", "native-setup-interrupt", flag] }
    cases.concat([["native", "native-setup-no-cleanup", true], ["native", "native-setup-second-pipe", true],
                  ["ios", "real-deadline", true], ["android", "real-deadline", true]])
    starts = directories = 0
    Process.stub(:spawn, ->(*) { starts += 1; raise "invalid proof acquired a child" }) do
      Dir.stub(:mktmpdir, ->(*) { directories += 1; raise "invalid proof acquired a directory" }) do
        cases.each do |platform, mode, flag|
          error = assert_raises(UploadProcessFixture::Failure) do
            UploadProcessFixture.run(platform: platform, root: @root, parameters: {}, mode: mode, observe_signals: flag)
          end
          assert_equal "fixture-input", error.kind
          UploadProcessFixture.atomic_json(File.join(@root, "input.json"),
                                           {"platform" => platform, "parameters" => {}, "mode" => mode, "observeSignals" => flag})
          error = assert_raises(UploadProcessFixture::Failure) { UploadProcessFixture.driver(@root) }
          assert_equal "fixture-input", error.kind
          assert_equal ["input.json"], Dir.children(@root)
        end
      end
    end
    assert_equal 0, starts
    assert_equal 0, directories
    File.unlink(File.join(@root, "input.json"))
  end

  def exercise_inert_controls(retired)
    contexts, evidence = [], []
    %w[live unknown reaped].each do |state|
      observer = UploadProcessFixture::NativeSignalProbe.new(:control, "native-setup-post-reap-cancel")
      context = observer.control_context(retired, state)
      contexts << context.reject { |key, _| key == "state" }
      if state == "live"
        assert_equal 1, observer.observe { observer.dispatch(context) }
      else
        original = RuntimeError.new("first inert signal-control failure")
        ios, secondary, returned = nil, nil, nil
        error = assert_raises(RuntimeError) do
          UploadProcessFixture.lifetime do |frame|
            ios = IO.pipe
            begin
              frame.active { raise original }
            ensure
              frame.cleanup do
                begin
                  observer.observe { returned = observer.dispatch(context) }
                rescue Exception => cleanup_error
                  secondary = cleanup_error
                  raise
                ensure
                  ios.each { |io| io.close unless io.closed? }
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
        assert_equal 2, ios.length
        assert ios.all?(&:closed?)
      end
      assert observer.hooks_restored
      assert_nil UploadProcessFixture::NativeSignalProbe.current
      assert_nil UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      refute Thread.current.pending_interrupt?
      assert_empty observer.records # Controls did not acquire, revive, or adopt a child.
      assert_equal 1, observer.requests.length
      expected_reason = {"live" => nil, "unknown" => "unknown", "reaped" => "post-reap"}.fetch(state)
      assert_equal expected_reason, observer.requests.first.fetch("rejection")
      proof = observer.evidence.merge("syntheticControl" => true, "stateVariant" => state)
      UploadProcessFixture.atomic_json(File.join(@root, "#{state}.inert-signal-control.json"), proof)
      evidence << proof
    end
    assert_equal [contexts.first] * 3, contexts # No collateral source/owner/target change.
    evidence
  end
end
