# frozen_string_literal: true

# Inert API models only: IO.pipe, Process.spawn and Process.waitpid2 are replaced
# before the adapter is entered. No child/thread/FD/signal/native fixture exists
# here. These assertions are not evidence of real process-family settlement.
# Authoring/syntax review is separate from authorization to execute this file.
require "minitest/autorun"
require "minitest/mock"
require_relative "../../fastlane/store_lane_lifetime"
require_relative "../../fastlane/ios_upload_validation"

class StoreLaneLifetimeTest < Minitest::Test
  Lifetime = MobileReleaseKit::StoreLaneLifetime
  ModeledStatus = Struct.new(:pid, :exitstatus, :signal) do
    def exited?
      signal.nil?
    end

    def signaled?
      !signal.nil?
    end
  end

  class ModeledEndpoint
    attr_accessor :close_on_exec, :close_error, :read_error, :writer, :fileno_value,
                  :pid_value, :arm_error, :arm_nonlocal, :arm_confirmed,
                  :disarm_error, :disarm_nonlocal, :close_nonlocal,
                  :close_after_effect, :close_return, :closed_report
    attr_reader :autoclose, :close_calls, :reads, :flag_calls, :close_flags,
                :descriptor_retired, :wrapper_closed

    def initialize(role, events, lines = [])
      @role, @events, @lines = role, events, lines.dup
      @close_calls, @reads = 0, 0
      @fileno_value = {stdin_read: 81, stdin_write: 82, stdout_read: 83, stdout_write: 84}.fetch(role)
      @autoclose, @arm_confirmed, @closed_report = true, true, true
      @flag_calls, @close_flags = [], []
      @wrapper_closed = @descriptor_retired = false
    end

    def fileno
      @fileno_value # Inert label only; never passed to an FD-taking API.
    end

    def pid
      @pid_value
    end

    def autoclose=(value)
      @flag_calls << value
      @events << [:autoclose, @role, value]
      raise IOError, "synthetic closed-wrapper disarm" if @wrapper_closed
      if value
        @autoclose = true
        raise @arm_error, cause: @arm_error.cause if @arm_error
        throw :store_close_nonlocal, :escaped_arm if @arm_nonlocal
      else
        # The first false is acquisition, not an unconfirmed-close disarm.
        if @prepared
          raise @disarm_error, cause: @disarm_error.cause if @disarm_error
          throw :store_close_nonlocal, :escaped_disarm if @disarm_nonlocal
        end
        @prepared, @autoclose = true, false
      end
      value
    end

    def autoclose?
      @autoclose && @arm_confirmed
    end

    def closed?
      @wrapper_closed && @closed_report
    end

    def close
      @close_calls += 1
      @close_flags << @autoclose
      @events << [:close, @role]
      raise @close_error, cause: @close_error.cause if @close_error && !@close_after_effect
      throw :store_close_nonlocal, :escaped_close if @close_nonlocal
      # Pinned MRI may close a non-owning wrapper WITHOUT retiring its FD.
      @wrapper_closed = true
      @descriptor_retired = @autoclose == true && @fileno_value.instance_of?(Integer) && @fileno_value >= 3 && @pid_value.nil?
      raise @close_error, cause: @close_error.cause if @close_error
      @close_return
    end

    def gets(separator, limit)
      raise "unbounded/changed reader contract" unless separator == "\n" && limit == 65_537
      @reads += 1
      raise @read_error if @read_error
      line = @lines.shift
      raise IOError, "synthetic EOF still has an original writer" if line.nil? && @writer && !@writer.descriptor_retired
      @events << [line.nil? ? :eof : :line, @role]
      line
    end
  end

  class Model
    attr_reader :events, :endpoints, :spawn_calls, :wait_calls, :status, :pipe_calls
    attr_accessor :spawn_error, :wait_error, :nonblocking_unreaped, :second_pipe_error,
                  :wrong_wait_pid

    def initialize(lines: ["output\n"], code: 0, signal: nil)
      @events, @spawn_calls, @wait_calls = [], [], []
      @endpoints = [ModeledEndpoint.new(:stdin_read, @events), ModeledEndpoint.new(:stdin_write, @events),
                    ModeledEndpoint.new(:stdout_read, @events, lines), ModeledEndpoint.new(:stdout_write, @events)]
      @endpoints[2].writer = @endpoints[3]
      @status = ModeledStatus.new(4141, signal.nil? ? code : nil, signal)
      @pipe_calls = 0
    end

    def pipe
      @pipe_calls += 1
      raise @second_pipe_error if @pipe_calls == 2 && @second_pipe_error
      raise "unexpected additional pipe" unless @pipe_calls.between?(1, 2)
      @endpoints.slice((@pipe_calls - 1) * 2, 2)
    end

    def spawn(command, **options)
      @spawn_calls << [command, options]
      @events << [:spawn]
      raise @spawn_error if @spawn_error
      @status.pid
    end

    def wait(pid, flags)
      @wait_calls << [pid, flags]
      @events << [:wait, flags]
      raise @wait_error if @wait_error
      return nil if @nonblocking_unreaped && flags == Process::WNOHANG
      [@wrong_wait_pid || pid, @status]
    end
  end

  def invocation(upload: false)
    Lifetime::Invocation.new(lane: "ios_testflight_internal", nonce: "n" * 16,
      output: "/model/store-receipt.json", mode: upload ? "execute" : nil,
      run_deadline_ns: upload ? MobileReleaseKit::NativeUploadProcess.monotonic_ns + 60_000_000_000 : nil)
  end

  def bound_ios_dispatch(record, expires:)
    # The real capture/observation and strict result acceptance are used. Only
    # native execution and the inert artifact's size/digest are modeled.
    native, adapter = MobileReleaseKit::NativeUploadValidation, MobileReleaseKit::IosUploadValidation
    type = native.const_get(:CaptureSession, false)
    artifact, digest = "/model/original.ipa", "b" * 64
    output = JSON.generate("documentType" => "ios-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64, "ipaSha256" => digest, "ipaSize" => 1,
      "notBefore" => "2020-01-01T00:00:00Z", "notAfter" => expires.iso8601).freeze
    binding = record.reserve_current_validation!(role: "current-ios", adapter: adapter,
      environment: {}, argv: ["inert-validator"], tooling_directory: "/model", intent_sha256: "a" * 64, artifact: artifact)
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
    Lifetime.stub(:current_invocation, record) do
      type.stub(:new, constructor) do
        returned = native.capture({}, ["inert-validator"], "/model", max_seconds: 1,
          max_output_bytes: 1024, label: "inert", failure_message: "inert", store_binding: binding)
        File.stub(:size, 1) do
          Digest::SHA256.stub(:file, Struct.new(:hexdigest).new(digest)) do
            binding.accept_result!(adapter: adapter, output: returned)
          end
        end
      end
    end
    record.begin_ios_transporter_dispatch!(command: "inert-upload", artifact: artifact)
  end

  def modeled(model)
    no_process_operation = ->(*) { raise "unexpected process operation in inert adapter test" }
    IO.stub(:pipe, -> { model.pipe }) do
      Process.stub(:spawn, ->(command, **options) { model.spawn(command, **options) }) do
        Process.stub(:waitpid2, ->(pid, flags) { model.wait(pid, flags) }) do
          Process.stub(:kill, no_process_operation) do
            Process.stub(:detach, no_process_operation) do
              Process.stub(:setsid, no_process_operation) { yield }
            end
          end
        end
      end
    end
  end

  def original_error(type = IOError)
    cause = ArgumentError.new("synthetic original cause")
    primary = type == SystemExit ? SystemExit.new(19, "synthetic close exit") : type.new("synthetic close failure")
    begin
      raise primary, cause: cause
    rescue Exception => observed # rubocop:disable Lint/RescueException
      assert_same primary, observed
    end
    primary
  end

  def pending_close_delivery(error)
    # Synchronous original-method seam, not Thread#raise or asynchronous
    # delivery. Only the first direct close boundary loses its return/unwind.
    original, depth, delivered = Thread.method(:handle_interrupt), 0, false
    wrapper = lambda do |policy, &body|
      outer = depth.zero?
      depth += 1
      begin
        original.call(policy, &body)
      ensure
        depth -= 1
        if outer && !delivered
          delivered = true
          raise error, cause: error.cause
        end
      end
    end
    Thread.stub(:handle_interrupt, wrapper) { yield }
    assert delivered
  end

  def test_inherited_group_wiring_bounded_view_eof_close_then_original_wait
    nonowning = ModeledEndpoint.new(:stdout_write, [])
    nonowning.autoclose = false
    assert_nil nonowning.close
    assert nonowning.closed?
    refute nonowning.descriptor_retired, "wrapper closure is not descriptor retirement"
    reader = ModeledEndpoint.new(:stdout_read, [])
    reader.writer = nonowning
    assert_raises(IOError) { reader.gets("\n", 65_537) }

    record = invocation
    lines = ["stdout\n", "stderr\n", "\xff\x00tail".b]
    model = Model.new(lines: lines)
    seen = []
    modeled(model) do
      assert_equal 0, record.spawn_with_pipes("synthetic-command") { |stdout, stdin, pid|
        assert stdin.closed?
        refute_respond_to stdin, :fileno
        refute_respond_to stdin, :reopen
        refute_respond_to stdout, :close
        refute_respond_to stdout, :to_io
        assert_equal 4141, pid
        stdout.each { |line| seen << line }
      }
    end
    assert_equal lines, seen
    command, options = model.spawn_calls.fetch(0)
    assert_equal "synthetic-command", command
    assert command.frozen?
    assert_equal({in: model.endpoints[0], out: model.endpoints[3], err: model.endpoints[3], close_others: true}, options)
    model.endpoints.each do |endpoint|
      assert_equal [false, true], endpoint.flag_calls
      assert_equal [true], endpoint.close_flags
      assert endpoint.close_calls == 1 && endpoint.descriptor_retired && endpoint.closed? && endpoint.close_on_exec
    end
    assert_operator model.events.index([:eof, :stdout_read]), :<, model.events.index([:wait, 0])
    assert_operator model.events.index([:close, :stdout_read]), :<, model.events.index([:wait, 0])
    assert_equal [[4141, 0]], model.wait_calls
    assert record.require_adapter_continuation!
    refute record.adapters_sealed_and_retired?
    assert record.seal_adapters!
    assert record.adapters_sealed_and_retired?
  end

  def test_short_callback_is_drained_without_exposing_remaining_private_output
    model, record = Model.new(lines: ["one\n", "two\n"]), invocation
    modeled(model) { assert_equal 0, record.spawn_with_pipes("synthetic-command") { |_stdout, _stdin, _pid| nil } }
    assert_equal 3, model.endpoints[2].reads
    assert_operator model.events.index([:eof, :stdout_read]), :<, model.events.index([:wait, 0])
    assert record.require_adapter_continuation!
  end

  def test_real_wait_result_policy_distinguishes_nonzero_and_signaled_from_unknown
    model, record = Model.new(code: 23), invocation
    modeled(model) { assert_equal 23, record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each {} } }
    refute record.unknown?
    assert record.require_adapter_continuation!

    model, record = Model.new(signal: 15), invocation
    error = modeled(model) do
      assert_raises(Lifetime::CommandExitError) { record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each {} } }
    end
    assert_same model.status, error.process_status
    assert_equal(-1, error.exit_status)
    refute record.unknown?
    assert record.require_adapter_continuation!
  end

  def test_callback_failure_stays_unknown_after_fastlane_style_error_conversion_and_reap
    model, record = Model.new, invocation
    primary = IOError.new("synthetic private callback detail")
    modeled(model) do
      error = assert_raises(Lifetime::LifetimeError) do
        record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each {}; raise primary }
      end
      assert record.unknown? # Already latched before an ordinary upstream rescue.
      assert_same primary, error.primary
      refute_includes error.message, primary.message
      upstream_error = StandardError.new("upstream converted the adapter error")
      assert upstream_error
      assert_same error, assert_raises(Lifetime::LifetimeError) { record.require_adapter_continuation! }
      before = model.spawn_calls.length
      assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("another-command") {} }
      assert_equal before, model.spawn_calls.length
    end
    assert_equal [[4141, Process::WNOHANG]], model.wait_calls
    assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
  end

  def test_original_interrupt_or_system_exit_outlives_later_cleanup_failure
    [original_error(Interrupt), original_error(SystemExit)].each do |primary|
      model, record = Model.new, invocation
      cause = primary.cause
      cleanup = IOError.new("synthetic close failure")
      model.endpoints[2].close_error = cleanup
      disarm = IOError.new("synthetic disarm failure")
      model.endpoints[2].disarm_error = disarm
      observed = modeled(model) do
        assert_raises(primary.class) { record.spawn_with_pipes("synthetic-command") { raise primary } }
      end
      assert_same primary, observed
      assert_same primary, record.first_primary
      assert_same cause, primary.cause
      assert_includes record.cleanup_errors, cleanup
      assert_includes record.cleanup_errors, disarm
      assert_includes record.secondary_errors, cleanup
      assert_includes record.secondary_errors, disarm
      assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
      assert model.endpoints[2].autoclose, "failed disarm retains the original armed model"
      adapter = record.instance_variable_get(:@adapters).fetch(0)
      assert_same model.endpoints[2], adapter.instance_variable_get(:@stdout_read).io
      assert_same primary, assert_raises(primary.class) { record.require_adapter_continuation! }
      assert_equal 19, primary.status if primary.is_a?(SystemExit)
    end
  end

  def test_nonlocal_callback_exit_cannot_bypass_failure_latching
    model, record = Model.new, invocation
    modeled(model) do
      assert_raises(Lifetime::LifetimeError) do
        record.spawn_with_pipes("synthetic-command") { break :false_success }
      end
    end
    assert record.unknown?
    assert_equal [[4141, Process::WNOHANG]], model.wait_calls
    assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
  end

  def test_one_close_failure_does_not_skip_other_original_endpoints_or_enter_callback
    cuts = %i[before after interrupt system_exit arm arm_nonlocal arm_unconfirmed
              close_nonlocal disarm_error disarm_nonlocal nonnil closed_unconfirmed]
    cuts.each do |cut|
      model, record = Model.new, invocation
      io = model.endpoints.first
      primary = original_error(cut == :interrupt ? Interrupt : cut == :system_exit ? SystemExit : IOError)
      cause = primary.cause
      secondary = IOError.new("synthetic independent disarm error")
      case cut
      when :before, :interrupt, :system_exit then io.close_error = primary
      when :after then io.close_error, io.close_after_effect = primary, true
      when :arm then io.arm_error = primary
      when :arm_nonlocal then io.arm_nonlocal = true
      when :arm_unconfirmed then io.arm_confirmed = false
      when :close_nonlocal then io.close_nonlocal = true
      when :disarm_error then io.close_error, io.disarm_error = primary, secondary
      when :disarm_nonlocal then io.close_error, io.disarm_nonlocal = primary, true
      when :nonnil then io.close_return = false
      when :closed_unconfirmed then io.closed_report = false
      end
      called = false
      error = catch(:store_close_nonlocal) do
        modeled(model) do
          assert_raises(%i[interrupt system_exit].include?(cut) ? primary.class : Lifetime::LifetimeError) do
            record.spawn_with_pipes("synthetic-command") { called = true }
          end
        end
      end
      assert_kind_of Exception, error, "#{cut} escaped independent cleanup"
      refute called
      if %i[before after interrupt system_exit arm disarm_error disarm_nonlocal].include?(cut)
        assert_same primary, record.first_primary
        assert_same cause, primary.cause
      else
        assert_instance_of Lifetime::LifetimeError, record.first_primary
      end
      assert record.unknown?
      assert_equal(%i[arm arm_nonlocal arm_unconfirmed].include?(cut) ? 0 : 1, io.close_calls)
      assert_equal [false, true, false], io.flag_calls
      assert model.endpoints.drop(1).all? { |endpoint| endpoint.close_calls == 1 && endpoint.descriptor_retired }
      assert_equal [[4141, Process::WNOHANG]], model.wait_calls
      assert_includes record.cleanup_errors, record.first_primary
      assert_includes record.cleanup_errors, secondary if cut == :disarm_error
      assert_operator record.cleanup_errors.length, :>=, 2 if %i[after disarm_nonlocal nonnil closed_unconfirmed].include?(cut)
      assert_equal record.cleanup_errors.map(&:object_id).uniq, record.cleanup_errors.map(&:object_id)
      assert record.cleanup_errors.frozen?
      refute_same record.cleanup_errors, record.cleanup_errors
      adapters = record.instance_variable_get(:@adapters)
      endpoint = adapters.fetch(0).instance_variable_get(:@stdin_read)
      assert_same io, endpoint.io
      assert_equal :unknown, endpoint.state
      before = [io.close_calls, io.flag_calls.dup, record.cleanup_errors]
      endpoint.close_once
      assert_equal before, [io.close_calls, io.flag_calls, record.cleanup_errors]
      refute endpoint.retired?
      refute record.adapters_sealed_and_retired?
      assert io.autoclose if %i[disarm_error disarm_nonlocal].include?(cut)
    end

    [[0, nil], [1, nil], [2, nil], [-1, nil], ["81", nil], [81.0, nil], [81, 4141]].each do |fd, pid|
      model, record = Model.new, invocation
      io = model.endpoints.first
      io.fileno_value, io.pid_value = fd, pid
      modeled(model) do
        assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") { flunk "invalid original FD entered callback" } }
      end
      assert_equal 0, io.close_calls
      assert_equal [false, false], io.flag_calls
      refute io.descriptor_retired
      assert model.endpoints.drop(1).all?(&:descriptor_retired)
      assert record.unknown?
    end

    [false, true].each do |earlier_failure|
      record, io = invocation, ModeledEndpoint.new(:stdin_read, [])
      endpoint = Lifetime.const_get(:Endpoint, false).new(record)
      endpoint.bind(io)
      endpoint.prepare
      primary, pending = original_error, original_error(Interrupt)
      cause, pending_cause = primary.cause, pending.cause
      secondary = IOError.new("synthetic independent disarm failure before pending delivery")
      io.close_error = primary if earlier_failure
      io.disarm_error = secondary if earlier_failure
      pending_close_delivery(pending) { endpoint.close_once }
      assert_same(earlier_failure ? primary : pending, record.first_primary)
      assert_same cause, primary.cause
      assert_same pending_cause, pending.cause
      assert_includes record.cleanup_errors, pending
      assert_includes record.cleanup_errors, secondary if earlier_failure
      assert_equal 3, record.cleanup_errors.length if earlier_failure
      assert_equal 1, io.close_calls
      assert_equal [false, true, false], io.flag_calls
      assert_equal !earlier_failure, io.descriptor_retired
      assert_equal :unknown, endpoint.state
      assert_same io, endpoint.io
      before = [io.close_calls, io.flag_calls.dup, record.cleanup_errors]
      endpoint.close_once
      assert_equal before, [io.close_calls, io.flag_calls, record.cleanup_errors]
      refute endpoint.retired?
    end
  end

  def test_creation_failure_or_lost_return_never_adopts_or_waits_a_guessed_pid
    [IOError.new("synthetic creation failure"), Interrupt.new("synthetic lost return")].each do |primary|
      model, record = Model.new, invocation
      model.spawn_error = primary
      observed = modeled(model) do
        assert_raises(primary.is_a?(Interrupt) ? Interrupt : Lifetime::LifetimeError) do
          record.spawn_with_pipes("synthetic-command") { flunk "creation failure reached callback" }
        end
      end
      assert_same primary, primary.is_a?(Interrupt) ? observed : observed.primary
      assert record.unknown?
      assert_empty model.wait_calls
      assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
    end
  end

  def test_wait_failure_or_foreign_result_is_never_retried_or_changed_into_success
    [Errno::ECHILD.new("synthetic wait uncertainty"), :foreign_result].each do |fault|
      model, record = Model.new, invocation
      fault == :foreign_result ? model.wrong_wait_pid = 9999 : model.wait_error = fault
      error = modeled(model) do
        assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each {} } }
      end
      assert_same fault, error.primary unless fault == :foreign_result
      assert_equal [[4141, 0]], model.wait_calls
      assert record.unknown?
      assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
    end
  end

  def test_pending_child_after_failed_callback_is_not_detached_or_given_a_new_timeout
    model, record = Model.new, invocation
    model.nonblocking_unreaped = true
    primary = IOError.new("synthetic callback failure")
    error = modeled(model) do
      assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") { raise primary } }
    end
    assert_same primary, error.primary
    assert_equal [[4141, Process::WNOHANG]], model.wait_calls
    assert record.unknown?
    refute_empty record.cleanup_errors
    assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
  end

  def test_second_pipe_acquisition_failure_closes_only_acquired_original_endpoints
    model, record = Model.new, invocation
    primary = IOError.new("synthetic pipe allocation failure")
    model.second_pipe_error = primary
    error = modeled(model) do
      assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") {} }
    end
    assert_same primary, error.primary
    assert_equal [1, 1, 0, 0], model.endpoints.map(&:close_calls)
    assert_empty model.spawn_calls
    assert_empty model.wait_calls
    assert record.unknown?
  end

  def test_line_and_aggregate_output_limits_fail_before_unbounded_callback_retention
    [["x" * 65_537], Array.new(65, "x" * 65_535 + "\n")].each_with_index do |lines, index|
      model, record = Model.new(lines: lines), invocation
      count = 0
      modeled(model) do
        assert_raises(Lifetime::LifetimeError) do
          record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each { |_line| count += 1 } }
        end
      end
      assert_equal(index.zero? ? 0 : 64, count)
      assert record.unknown?
      assert_equal [[4141, Process::WNOHANG]], model.wait_calls
    end
  end

  def test_read_failure_cannot_be_ignored_as_historical_pty_eio
    model, record = Model.new, invocation
    primary = Errno::EIO.new("synthetic ordinary-pipe read failure")
    model.endpoints[2].read_error = primary
    error = modeled(model) do
      assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") { |stdout| stdout.each {} } }
    end
    assert_same primary, error.primary
    assert record.unknown?
    assert_equal [[4141, Process::WNOHANG]], model.wait_calls
  end

  def test_sealed_admission_and_reentrant_callback_refuse_before_another_creation
    model, record = Model.new, invocation
    assert record.seal_adapters!
    modeled(model) { assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("synthetic-command") {} } }
    assert_empty model.spawn_calls
    assert_equal 0, model.pipe_calls

    model, record = Model.new, invocation
    modeled(model) do
      assert_raises(Lifetime::LifetimeError) do
        record.spawn_with_pipes("synthetic-command") { record.spawn_with_pipes("nested-command") {} }
      end
    end
    assert_equal 1, model.spawn_calls.length
    assert record.unknown?
  end

  def test_foreign_origin_cannot_change_parent_latch_and_stale_view_cannot_read
    record = invocation
    original_pid = Process.pid
    Process.stub(:pid, original_pid + 1) do
      assert_raises(Lifetime::LifetimeError) { record.mark_unknown!(IOError.new("foreign model")) }
    end
    refute record.unknown?

    model = Model.new
    retained_view = nil
    modeled(model) { record.spawn_with_pipes("synthetic-command") { |stdout| retained_view = stdout; stdout.each {} } }
    reads = model.endpoints[2].reads
    assert_raises(Lifetime::LifetimeError) { retained_view.each {} }
    assert_equal reads, model.endpoints[2].reads
    assert record.unknown?
  end

  def test_original_dispatch_expiry_after_final_pipe_configuration_has_no_native_attempt
    [0, 1].each do |past_expiry|
      model, record = Model.new, invocation(upload: true)
      clock = Time.utc(2026, 9, 16, 12)
      expiry = clock + 1
      Time.stub(:now, -> { clock }) do
        command = bound_ios_dispatch(record, expires: expiry)
        original = model.endpoints.last.method(:close_on_exec=)
        model.endpoints.last.define_singleton_method(:close_on_exec=) do |value|
          original.call(value)
          clock = expiry + past_expiry
        end
        error = modeled(model) do
          assert_raises(Lifetime::IosDispatchRefused) do
            record.spawn_with_pipes(command) { flunk "expired send reached callback" }
          end
        end
        assert_same error, record.first_primary
        refute record.unknown?
        assert record.require_upload_continuation!
        assert record.instance_variable_get(:@adapters).all?(&:retired?)
        assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
        assert_empty model.spawn_calls
        assert_empty model.wait_calls
        assert model.endpoints.all? { |endpoint| endpoint.reads.zero? }
        record.end_ios_transporter_dispatch!
        modeled(model) do
          assert_same error, assert_raises(Lifetime::IosDispatchRefused) { record.spawn_with_pipes(command) {} }
        end
        assert_equal 2, model.pipe_calls
        assert record.seal_uploads!
        assert record.uploads_sealed_and_retired?
      end
    end
  end

  def test_original_no_send_refusal_is_primary_when_an_independent_pipe_close_fails
    model, record = Model.new, invocation(upload: true)
    clock = Time.utc(2026, 9, 16, 12)
    Time.stub(:now, -> { clock }) do
      command = bound_ios_dispatch(record, expires: clock + 1)
      clock += 1
      cleanup = IOError.new("original no-send close uncertainty")
      model.endpoints.first.close_error = cleanup
      error = modeled(model) do
        assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes(command) {} }
      end
      assert_instance_of Lifetime::IosDispatchRefused, record.first_primary
      assert_same record.first_primary, error.primary
      assert_includes record.cleanup_errors, cleanup
      assert record.unknown?
      assert model.endpoints.all? { |endpoint| endpoint.close_calls == 1 }
      assert_empty model.spawn_calls
      assert_empty model.wait_calls
      refute record.uploads_sealed_and_retired?
    end
  end

  def test_scoped_transporter_command_cannot_be_replaced_or_dispatched_twice
    [false, true].each do |second_send|
      model, record = Model.new, invocation(upload: true)
      command = bound_ios_dispatch(record, expires: Time.now.utc + 60)
      modeled(model) do
        record.spawn_with_pipes(command) { |stdout| stdout.each {} } if second_send
        assert_raises(Lifetime::LifetimeError) do
          record.spawn_with_pipes(second_send ? command : command.dup) {}
        end
      end
      assert_equal(second_send ? 1 : 0, model.spawn_calls.length)
      assert_equal(second_send ? 2 : 0, model.pipe_calls)
      assert record.unknown?
    end
  end

  def test_only_original_gate_can_retire_no_send_and_valid_dispatch_can_finish_after_expiry
    model, record = Model.new, invocation
    forged = Lifetime::IosDispatchRefused.new(StandardError.new("not issued by original gate"))
    model.second_pipe_error = forged
    modeled(model) do
      assert_same forged, assert_raises(Lifetime::LifetimeError) { record.spawn_with_pipes("inert-upload") {} }.primary
    end
    assert record.unknown?
    refute record.adapters_sealed_and_retired?

    model, record = Model.new, invocation(upload: true)
    clock = Time.utc(2026, 9, 16, 12)
    Time.stub(:now, -> { clock }) do
      command = bound_ios_dispatch(record, expires: clock + 1)
      modeled(model) do
        assert_equal 0, record.spawn_with_pipes(command) { |stdout| clock += 2; stdout.each {} }
      end
      record.end_ios_transporter_dispatch!
      assert_equal 1, model.spawn_calls.length
      assert record.require_ios_dispatch_not_refused!
      assert record.require_upload_continuation!
      assert record.seal_uploads!
      assert record.uploads_sealed_and_retired?
      refute record.unknown?
    end
  end
end
