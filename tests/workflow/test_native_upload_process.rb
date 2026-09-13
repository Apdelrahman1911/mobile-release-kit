# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "fcntl"
require "digest"
require_relative "../../fastlane/native_upload_process"

# This file's fixed healthy/singleton captures do not rely on an assumed
# Minitest failfast option. Every actual case crosses this effect-free entry
# gate; a failed case or retained UNKNOWN permits reporting, never a new case.
module NativeUploadFixtureGuard
  @reuse_forbidden = false
  @retained_cases = []
  FAILURE_LOCATION = %r{\A(?:(?:/[^/:\x00-\x1f\x7f]+)*/)?(tests/workflow/test_native_upload_process\.rb|fastlane/native_upload_process\.rb|fastlane/native_process_spawn\.rb):([1-9][0-9]{0,5})(?::in [`'][^\x00-\x1f\x7f]*')?\z}n.freeze

  def self.before_case!
    raise "native owner fixture reuse forbidden after an adverse case" if @reuse_forbidden
  end

  def self.forbid_reuse!(test)
    @reuse_forbidden = true
    @retained_cases << test
  end

  def self.custody_retained?
    !NativeUploadRoleTest::RETAINED.empty? || !NativeUploadTaskSlotTest::RETAINED.empty?
  end

  def self.report_failure_locations(result)
    return if result.instance_variable_get(:@mrk_failure_locations_attempted)

    # Result-local, so inert controls cannot consume the actual capture's
    # report. The unchanged first-adverse-case veto prevents another real one.
    result.instance_variable_set(:@mrk_failure_locations_attempted, true)
    failures = result.failures
    return unless failures.instance_of?(Array)

    locations = []
    failures.first(4).each do |failure|
      backtrace = failure.backtrace
      next unless backtrace.instance_of?(Array)

      backtrace.first(32).each do |row|
        next unless row.instance_of?(String) && row.bytesize <= 1_024

        match = FAILURE_LOCATION.match(row.b)
        next unless match
        next if row.split(":", 2).first.split("/").any? { |part| part == "." || part == ".." }

        location = "#{match[1]}:#{match[2]}"
        locations << location unless locations.include?(location)
        break if locations.length == 4
      end
      break if locations.length == 4
    end
    return if locations.empty?

    output = "\nMRK_NATIVE_OWNER_FAILURE_LOCATIONS=\n" + locations.join("\n") + "\n"
    return unless output.ascii_only? && output.bytesize <= 1_024

    # Ordinary captured output AFTER original teardown and the reuse veto.
    # No flush, retry, descriptor change, native observation or finality claim.
    STDERR.write(output)
    nil
  rescue Exception
    nil # Optional diagnostics must not replace the original adverse result.
  end

  def run
    NativeUploadFixtureGuard.before_case!
    begin
      result = super
      unless passed? && !NativeUploadFixtureGuard.custody_retained?
        NativeUploadFixtureGuard.forbid_reuse!(self)
        NativeUploadFixtureGuard.report_failure_locations(result)
      end
      result
    rescue Exception
      NativeUploadFixtureGuard.forbid_reuse!(self)
      raise
    end
  end
end

class NativeUploadProtocolTest < Minitest::Test
  prepend NativeUploadFixtureGuard
  Owner = MobileReleaseKit::NativeUploadProcess
  Protocol = Owner::Protocol
  SIGNAL_LIMIT = 65

  def configuration(role = "custodian")
    {
      "v" => 1, "type" => "CONFIG", "role" => role, "cwd" => "/fixture",
      "validator_argv" => ["/fixture/python", "-I", "-S", "-c", "print('fixture')"],
      "validator_env" => { "LANG" => "C", "LC_ALL" => "C" },
      "run_deadline_ns" => 50_000_000_000, "hard_cleanup_deadline_ns" => 55_000_000_000,
      "max_output_bytes" => 65_536, "capture_kind" => "native",
    }
  end

  def simple(type)
    { "v" => 1, "type" => type }
  end

  def child(pid, code = 0)
    { "state" => "reaped", "pid" => pid, "status_kind" => "exit", "status_code" => code }
  end

  def terminal(outcome = "ok", code: 0)
    {
      "v" => 1, "type" => "FINAL", "outcome" => outcome, "cleanup" => "confirmed",
      "keeper" => child(102), "validator" => child(103, code),
      "group" => { "state" => "retired", "id" => 102, "absent" => true },
    }
  end

  def normal_prefix
    [
      { "v" => 1, "type" => "HELLO", "pid" => 101, "ppid" => 100, "sid" => 101, "pgid" => 101, "fd_map_version" => 1 },
      { "v" => 1, "type" => "RESERVED", "keeper_pid" => 102, "group_id" => 102, "session_id" => 101 },
      { "v" => 1, "type" => "READY", "validator_pid" => 103, "group_id" => 102, "keeper_pgid" => 101 },
      { "v" => 1, "type" => "STATUS", "validator_pid" => 103, "status_kind" => "exit", "status_code" => 0 },
    ]
  end

  def encoded(frame, direction)
    Protocol.encode(frame, direction: direction, nsig: SIGNAL_LIMIT)
  end

  def decoded(frames, direction)
    decoder = Protocol::Decoder.new(direction: direction, nsig: SIGNAL_LIMIT)
    result = decoder.feed(frames.map { |frame| encoded(frame, direction) }.join)
    assert decoder.eof
    result
  end

  def rejected(frame, direction)
    error = assert_raises(Owner::ProtocolError) { encoded(frame, direction) }
    assert_equal "native capture protocol failure", error.message
  end

  def raw_rejected(payload, direction)
    decoder = Protocol::Decoder.new(direction: direction, nsig: SIGNAL_LIMIT)
    error = assert_raises(Owner::ProtocolError) { decoder.feed([payload.bytesize].pack("N") + payload.b) }
    assert_equal "native capture protocol failure", error.message
    assert_equal 0, decoder.frame_count
    assert_raises(Owner::ProtocolError) { decoder.feed("".b) }
    assert_raises(Owner::ProtocolError) { decoder.eof }
  end

  def test_incremental_framing_freezes_exact_terminal_records
    frames = normal_prefix + [terminal]
    bytes = frames.map { |frame| encoded(frame, :c_to_o) }.join
    decoder = Protocol::Decoder.new(direction: :c_to_o, nsig: SIGNAL_LIMIT)
    observed = []
    bytes.bytes.each_slice(7) { |part| observed.concat(decoder.feed(part.pack("C*"))) }
    assert_equal frames, observed
    assert_equal 5, decoder.frame_count
    assert observed.all?(&:frozen?)
    assert observed.last.fetch("validator").frozen?
    assert observed.last.fetch("validator").keys.all?(&:frozen?)
    assert decoder.eof
  end

  def test_configuration_is_bounded_data_not_a_helper_option_source
    frame = configuration
    frame["validator_argv"] << "--enable=rubyopt"
    frame["validator_argv"] << "\nprivate fixture data\n"
    result = decoded([frame], :o_to_c).first
    assert_equal frame, result
    assert result.fetch("validator_argv").frozen?
    assert result.fetch("validator_env").frozen?
    assert_raises(FrozenError) { result.fetch("validator_env")["NEW"] = "value" }
    frame.fetch("validator_env")["LANG"] = "changed"
    assert_equal "C", result.fetch("validator_env").fetch("LANG")
  end

  def test_duplicate_keys_are_rejected_at_every_nesting_level
    config = JSON.generate(configuration)
    last_environment = configuration
    last_environment.fetch("validator_env")["LANG"] = "private-protocol-marker"
    cases = [
      [config.sub('"v":1') { '"v":1,"\\u0076":1' }, configuration, :o_to_c],
      [config.sub('"LANG":"C"', '"LANG":"C","LANG":"private-protocol-marker"'), last_environment, :o_to_c],
      ['{"v":1,"type":"RELEASED","validator":{"state":"unknown","state":"not_attempted"}}',
       simple("RELEASED").merge("validator" => { "state" => "not_attempted" }), :k_to_c],
      ['{"v":1,"type":"RELEASED","validator":{"state":"reaped","pid":1,"pid":2,"status_kind":"exit","status_code":0}}',
       simple("RELEASED").merge("validator" => child(2)), :k_to_c],
    ]
    cases.each do |payload, last_wins, direction|
      # A schema/order failure must not masquerade as duplicate rejection.
      assert_equal [last_wins], decoded([last_wins], direction)
      raw_rejected(payload, direction)
    end
  end

  def test_closed_schema_rejects_missing_extra_and_old_flattened_fields
    rejected(simple("ADMIT").merge("private" => "private-protocol-marker"), :o_to_c)
    rejected(simple("ADMIT").reject { |key, _| key == "v" }, :o_to_c)
    rejected(configuration.merge("module_path" => "/untrusted"), :o_to_c)
    old = {
      "v" => 1, "type" => "FINAL", "outcome" => "ok", "cleanup" => "confirmed",
      "group_absent" => true, "keeper_pid" => 102, "keeper_status_kind" => "exit", "keeper_status_code" => 0,
    }
    rejected(old, :c_to_o)
    rejected(terminal.merge("group_absent" => true), :c_to_o)
    rejected(terminal.reject { |key, _| key == "validator" }, :c_to_o)
  end

  def test_pid_status_enum_and_boolean_types_are_strict
    [true, false, 0, -1, 2_147_483_648, 1.0, "101", nil].each do |value|
      rejected(normal_prefix.first.merge("pid" => value), :c_to_o)
    end
    [true, 0, "1", 1.0].each { |value| rejected(simple("ADMIT").merge("v" => value), :o_to_c) }
    rejected(normal_prefix.first.merge("fd_map_version" => true), :c_to_o)
    rejected(normal_prefix[1].merge("group_id" => 104), :c_to_o)
    ["success", "stopped", nil].each do |kind|
      rejected(normal_prefix.last.merge("status_kind" => kind), :c_to_o)
    end
    [true, -1, 256, 0.0, nil].each do |code|
      rejected(normal_prefix.last.merge("status_code" => code), :c_to_o)
    end
    [0, SIGNAL_LIMIT, true, 1.0].each do |code|
      rejected(normal_prefix.last.merge("status_kind" => "signal", "status_code" => code), :c_to_o)
    end
    rejected(terminal.merge("group" => { "state" => "retired", "id" => 102, "absent" => 1 }), :c_to_o)
  end

  def test_invalid_lengths_truncation_encoding_and_post_eof_input_fail_closed
    [0, Protocol::CONFIG_LIMIT + 1, 0xffff_ffff].each do |length|
      decoder = Protocol::Decoder.new(direction: :o_to_c, nsig: SIGNAL_LIMIT)
      assert_raises(Owner::ProtocolError) { decoder.feed([length].pack("N")) }
    end
    ["\0".b, encoded(configuration, :o_to_c).byteslice(0, 13)].each do |partial|
      decoder = Protocol::Decoder.new(direction: :o_to_c, nsig: SIGNAL_LIMIT)
      assert_empty decoder.feed(partial)
      assert_raises(Owner::ProtocolError) { decoder.eof }
      assert_raises(Owner::ProtocolError) { decoder.feed("".b) }
    end
    decoder = Protocol::Decoder.new(direction: :o_to_c, nsig: SIGNAL_LIMIT)
    assert decoder.eof
    assert_raises(Owner::ProtocolError) { decoder.feed("".b) }
    raw_rejected("\xff".b, :o_to_c)
    raw_rejected('{"v":1,"type":"ADMIT"} {"v":1,"type":"RUN"}', :o_to_c)
    raw_rejected(JSON.generate(simple("ADMIT")) + " " * Protocol::FRAME_LIMIT, :o_to_c)
  end

  def test_wrong_edges_duplicate_messages_and_out_of_order_frames_are_rejected
    rejected(simple("RUN"), :k_to_c)
    rejected(normal_prefix[1], :c_to_k)
    rejected(configuration("keeper"), :o_to_c)
    assert_raises(Owner::ProtocolError) { decoded([simple("ADMIT")], :o_to_c) }
    assert_raises(Owner::ProtocolError) { decoded([normal_prefix[2]], :c_to_o) }
    assert_raises(Owner::ProtocolError) { decoded(normal_prefix + [normal_prefix.last], :c_to_o) }
    assert_raises(Owner::ProtocolError) { decoded(normal_prefix + [terminal, terminal], :c_to_o) }
    assert_raises(Owner::ProtocolError) { decoded([configuration, configuration], :o_to_c) }
  end

  def test_commit_and_release_are_requests_not_terminal_cancellation_barriers
    cancel = simple("CANCEL").merge("reason_code" => "cancelled", "cleanup_deadline_ns" => 51_000_000_000)
    outer = [configuration, simple("ADMIT"), simple("RUN"), simple("COMMIT"), cancel]
    assert_equal outer, decoded(outer, :o_to_c)
    retired = simple("GROUP_RETIRED").merge("group_id" => 102, "absent" => true)
    keeper = [configuration("keeper"), simple("RUN"), retired, simple("RELEASE"), cancel]
    assert_equal keeper, decoded(keeper, :c_to_k)
    assert_raises(Owner::ProtocolError) { decoded(outer + [cancel], :o_to_c) }
  end

  def test_cancellation_and_retirement_cannot_reopen_run
    cancel = simple("CANCEL").merge("reason_code" => "deadline", "cleanup_deadline_ns" => 51_000_000_000)
    retired = simple("GROUP_RETIRED").merge("group_id" => 102, "absent" => true)
    assert_raises(Owner::ProtocolError) { decoded([configuration, simple("ADMIT"), cancel, simple("RUN")], :o_to_c) }
    assert_raises(Owner::ProtocolError) { decoded([configuration("keeper"), retired, simple("RUN")], :c_to_k) }
    assert_raises(Owner::ProtocolError) { decoded([configuration("keeper"), cancel, simple("RUN")], :c_to_k) }
    assert_raises(Owner::ProtocolError) { decoded([configuration("keeper"), simple("RELEASE")], :c_to_k) }
    assert_equal [cancel], decoded([cancel], :o_to_c)
    assert_raises(Owner::ProtocolError) { decoded([cancel, configuration], :o_to_c) }

    # Decision/transport models only: allocated C, inert endpoints and no native
    # receipts. The genuine process/EOF/wait matrix remains a separate owner run.
    with_inert_keeper_control_effects_rejected do
      Owner.stub(:monotonic_ns, -> { 1_000_000_000 }) do
        Process.stub(:ppid, 100) do
          released = simple("RELEASED").merge("validator" => child(103))
          fixture = inert_keeper_control(reads: [encoded(released, :k_to_c), :wait_readable, nil])
          role, channel, reader, writer = fixture.values_at(:role, :channel, :reader, :writer)
          channel.queue(configuration("keeper"))
          channel.queue(simple("RUN"))
          role.send(:flush_keeper)
          assert channel.written?("RUN")
          primary = IOError.new("inert original operation error")
          role.send(:fail!, "deadline", error: primary, cutoff: 3_000_000_000)
          role.send(:send_keeper_cancel)
          history = keeper_control_history(channel)
          original_fail = role.method(:fail!)
          role.define_singleton_method(:fail!) do |*arguments, **keywords|
            raise "terminal callback preceded retirement" unless channel.writes_retired?
            raise "terminal callback preceded accounting" unless @released

            send(:queue_keeper, { "v" => 1, "type" => "RUN" })
            send(:flush_keeper)
            original_fail.call(*arguments, **keywords)
          end
          role.send(:receive_keeper)
          assert_equal released, role.instance_variable_get(:@released)
          assert channel.writes_retired?
          refute channel.eof?, "RELEASED does not imply status EOF"
          refute channel.write_failed?
          assert channel.pending?, "retirement must not fabricate publication"
          assert_equal history, keeper_control_history(channel)
          assert_same primary, role.instance_variable_get(:@first_error)
          assert_equal 3_000_000_000, role.send(:effective_deadline_ns)
          refute role.instance_variable_get(:@release_requested)
          assert_equal 1, writer.closes
          assert_equal :open, reader.state
          assert_inert_keeper_route_retired(fixture)
          keeper_record, group_record = child(102, 2), { "state" => "retired", "id" => 102, "absent" => true }
          refute role.send(:records_confirmed?, keeper_record, child(103), group_record)
          refute role.send(:own_resources_settled?)
          role.send(:receive_keeper)
          assert channel.eof?
          assert_equal 1, reader.closes
          assert role.send(:records_confirmed?, keeper_record, child(103), group_record)
          assert role.send(:own_resources_settled?)
          assert_equal history, keeper_control_history(channel)
          refute role.instance_variable_get(:@release_requested)
          assert_same primary, role.instance_variable_get(:@first_error)
          assert_equal 3_000_000_000, role.send(:effective_deadline_ns)

          # Keep every original finality conjunction: a terminal, EOF and an
          # obsolete writer alone cannot repair bad/missing cleanup operands.
          [child(102, 1), child(102).merge("status_kind" => "signal", "status_code" => 9),
           { "state" => "unknown" }].each do |record|
            refute role.send(:records_confirmed?, record, child(103), group_record)
          end
          refute role.send(:records_confirmed?, keeper_record, { "state" => "unknown" }, group_record)
          refute role.send(:records_confirmed?, keeper_record, child(103), group_record.merge("absent" => false))
          role.instance_variable_set(:@released, nil)
          refute role.send(:records_confirmed?, keeper_record, child(103), group_record)
          role.instance_variable_set(:@released, released)
          writer.state = :unknown
          refute role.send(:own_resources_settled?)
          writer.state = :closed
          role.instance_variable_set(:@settled, {})
          refute role.send(:own_resources_settled?)
          role.instance_variable_set(:@settled, { fixture.fetch(:acquisition).object_id => true })
          unjoined = Object.new
          unjoined.define_singleton_method(:start_attempted?) { true }
          unjoined.define_singleton_method(:joined?) { false }
          role.instance_variable_set(:@slots, [unjoined])
          refute role.send(:own_resources_settled?)
          role.instance_variable_set(:@slots, [])
          role.instance_variable_set(:@cleanup_unknown, true)
          refute role.send(:own_resources_settled?)

          # The pre-observation EPIPE disposition is fixed on FIRST retirement.
          # A later terminal must neither clear write_failed nor poison the same
          # already-classified transport merely because write_failed is now true.
          closed = Errno::EPIPE.new
          fixture = inert_keeper_control(writes: [closed])
          role, channel, writer = fixture.values_at(:role, :channel, :writer)
          channel.queue(configuration("keeper"))
          role.send(:flush_keeper)
          assert_same closed, channel.write_error
          assert channel.original_unfragmented_write_error?(closed)
          assert channel.write_failed?
          assert channel.writes_retired?
          assert channel.write_attempted?("CONFIG")
          refute channel.written?("CONFIG")
          assert channel.pending?
          assert_same closed, role.instance_variable_get(:@first_error)
          assert role.instance_variable_get(:@failed)
          refute role.instance_variable_get(:@cleanup_unknown)
          refute role.send(:own_resources_settled?)
          assert_equal 1, writer.closes
          cutoff = role.send(:effective_deadline_ns)
          history = keeper_control_history(channel)
          not_attempted = { "state" => "not_attempted" }
          early = simple("RELEASED").merge("validator" => not_attempted)
          fixture.fetch(:reads).concat([encoded(early, :k_to_c), :wait_readable, nil])
          role.send(:receive_keeper)
          refute channel.eof?
          refute role.send(:records_confirmed?, keeper_record, not_attempted, group_record)
          role.send(:receive_keeper)
          assert channel.eof?
          assert role.send(:records_confirmed?, keeper_record, not_attempted, group_record)
          assert role.send(:own_resources_settled?)
          refute role.instance_variable_get(:@cleanup_unknown)
          assert_equal history, keeper_control_history(channel)
          assert_same closed, role.instance_variable_get(:@first_error)
          assert_equal cutoff, role.send(:effective_deadline_ns)
          refute role.instance_variable_get(:@release_requested)
          assert_equal 1, writer.closes
          assert_inert_keeper_route_retired(fixture)

          # A positively recorded prefix or prior failure is not the clean
          # pre-call context above. Neither terminal observation can repair it.
          partial_error = Errno::EPIPE.new
          fixture = inert_keeper_control(writes: [1, :wait_writable, partial_error])
          role, channel = fixture.values_at(:role, :channel)
          channel.queue(configuration("keeper"))
          role.send(:flush_keeper)
          assert channel.partial_frame?
          prefix = keeper_control_history(channel)
          role.send(:flush_keeper)
          assert_same partial_error, channel.write_error
          refute channel.original_unfragmented_write_error?(partial_error)
          assert_equal prefix, keeper_control_history(channel)
          assert role.instance_variable_get(:@cleanup_unknown)
          role.send(:accept_released, early)
          assert role.instance_variable_get(:@cleanup_unknown)
          assert_inert_keeper_route_retired(fixture)

          [:partial, :prior_failure, :prior_unknown].each do |mode|
            script = mode == :partial ? [1, :wait_writable] : [mode == :prior_unknown ? Errno::EPIPE.new : IOError.new]
            fixture = inert_keeper_control(writes: script)
            role, channel = fixture.values_at(:role, :channel)
            channel.queue(configuration("keeper"))
            if mode == :partial
              role.send(:flush_keeper)
            elsif mode == :prior_failure
              assert_raises(IOError) { channel.flush(deadline_ns: 55_000_000_000, launch_allowed: -> { true }) }
            else
              role.instance_variable_set(:@cleanup_unknown, true)
              role.send(:flush_keeper)
            end
            role.send(:accept_released, early)
            assert role.instance_variable_get(:@cleanup_unknown), mode.to_s
            assert_inert_keeper_route_retired(fixture)
          end

          # Identical errno is insufficient: accessor, callback, encoder and
          # post-return publication exceptions never came from the actual write.
          [:accessor, :callback, :encoder, :publication, :other_write, :invalid_return].each do |mode|
            error = mode == :other_write ? IOError.new("inert write error") : Errno::EPIPE.new
            returned = Object.new
            returned.define_singleton_method(:==) { |_other| raise error }
            scripted = case mode
                       when :publication then [returned]
                       when :other_write then [error]
                       when :invalid_return then [nil]
                       else []
                       end
            fixture = inert_keeper_control(writes: scripted)
            role, channel, writer = fixture.values_at(:role, :channel, :writer)
            if mode == :encoder
              Protocol.stub(:encode, ->(*_arguments, **_keywords) { raise error }) do
                refute role.send(:queue_keeper, configuration("keeper"))
              end
            else
              channel.queue(configuration("keeper"))
              if mode == :callback
                role.send(:flush_keeper)
                channel.queue(simple("RUN"))
                role.define_singleton_method(:launch_allowed?) { raise error }
              elsif mode == :accessor
                writer.define_singleton_method(:io) { raise error }
              end
              role.send(:flush_keeper)
            end
            assert role.instance_variable_get(:@cleanup_unknown), mode.to_s
            assert channel.writes_retired?, mode.to_s
            assert_equal 1, writer.closes, mode.to_s
            refute channel.original_unfragmented_write_error?(error) unless mode == :other_write
            assert_same error, role.instance_variable_get(:@first_error) unless mode == :invalid_return
            assert_inert_keeper_route_retired(fixture)
          end

          # An eligible transport failure still cannot hide an owned close
          # failure or suppress that close when error-recording callbacks unwind.
          [:close_failure, :recording_unwind].each do |mode|
            error = Errno::EPIPE.new
            fixture = inert_keeper_control(writes: [error])
            role, channel, writer = fixture.values_at(:role, :channel, :writer)
            channel.queue(configuration("keeper"))
            if mode == :close_failure
              writer.close_error = IOError.new("inert close error")
              role.send(:flush_keeper)
              assert_equal :unknown, writer.state
            else
              recording = RuntimeError.new("inert recording unwind")
              original_fail = role.method(:fail!)
              role.define_singleton_method(:fail!) do |*arguments, **keywords|
                raise "write failure callback preceded retirement" unless channel.writes_retired?

                send(:queue_keeper, { "v" => 1, "type" => "RUN" })
                send(:flush_keeper)
                original_fail.call(*arguments, **keywords)
                raise recording
              end
              close_body = writer.method(:close_once)
              writer.define_singleton_method(:close_once) do
                raise "owned close preceded retirement" unless channel.writes_retired?

                role.send(:flush_keeper)
                close_body.call
              end
              assert_same recording, assert_raises(RuntimeError) { role.send(:flush_keeper) }
              assert_equal :closed, writer.state
            end
            assert channel.original_unfragmented_write_error?(error)
            assert_same error, role.instance_variable_get(:@first_error)
            assert role.instance_variable_get(:@cleanup_unknown)
            refute role.send(:own_resources_settled?)
            role.send(:retire_keeper_writes)
            assert_equal 1, writer.closes
            assert_inert_keeper_route_retired(fixture)
          end

          # Retirement during an ordinary launch callback cannot permit the
          # pending RUN (or a later callback) to reach even this inert endpoint.
          fixture = inert_keeper_control
          role, channel = fixture.values_at(:role, :channel)
          channel.queue(configuration("keeper"))
          role.send(:flush_keeper)
          channel.queue(simple("RUN"))
          calls = fixture.fetch(:writes).dup
          channel.flush(deadline_ns: 55_000_000_000, launch_allowed: -> { channel.retire_writes!; true })
          assert_equal calls, fixture.fetch(:writes)
          refute channel.write_attempted?("RUN")
          refute channel.written?("RUN")
          refute channel.retire_writes!, "retirement is irreversible and idempotent"
          refute channel.flush(deadline_ns: 55_000_000_000, launch_allowed: -> { flunk "retired callback" })
          assert_raises(Owner::ProtocolError) { role.send(:receive_command, simple("RUN")) }
          refute role.instance_variable_get(:@run_forwarded)
          role.send(:retire_keeper_writes)
          assert_inert_keeper_route_retired(fixture)

          # A malformed/extra status stream is still adverse after retirement;
          # the terminal is never a substitute for reading its actual tail.
          fixture = inert_keeper_control(reads: [encoded(early, :k_to_c), :wait_readable,
                                                 encoded(early, :k_to_c), nil])
          role = fixture.fetch(:role)
          role.send(:receive_keeper)
          refute role.instance_variable_get(:@cleanup_unknown)
          role.send(:receive_keeper)
          assert role.instance_variable_get(:@cleanup_unknown)
          assert fixture.fetch(:channel).read_failed?
          refute fixture.fetch(:channel).eof?
        end
      end
    end
  end

  def test_early_failed_final_is_truthful_without_fabricated_success_phases
    no_attempt = terminal("failed").merge(
      "keeper" => { "state" => "not_attempted" }, "validator" => { "state" => "not_attempted" },
      "group" => { "state" => "not_created" },
    )
    assert_equal [no_attempt], decoded([no_attempt], :c_to_o)
    assert_raises(Owner::ProtocolError) { decoded([terminal], :c_to_o) }
    early_reaped = terminal("failed").merge("validator" => child(103, 1))
    assert_equal [early_reaped], decoded([early_reaped], :c_to_o)
    assert_raises(Owner::ProtocolError) { decoded([early_reaped, normal_prefix.first], :c_to_o) }
  end

  def test_no_attempt_records_cannot_hide_a_native_attempt_or_claim_success
    no_keeper = terminal("failed").merge("keeper" => { "state" => "not_attempted" })
    rejected(no_keeper, :c_to_o)
    no_validator = terminal("failed").merge("validator" => { "state" => "not_attempted" })
    assert_equal [no_validator], decoded([no_validator], :c_to_o)
    rejected(no_validator.merge("outcome" => "ok"), :c_to_o)
    rejected(no_validator.merge("outcome" => "rejected"), :c_to_o)
    not_created = no_validator.merge("group" => { "state" => "not_created" })
    assert_equal [not_created], decoded([not_created], :c_to_o)
    rejected(not_created.merge("validator" => child(103)), :c_to_o)
    rejected(no_validator.merge("validator" => { "state" => "not_attempted", "pid" => 0 }), :c_to_o)
  end

  def test_unknown_child_group_or_absence_forces_unknown_failed_cleanup
    %w[keeper validator group].each do |name|
      unknown = terminal("failed").merge(name => { "state" => "unknown" })
      rejected(unknown, :c_to_o)
      accepted = unknown.merge("cleanup" => "unknown")
      assert_equal [accepted], decoded([accepted], :c_to_o)
      rejected(accepted.merge("outcome" => "ok"), :c_to_o)
    end
    unresolved = terminal("failed").merge("group" => { "state" => "retired", "id" => 102, "absent" => false })
    rejected(unresolved, :c_to_o)
    assert_equal [unresolved.merge("cleanup" => "unknown")], decoded([unresolved.merge("cleanup" => "unknown")], :c_to_o)
    rejected(terminal.merge("group" => { "state" => "retired", "id" => 104, "absent" => true }), :c_to_o)
  end

  def test_rejection_requires_ordinary_validator_exit_and_confirmed_cleanup
    prefix = normal_prefix
    prefix.last["status_code"] = 7
    rejected_result = terminal("rejected", code: 7)
    assert_equal prefix + [rejected_result], decoded(prefix + [rejected_result], :c_to_o)
    rejected(terminal("rejected"), :c_to_o)
    rejected(rejected_result.merge("cleanup" => "unknown"), :c_to_o)
    signalled = rejected_result.merge("validator" => child(103).merge("status_kind" => "signal", "status_code" => 9))
    rejected(signalled, :c_to_o)
    rejected(terminal.merge("keeper" => child(102, 1)), :c_to_o)
    rejected(terminal.merge("validator" => child(103, 1)), :c_to_o)
  end

  def test_released_requires_one_exact_validator_record_not_an_empty_ack
    [{ "state" => "not_attempted" }, { "state" => "unknown" }, child(103)].each do |record|
      frame = simple("RELEASED").merge("validator" => record)
      assert_equal [frame], decoded([frame], :k_to_c)
    end
    rejected(simple("RELEASED"), :k_to_c)
    rejected(simple("RELEASED").merge("validator" => nil), :k_to_c)
    rejected(simple("RELEASED").merge("validator" => { "state" => "unknown", "status_code" => 0 }), :k_to_c)
    rejected(simple("RELEASED").merge("validator" => child(0)), :k_to_c)
  end

  def test_configuration_enforces_independent_collection_value_path_and_deadline_bounds
    rejected(configuration.merge("validator_argv" => []), :o_to_c)
    rejected(configuration.merge("validator_argv" => ["/fixture/v"] + [""] * 64), :o_to_c)
    rejected(configuration.merge("validator_argv" => ["/fixture/v", "x" * 8_193]), :o_to_c)
    rejected(configuration.merge("validator_argv" => ["/fixture/v"] + ["x" * 8_191] * 8), :o_to_c)
    rejected(configuration.merge("validator_argv" => ["relative"]), :o_to_c)
    rejected(configuration.merge("validator_env" => (1..65).to_h { |index| ["K#{index}", ""] }), :o_to_c)
    rejected(configuration.merge("validator_env" => { "A=B" => "value" }), :o_to_c)
    rejected(configuration.merge("validator_env" => { "A" => "private\0marker" }), :o_to_c)
    rejected(configuration.merge("validator_env" => (1..8).to_h { |index| ["K#{index}", "x" * 8_192] }), :o_to_c)
    rejected(configuration.merge("cwd" => "/private\nmarker"), :o_to_c)
    rejected(configuration.merge("cwd" => "relative"), :o_to_c)
    rejected(configuration.merge("capture_kind" => "profile"), :o_to_c)
    rejected(configuration.merge("run_deadline_ns" => true), :o_to_c)
    rejected(configuration.merge("run_deadline_ns" => 0), :o_to_c)
    rejected(configuration.merge("hard_cleanup_deadline_ns" => 55_000_000_001), :o_to_c)
    rejected(configuration.merge("hard_cleanup_deadline_ns" => 49_999_999_999), :o_to_c)
    [0, true, 65_537].each { |limit| rejected(configuration.merge("max_output_bytes" => limit), :o_to_c) }
  end

  def test_helper_argv_and_environment_have_no_ambient_startup_or_path_fallback
    context = { parent_pid: 100, session_id: 90 }
    deadlines = { run_deadline_ns: 50_000_000_000, hard_cleanup_deadline_ns: 55_000_000_000 }
    argv = Owner.helper_argv(role: "custodian", parent_context: context, deadlines: deadlines)
    assert_equal File.realpath(RbConfig.ruby), argv.first
    assert_equal Owner::HELPER_FLAGS, argv[1, Owner::HELPER_FLAGS.length]
    assert_equal "--", argv[4]
    assert_equal File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__)), argv[5]
    assert_equal ["custodian", "100", "90", "50000000000", "55000000000"], argv[6..]
    assert argv.frozen?
    assert argv.all?(&:frozen?)
    assert_equal({ "LANG" => "C", "LC_ALL" => "C", "TZ" => "UTC" }, Owner.helper_environment)
    assert Owner.helper_environment.frozen?
    assert_raises(Owner::ProtocolError) { Owner.helper_argv(role: "--enable=gems", parent_context: context, deadlines: deadlines) }
    assert_raises(Owner::ProtocolError) { Owner.helper_argv(role: "keeper", parent_context: context.merge(path: "/application"), deadlines: deadlines) }
    assert_raises(Owner::ProtocolError) { Owner.helper_argv(role: "keeper", parent_context: context.merge(parent_pid: true), deadlines: deadlines) }
  end

  private

  def with_inert_keeper_control_effects_rejected(&body)
    effects = []
    reject = lambda do |*_arguments, **_keywords|
      effects << :unexpected_effect
      raise "inert keeper-control model attempted an effect"
    end
    operations = [[Owner, :native], [Owner, :nsig], [Owner::Custodian, :new], [Owner::Keeper, :new],
                  [Thread, :new], [Thread, :start], [Owner::TaskSlot, :retain],
                  [File, :open], [File, :read], [File, :binread], [File, :write],
                  [IO, :pipe], [IO, :new], [IO, :for_fd], [Process, :spawn], [Process, :fork],
                  [Process, :kill], [Process, :waitpid], [Process, :waitpid2],
                  [Process, :setsid], [Process, :setpgid], [Process, :getsid], [Process, :getpgid],
                  [Process, :clock_gettime], [Signal, :trap]]
    enter = lambda do |index|
      if index == operations.length
        body.call
      else
        object, name = operations.fetch(index)
        object.stub(name, reject) { enter.call(index + 1) }
      end
    end
    enter.call(0)
    assert_empty effects, "a rescued error swallowed an inert-effect tripwire"
  end

  def inert_keeper_control(reads: [], writes: [])
    # No descriptor numbers or native child/group instances exist in this model.
    calls = []
    input, output = Object.new, Object.new
    input.define_singleton_method(:read_nonblock) do |_size, exception:|
      raise "blocking model read" unless exception == false

      reads.empty? ? :wait_readable : reads.shift
    end
    output.define_singleton_method(:write_nonblock) do |bytes, exception:|
      raise "blocking model write" unless exception == false

      calls << bytes.dup.freeze
      result = writes.empty? ? bytes.bytesize : writes.shift
      raise result if result.is_a?(Exception)

      result
    end
    lease_type = Struct.new(:state, :io, :closes, :close_error) do
      def process_lifetime?
        false
      end

      def close_once
        self.closes += 1
        self.state = close_error ? :unknown : :closed
        raise close_error if close_error

        true
      end
    end
    reader, writer = lease_type.new(:open, input, 0, nil), lease_type.new(:open, output, 0, nil)
    channel = Owner::Channel.new(reader: reader, writer: writer, incoming: :k_to_c, outgoing: :c_to_k, nsig: SIGNAL_LIMIT)
    acquisition = Struct.new(:resources).new({ reader: reader, writer: writer })
    parent_channel = Object.new
    parent_channel.define_singleton_method(:written?) { |type| type == "RESERVED" }
    group = Struct.new(:id).new(102)
    group.define_singleton_method(:retired?) { false }
    role = Owner::Custodian.allocate
    { pid: 101, parent_pid: 100, run_deadline_ns: 50_000_000_000, hard_cleanup_deadline_ns: 55_000_000_000,
      cleanup_unknown: false, failed: false, first_error: nil, cleanup_deadline_ns: nil,
      terminal_started: false, slots: [], acquisitions: [acquisition], roles: {},
      settled: { acquisition.object_id => true }, close_attempted: {}, keeper_channel: channel,
      keeper: Struct.new(:pid).new(102), keeper_hello: true, group: group, parent_channel: parent_channel,
      release_requested: false, run_forwarded: false, cleanup_started: false, group_routes_retired: false,
      cancel_sent: false }.each { |name, value| role.instance_variable_set(:"@#{name}", value) }
    { role: role, channel: channel, reader: reader, writer: writer, reads: reads, writes: calls, acquisition: acquisition }
  end

  def keeper_control_history(channel)
    [channel.instance_variable_get(:@queue).map(&:dup),
     channel.instance_variable_get(:@write_attempted).dup, channel.instance_variable_get(:@written_types).dup]
  end

  def assert_inert_keeper_route_retired(fixture)
    role, channel = fixture.values_at(:role, :channel)
    history, writes = keeper_control_history(channel), fixture.fetch(:writes).dup
    assert channel.writes_retired?
    [configuration("keeper"), simple("RUN"), simple("CANCEL"), simple("GROUP_RETIRED"), simple("RELEASE")].each do |frame|
      assert_raises(Owner::LifecycleError) { channel.queue(frame) }
      refute role.send(:queue_keeper, frame)
    end
    original_group = role.instance_variable_get(:@group)
    original_routes = role.instance_variable_get(:@group_routes_retired)
    release_requested = role.instance_variable_get(:@release_requested)
    retired_group = Struct.new(:id).new(102)
    retired_group.define_singleton_method(:retired?) { true }
    retired_group.define_singleton_method(:absent?) { true }
    begin
      role.instance_variable_set(:@group, retired_group)
      role.instance_variable_set(:@group_routes_retired, true)
      role.send(:send_keeper_cancel)
      role.send(:release_keeper)
      role.send(:flush_keeper)
      assert_equal release_requested, role.instance_variable_get(:@release_requested)
    ensure
      role.instance_variable_set(:@group, original_group)
      role.instance_variable_set(:@group_routes_retired, original_routes)
    end
    refute channel.flush(deadline_ns: 55_000_000_000, launch_allowed: -> { flunk "retired launch callback" })
    assert_equal history, keeper_control_history(channel)
    assert_equal writes, fixture.fetch(:writes)
  end
end

# A direct native O fixture, not a Process.spawn/Open3 wrapper. Its only child
# is the actual C acquired by the production leaf. It NEVER signals C or G,
# discovers children by numeric lookup, or fabricates a join/EOF/wait receipt.
# All process-bearing methods below are disposable-hosted-owner selectors.
class NativeUploadRoleHarness
  Owner = MobileReleaseKit::NativeUploadProcess
  attr_reader :directory, :slot, :acquisition, :channel, :frames, :stdout, :stderr,
              :run_deadline_ns, :hard_deadline_ns, :receipt, :map_facts, :collision_count

  def initialize(directory:, validator:, seconds: 4.0, helper: nil, collision_source: nil)
    @directory = directory
    @validator = validator
    @run_deadline_ns = Owner.monotonic_ns + (seconds * 1_000_000_000).to_i
    @hard_deadline_ns = @run_deadline_ns + Owner::CLEANUP_GRACE_NS
    @helper = helper
    @collision_source = collision_source
    @collision_count = 0
    @slot = Owner::TaskSlot.new(run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_deadline_ns)
    @acquisition = Owner.native::Acquisition.new(owner_slot: @slot, run_deadline_ns: @run_deadline_ns,
                                                hard_cleanup_deadline_ns: @hard_deadline_ns)
    @frames = []
    @stdout = +"".b
    @stderr = +"".b
    @eof = { stdout: false, stderr: false }
    @finish_attempted = @finished_creation = false
    @channel = @receipt = nil
    @cancel_sent = @wait_broken = false
    @close_attempted = {}
    @map_facts = nil
  end

  def launch(configure: true)
    native = Owner.native
    @slot.start do
      %i[stdin stdout stderr].each do |name|
        native.null(@acquisition, role: :"null_#{name}", access: name == :stdin ? :read : :write)
      end
      %i[control status stdin stdout stderr].each do |name|
        native.pipe(@acquisition, read_role: :"#{name}_read", write_role: :"#{name}_write")
      end
      resources = @acquisition.resources
      names = %i[null_stdin null_stdout null_stderr control_read status_write stdin_read stdout_write stderr_write]
      sources = names.map { |name| resources.fetch(name) }
      @map_facts = sources.map do |source|
        stat = source.io.stat
        { "dev" => stat.dev, "ino" => stat.ino, "kind" => stat.ftype,
          "mode" => source.io.fcntl(Fcntl::F_GETFL, 0) & Fcntl::O_ACCMODE }
      end.freeze
      install_collision_actions if @collision_source
      argv = Owner.helper_argv(role: "custodian", parent_context: { parent_pid: Process.pid, session_id: Process.getsid(0) },
                               deadlines: { run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_deadline_ns }).dup
      argv[5] = @helper if @helper # Explicitly labeled copied-helper variant.
      spec = native::SpawnSpec.new(executable: argv.first, argv: argv, env: Owner.helper_environment, fd_sources: sources)
      native.create(@acquisition, spec)
    end
    raise "native fixture was not admitted" unless @slot.admit!
    settle_creator
    raise @slot.first_error if @slot.first_error
    raise "native fixture has no acquired C" unless @acquisition.child

    send_configuration if configure
    self
  end

  def configuration
    { "v" => 1, "type" => "CONFIG", "role" => "custodian", "cwd" => @directory,
      "validator_argv" => @validator, "validator_env" => Owner.helper_environment,
      "run_deadline_ns" => @run_deadline_ns, "hard_cleanup_deadline_ns" => @hard_deadline_ns,
      "max_output_bytes" => Owner::MAX_OUTPUT_BYTES, "capture_kind" => "native" }
  end

  def send_configuration
    send_frame(configuration)
  end

  def send_command(type, fields = {})
    @cancel_sent = true if type == "CANCEL"
    send_frame({ "v" => 1, "type" => type }.merge(fields))
  end

  def send_frame(frame)
    @channel.queue(frame)
    until !@channel.pending?
      raise "original fixture control cutoff exceeded" if Owner.monotonic_ns >= @hard_deadline_ns

      @channel.flush(deadline_ns: @hard_deadline_ns, launch_allowed: -> { Owner.monotonic_ns < @run_deadline_ns })
      pump
      sleep(0.002) if @channel.pending?
    end
    true
  end

  def send_invalid_configuration
    # Deliberately malformed opposite-role CONFIG, over only the owned pipe.
    payload = JSON.generate(configuration.merge("role" => "keeper")).b
    bytes = [payload.bytesize].pack("N") + payload
    offset = 0
    while offset < bytes.bytesize
      raise "invalid-frame test exceeded original cutoff" if Owner.monotonic_ns >= @run_deadline_ns

      returned = @acquisition.resources.fetch(:control_write).io.write_nonblock(bytes.byteslice(offset..), exception: false)
      if returned == :wait_writable
        pump
        sleep(0.002)
      else
        raise "invalid-frame write failed" unless returned.instance_of?(Integer) && returned.positive?

        offset += returned
      end
    end
  end

  def wait_frame(type)
    await { frame(type) }
  end

  def frame(type)
    @frames.find { |value| value.fetch("type") == type }
  end

  def await
    loop do
      pump
      value = yield
      return value if value
      raise "native fixture exceeded original hard deadline" if Owner.monotonic_ns >= @hard_deadline_ns

      sleep(0.002)
    end
  end

  def close_stdin
    close_lease(@acquisition.resources[:stdin_write])
  end

  def close_control
    close_lease(@acquisition.resources[:control_write])
  end

  def data_eof?
    @eof.values.all?
  end

  def pump
    return unless @finished_creation

    if @channel
      @channel.read_frames.each { |value| @frames << value }
      close_lease(@channel.reader) if @channel.eof?
      close_control if frame("FINAL")
      terminal_validator = frame("FINAL")&.fetch("validator")
      close_stdin if terminal_validator && %w[reaped not_attempted].include?(terminal_validator.fetch("state"))
    end
    drain(:stdout)
    drain(:stderr)
    child = @acquisition.child
    if child && !@receipt && !@wait_broken && Owner.monotonic_ns < @hard_deadline_ns
      begin
        child.retire_numeric!
        @receipt = child.poll_wait
      rescue Exception
        @wait_broken = true
        raise
      end
    end
    @receipt
  end

  def finish
    await { @receipt && @channel&.eof? && data_eof? }
    close_control
    close_stdin
    close_originals
    self
  end

  def physical_owner_settled?
    creator_sources_released? && @receipt && @channel&.eof? && data_eof? &&
      @acquisition.resources.values.all? { |lease| %i[closed not_acquired].include?(lease.state) }
  end

  def creator_sources_released?
    @slot.joined? && @finished_creation
  end

  def confirmed?
    final = frame("FINAL")
    return false unless final && final.fetch("cleanup") == "confirmed" && physical_owner_settled?

    @receipt.status_kind.to_s == "exit" && @receipt.status_code == (final.fetch("outcome") == "failed" ? 2 : 0)
  end

  def shutdown
    return self if physical_owner_settled?

    @slot.cancel!(reason_code: "cancelled") unless @slot.joined?
    settle_creator unless @finish_attempted
    if @channel && !frame("FINAL") && !@cancel_sent && @channel.writer.state == :open &&
       !@channel.write_failed? && Owner.monotonic_ns < @hard_deadline_ns
      @cancel_sent = true
      send_command("CANCEL", "reason_code" => "cancelled",
                             "cleanup_deadline_ns" => [Owner.monotonic_ns + Owner::CLEANUP_GRACE_NS, @hard_deadline_ns].min)
    end
    close_control if @finished_creation
    close_stdin if frame("READY")
    finish if @finished_creation && @acquisition.child && !@wait_broken
    close_originals if @finished_creation
    self
  end

  private

  def settle_creator
    raise "actual fixture creator did not join" unless @slot.join_until(deadline_ns: @hard_deadline_ns)
    unless @finish_attempted
      @finish_attempted = true
      @finished_creation = @acquisition.finish_creation!(creator_slot: @slot) == true
    end
    raise "fixture native creation UNKNOWN" unless @finished_creation

    resources = @acquisition.resources
    %i[null_stdin null_stdout null_stderr control_read status_write stdin_read stdout_write stderr_write].each do |name|
      close_lease(resources[name])
    end
    if resources[:status_read]&.state == :open && resources[:control_write]&.state == :open
      @channel ||= Owner::Channel.new(reader: resources.fetch(:status_read), writer: resources.fetch(:control_write),
                                      incoming: :c_to_o, outgoing: :o_to_c, nsig: Owner.nsig)
    end
  end

  def close_lease(lease)
    return true unless lease
    return true if %i[closed not_acquired].include?(lease.state)
    raise "fixture close already uncertain" if @close_attempted[lease.object_id]

    @close_attempted[lease.object_id] = true
    lease.close_once
    raise "fixture endpoint close not confirmed" unless lease.state == :closed

    true
  end

  def close_originals
    @acquisition.resources.each_value { |lease| close_lease(lease) }
  end

  def drain(name)
    return if @eof.fetch(name)

    lease = @acquisition.resources[:"#{name}_read"]
    return unless lease && lease.state == :open

    32.times do
      returned = lease.io.read_nonblock(4_096, exception: false)
      if returned.nil?
        @eof[name] = true
        close_lease(lease)
        break
      end
      break if returned == :wait_readable
      raise "unexpected native fixture data return" unless returned.instance_of?(String)

      buffer = name == :stdout ? @stdout : @stderr
      buffer << returned
      raise "native fixture independent output cap exceeded" if buffer.bytesize > Owner::MAX_OUTPUT_BYTES
    end
  end

  def install_collision_actions
    source = @collision_source
    original = @acquisition.method(:native_call!)
    fixture = self
    injected = false
    @acquisition.define_singleton_method(:native_call!) do |name, *arguments, **keywords|
      if name == "posix_spawn_file_actions_adddup2" && !injected
        injected = true
        # CHILD-ONLY pre-map collisions. Never dup2 into the embedding MRI's
        # 0..7, and never explicitly inherit a high sentinel on Darwin.
        8.times do |destination|
          call = original.call(name, arguments.fetch(0), source.fileno, destination)
          raise "pre-map collision action failed" unless call.result == 0

          fixture.instance_variable_set(:@collision_count, fixture.collision_count + 1)
        end
      end
      original.call(name, *arguments, **keywords)
    end
    @acquisition.singleton_class.send(:private, :native_call!)
  end
end

# Every test in this class creates real native processes and owned descriptors.
# These selectors are intended for the disposable hosted owner, never a local
# fake-only batch. Copied-helper observations are explicitly labeled below.
# The eight deliberate UNKNOWN close/signal-fault selectors require fixed singleton
# captures; direct O settlement is not helper/group finality or reuse authority.
class NativeUploadRoleTest < Minitest::Test
  prepend NativeUploadFixtureGuard
  Owner = MobileReleaseKit::NativeUploadProcess
  RETAINED = {}
  HELPER_PATH = File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__))
  LEAF_PATH = File.realpath(File.expand_path("../../fastlane/native_process_spawn.rb", __dir__))

  def setup
    flunk "earlier native role fixture retained UNKNOWN custody; new work forbidden" unless RETAINED.empty?
    flunk "earlier Ruby task fixture retained custody; new native work forbidden" unless NativeUploadTaskSlotTest::RETAINED.empty?
    @directories = []
    @harnesses = []
    @owned_files = []
  end

  def teardown
    return unless @harnesses # The entry guard may have refused all new work.

    errors = []
    @harnesses.reverse_each do |harness|
      begin
        harness.shutdown
      rescue Exception => error
        errors << error
      end
    end
    # The collision sentinel may still be referenced by an in-flight original
    # native action. Conservatively retain every injected source unless all
    # original creators genuinely joined AND completed native settlement.
    sources_released = @harnesses.all?(&:creator_sources_released?)
    if sources_released
      @owned_files.each do |file|
        begin
          unless file.closed?
            returned = file.close
            raise "fixture original sentinel close not confirmed" unless returned.nil? && file.closed?
          end
        rescue Exception => error
          errors << error
        end
      end
    end
    @directories.each do |directory|
      owners = @harnesses.select { |value| value.directory == directory }
      removed = false
      begin
        if passed? && errors.empty? && sources_released && !owners.empty? && owners.all?(&:confirmed?)
          FileUtils.remove_entry(directory)
          removed = true
        end
      rescue Exception => error
        errors << error
      end
      unless removed
        # A removal error or earlier assertion cannot bypass the same-process
        # veto. The entry is never cleared to permit a later capture.
        RETAINED[directory] = [owners, @owned_files.dup, errors]
        warn "Preserve native-helper test artifacts: #{directory}"
      end
    end
    assert_empty errors, "native helper fixture cleanup did not settle"
    assert @harnesses.all?(&:physical_owner_settled?), "native fixture retained unresolved actual C/IO/task custody"
  end

  def test_native_real_session_group_movement_and_three_genuine_receipts
    # Exercise the default codec inside the existing owned, gem-disabled V;
    # this is not a claim that C rejected a malformed CONFIG.
    harness = build("require #{HELPER_PATH.dump}\n" + <<~'RUBY')
      require "json"
      raise "default JSON version differs" unless JSON::VERSION == "2.7.2"

      protocol = MobileReleaseKit::NativeUploadProcess::Protocol
      last_wins = { "v" => 1, "type" => "RELEASED", "validator" => { "state" => "not_attempted" } }
      payloads = [
        '{"v":1,"\\u0076":1,"type":"RELEASED","validator":{"state":"not_attempted"}}',
        '{"v":1,"type":"RELEASED","validator":{"state":"unknown","state":"not_attempted"}}',
      ]
      reject = lambda do |operation|
        begin
          operation.call
        rescue MobileReleaseKit::NativeUploadProcess::ProtocolError => error
          unless error.message == "native capture protocol failure"
            raise "default codec public error differs", cause: nil
          end
        rescue StandardError
          raise "default codec error type differs", cause: nil
        else
          raise "default codec accepted invalid input"
        end
      end
      payloads.each do |payload|
        control = protocol::Decoder.new(direction: :k_to_c, nsig: 65)
        accepted = control.feed(protocol.encode(last_wins, direction: :k_to_c, nsig: 65))
        unless accepted == [last_wins] && control.frame_count == 1 && control.eof
          raise "default codec positive control differs"
        end

        decoder = protocol::Decoder.new(direction: :k_to_c, nsig: 65)
        reject.call(-> { decoder.feed([payload.bytesize].pack("N") + payload.b) })
        raise "default codec admitted invalid frame" unless decoder.frame_count.zero?
        reject.call(-> { decoder.feed("".b) })
        reject.call(-> { decoder.eof })
      end

      STDOUT.sync = true
      STDOUT.puts(JSON.generate("pid" => Process.pid, "ppid" => Process.ppid,
                               "sid" => Process.getsid(0), "pgid" => Process.getpgrp))
      raise "test expected actual stdin EOF" unless STDIN.read.empty?
    RUBY
    hello, reserved, ready = run_to_ready(harness)
    assert_equal harness.acquisition.child.pid, hello.fetch("pid")
    assert_equal hello.fetch("pid"), Process.getsid(reserved.fetch("keeper_pid"))
    assert_equal hello.fetch("pid"), Process.getpgid(reserved.fetch("keeper_pid"))
    assert_equal reserved.fetch("keeper_pid"), reserved.fetch("group_id")
    assert_equal reserved.fetch("group_id"), ready.fetch("group_id")
    harness.close_stdin
    complete_success(harness)
    validator = JSON.parse(harness.stdout)
    assert_equal ready.fetch("validator_pid"), validator.fetch("pid")
    assert_equal reserved.fetch("keeper_pid"), validator.fetch("ppid")
    assert_equal hello.fetch("pid"), validator.fetch("sid")
    assert_equal reserved.fetch("group_id"), validator.fetch("pgid")
    assert_success_receipts(harness)
  end

  def test_native_writer_holding_descendant_is_cleaned_before_commit_and_real_eof
    harness = build(<<~'RUBY')
      STDOUT.sync = STDERR.sync = true
      raise "test expected actual stdin EOF" unless STDIN.read.empty?
      reader, writer = IO.pipe # Created after V exec; never an inherited V FD.
      Process.fork do
        reader.close
        STDOUT.write("descendant-live\n")
        STDERR.write("independent-error-stream\n")
        writer.write("R")
        writer.close
        sleep 8 # Production C must KILL this writer before the original run cap.
        Process.exit!(77)
      end
      writer.close
      raise "bounded post-exec readiness failed" unless IO.select([reader], nil, nil, 1.0) && reader.read(1) == "R"
      reader.close
      Process.exit!(0)
    RUBY
    run_to_ready(harness)
    harness.close_stdin
    assert_equal 0, harness.wait_frame("STATUS").fetch("status_code")
    harness.await { harness.data_eof? }
    assert_nil harness.frame("FINAL"), "C improperly accepted before COMMIT"
    assert_nil harness.receipt, "C exited instead of awaiting the still-withheld COMMIT"
    assert_equal "descendant-live\n", harness.stdout
    assert_equal "independent-error-stream\n", harness.stderr
    assert_operator Owner.monotonic_ns, :<, harness.run_deadline_ns
    harness.send_command("COMMIT")
    harness.finish
    assert_success_receipts(harness)
  end

  def test_native_permanently_withheld_commit_finishes_failed_within_original_deadlines
    harness = build('STDOUT.write("ordinary-output"); STDIN.read; exit 0', seconds: 2.5)
    run_to_ready(harness)
    harness.close_stdin
    harness.wait_frame("STATUS")
    harness.await { harness.data_eof? }
    assert_nil harness.frame("FINAL")
    assert_nil harness.receipt
    harness.finish # No COMMIT is ever queued by this owner.
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal "reaped", final.fetch("keeper").fetch("state")
    assert_equal 0, final.fetch("validator").fetch("status_code")
    assert_equal 2, harness.receipt.status_code
    assert harness.confirmed?
    assert_operator Owner.monotonic_ns, :<, harness.hard_deadline_ns
  end

  def test_native_pre_admit_cancel_is_a_positive_never_attempted_keeper_branch
    harness = build('raise "validator must never execute"')
    harness.wait_frame("HELLO")
    cancel(harness)
    harness.finish
    final = harness.frame("FINAL")
    assert_equal({ "state" => "not_attempted" }, final.fetch("keeper"))
    assert_equal({ "state" => "not_attempted" }, final.fetch("validator"))
    assert_equal({ "state" => "not_created" }, final.fetch("group"))
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal "failed", final.fetch("outcome")
    assert_equal 2, harness.receipt.status_code
    assert harness.confirmed?
    assert_empty harness.stdout
    assert_empty harness.stderr
    assert_equal %w[HELLO FINAL], harness.frames.map { |frame| frame.fetch("type") }
  end

  def test_native_pre_run_cancel_reaps_the_real_keeper_without_creating_validator
    harness = build('raise "validator must never execute"')
    harness.wait_frame("HELLO")
    harness.send_command("ADMIT")
    reserved = harness.wait_frame("RESERVED")
    cancel(harness)
    harness.finish
    final = harness.frame("FINAL")
    assert_equal({ "state" => "reaped", "pid" => reserved.fetch("keeper_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("keeper"))
    assert_equal({ "state" => "not_attempted" }, final.fetch("validator"))
    assert_equal({ "state" => "retired", "id" => reserved.fetch("group_id"), "absent" => true }, final.fetch("group"))
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal 2, harness.receipt.status_code
    assert harness.confirmed?
    assert_nil harness.frame("READY")
    assert_nil harness.frame("STATUS")
    assert_empty harness.stdout
    assert_empty harness.stderr
  end

  def test_native_parent_control_eof_starts_pre_run_cleanup_without_commit
    # These controls stop at a Ruby decision seam, never a synthetic native
    # receipt. All stubs are restored before the genuine owned fixture below.
    with_inert_native_role_effects_rejected do
      assert_forwarded_parent_loss_decision
      assert_failure_location_reporting
    end
    harness = build('raise "validator must never execute"')
    harness.wait_frame("HELLO")
    harness.send_command("ADMIT")
    reserved = harness.wait_frame("RESERVED")
    harness.close_control
    harness.finish
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal({ "state" => "reaped", "pid" => reserved.fetch("keeper_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("keeper"))
    assert_equal({ "state" => "not_attempted" }, final.fetch("validator"))
    assert final.fetch("group").fetch("absent")
    assert_equal 2, harness.receipt.status_code
    assert harness.confirmed?
    assert_nil harness.frame("READY")
  end

  def test_native_invalid_configuration_fails_before_keeper_attempt_without_private_output
    harness = build('raise "validator must never execute"', configure: false)
    harness.wait_frame("HELLO")
    harness.send_invalid_configuration
    harness.finish
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal({ "state" => "not_attempted" }, final.fetch("keeper"))
    assert_equal({ "state" => "not_attempted" }, final.fetch("validator"))
    assert_equal 2, harness.receipt.status_code
    assert harness.confirmed?
    assert_empty harness.stdout
    assert_empty harness.stderr
  end

  def test_native_helpers_reset_their_own_inherited_ignore_and_postassert_waitability
    directory = new_directory
    helper = observed_helper(directory, reset_ignore: true)
    harness = build('STDIN.read; exit 0', directory: directory, helper: helper)
    run_to_ready(harness)
    harness.close_stdin
    complete_success(harness)
    assert_success_receipts(harness)
    %w[custodian keeper].each do |role|
      report = read_report(directory, role)
      assert_equal true, report.fetch("installedIgnoreBeforeBootstrap")
      refute_empty report.fetch("waitability")
      report.fetch("waitability").each do |record|
        assert_equal 0, record.fetch("result")
        # MRI DEFAULT is its own nonreaping handler, not SIG_DFL (0) or the
        # explicit ignored disposition (1); the pinned signal.c audit binds it.
        assert_operator record.fetch("handler"), :>, Owner.native.declared_abi.fetch("constants").fetch("SIG_IGN")
        assert_equal 0, record.fetch("flags") & Owner.native.declared_abi.fetch("constants").fetch("SA_NOCLDWAIT")
      end
      assert_equal true, report.fetch("productionTailReturned")
    end
  end

  def test_native_low_high_and_colliding_fd_sentinels_are_scrubbed_across_all_roles
    directory = new_directory
    sentinels = %w[outer custodian keeper].map { |role| File.join(directory, "#{role}.sentinel") }
    sentinels.each { |path| File.write(path, "public-test-sentinel", mode: "wb", perm: 0o600) }
    outer = File.open(sentinels.first, "rb")
    @owned_files << outer
    high = IO.for_fd(outer.fcntl(Fcntl::F_DUPFD, 128), "rb", autoclose: true)
    @owned_files << high
    high.close_on_exec = false
    flags_before = high.fcntl(Fcntl::F_GETFD, 0)
    assert_equal 0, flags_before & Fcntl::FD_CLOEXEC
    helper = observed_helper(directory, sentinel_paths: sentinels, outer_fd: high.fileno)
    script = <<~RUBY
      require "json"
      require "fcntl"
      sentinels = #{sentinels.inspect}
      expected = sentinels.map { |path| stat = File.stat(path); [stat.dev, stat.ino] }
      probe_wrappers = [] # Nonowning metadata only; never close arbitrary FDs.
      observations = [#{high.fileno}, 256, 384].map do |fd|
        begin
          wrapped = IO.for_fd(fd, autoclose: false)
          probe_wrappers << wrapped
          stat = wrapped.stat
          raise "foreign sentinel reached validator" if expected.include?([stat.dev, stat.ino])
          { "fd" => fd, "sentinelAbsent" => true }
        rescue Errno::EBADF
          { "fd" => fd, "sentinelAbsent" => true }
        end
      end
      standard = [STDIN, STDOUT, STDERR].map do |io|
        stat = io.stat
        { "dev" => stat.dev, "ino" => stat.ino, "kind" => stat.ftype,
          "mode" => io.fcntl(Fcntl::F_GETFL, 0) & Fcntl::O_ACCMODE }
      end
      STDIN.read
      STDOUT.write(JSON.generate("sentinels" => observations, "standard" => standard))
    RUBY
    harness = build(script, directory: directory, helper: helper, collision_source: high)
    run_to_ready(harness)
    assert_equal flags_before, high.fcntl(Fcntl::F_GETFD, 0), "production changed a foreign parent FD flag"
    assert_equal 8, harness.collision_count
    harness.close_stdin
    complete_success(harness)
    assert_success_receipts(harness)
    c, k = %w[custodian keeper].map { |role| read_report(directory, role) }
    [c, k].each do |report|
      assert_equal (0..7).to_a, report.fetch("map").map { |record| record.fetch("fd") }
      assert_equal [0, 1, 1, 0, 1, 0, 1, 1], report.fetch("map").map { |record| record.fetch("mode") }
      assert report.fetch("map").all? { |record| record.fetch("cloexec") }
      assert report.fetch("sentinels").all? { |record| record.fetch("sentinelAbsent") }
      assert_equal true, report.fetch("foreignSourcesReleased")
      assert_equal 0, report.fetch("foreignFlagsAtClose") & Fcntl::FD_CLOEXEC
      assert_equal true, report.fetch("foreignOriginalClosed")
      assert_equal true, report.fetch("productionTailReturned")
    end
    assert_equal 8, c.fetch("childPreMapCollisions")
    assert_equal 3, k.fetch("childPreMapCollisions")
    assert_equal harness.map_facts, c.fetch("map").map { |record| record.reject { |key, _| %w[fd cloexec].include?(key) } }
    assert_equal c.fetch("childControlSourceIdentity"), k.fetch("map").fetch(3).values_at("dev", "ino")
    assert_equal c.fetch("childStatusSourceIdentity"), k.fetch("map").fetch(4).values_at("dev", "ino")
    assert_equal c.fetch("map").values_at(5, 6, 7).map { |record| record.values_at("dev", "ino") },
                 k.fetch("map").values_at(5, 6, 7).map { |record| record.values_at("dev", "ino") }
    validator = JSON.parse(harness.stdout)
    assert validator.fetch("sentinels").all? { |record| record.fetch("sentinelAbsent") }
    assert_equal harness.map_facts.values_at(5, 6, 7), validator.fetch("standard")
    assert_equal flags_before, high.fcntl(Fcntl::F_GETFD, 0)
  end

  def test_native_custodian_preoffer_close_fault_cannot_claim_settled_failure
    harness, report = custodian_close_fault(:control)
    assert_equal "failed", harness.frame("FINAL").fetch("outcome")
    assert_equal "unknown", harness.frame("FINAL").fetch("cleanup")
    assert_equal 1, harness.receipt.status_code
    refute harness.confirmed?
    assert_equal false, report.fetch("faultAfterOffer")
    assert_equal true, report.fetch("actualOriginalCloseReturned")
  end

  def test_native_custodian_postoffer_tail_fault_downgrades_intended_two_to_unknown_one
    harness, report = custodian_close_fault(:status)
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup") # The frame alone is not finality.
    assert_equal({ "state" => "not_attempted" }, final.fetch("keeper"))
    assert_equal 2, report.fetch("intendedExitAtFault")
    assert_equal true, report.fetch("faultAfterOffer")
    assert_equal true, report.fetch("actualOriginalCloseReturned")
    assert_equal 1, harness.receipt.status_code
    refute harness.confirmed?
  end

  def test_native_keeper_preoffer_close_fault_preserves_v_receipt_but_not_cleanup
    harness, report = keeper_close_fault(:control)
    assert_keeper_cleanup_fault(harness, report)
    assert_equal false, report.fetch("faultAfterOffer")
  end

  def test_native_keeper_postoffer_tail_fault_cannot_launder_confirmed_cleanup
    harness, report = keeper_close_fault(:status)
    assert_keeper_cleanup_fault(harness, report)
    assert_equal true, report.fetch("faultAfterOffer")
    assert_equal 0, report.fetch("intendedExitAtFault")
  end

  def test_native_custodian_before_exit_arm_callback_rejects_saved_settled_failure
    harness, report = terminal_arm_case(role: "custodian", phase: :before)
    assert_custodian_arm_unknown(harness)
    assert_terminal_arm_report(report, role: "custodian", phase: :before, pid: harness.acquisition.child.pid)
  end

  def test_native_custodian_after_exit_arm_signal_cannot_accept_saved_settled_failure
    harness, report = terminal_arm_case(role: "custodian", phase: :after)
    assert_custodian_arm_unknown(harness)
    assert_terminal_arm_report(report, role: "custodian", phase: :after, pid: harness.acquisition.child.pid)
  end

  def test_native_keeper_before_exit_arm_callback_invalidates_saved_release
    harness, report = terminal_arm_case(role: "keeper", phase: :before)
    assert_keeper_arm_unknown(harness)
    assert_terminal_arm_report(report, role: "keeper", phase: :before, pid: harness.frame("RESERVED").fetch("keeper_pid"))
  end

  def test_native_keeper_after_exit_arm_signal_cannot_accept_saved_release
    harness, report = terminal_arm_case(role: "keeper", phase: :after)
    assert_keeper_arm_unknown(harness)
    assert_terminal_arm_report(report, role: "keeper", phase: :after, pid: harness.frame("RESERVED").fetch("keeper_pid"))
  end

  private

  def with_inert_native_role_effects_rejected(&body)
    effects = []
    reject = lambda do |*arguments, **keywords|
      effects << :unexpected_effect
      raise "inert native-role control attempted an effect"
    end
    operations = [[Owner, :native], [NativeUploadRoleHarness, :new], [Thread, :new],
                  [Owner::TaskSlot, :retain], [File, :open], [File, :read], [File, :binread],
                  [File, :write], [IO, :pipe], [Process, :spawn], [Process, :fork],
                  [Process, :kill], [Process, :waitpid], [Process, :waitpid2],
                  [Process, :setsid], [Process, :setpgid], [Process, :clock_gettime],
                  [STDERR, :flush], [STDERR, :write_nonblock]]
    enter = lambda do |index|
      if index == operations.length
        body.call
      else
        object, name = operations.fetch(index)
        object.stub(name, reject) { enter.call(index + 1) }
      end
    end
    enter.call(0)
    assert_empty effects, "a no-throw diagnostic swallowed an effect tripwire"
  end

  def assert_forwarded_parent_loss_decision
    now = 1_000_000_000
    hard = 10_000_000_000
    boundary_error = Class.new(StandardError).new("inert terminal decision boundary")
    entries = []
    Owner.stub(:monotonic_ns, -> { now }) do
      bootstrap = Owner::TaskSlot.new(run_deadline_ns: 5_000_000_000, hard_cleanup_deadline_ns: hard)
      descendant = Owner::TaskSlot.new(parent_slot: bootstrap, run_deadline_ns: 5_000_000_000,
                                       hard_cleanup_deadline_ns: hard)
      keeper = Owner::Keeper.allocate
      { bootstrap_slot: bootstrap, slots: [bootstrap, descendant], hard_cleanup_deadline_ns: hard,
        failed: false, local_failure: false, parent_lost: false, terminal_started: false,
        release_received: false, group_created: false, signal_generation: 0 }.each do |name, value|
        keeper.instance_variable_set(:"@#{name}", value)
      end
      # No child, group, acquisition, wait, EOF or native cleanup fact exists
      # in this model. Stop immediately on entry to the terminal decision tail.
      record_placeholder = Object.new
      keeper.define_singleton_method(:validator_record) { record_placeholder }
      keeper.define_singleton_method(:receive_parent) do
        entries << :terminal_decision
        raise boundary_error
      end
      %i[tick! prepare_terminal_io start_terminal abandon_terminal own_resources_settled?
         move_to_parent_group cleanup_group poll_validator].each do |name|
        keeper.define_singleton_method(name) { |*args, **kwargs| raise "inert decision crossed its tripwire" }
      end

      keeper.send(:fail!, "parent_lost", cutoff: 3_000_000_000, from_parent: true)
      assert keeper.instance_variable_get(:@failed)
      refute keeper.instance_variable_get(:@local_failure)
      refute keeper.instance_variable_get(:@parent_lost)
      assert keeper.instance_variable_get(:@validator_launch_closed)
      assert_equal "parent_lost", keeper.instance_variable_get(:@failure_reason)
      assert_nil keeper.send(:finish_if_ready)
      assert_empty entries, "an ancestor's loss must not authorize autonomous K release"
      [bootstrap, descendant].each do |slot|
        assert slot.cancelled?
        assert slot.launch_retired?
        refute slot.start_attempted?
        assert_equal 3_000_000_000, slot.cleanup_deadline_ns
      end

      first = IOError.new("private inert original error")
      now += 100_000_000
      keeper.send(:fail!, "parent_lost", error: first, cutoff: hard, from_parent: true)
      assert_same first, keeper.instance_variable_get(:@first_error)
      assert_same first, bootstrap.first_error
      assert_same first, descendant.first_error
      assert_equal 3_000_000_000, keeper.instance_variable_get(:@cleanup_deadline_ns)
      assert_nil keeper.send(:finish_if_ready)
      assert_empty entries

      keeper.send(:fail!, "parent_lost") # A subsequent LOCAL observation still counts.
      assert keeper.instance_variable_get(:@parent_lost)
      assert keeper.instance_variable_get(:@local_failure)
      returned = assert_raises(boundary_error.class) { keeper.send(:finish_if_ready) }
      assert_same boundary_error, returned
      assert_equal [:terminal_decision], entries
      now += 100_000_000
      keeper.send(:fail!, "parent_lost", error: RuntimeError.new("later private error"),
                  cutoff: 2_500_000_000, from_parent: true)
      assert keeper.instance_variable_get(:@parent_lost), "forwarding must never clear local parent loss"
      assert_same first, keeper.instance_variable_get(:@first_error)
      assert_equal "parent_lost", keeper.instance_variable_get(:@failure_reason)
      assert_equal 2_500_000_000, keeper.instance_variable_get(:@cleanup_deadline_ns)
      [bootstrap, descendant].each do |slot|
        assert_same first, slot.first_error
        assert_equal 2_500_000_000, slot.cleanup_deadline_ns
        refute slot.start_attempted?
      end
    end
  end

  def assert_failure_location_reporting
    guard = NativeUploadFixtureGuard
    original_guard = [guard.instance_variable_get(:@reuse_forbidden), guard.instance_variable_get(:@retained_cases).dup]
    failure_type = Struct.new(:backtrace)
    result_type = Struct.new(:failures)
    private_marker = "private-native-diagnostic-marker"
    first_location = "tests/workflow/test_native_upload_process.rb:862"
    bounded_row = "/" + "x" * (1_024 - first_location.bytesize - 2) + "/" + first_location
    valid_rows = [bounded_row,
                  "/private/#{private_marker}/fastlane/native_upload_process.rb:1173:in `#{private_marker}'",
                  "fastlane/native_process_spawn.rb:1", "fastlane/native_process_spawn.rb:1",
                  "fastlane/native_upload_process.rb:999999",
                  "fastlane/native_upload_process.rb:2"]
    make_result = ->(rows) { result_type.new([failure_type.new(rows)]) }
    expected = "\nMRK_NATIVE_OWNER_FAILURE_LOCATIONS=\n" +
               [first_location, "fastlane/native_upload_process.rb:1173", "fastlane/native_process_spawn.rb:1",
                "fastlane/native_upload_process.rb:999999"].join("\n") + "\n"
    single_expected = "\nMRK_NATIVE_OWNER_FAILURE_LOCATIONS=\n#{first_location}\n"
    result = make_result.call(valid_rows)
    original_failure = result.failures.first
    writes, attempts = [], []
    STDERR.stub(:write, lambda { |bytes|
      writes << bytes
      attempts << result.instance_variable_get(:@mrk_failure_locations_attempted)
      bytes.bytesize
    }) do
      2.times { assert_nil guard.report_failure_locations(result) }
    end
    assert_equal [expected], writes
    assert_equal [true], attempts
    assert_same original_failure, result.failures.first
    assert writes.first.ascii_only?
    assert_operator writes.first.bytesize, :<=, 1_024
    refute_includes writes.first, private_marker
    refute_includes writes.first, "/private/"

    overlong = "/" + "x" * (1_025 - first_location.bytesize - 2) + "/" + first_location
    invalid_rows = [nil, Class.new(String).new(first_location), overlong,
                    "fastlane/native_upload_process.rb:0", "fastlane/native_upload_process.rb:01",
                    "fastlane/native_upload_process.rb:1000000", "fastlane/native_upload_process.rb.bak:1",
                    "notfastlane/native_upload_process.rb:1", "/private/../fastlane/native_upload_process.rb:1",
                    "#{first_location}\n#{private_marker}", "fastlane/native_upload_process.rb:1:unframed"]
    bounded_reads = []
    beyond_four = Object.new
    beyond_four.define_singleton_method(:backtrace) { bounded_reads << :fifth_failure; [first_location] }
    bounded_failures = Array.new(4) { failure_type.new(Array.new(32, "ignored") + [first_location]) } + [beyond_four]
    malformed = [make_result.call(invalid_rows), result_type.new(nil),
                 result_type.new(Class.new(Array).new([original_failure])), make_result.call(first_location),
                 make_result.call(Class.new(Array).new([first_location])), result_type.new(bounded_failures)]
    writes = []
    STDERR.stub(:write, ->(bytes) { writes << bytes; bytes.bytesize }) do
      malformed.each { |value| assert_nil guard.report_failure_locations(value) }
    end
    assert_empty writes
    assert_empty bounded_reads

    # Failure/backtrace inspection and output errors remain optional; an
    # already-attempted result is never retried, including a short write.
    [:short, :raise, :backtrace_error].each do |fault|
      value = make_result.call([first_location])
      failure = value.failures.first
      inspections = []
      if fault == :backtrace_error
        failure.define_singleton_method(:backtrace) do
          inspections << :read
          raise IOError, private_marker
        end
      end
      writes = []
      STDERR.stub(:write, lambda { |bytes|
        writes << bytes
        raise IOError, private_marker if fault == :raise

        0
      }) do
        2.times { assert_nil guard.report_failure_locations(value) }
      end
      assert_equal(fault == :backtrace_error ? [] : [single_expected], writes)
      assert_equal(fault == :backtrace_error ? [:read] : [], inspections)
      assert_same failure, value.failures.first
      assert value.instance_variable_get(:@mrk_failure_locations_attempted)
    end

    # The superclass is inert, not Minitest::Test; these are never registered
    # cases. Stub the three hooks, never mutate/reset the real capture's veto.
    [:adverse, :body_error, :entry_error].each do |mode|
      events, latched = [], []
      value = make_result.call([first_location])
      original_error = RuntimeError.new(private_marker)
      parent = Class.new do
        define_method(:run) do
          events << :body
          begin
            raise original_error if mode == :body_error

            value
          ensure
            events << :teardown
          end
        end
        define_method(:passed?) { false }
      end
      runner = Class.new(parent) { prepend NativeUploadFixtureGuard }.new
      entry = lambda do
        events << :entry
        raise original_error if mode == :entry_error
      end
      latch = ->(test) { events << :veto; latched << test }
      STDERR.stub(:write, ->(bytes) { events << :write; bytes.bytesize }) do
        guard.stub(:before_case!, entry) do
          guard.stub(:forbid_reuse!, latch) do
            guard.stub(:custody_retained?, -> { events << :custody; false }) do
              if mode == :adverse
                assert_same value, runner.run
              else
                assert_same original_error, assert_raises(RuntimeError) { runner.run }
              end
            end
          end
        end
      end
      expected_events = mode == :entry_error ? [:entry] : [:entry, :body, :teardown, :veto]
      expected_events << :write if mode == :adverse
      assert_equal expected_events, events
      assert_equal(mode == :entry_error ? [] : [runner], latched)
    end
    assert_equal original_guard, [guard.instance_variable_get(:@reuse_forbidden),
                                  guard.instance_variable_get(:@retained_cases)]
  end

  def new_directory
    directory = File.realpath(Dir.mktmpdir("mrk-native-role-"))
    @directories << directory
    directory
  end

  def build(script, directory: nil, helper: nil, seconds: 4.0, collision_source: nil, configure: true)
    directory ||= new_directory
    validator = File.join(directory, "validator.rb")
    File.write(validator, script, mode: "wb", perm: 0o600)
    ruby = File.realpath(RbConfig.ruby)
    harness = NativeUploadRoleHarness.new(directory: directory, validator: [ruby, *Owner::HELPER_FLAGS, "--", validator],
                                         seconds: seconds, helper: helper, collision_source: collision_source)
    @harnesses << harness # Before actual native or task acquisition.
    harness.launch(configure: configure)
  end

  def run_to_ready(harness)
    hello = harness.wait_frame("HELLO")
    harness.send_command("ADMIT")
    reserved = harness.wait_frame("RESERVED")
    harness.send_command("RUN")
    [hello, reserved, harness.wait_frame("READY")]
  end

  def complete_success(harness)
    status = harness.wait_frame("STATUS")
    assert_equal "exit", status.fetch("status_kind")
    assert_equal 0, status.fetch("status_code")
    harness.await { harness.data_eof? }
    harness.send_command("COMMIT")
    harness.finish
  end

  def cancel(harness)
    harness.send_command("CANCEL", "reason_code" => "cancelled",
                                  "cleanup_deadline_ns" => [Owner.monotonic_ns + Owner::CLEANUP_GRACE_NS,
                                                             harness.hard_deadline_ns].min)
  end

  def assert_success_receipts(harness)
    final = harness.frame("FINAL")
    assert_equal "ok", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup")
    assert_equal "exit", harness.receipt.status_kind.to_s
    assert_equal 0, harness.receipt.status_code
    assert_equal harness.acquisition.child.pid, harness.receipt.pid
    assert_equal({ "state" => "reaped", "pid" => harness.frame("RESERVED").fetch("keeper_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("keeper"))
    assert_equal({ "state" => "reaped", "pid" => harness.frame("READY").fetch("validator_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("validator"))
    assert_equal({ "state" => "retired", "id" => harness.frame("RESERVED").fetch("group_id"), "absent" => true }, final.fetch("group"))
    assert harness.slot.joined?
    assert harness.data_eof?
    assert harness.channel.eof?
    assert harness.confirmed?
    assert_empty harness.acquisition.cleanup_errors
  end

  def read_report(directory, role)
    JSON.parse(File.binread(File.join(directory, "#{role}.observation.json")))
  end

  def copied_helper(directory, injection)
    source = File.binread(HELPER_PATH)
    footer = "# NativeUploadProcess fixed executable entrypoint.\n"
    raise "fixed helper footer changed" unless source.scan(footer).length == 1

    binding = <<~RUBY
      # TEST-ONLY COPIED HELPER; never an unchanged installed-helper proof.
      module MobileReleaseKit::NativeUploadProcess
        def self.native
          require #{LEAF_PATH.dump}
          MobileReleaseKit::NativeProcessSpawn
        end
      end
    RUBY
    path = File.join(directory, "observed-helper.rb")
    File.write(path, source.sub(footer, binding + injection + "\n" + footer), mode: "wb", perm: 0o600)
    assert_equal Digest::SHA256.hexdigest(source), Digest::SHA256.file(HELPER_PATH).hexdigest
    File.realpath(path)
  end

  def close_fault_helper(directory, role:, endpoint:)
    injection = <<~RUBY
      module NativeRoleCloseFault
        def close_lease(lease)
          if @role == #{role.dump} && lease && lease.equal?(@roles[#{endpoint.inspect}]) && !@fixture_fault_injected
            @fixture_fault_injected = true
            path = #{File.join(directory, "#{role}.observation.json").dump}
            report = { "faultAfterOffer" => @terminal_started, "intendedExitAtFault" => @intended_exit,
                       "actualOriginalCloseReturned" => false }
            original = lease.io.method(:close)
            lease.io.define_singleton_method(:close) do
              returned = original.call
              raise "fixture original close did not return nil" unless returned.nil?
              report["actualOriginalCloseReturned"] = true
              File.write(path, JSON.generate(report))
              raise IOError, "test-only close return publication loss"
            end
          end
          super
        end
      end
      MobileReleaseKit::NativeUploadProcess::Role.prepend(NativeRoleCloseFault)
    RUBY
    copied_helper(directory, injection)
  end

  def terminal_arm_helper(directory, role:, phase:)
    injection = <<~RUBY
      module NativeExitArmObservation
        ROLE = ARGV.fetch(0).freeze
        TARGET = #{role.dump}.freeze
        PHASE = #{phase.inspect}
        PATH = #{File.join(directory, "#{role}.observation.json").dump}.freeze
        EXPECTED = TARGET == "custodian" ? 2 : 0
        REPORT = { "role" => ROLE, "phase" => PHASE.to_s }
        class << self
          attr_accessor :handler, :owner
          def write
            bytes = JSON.generate(REPORT)
            written = File.write(PATH, bytes, mode: "wb", perm: 0o600)
            raise "fixture signal report incomplete" unless written == bytes.bytesize
          end
        end
      end
      module NativeExitArmTrapObservation
        def trap(signal, *arguments, &block)
          returned = super
          if signal == :TERM && block && NativeExitArmObservation::ROLE == NativeExitArmObservation::TARGET
            # Retain the ACTUAL successfully installed Proc. Do not replace its
            # disposition, wrap its body, change masks, or obtain it by reset.
            NativeExitArmObservation.handler = block
          end
          returned
        end
      end
      Signal.singleton_class.prepend(NativeExitArmTrapObservation)
      module NativeExitArmRoleObservation
        def seal_exit_handoff(exit_code)
          return super unless @role == NativeExitArmObservation::TARGET

          NativeExitArmObservation.owner = self
          raise "fixture expected a genuinely settled run offer" unless exit_code == NativeExitArmObservation::EXPECTED
          report = NativeExitArmObservation::REPORT
          report.merge!("runCode" => exit_code, "offerEpoch" => @terminal_signal_generation,
                        "epochBefore" => @signal_generation, "armedBefore" => @terminal_exit_armed,
                        "handlerCaptured" => NativeExitArmObservation.handler.instance_of?(Proc))
          if NativeExitArmObservation::PHASE == :before
            raise "fixture did not capture installed handler" unless NativeExitArmObservation.handler.instance_of?(Proc)
            NativeExitArmObservation.handler.call
            report["callbackEpochAfter"] = @signal_generation
          end
          returned = super
          report["handoffCode"] = returned
          report["armedAfter"] = @terminal_exit_armed
          NativeExitArmObservation.write
          returned
        end
      end
      MobileReleaseKit::NativeUploadProcess::Role.prepend(NativeExitArmRoleObservation)
      module NativeExitArmMainObservation
        def helper_main(argv)
          saved = super
          return saved unless NativeExitArmObservation::ROLE == NativeExitArmObservation::TARGET &&
                              NativeExitArmObservation::PHASE == :after

          # This is AFTER the production arm and its last agreeing gate, with
          # the selected 0/2 already saved for the unchanged executable footer.
          # Genuine self-TERM must cause the original handler's own exit!(1).
          # Unrelated shim errors/timeouts use DISTINCT 96/97, never a fake1.
          begin
            raise "fixture handoff was not settled" unless saved == NativeExitArmObservation::EXPECTED
            report = NativeExitArmObservation::REPORT
            report.merge!("mainCode" => saved, "selfSignal" => "TERM", "selfSignalPid" => Process.pid,
                          "signalAttempted" => true)
            NativeExitArmObservation.write
            Process.exit!(96) unless Process.kill("TERM", Process.pid) == 1
            cutoff = Integer(argv.fetch(4), 10) # ORIGINAL helper hard deadline.
            loop do
              # A broken, unarmed old handler would advance the epoch and let
              # the footer consume its stale saved code, reproducing the bug.
              return saved if NativeExitArmObservation.owner.instance_variable_get(:@signal_generation) != report.fetch("epochBefore")
              Process.exit!(97) if MobileReleaseKit::NativeUploadProcess.monotonic_ns >= cutoff
              sleep(0.001)
            end
          rescue Exception
            Process.exit!(96)
          end
        end
      end
      MobileReleaseKit::NativeUploadProcess.singleton_class.prepend(NativeExitArmMainObservation)
    RUBY
    copied_helper(directory, injection)
  end

  def observed_helper(directory, reset_ignore: false, sentinel_paths: [], outer_fd: 128)
    injection = <<~RUBY
      require "fcntl"
      module NativeRoleObservation
        ROLE = ARGV.fetch(0).freeze
        DIRECTORY = #{directory.dump}.freeze
        SENTINEL_PATHS = #{sentinel_paths.inspect}.freeze
        PROBES = [#{outer_fd}, 256, 384].freeze
        PROBE_WRAPPERS = [] # Retain nonowning metadata until this helper exits.
        REPORT = { "installedIgnoreBeforeBootstrap" => #{reset_ignore.inspect}, "waitability" => [],
                   "childPreMapCollisions" => 0 }
        class << self
          attr_accessor :foreign
          def write
            File.write(File.join(DIRECTORY, ROLE + ".observation.json"), JSON.generate(REPORT))
          end
          def identities
            SENTINEL_PATHS.map { |path| stat = File.stat(path); [stat.dev, stat.ino] }
          end
          def observe_sentinels
            expected = identities
            PROBES.map do |fd|
              begin
                wrapped = IO.for_fd(fd, autoclose: false)
                PROBE_WRAPPERS << wrapped
                stat = wrapped.stat
                raise "ancestor sentinel reached helper" if expected.include?([stat.dev, stat.ino])
                { "fd" => fd, "sentinelAbsent" => true }
              rescue Errno::EBADF
                { "fd" => fd, "sentinelAbsent" => true }
              end
            end
          end
        end
      end
      # This actual ignored disposition is installed only in each fresh copied
      # helper. The embedding caller is never changed. Production bootstrap must
      # reset it, and the real sigaction return below independently observes it.
      Signal.trap(:CHLD, "IGNORE") if #{reset_ignore.inspect}
      module NativeRoleNativeObservation
        def native_call!(name, *arguments, **keywords)
          if name == "posix_spawn_file_actions_adddup2" && NativeRoleObservation.foreign && !@fixture_collision_entered
            @fixture_collision_entered = true
            count = NativeRoleObservation::ROLE == "custodian" ? 8 : 3
            count.times do |destination|
              call = super(name, arguments.fetch(0), NativeRoleObservation.foreign.fileno, destination)
              raise "helper pre-map collision action failed" unless call.result == 0
              NativeRoleObservation::REPORT["childPreMapCollisions"] += 1
            end
          end
          result = super(name, *arguments, **keywords)
          if name == "sigaction" && arguments.fetch(1) == 0 && result.result == 0
            abi = MobileReleaseKit::NativeProcessSpawn.declared_abi
            layout = abi.fetch("sigaction").fetch("fields")
            handler = layout.fetch("handler")
            flags = layout.fetch("flags")
            pointer = arguments.fetch(2)
            NativeRoleObservation::REPORT.fetch("waitability") << {
              "result" => result.result,
              "handler" => pointer[handler.fetch("offset"), handler.fetch("size")].unpack1("Q<"),
              "flags" => pointer[flags.fetch("offset"), flags.fetch("size")].unpack1("L<")
            }
          end
          result
        end
        private :native_call!
      end
      MobileReleaseKit::NativeUploadProcess.native::Acquisition.prepend(NativeRoleNativeObservation)
      module NativeRoleMapObservation
        def send_hello
          report = NativeRoleObservation::REPORT
          ordered = @roles.values.sort_by { |lease| lease.io.fileno }
          report["map"] = ordered.map do |lease|
            io = lease.io
            stat = io.stat
            { "fd" => io.fileno, "dev" => stat.dev, "ino" => stat.ino, "kind" => stat.ftype,
              "mode" => io.fcntl(Fcntl::F_GETFL, 0) & Fcntl::O_ACCMODE, "cloexec" => io.close_on_exec? }
          end
          unless NativeRoleObservation::SENTINEL_PATHS.empty?
            report["sentinels"] = NativeRoleObservation.observe_sentinels
            index, target = @role == "custodian" ? [1, 256] : [2, 384]
            source = File.open(NativeRoleObservation::SENTINEL_PATHS.fetch(index), "rb")
            begin
              duplicate = source.fcntl(Fcntl::F_DUPFD, target)
              raise "fixture high sentinel target unexpectedly occupied" unless duplicate == target
              NativeRoleObservation.foreign = IO.for_fd(duplicate, "rb", autoclose: true)
              NativeRoleObservation.foreign.close_on_exec = false
            ensure
              source.close
            end
          end
          NativeRoleObservation.write
          super
        end
        def finish_local_tail
          returned = super
          if NativeRoleObservation.foreign
            io = NativeRoleObservation.foreign
            # A source used by injected native actions has the same original
            # creator-custody obligation as every production borrowed source.
            # An unresolved creator leaves this IO rooted until process exit.
            sources_released = @slots.none? { |slot| slot.start_attempted? && !slot.joined? } &&
                               @acquisitions.all? { |acquisition| @settled[acquisition.object_id] == true }
            NativeRoleObservation::REPORT["foreignSourcesReleased"] = sources_released
            NativeRoleObservation::REPORT["foreignOriginalClosed"] = false
            if sources_released
              NativeRoleObservation::REPORT["foreignFlagsAtClose"] = io.fcntl(Fcntl::F_GETFD, 0)
              closed = io.close
              raise "fixture foreign source close did not return nil" unless closed.nil? && io.closed?
              NativeRoleObservation::REPORT["foreignOriginalClosed"] = true
            end
          end
          NativeRoleObservation::REPORT["productionTailReturned"] = returned
          NativeRoleObservation.write
          returned
        end
      end
      module NativeCustodianChildMapObservation
        def settle_creator(slot, acquisition)
          returned = super
          report = NativeRoleObservation::REPORT
          if returned == true && acquisition.equal?(@creator_acquisition) && slot.equal?(@creator_slot) &&
             slot.joined? && !report.key?("childControlSourceIdentity")
            # Observe the EXACT original child sources after genuine creator
            # join/native finish, before settle_keeper_creator closes them.
            # Opposite pipe endpoints need not have equal metadata on Darwin.
            resources = acquisition.resources
            control = resources.fetch(:keeper_control_read).io.stat
            status = resources.fetch(:keeper_status_write).io.stat
            report["childControlSourceIdentity"] = [control.dev, control.ino]
            report["childStatusSourceIdentity"] = [status.dev, status.ino]
            NativeRoleObservation.write
          end
          returned
        end
      end
      MobileReleaseKit::NativeUploadProcess::Role.prepend(NativeRoleMapObservation)
      MobileReleaseKit::NativeUploadProcess::Custodian.prepend(NativeCustodianChildMapObservation)
    RUBY
    copied_helper(directory, injection)
  end

  def custodian_close_fault(endpoint)
    directory = new_directory
    helper = close_fault_helper(directory, role: "custodian", endpoint: endpoint)
    harness = build('raise "validator must never execute"', directory: directory, helper: helper)
    harness.wait_frame("HELLO")
    cancel(harness)
    harness.finish
    [harness, read_report(directory, "custodian")]
  end

  def terminal_arm_case(role:, phase:)
    directory = new_directory
    helper = terminal_arm_helper(directory, role: role, phase: phase)
    script = role == "custodian" ? 'raise "validator must never execute"' : 'STDIN.read; exit 0'
    harness = build(script, directory: directory, helper: helper)
    if role == "custodian"
      harness.wait_frame("HELLO")
      cancel(harness) # A genuinely settled FAILED offer is saved as C2.
    else
      run_to_ready(harness)
      harness.close_stdin
      harness.wait_frame("STATUS") # K's ordinary RELEASED offer would be K0.
    end
    harness.finish
    [harness, read_report(directory, role)]
  end

  def assert_custodian_arm_unknown(harness)
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "confirmed", final.fetch("cleanup") # Offer only, never finality.
    assert_equal({ "state" => "not_attempted" }, final.fetch("keeper"))
    assert_equal({ "state" => "not_attempted" }, final.fetch("validator"))
    assert_equal({ "state" => "not_created" }, final.fetch("group"))
    assert_equal "exit", harness.receipt.status_kind.to_s
    assert_equal 1, harness.receipt.status_code
    refute harness.confirmed?
  end

  def assert_keeper_arm_unknown(harness)
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "unknown", final.fetch("cleanup")
    assert_equal({ "state" => "reaped", "pid" => harness.frame("RESERVED").fetch("keeper_pid"),
                   "status_kind" => "exit", "status_code" => 1 }, final.fetch("keeper"))
    assert_equal({ "state" => "reaped", "pid" => harness.frame("READY").fetch("validator_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("validator"))
    assert_equal({ "state" => "retired", "id" => harness.frame("RESERVED").fetch("group_id"), "absent" => true }, final.fetch("group"))
    assert_equal "exit", harness.receipt.status_kind.to_s
    assert_equal 1, harness.receipt.status_code
    refute harness.confirmed?
  end

  def assert_terminal_arm_report(report, role:, phase:, pid:)
    expected = role == "custodian" ? 2 : 0
    assert_equal role, report.fetch("role")
    assert_equal phase.to_s, report.fetch("phase")
    assert_equal expected, report.fetch("runCode")
    assert_equal report.fetch("offerEpoch"), report.fetch("epochBefore")
    assert_equal true, report.fetch("handlerCaptured")
    assert_equal false, report.fetch("armedBefore")
    assert_equal true, report.fetch("armedAfter")
    assert_equal(phase == :before ? 1 : expected, report.fetch("handoffCode"))
    if phase == :before
      assert_equal report.fetch("epochBefore") + 1, report.fetch("callbackEpochAfter")
    else
      assert_equal expected, report.fetch("mainCode")
      assert_equal "TERM", report.fetch("selfSignal")
      assert_equal pid, report.fetch("selfSignalPid")
      assert_equal true, report.fetch("signalAttempted")
    end
  end

  def keeper_close_fault(endpoint)
    directory = new_directory
    helper = close_fault_helper(directory, role: "keeper", endpoint: endpoint)
    harness = build('STDIN.read; exit 0', directory: directory, helper: helper)
    run_to_ready(harness)
    harness.close_stdin
    harness.wait_frame("STATUS")
    harness.finish # A failed terminal never waits for COMMIT.
    [harness, read_report(directory, "keeper")]
  end

  def assert_keeper_cleanup_fault(harness, report)
    final = harness.frame("FINAL")
    assert_equal "failed", final.fetch("outcome")
    assert_equal "unknown", final.fetch("cleanup")
    assert_equal({ "state" => "reaped", "pid" => harness.frame("READY").fetch("validator_pid"),
                   "status_kind" => "exit", "status_code" => 0 }, final.fetch("validator"))
    assert_equal "reaped", final.fetch("keeper").fetch("state")
    assert_equal "exit", final.fetch("keeper").fetch("status_kind")
    assert_equal 1, final.fetch("keeper").fetch("status_code")
    assert final.fetch("group").fetch("absent")
    assert_equal 1, harness.receipt.status_code
    assert_equal true, report.fetch("actualOriginalCloseReturned")
    refute harness.confirmed?
  end
end

# These are real, bounded Ruby task tests, but they perform no process, native
# symbol, signal, descriptor or filesystem acquisition. Local execution still
# needs the reviewed explicit selector; real threads are not fake-only work.
class NativeUploadTaskSlotTest < Minitest::Test
  prepend NativeUploadFixtureGuard
  Owner = MobileReleaseKit::NativeUploadProcess
  RETAINED = []

  def setup
    flunk "earlier native role fixture retained UNKNOWN custody; new task work forbidden" unless NativeUploadRoleTest::RETAINED.empty?
    flunk "earlier Ruby task fixture retained custody; new task work forbidden" unless RETAINED.empty?
    @slots = []
  end

  def take(queue, seconds: 1.0)
    cutoff = Owner.monotonic_ns + (seconds * 1_000_000_000).to_i
    loop do
      begin
        return queue.pop(true)
      rescue ThreadError
        raise "bounded test synchronization expired" if Owner.monotonic_ns >= cutoff

        sleep(0.001)
      end
    end
  end

  def wait_for(seconds: 1.0)
    cutoff = Owner.monotonic_ns + (seconds * 1_000_000_000).to_i
    until yield
      raise "bounded test observation expired" if Owner.monotonic_ns >= cutoff

      sleep(0.001)
    end
  end

  def slot(seconds: 1.0, parent: nil)
    now = Owner.monotonic_ns
    deadline = now + (seconds * 1_000_000_000).to_i
    value = Owner::TaskSlot.new(caller: Thread.current, parent_slot: parent,
                                run_deadline_ns: deadline, hard_cleanup_deadline_ns: deadline + 500_000_000)
    @slots << value
    value
  end

  def teardown
    return unless @slots # A refused entry never resets the retained registry.

    failures = []
    visited = {}
    loop do
      # Every nested slot is registered BEFORE its real start. A parent joined
      # in this pass can publish another registered slot; do not lose that slot
      # merely because cleanup began with an earlier snapshot of the registry.
      pending = @slots.reverse.reject { |value| visited[value.object_id] }
      break if pending.empty?

      pending.each do |value|
        visited[value.object_id] = true
        next if value.joined?

        begin
          # Retire even a registered-but-not-started slot before inspecting its
          # attempt latch; otherwise its caller could start it after this pass.
          value.cancel!(reason_code: "cancelled")
        rescue Exception => error
          failures << [value.object_id, :cancel, error]
        end
        begin
          if !value.start_attempted?
            failures << [value.object_id, :no_start_unconfirmed] unless value.launch_retired? && value.thread.nil?
          elsif !value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
            failures << [value.object_id, :join_unconfirmed]
          end
        rescue Exception => error
          failures << [value.object_id, :join, error]
        end
      end
    end
    unresolved = @slots.select { |value| value.start_attempted? && !value.joined? }
    # Retain the ORIGINAL mutable registry so a late registration after an
    # unresolved parent cutoff is still rooted. This is not a cleanup receipt.
    RETAINED << [@slots, failures] unless passed? && failures.empty? && unresolved.empty?
    assert_empty failures, "independent original Ruby task cleanup attempts failed"
    assert_empty unresolved, "test-owned Ruby task custody remains unresolved"
  end

  def test_task_body_cannot_run_before_actual_identity_reconciliation_and_admission
    value = slot
    calls = []
    returned = value.start do |owned|
      owned.check_creation!
      calls << Thread.current
      :offer
    end
    assert_same value, returned
    assert_empty calls
    refute value.joined?
    refute value.finished?
    assert value.admit!
    assert value.join_until(deadline_ns: value.run_deadline_ns)
    assert_equal [value.thread], calls
    assert_equal :offer, value.offer
    assert value.finished?
    assert value.joined?
    refute value.unresolved?
    assert_nil value.first_error
  end

  def test_interrupted_return_publication_recovers_only_the_self_published_real_task
    value = slot
    first = Interrupt.new("private-return-publication-marker")
    calls = []
    value.define_singleton_method(:bind_returned!) { |_actual| raise first }
    observed = assert_raises(Interrupt) { value.start { calls << :forbidden } }
    assert_same first, observed
    assert_same first, value.first_error
    assert value.start_attempted?
    refute value.admit!
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_instance_of Thread, value.thread
    assert_empty calls
    assert value.joined?
    assert_nil value.offer
  end

  def test_delayed_publication_is_unknown_at_cutoff_and_cannot_launch_late
    value = slot
    release = Queue.new
    original = value.method(:publish_self!)
    bounded_take = method(:take)
    value.define_singleton_method(:publish_self!) { bounded_take.call(release); original.call }
    returned_thread = nil
    first = Interrupt.new("private-both-publications-marker")
    value.define_singleton_method(:bind_returned!) { |actual| returned_thread = actual; raise first }
    calls = []
    assert_same first, assert_raises(Interrupt) { value.start { calls << :forbidden } }
    refute value.admit!
    refute value.join_until(deadline_ns: Owner.monotonic_ns + 30_000_000)
    assert value.unresolved?
    assert_nil value.thread
    refute value.joined?
    release << true
    # Test-only custody of the actual Thread.new return allows the delayed
    # publication fixture itself to finish. This does not extend production GO.
    assert_same returned_thread, returned_thread.join(0.3)
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_empty calls
    assert_nil value.offer
    assert value.cancelled?
  ensure
    release << true if release
    assert_same returned_thread, returned_thread.join(1.0) if returned_thread
  end

  def test_whole_task_setup_errors_are_captured_without_a_raw_reporter
    value = slot
    first = RuntimeError.new("private-task-publication-marker")
    publish = value.method(:publish_self!)
    value.define_singleton_method(:publish_self!) { publish.call; raise first }
    old_report, old_abort = Thread.report_on_exception, Thread.abort_on_exception
    Thread.report_on_exception = true
    Thread.abort_on_exception = true
    output, errors = capture_io do
      value.start { flunk "task body ran after failed setup" }
      value.admit!
      assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    end
    assert_empty output
    assert_empty errors
    assert_same first, value.first_error
    refute value.thread.report_on_exception
    refute value.thread.abort_on_exception
    assert Thread.report_on_exception
    assert Thread.abort_on_exception
  ensure
    Thread.report_on_exception = old_report unless old_report.nil?
    Thread.abort_on_exception = old_abort unless old_abort.nil?
  end

  def test_task_tail_failure_remains_a_separate_cleanup_error_and_vetoes_offer
    value = slot
    error = IOError.new("private-task-tail-marker")
    close = value.method(:close_launch!)
    injected = false
    value.define_singleton_method(:close_launch!) do
      result = close.call
      unless injected
        injected = true
        raise error
      end
      result
    end
    value.start { :unaccepted_offer }
    assert value.admit!
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_equal [error], value.cleanup_errors
    assert value.cancelled?
    assert_same error, value.first_error
    assert value.joined?
    value.cancel!(error: Interrupt.new("private-caller-after-cleanup-marker"), reason_code: "cancelled")
    assert_same error, value.first_error
  end

  def test_task_first_error_is_not_replaced_by_later_caller_interrupt
    value = slot
    task_error = RuntimeError.new("private-task-first-marker")
    caller_error = Interrupt.new("private-caller-second-marker")
    value.start { raise task_error }
    assert value.admit!
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    value.cancel!(error: caller_error, reason_code: "cancelled")
    assert_same task_error, value.first_error
    assert value.cancelled?
  end

  def test_caller_first_system_exit_object_and_status_survive_later_task_failure
    value = slot
    entered, release = Queue.new, Queue.new
    first = SystemExit.new(41, "private-caller-first-marker")
    value.start do
      entered << true
      take(release)
      raise IOError, "private-task-second-marker"
    end
    assert value.admit!
    take(entered)
    value.cancel!(error: first, reason_code: "cancelled")
    release << true
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_same first, value.first_error
    assert_equal 41, value.first_error.status
    assert_equal "private-caller-first-marker", value.first_error.message
    assert_nil value.offer
    cleanup = IOError.new("private-cleanup-after-system-exit-marker")
    value.record_cleanup_error(cleanup)
    assert_same first, value.first_error
    assert_equal [cleanup], value.cleanup_errors
  ensure
    release << true if release
  end

  def test_nested_creator_and_caller_share_one_actual_first_recording_boundary
    parent = slot
    entered, release = Queue.new, Queue.new
    creator = nil
    first = RuntimeError.new("private-creator-first-marker")
    parent.start do |capture_slot|
      creator = Owner::TaskSlot.new(caller: Thread.current, parent_slot: capture_slot,
                                    run_deadline_ns: capture_slot.run_deadline_ns,
                                    hard_cleanup_deadline_ns: capture_slot.hard_cleanup_deadline_ns)
      @slots << creator
      creator.start { raise first }
      creator.admit!
      raise "test creator did not join" unless creator.join_until(deadline_ns: creator.hard_cleanup_deadline_ns)

      entered << true
      take(release)
    end
    assert parent.admit!
    take(entered)
    parent.cancel!(error: Interrupt.new("private-caller-later-marker"), reason_code: "cancelled")
    release << true
    assert parent.join_until(deadline_ns: parent.hard_cleanup_deadline_ns)
    assert_same first, creator.first_error
    assert_same first, parent.first_error
    assert_equal creator.cleanup_deadline_ns, parent.cleanup_deadline_ns
    assert creator.joined?
    assert parent.joined?
  ensure
    release << true if release
  end

  def test_parent_cancellation_permanently_prevents_nested_creation
    parent = slot
    entered, release = Queue.new, Queue.new
    creator = nil
    calls = []
    parent.start do |capture_slot|
      creator = Owner::TaskSlot.new(caller: Thread.current, parent_slot: capture_slot,
                                    run_deadline_ns: capture_slot.run_deadline_ns,
                                    hard_cleanup_deadline_ns: capture_slot.hard_cleanup_deadline_ns)
      @slots << creator
      creator.start { |owned| owned.check_creation!; calls << :forbidden }
      entered << true
      take(release)
      creator.admit!
      creator.join_until(deadline_ns: creator.hard_cleanup_deadline_ns)
    end
    assert parent.admit!
    take(entered)
    parent.cancel!(reason_code: "cancelled")
    release << true
    assert parent.join_until(deadline_ns: parent.hard_cleanup_deadline_ns)
    assert creator.joined?
    assert_empty calls
    assert creator.cancelled?
    assert_nil creator.offer
  ensure
    release << true if release
  end

  def test_first_failure_deadline_is_fixed_once_and_can_only_shorten
    now = 10_000_000_000
    Owner.stub(:monotonic_ns, -> { now }) do
      value = Owner::TaskSlot.new(caller: Thread.current, run_deadline_ns: 12_000_000_000,
                                  hard_cleanup_deadline_ns: 17_000_000_000)
      first = Interrupt.new("first cancellation")
      value.cancel!(error: first, reason_code: "cancelled")
      assert_equal 15_000_000_000, value.cleanup_deadline_ns
      now = 14_000_000_000
      value.cancel!(error: SystemExit.new(9), reason_code: "cancelled")
      assert_equal 15_000_000_000, value.cleanup_deadline_ns
      value.cancel!(reason_code: "deadline", cleanup_deadline_ns: 14_500_000_000)
      assert_equal 14_500_000_000, value.cleanup_deadline_ns
      value.cancel!(reason_code: "io", cleanup_deadline_ns: 17_000_000_000)
      assert_equal 14_500_000_000, value.cleanup_deadline_ns
      assert_same first, value.first_error
      refute value.start_attempted?
      refute value.unresolved?
      refute value.joined?
    end
  end

  def test_unadmitted_caller_is_not_the_actual_creation_task
    value = slot
    assert_raises(Owner::LifecycleError) { value.check_creation! }
    refute value.start_attempted?
    assert_raises(Owner::LifecycleError) { value.start { flunk "retired admission reopened" } }
    refute value.start_attempted?
    assert_nil value.thread
    refute value.joined?
  end

  def test_join_uses_actual_thread_not_value_and_does_not_fabricate_an_interrupted_receipt
    value = slot
    value.start { :complete }
    assert value.admit!
    actual = value.thread
    actual.define_singleton_method(:value) { Kernel.raise "Thread#value must never be used" }
    original_join = actual.method(:join)
    first = Interrupt.new("private-join-return-marker")
    injected = false
    actual.define_singleton_method(:join) do |timeout|
      result = original_join.call(timeout)
      if result && !injected
        injected = true
        Kernel.raise first
      end
      result
    end
    observed = assert_raises(Interrupt) { value.join_until(deadline_ns: value.hard_cleanup_deadline_ns) }
    assert_same first, observed
    assert injected
    assert_same first, value.first_error
    assert value.cancelled?
    assert value.unresolved?
    refute value.joined?
    value.cancel!(error: observed, reason_code: "cancelled")
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert value.joined?
    assert_same actual, value.thread
    assert_same first, value.first_error
  end

  def test_error_before_self_publication_still_joins_the_genuine_returned_thread
    value = slot
    first = IOError.new("private-before-self-publication-marker")
    value.define_singleton_method(:publish_self!) { raise first }
    calls = []
    value.start { calls << :forbidden }
    actual = value.thread
    assert_instance_of Thread, actual
    wait_for { value.finished? }
    refute value.publication_ready?
    refute value.admit!
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_same actual, value.thread
    assert_same first, value.first_error
    assert value.joined?
    assert_empty calls
    assert_nil value.offer
  end

  def test_cleanup_after_an_established_task_primary_remains_secondary
    value = slot
    first = RuntimeError.new("private-body-primary-marker")
    cleanup = IOError.new("private-tail-secondary-marker")
    close = value.method(:close_launch!)
    injected = false
    value.define_singleton_method(:close_launch!) do
      returned = close.call
      unless injected
        injected = true
        raise cleanup
      end
      returned
    end
    value.start { raise first }
    assert value.admit!
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    value.cancel!(error: SystemExit.new(19), reason_code: "cancelled")
    assert_same first, value.first_error
    assert_equal [cleanup], value.cleanup_errors
    assert value.cancelled?
    assert_nil value.offer
  end

  def test_caller_interrupt_first_survives_later_task_and_cleanup_errors
    value = slot
    entered, release = Queue.new, Queue.new
    first = Interrupt.new("private-caller-interrupt-first-marker")
    cleanup = IOError.new("private-cleanup-third-marker")
    value.start do
      entered << true
      take(release)
      raise RuntimeError, "private-task-second-marker"
    end
    assert value.admit!
    take(entered)
    value.cancel!(error: first, reason_code: "cancelled")
    release << true
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    value.record_cleanup_error(cleanup)
    assert_same first, value.first_error
    assert_equal [cleanup], value.cleanup_errors
    assert_equal "private-caller-interrupt-first-marker", value.first_error.message
    assert_nil value.offer
  ensure
    release << true if release
  end

  def test_cleanup_first_is_recorded_before_a_synchronized_later_caller_error
    value = slot
    entered, release, recorded = Queue.new, Queue.new, Queue.new
    cleanup = IOError.new("private-cleanup-first-marker")
    later = SystemExit.new(23, "private-caller-after-cleanup-marker")
    value.start do |owned|
      entered << true
      take(release)
      owned.record_cleanup_error(cleanup)
      recorded << true
    end
    assert value.admit!
    take(entered)
    release << true
    take(recorded)
    value.cancel!(error: later, reason_code: "cancelled")
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert_same cleanup, value.first_error
    assert_equal [cleanup], value.cleanup_errors
    assert value.launch_retired?
    assert_nil value.offer
  ensure
    release << true if release
  end

  def test_failure_shortens_a_join_which_is_already_running
    value = slot(seconds: 3.0)
    entered, release, joining = Queue.new, Queue.new, Queue.new
    value.start { entered << true; take(release, seconds: 2.0) }
    assert value.admit!
    take(entered)
    actual = value.thread
    original_join = actual.method(:join)
    actual.define_singleton_method(:join) { |timeout| joining << true; original_join.call(timeout) }
    first = IOError.new("private-failure-during-join-marker")
    cutoff = nil
    injector = slot
    injector.start do
      take(joining)
      cutoff = Owner.monotonic_ns + 80_000_000
      value.cancel!(error: first, reason_code: "io", cleanup_deadline_ns: cutoff)
    end
    assert injector.admit!
    started = Owner.monotonic_ns
    refute value.join_until(deadline_ns: value.run_deadline_ns)
    assert_operator Owner.monotonic_ns - started, :<, 1_000_000_000
    assert_equal cutoff, value.cleanup_deadline_ns
    assert_same first, value.first_error
    refute value.joined?
    assert injector.join_until(deadline_ns: injector.hard_cleanup_deadline_ns)
    release << true
    # A test-owned release ends the fixture body, not production admission.
    assert_same actual, original_join.call(1.0)
    assert value.join_until(deadline_ns: value.hard_cleanup_deadline_ns)
    assert value.launch_retired?
    assert_nil value.offer
  ensure
    release << true if release
    assert_same actual, original_join.call(1.0) if original_join
  end

  def test_caller_death_is_observed_inside_an_already_running_join
    caller_slot = slot
    published, entered, leave_caller, release, joining, cancellations = Array.new(6) { Queue.new }
    child = nil
    caller_slot.start do
      now = Owner.monotonic_ns
      child = Owner::TaskSlot.new(caller: Thread.current, run_deadline_ns: now + 600_000_000,
                                  hard_cleanup_deadline_ns: now + 1_100_000_000)
      @slots << child
      child.start { entered << true; take(release) }
      child.admit!
      published << child
      take(leave_caller)
    end
    assert caller_slot.admit!
    child = take(published)
    assert_instance_of Owner::TaskSlot, child
    take(entered)
    actual = child.thread
    original_join = actual.method(:join)
    actual.define_singleton_method(:join) { |timeout| joining << true; original_join.call(timeout) }
    original_cancel = child.method(:cancel!)
    child.define_singleton_method(:cancel!) do |**arguments|
      cancellations << [Thread.current, arguments.fetch(:reason_code), Owner.monotonic_ns]
      original_cancel.call(**arguments)
    end
    injector = slot
    injector.start { take(joining); leave_caller << true }
    assert injector.admit!
    refute child.join_until(deadline_ns: child.run_deadline_ns)
    observer, reason, recorded_at = take(cancellations)
    assert_same Thread.current, observer
    assert_equal "parent_lost", reason
    assert_operator recorded_at, :<, child.run_deadline_ns
    assert caller_slot.join_until(deadline_ns: caller_slot.hard_cleanup_deadline_ns)
    assert injector.join_until(deadline_ns: injector.hard_cleanup_deadline_ns)
    refute child.joined?
    release << true
    assert_same actual, original_join.call(1.0)
    assert child.join_until(deadline_ns: child.hard_cleanup_deadline_ns)
    assert child.cancelled?
    assert_nil child.offer
  ensure
    leave_caller << true if leave_caller
    release << true if release
    assert_same actual, original_join.call(1.0) if original_join
  end

  def test_joined_creator_does_not_rediscover_its_completed_caller_as_a_new_failure
    parent = slot
    creator = nil
    parent.start do |capture_slot|
      creator = Owner::TaskSlot.new(caller: Thread.current, parent_slot: capture_slot,
                                    run_deadline_ns: capture_slot.run_deadline_ns,
                                    hard_cleanup_deadline_ns: capture_slot.hard_cleanup_deadline_ns)
      @slots << creator
      creator.start { :genuine_offer }
      creator.admit!
      raise "bounded creator did not join" unless creator.join_until(deadline_ns: creator.hard_cleanup_deadline_ns)

      :capture_offer
    end
    assert parent.admit!
    assert parent.join_until(deadline_ns: parent.hard_cleanup_deadline_ns)
    assert creator.joined?
    refute creator.caller.alive?
    refute creator.cancelled?
    assert_nil creator.first_error
    assert_equal :genuine_offer, creator.offer
    assert_equal :capture_offer, parent.offer
    assert_equal creator.run_deadline_ns, creator.cleanup_deadline_ns
    # Joined does not sever the common failure record for a later real error.
    late = IOError.new("private-postjoin-caller-marker")
    parent.record_cleanup_error(late)
    assert_same late, creator.first_error
    assert_equal [late], creator.cleanup_errors
    assert creator.cancelled?
  end
end
