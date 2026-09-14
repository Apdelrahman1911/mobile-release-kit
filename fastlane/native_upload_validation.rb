# frozen_string_literal: true

require_relative "release_support"
require_relative "native_process_spawn"
require_relative "native_upload_process"

module MobileReleaseKit
  # Adapters own command selection and result policy. This module owns only a
  # bounded capture, including its actual tasks, endpoint leases and C child.
  module NativeUploadValidation
    REGISTRY_LOCK = Mutex.new
    SESSIONS = []
    private_constant :REGISTRY_LOCK, :SESSIONS

    module_function

    def capture(environment, argv, tooling_directory, max_seconds:, max_output_bytes:, label:, failure_message:)
      CaptureSession.new(
        environment: environment, argv: argv, tooling_directory: tooling_directory,
        max_seconds: max_seconds, max_output_bytes: max_output_bytes,
        label: label, failure_message: failure_message,
      ).execute
    rescue IOError, SystemCallError, NativeProcessSpawn::Error, NativeUploadProcess::Error
      # Redact only after selecting the actual original primary. Arbitrary
      # errors and the actual Interrupt/SystemExit object are not reconstructed.
      raise ContractError, "#{label} validator could not be executed safely; no upload is authorized", cause: nil
    end

    def register_session(session)
      Thread.handle_interrupt(Exception => :never) do
        REGISTRY_LOCK.synchronize do
          raise NativeUploadProcess::LifecycleError if SESSIONS.any?(&:retained_unknown?)
          SESSIONS << session
        end
      end
    end

    def release_session(session)
      Thread.handle_interrupt(Exception => :never) do
        REGISTRY_LOCK.synchronize { SESSIONS.delete_if { |owned| owned.equal?(session) } }
      end
    end

    def unresolved_sessions
      REGISTRY_LOCK.synchronize { SESSIONS.select(&:retained_unknown?).freeze }
    end

    private_class_method :register_session, :release_session, :unresolved_sessions

    # Retained on UNKNOWN through GC/caller unwind. This is not a public process
    # receipt API, a test callback, or a detached cleanup/reaping worker.
    class CaptureSession
      NANOSECONDS = 1_000_000_000
      CLEANUP_NS = 5 * NANOSECONDS
      MAX_SECONDS = 3_600
      MAX_OUTPUT_BYTES = 64 * 1024
      READ_BYTES = 4_096
      POLL_SECONDS = 0.02
      GRANTS = %w[ADMIT RUN COMMIT].freeze
      PARENT_ROLES = %i[control_write status_read stdin_write stdout_read stderr_read].freeze
      CHILD_ROLES = %i[
        control_read status_write stdin_read stdout_write stderr_write
        null_stdin null_stdout null_stderr
      ].freeze
      CLOSED_STATES = %i[closed not_acquired].freeze

      attr_reader :capture_slot, :creator_slot, :acquisition, :custodian_child,
                  :leases, :hello, :reserved, :ready, :validator_status, :final, :custodian_receipt,
                  :stdout_eof, :stderr_eof, :status_eof, :stdin_close_returned,
                  :phase, :first_error, :caller_primary

      def initialize(environment:, argv:, tooling_directory:, max_seconds:, max_output_bytes:, label:, failure_message:, caller: Thread.current)
        started_ns = monotonic_ns
        unless (max_seconds.is_a?(Integer) || max_seconds.is_a?(Float)) &&
               max_seconds.finite? && max_seconds.positive? && max_seconds <= MAX_SECONDS &&
               max_output_bytes.instance_of?(Integer) && max_output_bytes.positive? &&
               max_output_bytes <= MAX_OUTPUT_BYTES
          raise NativeUploadProcess::LifecycleError
        end
        @caller = caller
        @run_deadline_ns = started_ns + (max_seconds * NANOSECONDS).floor
        @hard_cleanup_deadline_ns = @run_deadline_ns + CLEANUP_NS
        @capture_slot = NativeUploadProcess::TaskSlot.new(
          caller: caller, parent_slot: nil, run_deadline_ns: @run_deadline_ns,
          hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
        )
        @environment, @argv, @tooling_directory = environment, argv, tooling_directory
        @max_output_bytes, @label, @failure_message = max_output_bytes, label, failure_message
        @leases = {}.freeze
        @close_attempts, @queued, @sent, @write_attempted = {}, {}, {}, {}
        @broken_reads, @output_exceeded = {}, {}
        @cleanup_errors, @outgoing, @incoming = [], [], []
        @task_errors, @caller_errors = [], []
        @stdout, @stderr = +"".b, +"".b
        @stdout_eof = @stderr_eof = @status_eof = false
        @stdin_close_returned = @status_decoded_eof = false
        @status_valid = true
        @transport_cancel = @retained_unknown = false
        @creator_entered = false
        @phase = :closed
      end

      # All nested TaskSlots share this one monotonic failure record, INCLUDING
      # wrapper setup/publication/tail errors. Later caller cancellation cannot
      # replace an established task primary, nor can the reverse happen.
      def primary_error
        @capture_slot.first_error
      end

      def cleanup_errors
        errors = @cleanup_errors + @capture_slot.cleanup_errors
        # Original endpoint closes occur AFTER creator settlement; those actual
        # leaf errors must not disappear behind an earlier finish-time snapshot.
        errors.concat(@acquisition.cleanup_errors) if @acquisition
        errors.uniq(&:object_id).freeze
      end

      def retained_unknown?
        @retained_unknown || @acquisition&.state == :unknown ||
          @custodian_child&.state == :unknown || (!@caller.alive? && !@released)
      end

      # Absence of a creator slot is never enough. This latch precedes ALL
      # creator setup and can prove no attempt only after the original root task
      # is positively never started or genuinely joined, with launch retired.
      def no_creator_attempt?
        !@creator_entered && @creator_slot.nil? && @acquisition.nil? &&
          @capture_slot.launch_retired? &&
          (!@capture_slot.start_attempted? || @capture_slot.joined?)
      end

      def settled?
        return false if @capture_slot.start_attempted? && !@capture_slot.joined?
        return false if @creator_slot&.start_attempted? && !@creator_slot.joined?
        return false if @run_entered && !@task_cleanup_complete
        return false unless creation_settled?
        return false unless @leases.values.all? { |lease| CLOSED_STATES.include?(lease.state) }
        return false if @custodian_child && !genuine_custodian_receipt?
        true
      end

      # Physical cleanup finality, NOT validation acceptance. An ordinary
      # rejection can finalize without authorizing an upload.
      def finality_confirmed?
        return false if @retained_unknown
        return false unless settled? && cleanup_errors.empty?
        return no_custodian_attempt? unless @custodian_child
        !!(@final && @final.fetch("cleanup") == "confirmed" && @status_valid &&
          @status_decoded_eof && @status_eof && @stdout_eof && @stderr_eof && custodian_exit_agrees?)
      end

      def execute
        # Protect cleanup ENTRY, not blocking work. Start/join and final pending
        # cancellation delivery are immediate inside the whole-lifecycle guard.
        Thread.handle_interrupt(Exception => :never) do
          begin
            Thread.handle_interrupt(Exception => :immediate) do
              Thread.handle_interrupt(Exception => :never) do
                NativeUploadValidation.send(:register_session, self)
                @registered = true
              end
              @capture_slot.start { |slot| run(slot) }
              if @capture_slot.admit!
                joined = @capture_slot.join_until(deadline_ns: @run_deadline_ns)
                task_failure(timeout_error, reason: "deadline") unless joined
              else
                task_failure(@capture_slot.first_error || admission_error, reason: admission_reason)
              end
            end
          rescue Exception => error # rubocop:disable Lint/RescueException
            caller_failure(error)
          ensure
            begin
              finish_caller_ownership
            rescue Exception => error # rubocop:disable Lint/RescueException
              caller_failure(error)
              @retained_unknown = true
              record_cleanup_error(error)
            end
          end
          # All required closes/waits/joins/registry retirement precede this
          # final pending-delivery/acceptance boundary. No cleanup follows it.
          deliver_pending_cancellation
          begin
            Thread.handle_interrupt(Exception => :immediate) do
              task_failure(timeout_error, reason: "deadline") if primary_error.nil? && monotonic_ns >= @run_deadline_ns
              unless primary_error || successful_offer?
                task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle")
              end
              if primary_error.nil?
                @phase = :accepted
                return @capture_slot.offer
              end
            end
          rescue Exception => error # rubocop:disable Lint/RescueException
            caller_failure(error)
          end
          raise primary_error
        end
      end

      # Real capture TaskSlot body. Its short-lived creator is a DISTINCT task:
      # retained native writer duplicates must not depend on the drainer's EOF.
      def run(owned_slot)
        Thread.handle_interrupt(Exception => :never) do
          @run_entered = true
          begin
            Thread.handle_interrupt(Exception => :immediate) do
              unless owned_slot.equal?(@capture_slot) && owned_slot.thread.equal?(Thread.current)
                raise NativeUploadProcess::LifecycleError
              end
              prepare_configuration
              start_creator
              settle_creator
              prepare_channels if @custodian_child && creator_released?
              drive_channels if @channels_prepared
              @run_body_returned = true
            end
          rescue Exception => error # rubocop:disable Lint/RescueException
            task_failure(error, reason: reason_for(error))
          ensure
            finish_task_ownership
          end
          raise primary_error if primary_error
          @stdout.freeze
        end
      end

      # First normal stdin close only after genuinely bound READY. IOLease
      # retires the route before its single close; IO#closed? cannot repair an
      # ambiguous return or authorize retrying a raw descriptor.
      def close_stdin_after_ready
        raise NativeUploadProcess::LifecycleError unless @ready && @sent["RUN"]
        lease = @leases.fetch(:stdin_write)
        @close_attempts[lease] = true
        lease.close_once
        @stdin_close_returned = true
      end

      private

      def monotonic_ns
        Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      end

      def timeout_error
        ContractError.new("#{@label} validation timed out; no upload is authorized")
      end

      def output_error
        ContractError.new("#{@label} validation output exceeded its safety bound")
      end

      def admission_reason
        monotonic_ns >= @run_deadline_ns ? "deadline" : "lifecycle"
      end

      def admission_error
        admission_reason == "deadline" ? timeout_error : NativeUploadProcess::LifecycleError.new
      end

      def reason_for(error)
        case error
        when Interrupt, SystemExit then "cancelled"
        when IOError, SystemCallError then "io"
        when NativeUploadProcess::ProtocolError then "protocol"
        when NativeProcessSpawn::Error then "creation"
        else "lifecycle"
        end
      end

      def task_failure(error, reason:, transport_cancel: true, cleanup: false)
        Thread.handle_interrupt(Exception => :never) do
          @capture_slot.cancel!(error: error, reason_code: reason)
          @first_error ||= error
          @task_errors << error unless @task_errors.any? { |entry| entry.equal?(error) }
          @cancel_reason ||= reason
          @transport_cancel = true if transport_cancel
          record_cleanup_error(error) if cleanup
          close_launch_routes
        end
      end

      def caller_failure(error)
        Thread.handle_interrupt(Exception => :never) do
          @capture_slot.cancel!(error: error, reason_code: reason_for(error))
          @caller_primary ||= error
          @caller_errors << error unless @caller_errors.any? { |entry| entry.equal?(error) }
          @cancel_reason ||= reason_for(error)
          @transport_cancel = true
          close_launch_routes
        end
      end

      def record_cleanup_error(error)
        @capture_slot.cancel!(error: error, reason_code: reason_for(error))
        @cleanup_errors << error unless @cleanup_errors.any? { |entry| entry.equal?(error) }
        @capture_slot.record_cleanup_error(error)
      end

      def close_launch_routes
        @capture_slot.close_launch!
        @creator_slot&.close_launch!
        @acquisition&.close_launch!
      end

      def cleanup_deadline_ns
        [@capture_slot.cleanup_deadline_ns, @creator_slot&.cleanup_deadline_ns,
         @hard_cleanup_deadline_ns].compact.min
      end

      def active_deadline_ns
        primary_error || @capture_slot.cancelled? ? cleanup_deadline_ns : @run_deadline_ns
      end

      def prepare_configuration
        @capture_slot.check_creation!
        @nsig = NativeUploadProcess.nsig
        @parent_context = { parent_pid: Process.pid, session_id: Process.getsid(0) }.freeze
        deadlines = {
          run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
        }.freeze
        @helper_argv = NativeUploadProcess.helper_argv(
          role: "custodian", parent_context: @parent_context, deadlines: deadlines,
        )
        @helper_environment = NativeUploadProcess.helper_environment
        configuration = {
          "v" => 1, "type" => "CONFIG", "role" => "custodian",
          "cwd" => File.realpath(@tooling_directory), "validator_argv" => @argv,
          "validator_env" => @environment, "run_deadline_ns" => @run_deadline_ns,
          "hard_cleanup_deadline_ns" => @hard_cleanup_deadline_ns,
          "max_output_bytes" => @max_output_bytes, "capture_kind" => "native",
        }
        # Freeze the complete bounded wire value BEFORE any FD/child acquisition.
        # Later caller mutation cannot alter the command handed to this helper.
        @configuration_bytes = NativeUploadProcess::Protocol.encode(configuration, direction: :o_to_c, nsig: @nsig)
        @decoder = NativeUploadProcess::Protocol::Decoder.new(direction: :c_to_o, nsig: @nsig)
      end

      def start_creator
        @creator_entered = true
        @capture_slot.check_creation!
        Thread.handle_interrupt(Exception => :never) do
          @creator_slot = NativeUploadProcess::TaskSlot.new(
            caller: Thread.current, parent_slot: @capture_slot,
            run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
          )
          @acquisition = NativeProcessSpawn::Acquisition.new(
            owner_slot: @creator_slot, run_deadline_ns: @run_deadline_ns,
            hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
          )
          @leases = @acquisition.resources
        end
        @creator_slot.start do |slot|
          begin
            slot.check_creation!
            NativeProcessSpawn.pipe(@acquisition, read_role: :control_read, write_role: :control_write)
            NativeProcessSpawn.pipe(@acquisition, read_role: :status_read, write_role: :status_write)
            NativeProcessSpawn.pipe(@acquisition, read_role: :stdin_read, write_role: :stdin_write)
            NativeProcessSpawn.pipe(@acquisition, read_role: :stdout_read, write_role: :stdout_write)
            NativeProcessSpawn.pipe(@acquisition, read_role: :stderr_read, write_role: :stderr_write)
            NativeProcessSpawn.null(@acquisition, role: :null_stdin, access: :read)
            NativeProcessSpawn.null(@acquisition, role: :null_stdout, access: :write)
            NativeProcessSpawn.null(@acquisition, role: :null_stderr, access: :write)
            sources = %i[
              null_stdin null_stdout null_stderr control_read status_write
              stdin_read stdout_write stderr_write
            ].map { |role| @leases.fetch(role) }.freeze
            spec = NativeProcessSpawn::SpawnSpec.new(
              executable: @helper_argv.fetch(0), argv: @helper_argv,
              env: @helper_environment, fd_sources: sources,
            )
            NativeProcessSpawn.create(@acquisition, spec)
          rescue Exception => error # rubocop:disable Lint/RescueException
            task_failure(error, reason: reason_for(error))
            raise
          end
        end
        unless @creator_slot.admit!
          task_failure(@creator_slot.first_error || admission_error, reason: admission_reason)
        end
      end

      def settle_creator
        return unless @creator_slot
        @creator_slot.close_launch! if primary_error || @capture_slot.cancelled?
        # The leaf has a distinct positive NEVER-STARTED creator branch. It
        # closes the original slot and verifies that no native/IO/task activity
        # was entered. That is NOT a joined thread, nor a nil-return inference.
        if !@creator_slot.start_attempted?
          @creator_slot.close_launch!
        elsif !@creator_slot.joined?
          joined = @creator_slot.join_until(deadline_ns: active_deadline_ns)
          unless joined
            task_failure(timeout_error, reason: "deadline") unless primary_error
            @creator_slot.cancel!(reason_code: @cancel_reason || "lifecycle", cleanup_deadline_ns: cleanup_deadline_ns)
            joined = @creator_slot.join_until(deadline_ns: cleanup_deadline_ns)
          end
          unless joined
            error = NativeUploadProcess::LifecycleError.new
            @retained_unknown = true
            @acquisition.mark_unknown!(error)
            task_failure(error, reason: "lifecycle", cleanup: true)
            return
          end
        end
        # Only this ACTUALLY JOINED short-lived creator permits native action/
        # attribute destruction and closing its high-FD source duplicates.
        unless @creation_finish_attempted
          @creation_finish_attempted = true
          @acquisition.close_launch!
          @acquisition.finish_creation!(creator_slot: @creator_slot)
          @creation_finish_returned = true
        end
        @custodian_child = @acquisition.child
        if @acquisition.first_error && primary_error.nil?
          task_failure(@acquisition.first_error, reason: reason_for(@acquisition.first_error))
        end
        @acquisition.cleanup_errors.each { |error| record_cleanup_error(error) }
        @phase = :custodian_published if @custodian_child
      end

      def creation_settled?
        return no_creator_attempt? unless @acquisition
        creator_released? && @acquisition.state != :unknown &&
          @acquisition.cleanup_errors.empty?
      end

      def creator_released?
        @creation_finish_returned && @creator_slot &&
          (@creator_slot.joined? || (!@creator_slot.start_attempted? &&
            @creator_slot.launch_retired? && @acquisition.not_attempted?))
      end

      def no_custodian_attempt?
        return no_creator_attempt? unless @acquisition
        @acquisition.not_attempted?
      end

      def prepare_channels
        return if @channels_prepared
        # No handoff/grant until genuine creator join and duplicate release.
        # Only the original endpoints belonging to this acquisition are closed.
        CHILD_ROLES.each { |role| close_lease(@leases.fetch(role)) }
        PARENT_ROLES.each do |role|
          lease = @leases.fetch(role)
          raise NativeUploadProcess::LifecycleError unless lease.state == :open && lease.io
          lease.io.binmode
        end
        @channels_prepared = true
        if primary_error || @capture_slot.cancelled?
          close_control
        else
          @outgoing << { type: "CONFIG", bytes: @configuration_bytes, offset: 0 }
          @queued["CONFIG"] = true
        end
      end

      def finish_task_ownership
        close_launch_routes
        unless @run_body_returned || primary_error
          # Thread.kill/non-Exception unwinds must not turn this ensure into a
          # fresh launch path just because no Exception object was delivered.
          task_failure(NativeUploadProcess::LifecycleError.new, reason: "cancelled")
        end
        # Repeated interruptions never inject cancellation into custody or
        # manufacture a join. Unsettled native creators keep their source leases.
        while @creator_slot&.start_attempted? && !@creator_slot.joined? && monotonic_ns < cleanup_deadline_ns
          begin
            Thread.handle_interrupt(Exception => :immediate) { settle_creator }
            break
          rescue Exception => error # rubocop:disable Lint/RescueException
            task_failure(error, reason: reason_for(error))
          end
        end
        if @creator_slot && !@creation_finish_attempted &&
           (@creator_slot.joined? || !@creator_slot.start_attempted?)
          begin
            Thread.handle_interrupt(Exception => :immediate) { settle_creator }
          rescue Exception => error # rubocop:disable Lint/RescueException
            task_failure(error, reason: reason_for(error), cleanup: true)
          end
        end
        @custodian_child ||= @acquisition&.child
        if @creator_slot && !@creator_slot.joined? && !creator_released?
          error = NativeUploadProcess::LifecycleError.new
          @retained_unknown = true
          @acquisition.mark_unknown!(error)
          task_failure(error, reason: "lifecycle", cleanup: true)
        elsif !@acquisition || creator_released?
          while @custodian_child && !channels_terminal? && monotonic_ns < cleanup_deadline_ns
            begin
              Thread.handle_interrupt(Exception => :immediate) do
                prepare_channels unless @channels_prepared
                drive_channels
              end
            rescue Exception => error # rubocop:disable Lint/RescueException
              task_failure(error, reason: reason_for(error))
              # A failed observer/hook must not spin or bypass all remaining
              # cleanup. Resume bounded work; genuine joins/closes still decide
              # finality, rather than classifying a delivered interruption as a
              # fictional completed (or permanently failed) native operation.
              remaining = (cleanup_deadline_ns - monotonic_ns).fdiv(NANOSECONDS)
              if remaining.positive?
                begin
                  Thread.handle_interrupt(Exception => :immediate) { sleep([remaining, POLL_SECONDS].min) }
                rescue Exception => later # rubocop:disable Lint/RescueException
                  task_failure(later, reason: reason_for(later))
                end
              end
            end
          end
          # A pre-READY no-validator cleanup retires stdin only after truthful
          # terminal/EOF/wait, or after positive no-custodian-attempt proof.
          @leases.each do |role, lease|
            next if role == :stdin_write && !@ready && @custodian_child && !descendant_terminal?
            close_lease(lease)
          end
        end
        @task_cleanup_complete = true
      end

      def close_lease(lease)
        return if CLOSED_STATES.include?(lease.state) || @close_attempts[lease]
        @close_attempts[lease] = true
        begin
          lease.close_once
        rescue Exception => error # rubocop:disable Lint/RescueException
          uncertain = !CLOSED_STATES.include?(lease.state)
          @retained_unknown = true if uncertain
          task_failure(error, reason: reason_for(error), cleanup: uncertain)
        end
      end

      def close_control
        @outgoing.clear
        lease = @leases[:control_write]
        close_lease(lease) if lease
        @control_closed = true
      end

      def queue_frame(type, fields = {})
        raise NativeUploadProcess::ProtocolError if @queued[type] || @control_closed
        frame = { "v" => 1, "type" => type }.merge(fields)
        bytes = NativeUploadProcess::Protocol.encode(frame, direction: :o_to_c, nsig: @nsig)
        @outgoing << { type: type, bytes: bytes, offset: 0 }
        @queued[type] = true
      end

      def observe_cancellation
        unless @caller.alive?
          task_failure(NativeUploadProcess::LifecycleError.new, reason: "parent_lost")
        end
        if primary_error.nil? && monotonic_ns >= @run_deadline_ns
          task_failure(timeout_error, reason: "deadline")
        end
        return unless @transport_cancel || (@capture_slot.cancelled? && primary_error.nil?)
        @transport_cancel = true
        close_launch_routes
        return if @control_closed || @final || @queued["CANCEL"]
        # Replacing a partly written frame corrupts framing and could repeat a
        # grant whose return was lost. Retire the edge instead; C owns bounded
        # cleanup on actual control EOF independently of COMMIT.
        if !@sent["CONFIG"] || @outgoing.any? { |entry| entry.fetch(:offset).positive? }
          close_control
        else
          @outgoing.clear
          queue_frame("CANCEL", "reason_code" => @cancel_reason || "cancelled",
                      "cleanup_deadline_ns" => cleanup_deadline_ns)
        end
      end

      def advance_protocol
        return if primary_error || @capture_slot.cancelled? || @control_closed || @final
        if monotonic_ns >= @run_deadline_ns
          task_failure(timeout_error, reason: "deadline")
          return
        end
        @capture_slot.check_creation!
        if @hello && @sent["CONFIG"] && !@queued["ADMIT"]
          queue_frame("ADMIT")
        elsif @reserved && @sent["ADMIT"] && !@queued["RUN"]
          queue_frame("RUN")
        elsif normal_validator_success? && @stdout_eof && @stderr_eof &&
              @stdin_close_returned && !@queued["COMMIT"] && cleanup_errors.empty?
          # C must already be cleaning G/releasing unused writers. Only genuine
          # independent data EOF plus a normal result can request late COMMIT.
          queue_frame("COMMIT")
        end
      end

      def write_control
        return if @control_closed || @outgoing.empty?
        entry = @outgoing.first
        begin
          # Bounded nonblocking operation + publication, not a mask around a
          # blocking write or the whole protocol transaction.
          Thread.handle_interrupt(Exception => :never) do
            if GRANTS.include?(entry.fetch(:type))
              if primary_error || @capture_slot.cancelled? || @capture_slot.launch_retired? ||
                 monotonic_ns >= @run_deadline_ns
                task_failure(admission_error, reason: admission_reason) unless primary_error
                @transport_cancel = true
                observe_cancellation
                return
              end
              # The actual write has its own admission boundary; an earlier
              # queue decision cannot authorize a post-cancellation grant.
              @capture_slot.check_creation!
            end
            @write_attempted[entry.fetch(:type)] = true
            bytes = entry.fetch(:bytes).byteslice(entry.fetch(:offset), READ_BYTES)
            count = @leases.fetch(:control_write).io.write_nonblock(bytes, exception: false)
            return if count == :wait_writable
            unless count.instance_of?(Integer) && count.positive? && count <= bytes.bytesize
              raise NativeUploadProcess::ProtocolError
            end
            entry[:offset] += count
            if entry.fetch(:offset) == entry.fetch(:bytes).bytesize
              @sent[entry.fetch(:type)] = true
              @outgoing.shift
              close_control if entry.fetch(:type) == "CANCEL"
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          task_failure(error, reason: reason_for(error))
          close_control
        end
      end

      def read_status
        drain_status_frames
        return if @status_eof || @broken_reads[:status_read]
        begin
          # Publish a whole decoded batch before dispatch. If the real READY
          # close raises, later STATUS/FINAL frames from that SAME read remain
          # owned and can still be consumed during cleanup; never replay READY.
          Thread.handle_interrupt(Exception => :never) do
            chunk = @leases.fetch(:status_read).io.read_nonblock(READ_BYTES, exception: false)
            return if chunk == :wait_readable
            if chunk.nil?
              @status_eof = true
              @status_decoded_eof = @decoder.eof if @status_valid
            elsif @status_valid
              @incoming.concat(@decoder.feed(chunk))
            end
          end
        rescue NativeUploadProcess::ProtocolError => error
          invalidate_status(error)
        rescue IOError, SystemCallError => error
          @broken_reads[:status_read] = true
          @status_valid = false
          task_failure(error, reason: "io")
        end
        drain_status_frames
        if @status_eof
          invalidate_status(NativeUploadProcess::ProtocolError.new) unless @final
          close_lease(@leases.fetch(:status_read))
        end
      end

      def drain_status_frames
        while @status_valid && !@incoming.empty?
          begin
            Thread.handle_interrupt(Exception => :never) do
              frame = @incoming.shift
              receive_frame(frame)
            end
          rescue NativeUploadProcess::ProtocolError => error
            invalidate_status(error)
          end
        end
      end

      def invalidate_status(error)
        @status_valid = false
        @incoming.clear
        task_failure(error, reason: "protocol")
      end

      def read_output(role, buffer, eof_name)
        return if instance_variable_get(eof_name) || @broken_reads[role]
        begin
          Thread.handle_interrupt(Exception => :never) do
            chunk = @leases.fetch(role).io.read_nonblock(READ_BYTES, exception: false)
            return if chunk == :wait_readable
            if chunk.nil?
              instance_variable_set(eof_name, true)
            elsif !@output_exceeded[role]
              if buffer.bytesize + chunk.bytesize > @max_output_bytes
                @output_exceeded[role] = true
                task_failure(output_error, reason: "lifecycle")
              else
                buffer << chunk
              end
            end
          end
        rescue IOError, SystemCallError => error
          @broken_reads[role] = true
          task_failure(error, reason: "io")
        end
        close_lease(@leases.fetch(role)) if instance_variable_get(eof_name)
      end

      def receive_frame(frame)
        # Decoder enforces terminal order too. Keep the owner's accepted FINAL
        # absorbing even if a later frame is independently supplied/decoded.
        raise NativeUploadProcess::ProtocolError if @final
        case frame.fetch("type")
        when "HELLO"
          unless !@hello && @custodian_child && frame.fetch("pid") == @custodian_child.pid &&
                 frame.fetch("ppid") == @parent_context.fetch(:parent_pid) &&
                 frame.fetch("sid") == @custodian_child.pid && frame.fetch("pgid") == @custodian_child.pid
            raise NativeUploadProcess::ProtocolError
          end
          @hello = frame
          @phase = :hello
        when "RESERVED"
          unless @hello && @sent["ADMIT"] && !@reserved &&
                 frame.fetch("session_id") == @custodian_child.pid &&
                 frame.fetch("keeper_pid") == frame.fetch("group_id") &&
                 ![@custodian_child.pid, @parent_context.fetch(:parent_pid)].include?(frame.fetch("keeper_pid"))
            raise NativeUploadProcess::ProtocolError
          end
          @reserved = frame
          @phase = :reserved
        when "READY"
          unless @reserved && @sent["RUN"] && !@ready &&
                 frame.fetch("group_id") == @reserved.fetch("group_id") &&
                 frame.fetch("keeper_pgid") == @custodian_child.pid &&
                 ![@custodian_child.pid, @reserved.fetch("keeper_pid"), @parent_context.fetch(:parent_pid)].include?(frame.fetch("validator_pid"))
            raise NativeUploadProcess::ProtocolError
          end
          @ready = frame
          @phase = :ready
          close_stdin_after_ready
        when "STATUS"
          unless @ready && !@validator_status && frame.fetch("validator_pid") == @ready.fetch("validator_pid")
            raise NativeUploadProcess::ProtocolError
          end
          @validator_status = frame
          @phase = :status
          unless normal_validator_success?
            task_failure(ContractError.new(@failure_message), reason: "lifecycle", transport_cancel: false)
          end
        when "FINAL"
          validate_final(frame)
          @final = frame
          @phase = :final
          case frame.fetch("outcome")
          when "rejected"
            task_failure(ContractError.new(@failure_message), reason: "lifecycle", transport_cancel: false) unless primary_error
          when "failed"
            task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle", transport_cancel: false) unless primary_error
          end
          if frame.fetch("cleanup") != "confirmed"
            task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle", transport_cancel: false, cleanup: true)
          end
          close_control
        else
          raise NativeUploadProcess::ProtocolError
        end
      end

      def validate_final(frame)
        raise NativeUploadProcess::ProtocolError if @final || !@custodian_child
        keeper, validator, group = frame.values_at("keeper", "validator", "group")
        if @reserved
          raise NativeUploadProcess::ProtocolError if keeper.fetch("state") == "not_attempted" || group.fetch("state") == "not_created"
          if keeper.fetch("state") == "reaped" && keeper.fetch("pid") != @reserved.fetch("keeper_pid")
            raise NativeUploadProcess::ProtocolError
          end
          if group.fetch("state") == "retired" && group.fetch("id") != @reserved.fetch("group_id")
            raise NativeUploadProcess::ProtocolError
          end
        elsif !@write_attempted["ADMIT"] && keeper.fetch("state") != "not_attempted"
          raise NativeUploadProcess::ProtocolError
        end
        if !@write_attempted["RUN"] && validator.fetch("state") != "not_attempted"
          raise NativeUploadProcess::ProtocolError
        end
        if @ready && validator.fetch("state") == "reaped" && validator.fetch("pid") != @ready.fetch("validator_pid")
          raise NativeUploadProcess::ProtocolError
        end
        if @ready && validator.fetch("state") == "not_attempted"
          raise NativeUploadProcess::ProtocolError
        end
        original_parents = [@custodian_child.pid, @parent_context.fetch(:parent_pid)]
        if keeper.fetch("state") == "reaped" && original_parents.include?(keeper.fetch("pid"))
          raise NativeUploadProcess::ProtocolError
        end
        if validator.fetch("state") == "reaped"
          original_parents << keeper.fetch("pid") if keeper.fetch("state") == "reaped"
          raise NativeUploadProcess::ProtocolError if original_parents.include?(validator.fetch("pid"))
        end
        if @validator_status
          unless validator.fetch("state") == "reaped" &&
                 validator.fetch("pid") == @validator_status.fetch("validator_pid") &&
                 validator.fetch("status_kind") == @validator_status.fetch("status_kind") &&
                 validator.fetch("status_code") == @validator_status.fetch("status_code")
            raise NativeUploadProcess::ProtocolError
          end
        end
        if frame.fetch("outcome") == "ok"
          unless @sent["COMMIT"] && @ready && normal_validator_success? &&
                 @stdout_eof && @stderr_eof && @stdin_close_returned
            raise NativeUploadProcess::ProtocolError
          end
        elsif frame.fetch("outcome") == "rejected"
          raise NativeUploadProcess::ProtocolError unless @ready && @validator_status && !normal_validator_success?
        end
      end

      def normal_validator_success?
        @validator_status && @validator_status.fetch("status_kind") == "exit" && @validator_status.fetch("status_code").zero?
      end

      def poll_custodian
        return if @custodian_receipt || @wait_broken
        begin
          # O has NO group signal/probe route. Even its direct C numeric route
          # retires irreversibly before the first potentially consuming wait.
          @custodian_child.retire_numeric!
          receipt = @custodian_child.poll_wait
          return unless receipt # Only a genuine non-consuming WNOHANG result.
          unless receipt.equal?(@custodian_child.receipt) && receipt.pid == @custodian_child.pid
            raise NativeUploadProcess::LifecycleError
          end
          @custodian_receipt = receipt
        rescue Exception => error # rubocop:disable Lint/RescueException
          @wait_broken = @retained_unknown = true
          task_failure(error, reason: reason_for(error), cleanup: true)
        end
      end

      def genuine_custodian_receipt?
        @custodian_receipt && @custodian_child.state == :reaped &&
          @custodian_receipt.equal?(@custodian_child.receipt) && @custodian_receipt.pid == @custodian_child.pid
      end

      def custodian_exit_agrees?
        return false unless genuine_custodian_receipt? && @final
        # FINAL cannot confirm its own offer. C must genuinely exit 0 for
        # ok/rejected or 2 for failed; exit 1, other codes and signals cannot
        # establish finality, even with FINAL cleanup="confirmed".
        expected = @final.fetch("outcome") == "failed" ? 2 : 0
        @custodian_receipt.status_kind == "exit" && @custodian_receipt.status_code == expected
      end

      def descendant_terminal?
        @final && @final.fetch("cleanup") == "confirmed" && @status_valid &&
          @status_eof && @status_decoded_eof && custodian_exit_agrees?
      end

      def channels_terminal?
        return false unless @channels_prepared
        (@status_eof || @broken_reads[:status_read]) &&
          (@stdout_eof || @broken_reads[:stdout_read]) &&
          (@stderr_eof || @broken_reads[:stderr_read]) && (@custodian_receipt || @wait_broken)
      end

      def drive_channels
        until channels_terminal?
          observe_cancellation
          if monotonic_ns >= active_deadline_ns
            @retained_unknown = true
            task_failure(NativeUploadProcess::LifecycleError.new, reason: "deadline", cleanup: true)
            break
          end
          advance_protocol
          write_control
          read_status
          read_output(:stdout_read, @stdout, :@stdout_eof)
          read_output(:stderr_read, @stderr, :@stderr_eof)
          poll_custodian
          advance_protocol
          break if channels_terminal?
          wait_for_channels
        end
        if @custodian_receipt && @final && !custodian_exit_agrees?
          task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle", cleanup: true)
        end
      end

      def wait_for_channels
        remaining = (active_deadline_ns - monotonic_ns).fdiv(NANOSECONDS)
        return unless remaining.positive?
        reads = []
        reads << @leases.fetch(:status_read).io unless @status_eof || @broken_reads[:status_read]
        reads << @leases.fetch(:stdout_read).io unless @stdout_eof || @broken_reads[:stdout_read]
        reads << @leases.fetch(:stderr_read).io unless @stderr_eof || @broken_reads[:stderr_read]
        writes = @control_closed || @outgoing.empty? ? [] : [@leases.fetch(:control_write).io]
        IO.select(reads, writes, nil, [remaining, POLL_SECONDS].min)
      end

      def finish_caller_ownership
        close_launch_routes
        unless @capture_slot.joined? || !@capture_slot.start_attempted?
          task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle") unless primary_error
          loop do
            break if monotonic_ns >= cleanup_deadline_ns
            begin
              joined = Thread.handle_interrupt(Exception => :immediate) do
                @capture_slot.join_until(deadline_ns: cleanup_deadline_ns)
              end
              break if joined || monotonic_ns >= cleanup_deadline_ns
            rescue Exception => error # rubocop:disable Lint/RescueException
              caller_failure(error)
            end
          end
        end
        if !settled? || !finality_confirmed?
          @retained_unknown = true
          task_failure(NativeUploadProcess::LifecycleError.new, reason: "lifecycle", cleanup: true)
        end
        if @registered && finality_confirmed?
          NativeUploadValidation.send(:release_session, self)
          @released = true
        end
      end

      def successful_offer?
        @capture_slot.joined? && primary_error.nil? && !@capture_slot.cancelled? &&
          finality_confirmed? && @final && @final.fetch("outcome") == "ok" &&
          @sent["COMMIT"] && normal_validator_success? && @stdin_close_returned &&
          @output_exceeded.empty? && @capture_slot.offer.equal?(@stdout)
      end

      def deliver_pending_cancellation
        first = true
        while first || (Thread.current.pending_interrupt? && monotonic_ns < cleanup_deadline_ns)
          first = false
          begin
            Thread.handle_interrupt(Exception => :immediate) { nil }
          rescue Exception => error # rubocop:disable Lint/RescueException
            caller_failure(error)
          end
        end
      end
    end

    private_constant :CaptureSession
  end
end
