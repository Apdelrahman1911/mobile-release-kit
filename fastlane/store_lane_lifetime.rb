# frozen_string_literal: true

require_relative "native_upload_process"

# An explicit adapter for the pinned FastlanePty callback, installed only by the
# composed StoreLaneRuntime after its original admission and source checks.
# No require of Fastlane, gem edit, automatic hook, native owner or new watchdog.
#
# The caller must keep the original Invocation for the whole lane. Its adapter
# predicate is ONE conjunct, not nested-validator or process-family finality.
# The actual outer C/A/W owner must bound creation, draining and waiting. This
# file deliberately supplies neither a fresh deadline nor a cleanup allowance.
module MobileReleaseKit
  module StoreLaneLifetime
    LANES = %w[
      android_internal_upload android_external_promote android_production_draft
      ios_testflight_internal ios_testflight_external ios_app_store_submit
    ].freeze
    FAILURE = "Store lane adapter lifetime is unconfirmed; continuation is forbidden"
    private_constant :LANES, :FAILURE

    # Installed explicitly by the composed entrypoint, never at require
    # time. One process invocation cannot replace a failed original record.
    def self.activate!(invocation)
      raise LifetimeError unless invocation.instance_of?(Invocation)
      invocation.send(:admit_activation!)
      if @invocation
        @invocation.origin!
        @invocation.mark_unknown!(LifetimeError.new)
        @invocation.raise_unknown!
      end
      @invocation = invocation
    end

    def self.current_invocation
      @invocation&.tap(&:origin!)
    end

    def self.reserve_current_validation!(**request)
      current_invocation&.reserve_current_validation!(**request)
    end

    def self.require_upload_continuation!
      # Standalone validators/the not-yet-activated entrypoint retain their
      # existing API. Once installed, every caller sees the same original cell.
      current_invocation&.require_upload_continuation! || true
    end

    def self.require_ios_dispatch_not_refused!
      current_invocation&.require_ios_dispatch_not_refused! || true
    end

    def self.admit_native_capture!(binding, environment:, argv:, tooling_directory:)
      invocation = current_invocation
      return nil if invocation.nil? && binding.nil?
      raise LifetimeError unless invocation
      invocation.send(:admit_native_capture!, binding,
                      environment: environment, argv: argv, tooling_directory: tooling_directory)
    end

    class LifetimeError < StandardError
      attr_reader :primary

      def initialize(primary = nil)
        super(FAILURE)
        @primary = primary
      end
      # Do not manufacture an exit status for uncertain ownership. Pinned
      # Fastlane can convert StandardError; the original Invocation stays fatal.
    end

    # This is a genuinely waited, signaled child, NOT uncertain ownership.
    # -1 is the pinned FastlanePtyError compatibility value for that case only.
    class CommandExitError < StandardError
      attr_reader :process_status

      def initialize(status)
        super("Process crashed")
        @process_status = status
      end

      def exit_status
        -1
      end
    end

    # This exception is not proof by itself. Only the original invocation's
    # fixed pre-send gate can retain it and retire a never-started adapter.
    class IosDispatchRefused < StandardError
      attr_reader :primary

      def initialize(primary)
        super("IPA signing/profile eligibility expired before native dispatch; no new upload was sent")
        @primary = primary
      end
    end

    class Invocation
      NESTED_ROLES = {
        "current-ios" => ["ios_testflight_internal", :IosUploadValidation].freeze,
        "current-android" => ["android_internal_upload", :AndroidUploadValidation].freeze,
      }.freeze
      NANOSECONDS = 1_000_000_000
      NESTED_CLEANUP_NS = 5 * NANOSECONDS
      private_constant :NESTED_ROLES, :NANOSECONDS, :NESTED_CLEANUP_NS

      attr_reader :lane, :nonce, :output, :first_primary, :mode, :run_deadline_ns

      def initialize(lane:, nonce:, output:, mode: nil, run_deadline_ns: nil)
        unless lane.instance_of?(String) && LANES.include?(lane) &&
               nonce.instance_of?(String) && nonce.bytesize == 16 &&
               output.instance_of?(String) && !output.include?("\0") &&
               output.start_with?(File::SEPARATOR) && File.expand_path(output) == output
          raise LifetimeError
        end
        @pid, @thread = Process.pid, Thread.current
        @lane, @nonce, @output = lane.dup.freeze, nonce.b.dup.freeze, output.dup.freeze
        # Nil keeps the original uninstalled pipe-only API usable. It cannot
        # activate or admit a nested validator without an original deadline.
        raise LifetimeError unless mode.nil? || %w[prepare execute].include?(mode)
        raise LifetimeError unless run_deadline_ns.nil? ||
          (run_deadline_ns.instance_of?(Integer) && run_deadline_ns.positive?)
        @mode, @run_deadline_ns = mode&.dup&.freeze, run_deadline_ns
        @adapters, @secondary_errors, @cleanup_errors = [], [], []
        @unknown = @launches_closed = @nested_launches_closed = false
        @nested = nil
        @resources = @document_reservation = @document = nil
        @ios_dispatch_command = @ios_dispatch_artifact = @ios_dispatch_adapter = @ios_dispatch_refusal = nil
        @ios_dispatch_active, @ios_dispatch_state = false, :unreserved
      end

      def origin!
        # A forked/copied reference cannot operate on the parent's invocation.
        raise LifetimeError unless @pid == Process.pid && @thread.equal?(Thread.current)
      end

      def unknown?
        origin!
        @unknown
      end

      def cleanup_errors
        origin!
        @cleanup_errors.dup.freeze
      end

      def secondary_errors
        origin!
        @secondary_errors.dup.freeze
      end

      def mark_unknown!(error, cleanup: false)
        origin!
        Thread.handle_interrupt(Exception => :never) do
          @unknown = true # Before optional error collection or exception conversion.
          error = LifetimeError.new unless error.is_a?(Exception)
          @first_primary ||= error
          if !error.equal?(@first_primary) && @secondary_errors.length < 8 &&
             !@secondary_errors.any? { |item| item.equal?(error) }
            @secondary_errors << error
          end
          if cleanup && @cleanup_errors.length < 8 &&
             !@cleanup_errors.any? { |item| item.equal?(error) }
            @cleanup_errors << error
          end
        end
      end

      def require_adapter_continuation!
        origin!
        return true if !@unknown && @adapters.all?(&:retired?)

        mark_unknown!(LifetimeError.new) unless @unknown
        raise_unknown!
      end

      def seal_adapters!
        origin!
        @launches_closed = true
        require_adapter_continuation!
      end

      def adapters_sealed_and_retired?
        origin!
        @launches_closed && !@unknown && @adapters.all?(&:retired?)
      end

      def reserve_current_validation!(role:, adapter:, environment:, argv:, tooling_directory:, intent_sha256:, artifact:)
        origin!
        require_upload_continuation!
        expected = NESTED_ROLES[role]
        unless expected && @lane == expected[0] && @mode == "execute" &&
               MobileReleaseKit.const_defined?(expected[1], false) && adapter.equal?(MobileReleaseKit.const_get(expected[1], false)) &&
               !@nested_launches_closed && @nested.nil? && @run_deadline_ns &&
               monotonic_ns < @run_deadline_ns - NESTED_CLEANUP_NS
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        # The only slot is rooted before the actual CaptureSession constructor
        # or native capture can be entered. An exception cannot erase it.
        @nested = NestedValidation.new(self, role: role, adapter: adapter,
          environment: environment, argv: argv, tooling_directory: tooling_directory,
          intent_sha256: intent_sha256, artifact: artifact,
          run_deadline_ns: @run_deadline_ns - NESTED_CLEANUP_NS,
          hard_cleanup_deadline_ns: @run_deadline_ns)
      end

      def require_upload_continuation!
        origin!
        document_settled = @document_reservation.nil? ||
          (@document.equal?(@document_reservation) && @document.successful?)
        return true if !@unknown && @adapters.all?(&:retired?) && (@nested.nil? || @nested.retired?) &&
          document_settled && (@resources.nil? || @resources.continuation_allowed?)
        mark_unknown!(LifetimeError.new) unless @unknown
        raise_unknown!
      end

      def begin_ios_transporter_dispatch!(command:, artifact:)
        origin!
        require_upload_continuation!
        require_ios_dispatch_not_refused!
        unless @lane == "ios_testflight_internal" && @mode == "execute" && !@launches_closed &&
               @nested && @ios_dispatch_command.nil? && command.instance_of?(String) &&
               !command.empty? && !command.include?("\0") && artifact.instance_of?(String)
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        @ios_dispatch_command, @ios_dispatch_artifact = command.dup.freeze, artifact.dup.freeze
        @ios_dispatch_active, @ios_dispatch_state = true, :ready
        check_ios_dispatch_current!
        @ios_dispatch_command
      end

      def end_ios_transporter_dispatch!
        origin!
        @ios_dispatch_active = false
      end

      def require_ios_dispatch_not_refused!
        origin!
        return true unless @ios_dispatch_refusal

        require_upload_continuation! # UNKNOWN cleanup is not settled no-send.
        raise @ios_dispatch_refusal, cause: nil
      end

      def bind_resources!(resources)
        origin!
        type = MobileReleaseKit::StoreLaneResources::Inventory
        unless resources.instance_of?(type) && resources.bound_to?(self) && @resources.nil? &&
               @adapters.empty? && @nested.nil? && !@launches_closed && !@unknown
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        @resources = resources
      end

      def reserve_store_document!(publication)
        origin!
        require_upload_continuation!
        unless publication.instance_of?(MobileReleaseKit::StoreDocument::Publication) &&
               !publication.successful? && publication.first_primary.nil? && @document_reservation.nil? &&
               !@launches_closed
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        # Retained BEFORE caller mkdir_p or any publication filesystem effect.
        @document_reservation = publication
      end

      def record_store_document!(publication)
        origin!
        original = publication.instance_of?(MobileReleaseKit::StoreDocument::Publication) &&
          !@document_reservation.nil? && publication.equal?(@document_reservation)
        unless original && @document.nil? && !@unknown &&
               !@launches_closed && publication.successful?
          mark_unknown!(original && publication.first_primary || LifetimeError.new)
          raise_unknown!
        end
        value = publication.result
        unless value.fetch("path") == @output && value.fetch("size").instance_of?(Integer) &&
               value.fetch("size").between?(1, 4 * 1_024 * 1_024) &&
               value.fetch("identity").fetch("mode") == 0o600 &&
               value.fetch("sha256").match?(/\A[0-9a-f]{64}\z/)
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        @document = publication
      rescue Exception => error # rubocop:disable Lint/RescueException
        mark_unknown!(error) unless unknown?
        raise
      end

      def store_document_result
        origin!
        require_upload_continuation!
        @document&.result
      end

      def seal_uploads!
        origin!
        @launches_closed = @nested_launches_closed = true
        @resources&.seal!
        require_upload_continuation!
      end

      def uploads_sealed_and_retired?
        origin!
        @launches_closed && @nested_launches_closed && !@unknown &&
          @adapters.all?(&:retired?) && (@nested.nil? || @nested.retired?) &&
          (@resources.nil? || @resources.sealed_and_retired?) &&
          (@document_reservation.nil? || (@document.equal?(@document_reservation) && @document.successful?))
      end

      def spawn_with_pipes(command, &callback)
        origin!
        require_upload_continuation!
        require_ios_dispatch_not_refused!
        unless !@launches_closed && command.instance_of?(String) &&
               !command.empty? && !command.include?("\0") && callback
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        if @ios_dispatch_active && !(@ios_dispatch_state == :ready && @ios_dispatch_adapter.nil? &&
                                    command.equal?(@ios_dispatch_command))
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        # Reserve the actual adapter before any pipe/child can have an effect.
        command = command.dup.freeze
        adapter = PipeAdapter.new(self)
        @adapters << adapter
        @ios_dispatch_adapter = adapter if @ios_dispatch_active
        adapter.execute(command, &callback)
      rescue Exception => error # rubocop:disable Lint/RescueException
        raise if error.is_a?(CommandExitError) && adapter&.retired? && !unknown?
        raise if error.equal?(@ios_dispatch_refusal) && (adapter.nil? || adapter.retired?) && !unknown?

        mark_unknown!(error) unless error.is_a?(LifetimeError) && unknown?
        raise_unknown!
      end

      def raise_unknown!
        origin!
        mark_unknown!(LifetimeError.new) unless @unknown
        if @first_primary.is_a?(Interrupt) || @first_primary.is_a?(SystemExit)
          raise @first_primary
        end
        @lifetime_error ||= LifetimeError.new(@first_primary)
        raise @lifetime_error, cause: nil
      end

      private

      def check_ios_dispatch_current!
        @nested.require_current_ios_dispatch!(artifact: @ios_dispatch_artifact)
      rescue MobileReleaseKit::ContractError => error
        Thread.handle_interrupt(Exception => :never) do
          @ios_dispatch_state = :refused
          @ios_dispatch_refusal ||= IosDispatchRefused.new(error)
          @first_primary ||= @ios_dispatch_refusal
        end
        raise @ios_dispatch_refusal, cause: nil
      end

      def require_current_ios_native_dispatch!(adapter, command)
        origin!
        return true unless @ios_dispatch_active

        unless @ios_dispatch_state == :ready && adapter.equal?(@ios_dispatch_adapter) &&
               command == @ios_dispatch_command
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        check_ios_dispatch_current!
        @ios_dispatch_state = :attempted
        true
      end

      def original_ios_dispatch_refusal?(adapter, error)
        origin!
        @ios_dispatch_state == :refused && adapter.equal?(@ios_dispatch_adapter) &&
          !error.nil? && error.equal?(@ios_dispatch_refusal)
      end

      def monotonic_ns
        NativeUploadProcess.monotonic_ns
      end

      def admit_activation!
        origin!
        unless %w[prepare execute].include?(@mode) && @run_deadline_ns &&
               @run_deadline_ns > monotonic_ns && @run_deadline_ns <= monotonic_ns + 3_600 * NANOSECONDS &&
               !@nested_launches_closed && !@launches_closed && @nested.nil? && @adapters.empty? && !@unknown
          raise LifetimeError
        end
      end

      def admit_native_capture!(binding, **request)
        origin!
        unless binding.instance_of?(NestedValidation) && binding.equal?(@nested) && !@unknown && !@nested_launches_closed
          mark_unknown!(LifetimeError.new)
          raise_unknown!
        end
        binding.send(:begin_capture!, **request)
        binding
      end
    end

    # A fixed role, request and original session, not a generic callback or
    # caller-supplied settled flag. Only the actual native owner issues the
    # observation, and the fixed platform adapter validates its original bytes.
    class NestedValidation
      def initialize(invocation, role:, adapter:, environment:, argv:, tooling_directory:, intent_sha256:, artifact:,
                     run_deadline_ns:, hard_cleanup_deadline_ns:)
        @invocation, @role, @adapter = invocation, role.dup.freeze, adapter
        raise LifetimeError unless intent_sha256.instance_of?(String) && intent_sha256.match?(/\A[0-9a-f]{64}\z/) &&
          artifact.instance_of?(String) && artifact.start_with?(File::SEPARATOR) && !artifact.include?("\0") &&
          tooling_directory.instance_of?(String) && argv.instance_of?(Array) && environment.instance_of?(Hash)
        @intent_sha256, @artifact = intent_sha256.dup.freeze, artifact.dup.freeze
        @argv = argv.map { |value| String.new(value).freeze }.freeze
        @environment = environment.to_h { |key, value| [String.new(key).freeze, String.new(value).freeze] }.freeze
        @tooling_directory = tooling_directory.dup.freeze
        @deadlines = [run_deadline_ns, hard_cleanup_deadline_ns].freeze
        @state = :reserved
      end

      def retired?
        @invocation.origin!
        %i[settled not_created].include?(@state)
      end

      def capture_deadlines
        @invocation.origin!
        refuse! unless @state == :attempted
        @deadlines
      end

      def capture_request
        @invocation.origin!
        refuse! unless @state == :attempted
        [@environment, @argv, @tooling_directory].freeze
      end

      def bind_session!(session)
        @invocation.origin!
        type = NativeUploadValidation.const_get(:CaptureSession, false)
        refuse! unless @state == :attempted && session.instance_of?(type) && @session.nil?
        @session, @state = session, :executing
      end

      def capture_returned!(observation, output:)
        @invocation.origin!
        refuse! unless @state == :executing && original_observation?(observation, :success, output)
        @observation, @output, @state = observation, output, :captured
      end

      def accept_result!(adapter:, output:)
        @invocation.origin!
        refuse! unless @state == :captured && adapter.equal?(@adapter) && output.equal?(@output) &&
          original_observation?(@observation, :success, output)
        # This calls only the exact fixed platform policy, not a supplied block.
        result = @adapter.send(:validated_result, output, intent_sha256: @intent_sha256, artifact: @artifact)
        @result, @state = result, :settled
        result
      rescue Exception => error # rubocop:disable Lint/RescueException
        fail_unless_retired!(error)
        raise
      end

      def require_current_ios_dispatch!(artifact:)
        @invocation.origin!
        refuse! unless @state == :settled && @role == "current-ios" && artifact == @artifact &&
          @adapter.equal?(MobileReleaseKit::IosUploadValidation) && @result&.frozen?
        # Reuse the original strict result (intent, IPA hash/size and interval),
        # never a new validator, supplied interval or later filesystem result.
        @adapter.require_current!(@result)
      end

      def capture_failed!(error, observation: nil)
        @invocation.origin!
        if @state == :executing && original_observation?(observation, :not_created, nil)
          @observation, @state = observation, :not_created
        else
          fail_unless_retired!(error)
        end
      end

      def fail_unless_retired!(error)
        @invocation.origin!
        return if retired?
        @state = :unknown
        @invocation.mark_unknown!(error)
      end

      def record_cleanup_error!(error)
        @invocation.origin!
        @state = :unknown unless retired?
        @invocation.mark_unknown!(error, cleanup: true)
      end

      def finish_call!
        fail_unless_retired!(LifetimeError.new)
      end

      private

      def begin_capture!(environment:, argv:, tooling_directory:)
        @invocation.origin!
        refuse! unless @state == :reserved && environment == @environment && argv == @argv && tooling_directory == @tooling_directory
        @state = :attempted
      end

      def original_observation?(observation, kind, output)
        type = NativeUploadValidation.const_get(:StoreObservation, false)
        observation.instance_of?(type) && observation.matches?(@session, self, kind, output) &&
          @session.send(:original_store_observation?, observation)
      end

      def refuse!
        @invocation.mark_unknown!(LifetimeError.new)
        @invocation.raise_unknown!
      end
    end
    private_constant :NestedValidation

    # Original IO objects, never a reopened pathname or a reusable numeric FD.
    # No callback receives an open endpoint with a close/rebind capability.
    class Endpoint
      attr_reader :io, :state

      def initialize(invocation)
        @invocation, @state = invocation, :reserved
      end

      def bind(io)
        @io, @state = io, :open
      end

      def prepare
        # Retain even UNKNOWN endpoints in the invocation instead of allowing
        # a GC finalizer to add a second, unrecorded close attempt later.
        @io.autoclose = false
        @io.close_on_exec = true
      end

      def close_once
        return if @state == :reserved || @state == :closed || @close_attempted

        begin
          Thread.handle_interrupt(Exception => :never) do
            @close_attempted, @state = true, :closing
            begin
              # MRI autoclose:false also suppresses the descriptor close in
              # IO#close. Arm only this retained original, never an FD wrapper.
              fd = @io.fileno
              raise LifetimeError unless fd.instance_of?(Integer) && fd >= 3 && @io.pid.nil?
              @io.autoclose = true
              raise LifetimeError unless @io.autoclose? == true
              returned = Thread.handle_interrupt(Exception => :immediate) { @io.close }
              raise LifetimeError unless returned.nil? && @io.closed? == true
              @state = :closed
            rescue Exception => error # rubocop:disable Lint/RescueException
              retain_close_error(error)
            ensure
              unconfirmed_close! unless @state == :closed
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          # Includes delivery at the mask exit after an otherwise returned
          # close. Earlier close/disarm errors already own their precedence.
          Thread.handle_interrupt(Exception => :never) do
            @close_attempted = true
            retain_close_error(error)
            begin
              unconfirmed_close!
            rescue Exception => failure # rubocop:disable Lint/RescueException
              retain_close_error(failure)
            end
          end
        end
      end

      def retired?
        @state == :closed || @state == :reserved
      end

      private

      def retain_close_error(error)
        @state = :unknown
        @first_close_error ||= error
        @invocation.mark_unknown!(@first_close_error, cleanup: true)
        @invocation.mark_unknown!(error, cleanup: true) unless error.equal?(@first_close_error)
      end

      def unconfirmed_close!
        retain_close_error(LifetimeError.new) unless @first_close_error
        unless @disarm_attempted
          @disarm_attempted = true
          returned, raised = false, false
          begin
            @io.autoclose = false
            returned = true
          rescue Exception => error # rubocop:disable Lint/RescueException
            raised = true
            retain_close_error(error)
          ensure
            retain_close_error(LifetimeError.new) unless returned || raised
            # Also intercept close/disarm throw/return here, not in the lane
            # body: later independent original endpoints must still be closed.
            raise @first_close_error, cause: @first_close_error.cause
          end
        end
        raise @first_close_error, cause: @first_close_error.cause
      end
    end
    private_constant :Endpoint

    class ClosedInputView
      def closed?
        true
      end

      def write(*)
        raise IOError, "closed noninteractive Store command input"
      end
    end
    private_constant :ClosedInputView

    # Pinned TransporterExecutor, AltoolTransporterExecutor and CommandExecutor
    # use only #each. A bounded view also bounds their retained @all_lines. It
    # does not hand over close, fileno, to_io, reopen or an independent drainer.
    class OutputView
      MAX_BYTES = 4 * 1024 * 1024
      MAX_LINE_BYTES = 64 * 1024
      MAX_LINES = 65_536

      attr_reader :eof

      def initialize(adapter, endpoint)
        @adapter, @endpoint = adapter, endpoint
        @bytes = @lines = 0
        @eof = false
      end

      def each
        return enum_for(:each) unless block_given?

        loop do
          @adapter.require_read_admission!
          break if @eof
          line = @endpoint.io.gets("\n", MAX_LINE_BYTES + 1)
          if line.nil?
            @eof = true
            break
          end
          @bytes += line.bytesize
          @lines += 1
          if line.bytesize > MAX_LINE_BYTES || @bytes > MAX_BYTES || @lines > MAX_LINES
            raise LifetimeError
          end
          yield line
        end
        self
      end
      alias each_line each
    end
    private_constant :OutputView

    class PipeAdapter
      def initialize(invocation)
        @invocation = invocation
        @stdin_read, @stdin_write, @stdout_read, @stdout_write = Array.new(4) { Endpoint.new(invocation) }
        @endpoints = [@stdin_read, @stdout_write, @stdin_write, @stdout_read].freeze
        @pairs = [nil, nil]
        @pair_states = [:reserved, :reserved]
        @creation = @wait = :reserved
        @finished = @reading = false
      end

      def execute(command)
        # Protect cleanup ENTRY and nonblocking state publication. Blocking
        # spawn/read/wait/close stay interruptible, under the real outer owner.
        Thread.handle_interrupt(Exception => :never) do
          begin
            Thread.handle_interrupt(Exception => :immediate) do
              create_pair(0, @stdin_read, @stdin_write)
              create_pair(1, @stdout_read, @stdout_write)
              @invocation.send(:require_current_ios_native_dispatch!, self, command)
              @creation = :attempted
              @pid = Process.spawn(command, in: @stdin_read.io, out: @stdout_write.io,
                                   err: @stdout_write.io, close_others: true)
              raise LifetimeError unless @pid.instance_of?(Integer) && @pid.positive?
              @creation = :returned
              # No setsid/pgroup option: the command stays in the original
              # outer group. API-key lanes are deliberately noninteractive.
              [@stdin_read, @stdout_write, @stdin_write].each(&:close_once)
              @invocation.raise_unknown! if @invocation.unknown?
              @view = OutputView.new(self, @stdout_read)
              @reading = true
              yield @view, ClosedInputView.new, @pid
              @view.each { |_line| } # A short callback must not wait before EOF.
              @reading = false
              @stdout_read.close_once
              @invocation.raise_unknown! if @invocation.unknown?
              wait_once(nonblocking: false)
              @body_returned = true
            end
          rescue Exception => error # rubocop:disable Lint/RescueException
            if @creation == :reserved && @invocation.send(:original_ios_dispatch_refusal?, self, error)
              @creation, @dispatch_refusal = :not_dispatched, error
            else
              remember_failure(error)
            end
          ensure
            # A callback's break/throw/nonlocal return is not successful drain
            # or wait completion. Latch before such control could bypass the
            # ordinary rescue and reach an upstream continuation.
            @invocation.mark_unknown!(LifetimeError.new) unless @body_returned || @dispatch_refusal || @invocation.unknown?
            @reading = false
            @endpoints.each(&:close_once)
            # Independent, nonblocking cleanup only. No signaling and no retry
            # after an uncertain wait; the outer owner still owns the group.
            if @creation == :returned && @wait == :reserved
              begin
                wait_once(nonblocking: true)
              rescue Exception => error # rubocop:disable Lint/RescueException
                @invocation.mark_unknown!(error, cleanup: true)
              end
            end
            @finished = true
            @invocation.raise_unknown! unless @body_returned || (@dispatch_refusal && retired? && !@invocation.unknown?)
          end
          Thread.handle_interrupt(Exception => :immediate) do
            @invocation.require_adapter_continuation!
            raise @dispatch_refusal, cause: nil if @dispatch_refusal
            raise CommandExitError.new(@status) if @status.signaled?
            @status.exitstatus
          end
        end
      rescue Exception => error # rubocop:disable Lint/RescueException
        # Includes pending delivery at the interrupt-mask exit itself. A real
        # signaled status remains an ordinary, fully retired command failure.
        raise if error.is_a?(CommandExitError) && retired? && !@invocation.unknown?
        raise if error.equal?(@dispatch_refusal) && retired? && !@invocation.unknown?

        remember_failure(error)
        @invocation.raise_unknown!
      end

      def require_read_admission!
        @invocation.origin!
        return true if @reading && !@finished && !@invocation.unknown? && @stdout_read.state == :open

        @invocation.mark_unknown!(LifetimeError.new)
        @invocation.raise_unknown!
      end

      def retired?
        return false unless @finished && @pair_states.all? { |state| state == :returned } && @endpoints.all?(&:retired?)
        return true if @creation == :not_dispatched && @wait == :reserved && @view.nil? &&
          @invocation.send(:original_ios_dispatch_refusal?, self, @dispatch_refusal)

        @creation == :returned && @view&.eof == true && @wait == :reaped
      end

      private

      def create_pair(index, read_endpoint, write_endpoint)
        # IO.pipe and endpoint assignments are a short acquisition boundary,
        # not a masked child launch/wait. Both original IOs are retained before
        # configuration can fail; a failed allocation never becomes no-attempt.
        Thread.handle_interrupt(Exception => :never) do
          @pair_states[index] = :attempted
          @pairs[index] = IO.pipe
          read_endpoint.bind(@pairs[index].fetch(0))
          write_endpoint.bind(@pairs[index].fetch(1))
          read_endpoint.prepare
          write_endpoint.prepare
          @pair_states[index] = :returned
        end
      end

      def wait_once(nonblocking:)
        @wait = :attempted # Retire wait admission BEFORE the actual wait call.
        begin
          result = Thread.handle_interrupt(Exception => :immediate) do
            Process.waitpid2(@pid, nonblocking ? Process::WNOHANG : 0)
          end
          if result.nil?
            @wait = :unreaped
            raise LifetimeError
          end
          waited_pid, status = result
          unless waited_pid == @pid && status.pid == @pid &&
                 (status.exited? || status.signaled?) &&
                 (!status.exited? || status.exitstatus.instance_of?(Integer))
            raise LifetimeError
          end
          @status, @wait = status, :reaped
        rescue Exception # rubocop:disable Lint/RescueException
          @wait = :unknown unless @wait == :unreaped
          raise
        end
      end

      def remember_failure(error)
        # Do not replace the actual first failure with our redacted wrapper.
        @invocation.mark_unknown!(error) unless error.is_a?(LifetimeError) && @invocation.unknown?
      end
    end
    private_constant :PipeAdapter
  end
end
