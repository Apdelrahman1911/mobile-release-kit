# frozen_string_literal: true

require "json"
require "rbconfig"

module MobileReleaseKit
  # Private, fixed native-upload supervision. Requiring this file does not
  # inspect signal policy, acquire descriptors, start tasks, or launch children.
  module NativeUploadProcess
    VERSION = 1
    MAX_SECONDS = 3_600
    MAX_OUTPUT_BYTES = 65_536
    CLEANUP_GRACE_NS = 5_000_000_000
    POLL_NS = 20_000_000
    MAX_PID = (1 << 31) - 1
    MAX_TIME = (1 << 63) - 1
    REASONS = %w[cancelled deadline parent_lost protocol io creation lifecycle].freeze

    class Error < StandardError
      attr_reader :code

      def initialize(code = "lifecycle")
        @code = REASONS.include?(code) ? code.freeze : "lifecycle"
        super("native capture #{@code} failure")
      end
    end

    class ProtocolError < Error
      def initialize
        super("protocol")
      end
    end

    class LifecycleError < Error; end

    def self.monotonic_ns
      Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    end

    def self.native
      require_relative "native_process_spawn"
      NativeProcessSpawn
    end

    def self.nsig
      native.nsig
    end

    def self.freeze_value(value)
      case value
      when Hash
        value.each { |key, item| key.freeze; freeze_value(item) }
      when Array
        value.each { |item| freeze_value(item) }
      end
      value.freeze
    end

    def self.reason_for(error)
      case error
      when Error then error.code
      when IOError, SystemCallError then "io"
      when Interrupt, SystemExit then "cancelled"
      else "lifecycle"
      end
    end

    module Protocol
      CONFIG_LIMIT = 128 * 1_024
      FRAME_LIMIT = 1_024
      FRAME_COUNT = 16
      COLLECTION_LIMIT = 64 * 1_024
      VALUE_LIMIT = 8 * 1_024
      STREAM_LIMIT = CONFIG_LIMIT + (FRAME_COUNT - 1) * FRAME_LIMIT + FRAME_COUNT * 4
      DIRECTIONS = {
        o_to_c: %w[CONFIG ADMIT RUN COMMIT CANCEL],
        c_to_o: %w[HELLO RESERVED READY STATUS FINAL],
        c_to_k: %w[CONFIG RUN CANCEL GROUP_RETIRED RELEASE],
        k_to_c: %w[HELLO MOVED STATUS RELEASED],
      }.transform_values(&:freeze).freeze
      FIELDS = {
        "CONFIG" => %w[role cwd validator_argv validator_env run_deadline_ns hard_cleanup_deadline_ns max_output_bytes capture_kind],
        "HELLO" => %w[pid ppid sid pgid fd_map_version],
        "ADMIT" => [],
        "RESERVED" => %w[keeper_pid group_id session_id],
        "RUN" => [],
        "MOVED" => %w[validator_pid group_id keeper_pgid],
        "READY" => %w[validator_pid group_id keeper_pgid],
        "STATUS" => %w[validator_pid status_kind status_code],
        "COMMIT" => [],
        "CANCEL" => %w[reason_code cleanup_deadline_ns],
        "GROUP_RETIRED" => %w[group_id absent],
        "RELEASE" => [],
        "RELEASED" => %w[validator],
        "FINAL" => %w[outcome cleanup keeper validator group],
      }.transform_values(&:freeze).freeze

      # Default JSON 2.7.2 invokes []= for each decoded member, including escaped
      # spellings. Bundled JSON 2.21.2 converts an already-parsed Hash instead,
      # so Decoder also requires its explicit duplicate-key rejection option.
      class StrictObject < Hash
        def []=(key, value)
          raise ProtocolError if key?(key)

          super
        end
      end

      module_function

      def exact!(object, names)
        raise ProtocolError unless object.instance_of?(Hash) && object.keys.all? { |key| key.instance_of?(String) }
        raise ProtocolError unless object.keys.sort == names.sort
      end

      def integer!(value, minimum, maximum)
        raise ProtocolError unless value.instance_of?(Integer) && value.between?(minimum, maximum)
      end

      def pid!(value)
        integer!(value, 1, MAX_PID)
      end

      def time!(value)
        integer!(value, 1, MAX_TIME)
      end

      def boolean!(value)
        raise ProtocolError unless value.equal?(true) || value.equal?(false)
      end

      def string!(value, limit: VALUE_LIMIT, empty: false)
        raise ProtocolError unless value.instance_of?(String) && value.bytesize <= limit
        raise ProtocolError if (!empty && value.empty?) || value.include?("\0")
        raise ProtocolError unless value.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      end

      def absolute!(value)
        string!(value)
        raise ProtocolError unless value.start_with?(File::SEPARATOR) && !value.match?(/[\x00-\x1f\x7f]/)
      end

      def status!(kind, code, nsig)
        case kind
        when "exit" then integer!(code, 0, 255)
        when "signal" then integer!(code, 1, nsig - 1)
        else raise ProtocolError
        end
      end

      def child!(record, nsig)
        raise ProtocolError unless record.instance_of?(Hash)

        case record["state"]
        when "not_attempted", "unknown"
          exact!(record, %w[state])
        when "reaped"
          exact!(record, %w[state pid status_kind status_code])
          pid!(record["pid"])
          status!(record["status_kind"], record["status_code"], nsig)
        else raise ProtocolError
        end
      end

      def group!(record)
        raise ProtocolError unless record.instance_of?(Hash)

        case record["state"]
        when "not_created", "unknown"
          exact!(record, %w[state])
        when "retired"
          exact!(record, %w[state id absent])
          pid!(record["id"])
          boolean!(record["absent"])
        else raise ProtocolError
        end
      end

      def configuration!(frame, direction)
        role = direction == :o_to_c ? "custodian" : "keeper"
        raise ProtocolError unless frame["role"] == role && frame["capture_kind"] == "native"

        absolute!(frame["cwd"])
        argv = frame["validator_argv"]
        raise ProtocolError unless argv.instance_of?(Array) && argv.length.between?(1, 64)

        argv.each { |item| string!(item, empty: true) }
        absolute!(argv.first)
        raise ProtocolError if argv.sum { |item| item.bytesize + 1 } > COLLECTION_LIMIT

        environment = frame["validator_env"]
        raise ProtocolError unless environment.instance_of?(Hash) && environment.length <= 64

        environment.each do |key, value|
          string!(key)
          raise ProtocolError unless key.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)

          string!(value, empty: true)
        end
        raise ProtocolError if environment.sum { |key, value| key.bytesize + value.bytesize + 2 } > COLLECTION_LIMIT

        time!(frame["run_deadline_ns"])
        time!(frame["hard_cleanup_deadline_ns"])
        unless frame["hard_cleanup_deadline_ns"].between?(frame["run_deadline_ns"], frame["run_deadline_ns"] + CLEANUP_GRACE_NS)
          raise ProtocolError
        end
        integer!(frame["max_output_bytes"], 1, MAX_OUTPUT_BYTES)
      end

      def terminal!(frame, nsig)
        raise ProtocolError unless %w[ok rejected failed].include?(frame["outcome"])
        raise ProtocolError unless %w[confirmed unknown].include?(frame["cleanup"])

        keeper, validator, group = frame.values_at("keeper", "validator", "group")
        child!(keeper, nsig)
        child!(validator, nsig)
        group!(group)
        if keeper["state"] == "not_attempted"
          unless validator == { "state" => "not_attempted" } && group == { "state" => "not_created" } && frame["outcome"] == "failed"
            raise ProtocolError
          end
        end
        if group["state"] == "not_created" && validator["state"] != "not_attempted"
          raise ProtocolError
        end
        if group["state"] == "retired" && keeper["state"] == "reaped" && group["id"] != keeper["pid"]
          raise ProtocolError
        end
        unresolved = [keeper, validator, group].any? { |record| record["state"] == "unknown" } ||
                     (group["state"] == "retired" && !group["absent"])
        if unresolved && (frame["cleanup"] != "unknown" || frame["outcome"] != "failed")
          raise ProtocolError
        end
        if frame["cleanup"] == "unknown" && frame["outcome"] != "failed"
          raise ProtocolError
        end
        if validator["state"] == "not_attempted" && frame["outcome"] != "failed"
          raise ProtocolError
        end
        return if frame["outcome"] == "failed"

        unless frame["cleanup"] == "confirmed" &&
               keeper["state"] == "reaped" && keeper["status_kind"] == "exit" && keeper["status_code"] == 0 &&
               validator["state"] == "reaped" && validator["status_kind"] == "exit" &&
               group["state"] == "retired" && group["absent"]
          raise ProtocolError
        end
        valid_code = frame["outcome"] == "ok" ? validator["status_code"] == 0 : validator["status_code"].positive?
        raise ProtocolError unless valid_code
      end

      # Copy only JSON primitives. In particular, do not invoke an arbitrary
      # object's to_json/to_h or let an input Hash subclass supply authority.
      def plain(value, parsed: false, depth: 0)
        raise ProtocolError if depth > 5

        if value.instance_of?(Hash) || (parsed && value.instance_of?(StrictObject))
          value.each_with_object({}) do |(key, item), result|
            raise ProtocolError unless key.instance_of?(String)

            result[key.dup.force_encoding(Encoding::UTF_8)] = plain(item, parsed: parsed, depth: depth + 1)
          end
        elsif value.instance_of?(Array)
          value.map { |item| plain(item, parsed: parsed, depth: depth + 1) }
        elsif value.instance_of?(String)
          value.dup.force_encoding(Encoding::UTF_8)
        elsif value.instance_of?(Integer) || value.equal?(true) || value.equal?(false)
          value
        else
          raise ProtocolError
        end
      end

      def validate(frame, direction:, nsig:)
        raise ProtocolError unless DIRECTIONS.key?(direction)

        integer!(nsig, 2, 128)
        raise ProtocolError unless frame.instance_of?(Hash)

        type = frame["type"]
        raise ProtocolError unless type.instance_of?(String) && DIRECTIONS.fetch(direction).include?(type)

        exact!(frame, %w[v type] + FIELDS.fetch(type))
        raise ProtocolError unless frame["v"].instance_of?(Integer) && frame["v"] == VERSION

        case type
        when "CONFIG" then configuration!(frame, direction)
        when "HELLO"
          %w[pid ppid sid pgid].each { |name| pid!(frame[name]) }
          raise ProtocolError unless frame["fd_map_version"].instance_of?(Integer) && frame["fd_map_version"] == 1
        when "RESERVED"
          %w[keeper_pid group_id session_id].each { |name| pid!(frame[name]) }
          raise ProtocolError unless frame["keeper_pid"] == frame["group_id"]
        when "MOVED", "READY"
          %w[validator_pid group_id keeper_pgid].each { |name| pid!(frame[name]) }
        when "STATUS"
          pid!(frame["validator_pid"])
          status!(frame["status_kind"], frame["status_code"], nsig)
        when "CANCEL"
          raise ProtocolError unless REASONS.include?(frame["reason_code"])

          time!(frame["cleanup_deadline_ns"])
        when "GROUP_RETIRED"
          pid!(frame["group_id"])
          boolean!(frame["absent"])
        when "RELEASED" then child!(frame["validator"], nsig)
        when "FINAL" then terminal!(frame, nsig)
        end
        frame
      end

      def encode(frame, direction:, nsig:)
        copy = plain(frame)
        validate(copy, direction: direction, nsig: nsig)
        payload = JSON.generate(copy, max_nesting: 6, allow_nan: false).b
        limit = copy["type"] == "CONFIG" ? CONFIG_LIMIT : FRAME_LIMIT
        raise ProtocolError if payload.empty? || payload.bytesize > limit

        ([payload.bytesize].pack("N") + payload).freeze
      rescue JSON::GeneratorError, ArgumentError, EncodingError
        raise ProtocolError
      end

      class Decoder
        attr_reader :frame_count

        def initialize(direction:, nsig:)
          raise ProtocolError unless DIRECTIONS.key?(direction)

          Protocol.integer!(nsig, 2, 128)
          @direction = direction
          @nsig = nsig
          @buffer = +"".b
          @length = nil
          @frame_count = 0
          @byte_count = 0
          @seen = {}
          @terminal = false
          @eof = false
          @failed = false
        end

        def feed(bytes)
          raise ProtocolError if @eof || @failed || !bytes.instance_of?(String)

          @byte_count += bytes.bytesize
          raise ProtocolError if @byte_count > STREAM_LIMIT

          @buffer << bytes.b
          frames = []
          loop do
            if @length.nil?
              break if @buffer.bytesize < 4

              @length = @buffer.slice!(0, 4).unpack1("N")
              limit = DIRECTIONS.fetch(@direction).include?("CONFIG") ? CONFIG_LIMIT : FRAME_LIMIT
              raise ProtocolError unless @length.between?(1, limit)
            end
            break if @buffer.bytesize < @length

            payload = @buffer.slice!(0, @length).force_encoding(Encoding::UTF_8)
            raise ProtocolError unless payload.valid_encoding?

            raw = JSON.parse(payload, object_class: StrictObject, array_class: Array,
                             create_additions: false, max_nesting: 6, allow_nan: false,
                             allow_duplicate_key: false)
            frame = Protocol.plain(raw, parsed: true)
            Protocol.validate(frame, direction: @direction, nsig: @nsig)
            raise ProtocolError if frame["type"] != "CONFIG" && @length > FRAME_LIMIT

            @length = nil
            @frame_count += 1
            raise ProtocolError if @frame_count > FRAME_COUNT

            check_order!(frame)
            frames << NativeUploadProcess.freeze_value(frame)
          end
          frames
        rescue JSON::ParserError, JSON::NestingError, ArgumentError, EncodingError, ProtocolError
          @failed = true
          raise ProtocolError
        end

        def eof
          raise ProtocolError if @eof || @failed || !@length.nil? || !@buffer.empty?

          @eof = true
          true
        rescue ProtocolError
          @failed = true
          raise
        end

        private

        def require_seen!(*types)
          raise ProtocolError unless types.all? { |type| @seen[type] }
        end

        # Only same-edge order belongs to the codec. Real publication, the
        # opposite edge's grants, PID/session checks, COMMIT and finality still
        # belong to the receiving owner. EOF is never a terminal receipt.
        def check_order!(frame)
          type = frame.fetch("type")
          raise ProtocolError if @terminal || @seen[type]

          case @direction
          when :o_to_c
            raise ProtocolError if @seen["CANCEL"] && type != "CANCEL"
            case type
            when "CONFIG" then raise ProtocolError unless @seen.empty?
            when "ADMIT" then require_seen!("CONFIG")
            when "RUN" then require_seen!("ADMIT")
            when "COMMIT" then require_seen!("RUN")
            end
          when :c_to_k
            case type
            when "CONFIG" then raise ProtocolError unless @seen.empty?
            when "RUN"
              require_seen!("CONFIG")
              raise ProtocolError if @seen["CANCEL"] || @seen["GROUP_RETIRED"]
            when "GROUP_RETIRED" then raise ProtocolError if @seen["RELEASE"]
            when "RELEASE" then require_seen!("GROUP_RETIRED")
            end
          when :c_to_o
            case type
            when "HELLO" then raise ProtocolError unless @seen.empty?
            when "RESERVED" then require_seen!("HELLO")
            when "READY" then require_seen!("RESERVED")
            when "STATUS" then require_seen!("READY")
            when "FINAL"
              require_seen!("STATUS") unless frame["outcome"] == "failed"
              @terminal = true
            end
          when :k_to_c
            case type
            when "HELLO" then raise ProtocolError unless @seen.empty?
            when "MOVED" then require_seen!("HELLO")
            when "STATUS" then require_seen!("MOVED")
            when "RELEASED" then @terminal = true
            end
          end
          @seen[type] = true
        end
      end
    end

    # A prepublished task record is not a thread receipt. In particular, an
    # interrupted Thread.new return cannot be repaired with Thread.list or an
    # assumed empty slot. Unknown slots stay rooted until their actual join.
    class TaskSlot
      @retained = {}
      @retained_lock = Mutex.new

      # All caller/task/creator paths in one capture use this SAME recording
      # boundary. A later caller Interrupt does not replace a task error already
      # recorded here; caller-first preserves the actual Interrupt/SystemExit.
      # There is no timestamp comparison or sampling of a different error slot.
      class FailureRecord
        def initialize
          @lock = Mutex.new
          @first_error = nil
          @cleanup_errors = []
          @failed = false
          @deadline_ns = nil
        end

        def record(error:, hard_cleanup_deadline_ns:, cleanup_deadline_ns:, cleanup: false)
          now = NativeUploadProcess.monotonic_ns
          @lock.synchronize do
            @first_error ||= error
            @cleanup_errors << error if cleanup
            @failed = true
            @deadline_ns ||= [now + CLEANUP_GRACE_NS, hard_cleanup_deadline_ns].min
            @deadline_ns = [@deadline_ns, hard_cleanup_deadline_ns].min
            @deadline_ns = [@deadline_ns, cleanup_deadline_ns].min if cleanup_deadline_ns
          end
        end

        def first_error
          @lock.synchronize { @first_error }
        end

        def cleanup_errors
          @lock.synchronize { @cleanup_errors.dup.freeze }
        end

        def failed?
          @lock.synchronize { @failed }
        end

        def deadline_ns
          @lock.synchronize { @deadline_ns }
        end
      end
      private_constant :FailureRecord

      class << self
        def retain(slot)
          @retained_lock.synchronize { @retained[slot.object_id] = slot }
        end

        def forget(slot)
          @retained_lock.synchronize { @retained.delete(slot.object_id) }
        end
      end

      attr_reader :caller, :parent_slot, :run_deadline_ns, :hard_cleanup_deadline_ns

      def initialize(caller: Thread.current, parent_slot: nil, run_deadline_ns:, hard_cleanup_deadline_ns:)
        raise LifecycleError unless caller.instance_of?(Thread)

        Protocol.time!(run_deadline_ns)
        Protocol.time!(hard_cleanup_deadline_ns)
        unless hard_cleanup_deadline_ns.between?(run_deadline_ns, run_deadline_ns + CLEANUP_GRACE_NS)
          raise LifecycleError
        end
        if parent_slot && (!parent_slot.instance_of?(TaskSlot) || run_deadline_ns > parent_slot.run_deadline_ns ||
                           hard_cleanup_deadline_ns > parent_slot.hard_cleanup_deadline_ns)
          raise LifecycleError
        end
        @caller = caller
        @parent_slot = parent_slot
        @run_deadline_ns = run_deadline_ns
        @hard_cleanup_deadline_ns = hard_cleanup_deadline_ns
        @failure = parent_slot ? parent_slot.__send__(:failure_record) : FailureRecord.new
        @lock = Mutex.new
        @launch = :closed
        @start_attempted = false
        @thread = nil
        @returned_thread = nil
        @joined = false
        @finished = false
        @cancelled = false
        @offer = nil
      end

      def start(&body)
        raise LifecycleError unless Thread.current.equal?(@caller) && body

        # MRI 3.3.12 inherits this mask into the real new task. Its first Ruby
        # instruction is therefore protected until whole-task rescue/reporting
        # setup exists, including an exception before self-publication.
        Thread.handle_interrupt(Exception => :never) do
          raise LifecycleError unless launch_context_live?

          @lock.synchronize do
            raise LifecycleError if @start_attempted || @cancelled || @launch == :retired

            @start_attempted = true
          end
          self.class.retain(self)
          returned = Thread.new { task_entry(body) }
          bind_returned!(returned)
        end
        self
      rescue Exception => error # Preserve the caller's actual object.
        cancel!(error: error, reason_code: NativeUploadProcess.reason_for(error))
        raise
      end

      def bind_returned!(returned)
        raise LifecycleError unless Thread.current.equal?(@caller) && returned.instance_of?(Thread)

        @lock.synchronize do
          raise LifecycleError if @returned_thread

          @returned_thread = returned
          raise LifecycleError if @thread && !@thread.equal?(returned)
        end
        true
      end

      def publish_self!
        actual = Thread.current
        @lock.synchronize do
          raise LifecycleError if @thread || actual.equal?(@caller)

          @thread = actual
          raise LifecycleError if @returned_thread && !@returned_thread.equal?(actual)
        end
        true
      end

      def admit!
        raise LifecycleError unless Thread.current.equal?(@caller)

        loop do
          return false unless launch_context_live?

          ready = @lock.synchronize do
            return false if @launch == :retired
            return true if @launch == :open

            if @thread && @returned_thread
              raise LifecycleError unless @thread.equal?(@returned_thread)

              @launch = :open
              true
            else
              false
            end
          end
          return true if ready

          bounded_pause(@run_deadline_ns)
        end
      end

      def check_creation!
        actual, launch = @lock.synchronize { [@thread, @launch] }
        unless actual.equal?(Thread.current) && launch == :open && launch_context_live?
          close_launch!
          raise LifecycleError
        end
        true
      end

      def close_launch!
        @lock.synchronize { @launch = :retired }
        true
      end

      def launch_retired?
        @lock.synchronize { @launch == :retired }
      end

      def publication_ready?
        @lock.synchronize { !!(@thread && @returned_thread && @thread.equal?(@returned_thread)) }
      end

      def cancel!(error: nil, reason_code:, cleanup_deadline_ns: nil)
        raise LifecycleError unless REASONS.include?(reason_code)

        Protocol.time!(cleanup_deadline_ns) unless cleanup_deadline_ns.nil?
        @failure.record(error: error, hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
                        cleanup_deadline_ns: cleanup_deadline_ns)
        @lock.synchronize do
          @cancelled = true
          @launch = :retired
        end
        true
      end

      def record_cleanup_error(error)
        # Cleanup-first is still the first actual failure; cleanup-after-primary
        # is secondary. Record both facts and close the shared deadline/admission
        # latch in one synchronized operation, before a later caller exception.
        @failure.record(error: error, hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
                        cleanup_deadline_ns: nil, cleanup: true)
        @lock.synchronize do
          @cancelled = true
          @launch = :retired
        end
        nil
      end

      def join_until(deadline_ns:)
        raise LifecycleError if Thread.current.equal?(thread)

        Protocol.time!(deadline_ns)
        cutoff = [deadline_ns, @hard_cleanup_deadline_ns].min
        loop do
          return true if joined?

          refresh_parent!
          failure_cutoff = @failure.deadline_ns
          cutoff = [cutoff, failure_cutoff].min if failure_cutoff
          actual = thread
          if actual
            remaining = cutoff - NativeUploadProcess.monotonic_ns
            # A zero-time join is still a genuine join, not alive?/status/value.
            joined = actual.join([remaining, POLL_NS].min.clamp(0, POLL_NS) / 1_000_000_000.0)
            if joined
              raise LifecycleError unless joined.equal?(actual)

              @lock.synchronize { @joined = true }
              if actual.pending_interrupt?
                cancel!(error: LifecycleError.new, reason_code: "cancelled")
              end
              self.class.forget(self)
              return true
            end
          else
            bounded_pause(cutoff)
          end
          return false if NativeUploadProcess.monotonic_ns >= cutoff
        end
      rescue Exception => error
        # The caller's failed join publication is not a join receipt. Preserve
        # its actual exception at the same shared boundary before propagating.
        cancel!(error: error, reason_code: NativeUploadProcess.reason_for(error))
        raise
      end

      def thread
        # Either reference is real custody, never a PID/name lookup. A task
        # which failed before self-publication still has to be joined through
        # the genuine Thread.new return if that publication succeeded.
        @lock.synchronize { @thread || @returned_thread }
      end

      def offer
        @lock.synchronize { @offer }
      end

      def first_error
        @failure.first_error
      end

      def cleanup_errors
        @failure.cleanup_errors
      end

      def joined?
        @lock.synchronize { @joined }
      end

      def start_attempted?
        @lock.synchronize { @start_attempted }
      end

      def finished?
        @lock.synchronize { @finished }
      end

      def unresolved?
        @lock.synchronize { @start_attempted && !@joined }
      end

      def cancelled?
        refresh_parent!
        @failure.failed?
      end

      def cleanup_deadline_ns
        refresh_parent!
        [@failure.deadline_ns || @run_deadline_ns, @hard_cleanup_deadline_ns].min
      end

      private

      def failure_record
        @failure
      end

      def bounded_pause(cutoff)
        remaining = cutoff - NativeUploadProcess.monotonic_ns
        sleep([remaining, POLL_NS].min / 1_000_000_000.0) if remaining.positive?
      end

      def refresh_parent!
        # Caller lifetime is an admission/unsettled-task prerequisite, not a
        # new post-join obligation. A joined short-lived creator commonly
        # outlives its normally completed capture caller as a receipt object.
        return if joined?

        if !@caller.alive?
          cancel!(reason_code: "parent_lost")
        elsif @parent_slot&.cancelled?
          cancel!(reason_code: "cancelled", cleanup_deadline_ns: @parent_slot.cleanup_deadline_ns)
        end
      end

      def launch_context_live?
        refresh_parent!
        if NativeUploadProcess.monotonic_ns >= @run_deadline_ns
          cancel!(reason_code: "deadline")
        end
        return false if @failure.failed?

        @lock.synchronize { !@cancelled && @launch != :retired }
      end

      def task_entry(body)
        begin
          actual = Thread.current
          actual.report_on_exception = false
          actual.abort_on_exception = false
          publish_self!
          while @lock.synchronize { @launch == :closed }
            break unless launch_context_live?

            bounded_pause(@run_deadline_ns)
          end
          return unless @lock.synchronize { @launch == :open } && launch_context_live?

          value = nil
          Thread.handle_interrupt(Exception => :immediate) do
            value = body.call(self)
            # The offer's producer tail must observe this task's deferred
            # interruptions too. The caller has a separate final delivery gate.
            Thread.handle_interrupt(Exception => :immediate) {}
          end
          @lock.synchronize { @offer = value } unless cancelled? || first_error
        rescue Exception => error
          cancel!(error: error, reason_code: NativeUploadProcess.reason_for(error))
        ensure
          begin
            close_launch!
            @lock.synchronize { @finished = true }
          rescue Exception => error
            record_cleanup_error(error)
          end
        end
        nil
      end
    end

    # A channel owns only its two already-leased, fixed pipe endpoints. It does
    # not infer a child identity from HELLO, and validator bytes never enter it.
    class Channel
      POSITIVE_TYPES = %w[HELLO ADMIT RESERVED RUN MOVED READY STATUS COMMIT].freeze

      attr_reader :reader, :writer

      def initialize(reader:, writer:, incoming:, outgoing:, nsig:)
        @reader = reader
        @writer = writer
        @incoming = Protocol::Decoder.new(direction: incoming, nsig: nsig)
        @outgoing_check = Protocol::Decoder.new(direction: outgoing, nsig: nsig)
        @outgoing_direction = outgoing
        @nsig = nsig
        @queue = []
        @read_eof = false
        @read_failed = false
        @write_failed = false
        @launch_vetoed = false
        @write_attempted = {}
        @written_types = {}
      end

      def read_frames
        return [] if @read_eof || @read_failed
        raise LifecycleError, "io" unless @reader && @reader.state == :open

        frames = []
        40.times do
          bytes = @reader.io.read_nonblock(4_096, exception: false)
          case bytes
          when nil
            @incoming.eof
            @read_eof = true
            break
          when :wait_readable then break
          when String then frames.concat(@incoming.feed(bytes))
          else raise ProtocolError
          end
        end
        frames
      rescue Exception
        @read_failed = true
        raise
      end

      def queue(frame)
        raise LifecycleError, "io" if @write_failed || !@writer || @writer.state != :open

        bytes = Protocol.encode(frame, direction: @outgoing_direction, nsig: @nsig)
        @outgoing_check.feed(bytes)
        @queue << [frame.fetch("type"), bytes, 0]
        true
      end

      def flush(deadline_ns:, launch_allowed:)
        return false if @write_failed

        40.times do
          break if @queue.empty? || NativeUploadProcess.monotonic_ns >= deadline_ns

          entry = @queue.first
          if POSITIVE_TYPES.include?(entry[0]) && !launch_allowed.call
            @launch_vetoed = true
            # No byte of an ungranted RUN is delivered late. A partial frame
            # cannot be retracted or replaced: retire that writer instead.
            if entry[2].zero?
              @queue.shift
              next
            end
            @write_failed = true
            raise LifecycleError, "cancelled"
          end
          remaining = entry[1].byteslice(entry[2]..)
          @write_attempted[entry[0]] = true
          count = @writer.io.write_nonblock(remaining, exception: false)
          break if count == :wait_writable
          unless count.instance_of?(Integer) && count.positive? && count <= remaining.bytesize
            raise LifecycleError, "io"
          end

          entry[2] += count
          if entry[2] == entry[1].bytesize
            @written_types[entry[0]] = true
            @queue.shift
          end
        end
        @queue.empty?
      rescue Exception
        @write_failed = true
        raise
      end

      def pending?
        !@queue.empty?
      end

      def eof?
        @read_eof
      end

      def read_failed?
        @read_failed
      end

      def write_failed?
        @write_failed
      end

      def launch_vetoed?
        @launch_vetoed
      end

      def written?(type)
        @written_types[type] == true
      end

      def write_attempted?(type)
        @write_attempted[type] == true
      end
    end

    # Only C owns this lease. Its original, actually acquired and not-yet-waited
    # K pins G even after K moves to C's group. The state guard deliberately
    # rejects :pollable as well as :reaped/:unknown: the FIRST consuming wait
    # retires numerical routes, not merely the wait which returns a status.
    class GroupLease
      attr_reader :keeper, :id, :session_id

      def initialize(keeper:, group_id:, session_id:, deadline:)
        Protocol.pid!(group_id)
        Protocol.pid!(session_id)
        unless keeper && keeper.pid == group_id && keeper.state == :running && keeper.receipt.nil? &&
               !keeper.numeric_retired? && deadline.respond_to?(:call)
          raise LifecycleError
        end
        @keeper = keeper
        @id = group_id
        @session_id = session_id
        @deadline = deadline
        @retired = false
        @absent = false
      end

      def request(signal)
        unless (signal == 0 || signal == "KILL") && !@retired && !@absent &&
               @keeper.state == :running && @keeper.receipt.nil? && !@keeper.numeric_retired? &&
               NativeUploadProcess.monotonic_ns < @deadline.call
          raise LifecycleError
        end
        # This is the single C group-request syscall seam. A controlled stale
        # target regression can veto here BEFORE a syscall; it is not a probe
        # that manufactures a lease from a recycled numeric identifier.
        result = Process.kill(signal, -@id)
        raise LifecycleError unless result == 1

        true
      rescue Errno::ESRCH
        @absent = true
        false
      end

      def retire!(absent:)
        Protocol.boolean!(absent)
        raise LifecycleError if absent && !@absent
        raise LifecycleError if @retired && @absent != absent

        @retired = true
        @absent = absent
        true
      end

      def retired?
        @retired
      end

      def absent?
        @absent
      end

      def record
        return { "state" => "unknown" }.freeze unless @retired

        { "state" => "retired", "id" => @id, "absent" => @absent }.freeze
      end
    end

    # Helpers have their own main-thread cancellation flags and cwd. Every
    # actual native/IO creator is a separate short-lived, prepublished TaskSlot;
    # its real join precedes destruction of buffers/duplicates and writer-copy
    # handoff. The main helper remains runnable while posix_spawn releases GVL.
    class Role
      FD_ROLES = [
        [4, :status, :write, :pipe],
        [0, :null_stdin, :read, :null],
        [1, :null_stdout, :write, :null],
        [2, :null_stderr, :write, :null],
        [3, :control, :read, :pipe],
        [5, :validator_stdin, :read, :pipe],
        [6, :validator_stdout, :write, :pipe],
        [7, :validator_stderr, :write, :pipe],
      ].map(&:freeze).freeze

      attr_reader :pid, :session_id, :parent_pid, :bootstrap_slot, :bootstrap_acquisition,
                  :creator_slot, :creator_acquisition

      def initialize(role:, parent_pid:, inherited_session_id:, run_deadline_ns:, hard_cleanup_deadline_ns:)
        @role = role
        @parent_pid = parent_pid
        @inherited_session_id = inherited_session_id
        @run_deadline_ns = run_deadline_ns
        @hard_cleanup_deadline_ns = hard_cleanup_deadline_ns
        @pid = Process.pid
        @session_id = nil
        @failed = false
        @local_failure = false
        @cancel_received = false
        @parent_lost = false
        @first_error = nil
        @cleanup_deadline_ns = nil
        @cleanup_unknown = false
        @signal_cancelled = false
        @signal_generation = 0
        @observed_signal_generation = 0
        @observed_slot_errors = {}
        @run_expiration_observed = false
        @configuration = nil
        @validator_result_failure = false
        @roles = {}
        @slots = []
        @acquisitions = []
        @settlement_attempted = {}
        @settled = {}
        @close_attempted = {}
        @parent_channel = nil
        @parent_eof_handled = false
        @terminal_started = false
        @terminal_complete = false
        @terminal_poisoned = false
        @terminal_signal_generation = nil
        @terminal_frame = nil
        @tail_settled = false
        @terminal_exit_armed = false
        @intended_exit = 1
      end

      def run
        begin
          bootstrap!
          establish_position! unless @failed
          send_hello unless @failed
        rescue Exception => error
          fail!(NativeUploadProcess.reason_for(error), error: error)
          @cleanup_unknown = true unless bootstrap_settled?
          recover_parent_channel
        end
        until @terminal_complete
          guarded { tick! }
          if @terminal_started
            guarded { flush_parent }
            break if !@parent_channel || @parent_channel.write_failed?
            if !@parent_channel.pending?
              @terminal_complete = true
              break
            end
          else
            guarded { receive_parent }
            guarded { step }
            guarded { flush_parent }
          end
          if NativeUploadProcess.monotonic_ns >= effective_deadline_ns
            guarded { seal_at_cutoff }
            break
          end
          sleep(POLL_NS / 1_000_000_000.0)
        end
        @tail_settled = finish_local_tail == true
        # Private process-tail discriminator shared with both actual parents:
        # 0 = settled normal, 2 = positively settled lifecycle failure,
        # 1 (including generic interpreter failure) = UNKNOWN. In particular a
        # failed FINAL offered as 2 cannot hide a later status-close failure.
        settled_exit_code
      rescue Exception
        # Null stdio remain bound for the entire interpreter lifetime. There
        # is no raw helper exception, implicit reaper or at_exit cleanup path.
        1
      end

      # Only the fixed fresh-helper entrypoint calls this after run completed
      # all attempted cleanup. Keep the ORIGINAL handlers and offer epoch:
      # a pre-arm callback invalidates that offer; a post-arm callback exits
      # this very process as UNKNOWN, even after this method returns its code.
      def seal_exit_handoff(exit_code)
        return 1 unless exit_code.instance_of?(Integer) && [0, 2].include?(exit_code)

        @terminal_exit_armed = true # Monotonic; never cleared on a failed recheck.
        settled_exit_code == exit_code ? exit_code : 1
      rescue Exception
        1 # No lifecycle/cleanup retry after the terminal handoff begins.
      end

      protected

      def settled_exit_code
        return 1 unless [0, 2].include?(@intended_exit) && @tail_settled && !@terminal_poisoned &&
                        @terminal_signal_generation == @signal_generation && @terminal_complete &&
                        @terminal_frame && @parent_channel && !@parent_channel.pending? &&
                        !@parent_channel.write_failed? && @parent_channel.written?(@terminal_frame.fetch("type")) &&
                        own_resources_settled?(excluding_status: false) && terminal_offer_settled? &&
                        Process.ppid == @parent_pid && NativeUploadProcess.monotonic_ns < effective_deadline_ns

        @intended_exit
      end

      def terminal_offer_settled?
        false
      end

      def guarded
        yield
      rescue Exception => error
        fail!(NativeUploadProcess.reason_for(error), error: error)
        nil
      end

      def launch_allowed?
        now = NativeUploadProcess.monotonic_ns
        if @bootstrap_slot
          return false if @bootstrap_slot.first_error
          return false if @bootstrap_slot.cancelled? && !@validator_result_failure
        end
        !@failed && !@signal_cancelled && !@terminal_started && now < @run_deadline_ns &&
          now < effective_deadline_ns && Process.ppid == @parent_pid
      end

      def effective_deadline_ns
        cutoffs = [@hard_cleanup_deadline_ns]
        cutoffs << @cleanup_deadline_ns if @cleanup_deadline_ns
        if @bootstrap_slot && @bootstrap_slot.cancelled?
          cutoffs << @bootstrap_slot.cleanup_deadline_ns
        end
        cutoffs << @run_deadline_ns if cutoffs.length == 1
        cutoffs.min
      end

      def fail!(reason, error: nil, cutoff: nil, from_parent: false)
        now = NativeUploadProcess.monotonic_ns
        candidate = @cleanup_deadline_ns || [now + CLEANUP_GRACE_NS, @hard_cleanup_deadline_ns].min
        candidate = [candidate, cutoff].min if cutoff
        # Bootstrap and every later creator share ONE original failure cell.
        # Record actual helper errors there before a private metadata latch;
        # the cell survives the bootstrap creator's genuine completed join.
        if @bootstrap_slot
          @bootstrap_slot.cancel!(error: error, reason_code: reason, cleanup_deadline_ns: candidate)
          candidate = [candidate, @bootstrap_slot.cleanup_deadline_ns].min
          @first_error = @bootstrap_slot.first_error || @first_error || error
        else
          @first_error ||= error
        end
        @cleanup_deadline_ns = candidate
        @failure_reason ||= @first_error ? NativeUploadProcess.reason_for(@first_error) : reason
        @failed = true
        @local_failure = true unless from_parent
        @parent_lost = true if reason == "parent_lost"
        if @terminal_started
          @terminal_poisoned = true
          @intended_exit = 1
        end
        @slots.each do |slot|
          slot.cancel!(reason_code: reason, cleanup_deadline_ns: @cleanup_deadline_ns)
        end
        close_descendant_launch!
        true
      end

      def close_descendant_launch!
        @creator_slot&.close_launch!
        @creator_acquisition&.close_launch!
      end

      def note_validator_failure
        # An ordinary nonzero validator result is a rejection, not a helper
        # lifecycle failure. It still fixes the same bounded cleanup endpoint.
        @validator_result_failure = true
        @cleanup_deadline_ns ||= [NativeUploadProcess.monotonic_ns + CLEANUP_GRACE_NS,
                                 @hard_cleanup_deadline_ns].min
        @slots.each { |slot| slot.cancel!(reason_code: "lifecycle", cleanup_deadline_ns: @cleanup_deadline_ns) }
      end

      def tick!
        if @signal_generation != @observed_signal_generation
          @observed_signal_generation = @signal_generation
          fail!("cancelled")
        end
        fail!("parent_lost") if Process.ppid != @parent_pid && !@parent_lost
        if NativeUploadProcess.monotonic_ns >= @run_deadline_ns && !@run_expiration_observed
          @run_expiration_observed = true
          fail!("deadline")
        end
        @slots.each do |slot|
          error = slot.first_error
          next if !error || @observed_slot_errors[slot.object_id].equal?(error)

          @observed_slot_errors[slot.object_id] = error
          fail!(NativeUploadProcess.reason_for(error), error: error, cutoff: slot.cleanup_deadline_ns)
        end
      end

      def new_creator
        slot = TaskSlot.new(caller: Thread.current, parent_slot: @bootstrap_slot, run_deadline_ns: @run_deadline_ns,
                            hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns)
        @slots << slot
        acquisition = NativeUploadProcess.native::Acquisition.new(
          owner_slot: slot, run_deadline_ns: @run_deadline_ns,
          hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns,
        )
        @acquisitions << acquisition
        [slot, acquisition]
      end

      def settle_creator(slot, acquisition)
        return @settled[acquisition.object_id] if @settlement_attempted[acquisition.object_id]
        absent = !slot.start_attempted? && slot.launch_retired? && slot.thread.nil?
        return false unless slot.joined? || absent

        @settlement_attempted[acquisition.object_id] = true
        @settled[acquisition.object_id] = acquisition.finish_creation!(creator_slot: slot) == true
        @cleanup_unknown = true unless @settled[acquisition.object_id]
        @settled[acquisition.object_id]
      rescue Exception => error
        @cleanup_unknown = true
        fail!(NativeUploadProcess.reason_for(error), error: error)
        false
      end

      def poll_creator(slot, acquisition)
        if slot.joined? || (!slot.start_attempted? && slot.launch_retired? && slot.thread.nil?)
          settle_creator(slot, acquisition)
          return true
        end

        cutoff = [NativeUploadProcess.monotonic_ns + POLL_NS, effective_deadline_ns].min
        return false unless slot.join_until(deadline_ns: cutoff)

        settle_creator(slot, acquisition)
        true
      end

      def bootstrap!
        # Only these fresh helpers reset CHLD. Parent/caller policy is never
        # changed; the native primitive independently asserts the reset result.
        Signal.trap(:CHLD, "DEFAULT")
        Signal.trap(:INT) do
          if @terminal_exit_armed
            Process.exit!(1)
          else
            @signal_cancelled = true
            @signal_generation += 1
          end
        end
        Signal.trap(:TERM) do
          if @terminal_exit_armed
            Process.exit!(1)
          else
            @signal_cancelled = true
            @signal_generation += 1
          end
        end
        @bootstrap_slot, @bootstrap_acquisition = new_creator
        @bootstrap_slot.start do
          FD_ROLES.each do |fd, role, access, kind|
            NativeUploadProcess.native.adopt_fd(@bootstrap_acquisition, fd: fd, role: role, access: access, kind: kind)
          end
          NativeUploadProcess.native.admit_waitability!(@bootstrap_acquisition)
          true
        end
        loop do
          tick!
          @bootstrap_slot.admit! if @bootstrap_slot.publication_ready? && launch_allowed?
          break if poll_creator(@bootstrap_slot, @bootstrap_acquisition)

          raise LifecycleError, "deadline" if NativeUploadProcess.monotonic_ns >= effective_deadline_ns
        end
        @roles = @bootstrap_acquisition.resources
        recover_parent_channel
        raise @bootstrap_slot.first_error if @bootstrap_slot.first_error
        raise LifecycleError unless bootstrap_settled?

        # Five distinct inherited pipe endpoint roles. Pipe topology comes
        # from the original distinct owned pipe acquisitions and exact source
        # maps, not from comparing metadata across opposite pipe endpoints.
        # No MRI-created descriptor is enumerated, wrapped, closed or assigned
        # a role here; a metadata collision simply fails closed.
        pipes = %i[control status validator_stdin validator_stdout validator_stderr].map do |name|
          lease = @roles.fetch(name)
          raise LifecycleError unless lease.state == :open

          stat = lease.io.stat
          raise LifecycleError unless stat.pipe?

          [stat.dev, stat.ino]
        end
        raise LifecycleError unless pipes.uniq.length == pipes.length
        raise LifecycleError unless Process.ppid == @parent_pid && Process.getsid(0) == @inherited_session_id
        raise LifecycleError unless NativeUploadProcess.monotonic_ns < @run_deadline_ns
      ensure
        @roles = @bootstrap_acquisition.resources if @bootstrap_acquisition
      end

      def bootstrap_settled?
        @bootstrap_slot && @bootstrap_slot.joined? && @bootstrap_acquisition &&
          @settled[@bootstrap_acquisition.object_id] == true
      end

      def recover_parent_channel
        return if @parent_channel || !@bootstrap_acquisition

        @roles = @bootstrap_acquisition.resources
        status = @roles[:status]
        return unless status && status.state == :open

        @parent_channel = Channel.new(
          reader: @roles[:control], writer: status,
          incoming: @role == "custodian" ? :o_to_c : :c_to_k,
          outgoing: @role == "custodian" ? :c_to_o : :k_to_c,
          nsig: NativeUploadProcess.nsig,
        )
      end

      def send_parent(type, fields = {})
        raise LifecycleError, "io" unless @parent_channel

        @parent_channel.queue({ "v" => VERSION, "type" => type }.merge(fields))
      end

      def send_hello
        raise LifecycleError unless launch_allowed?

        send_parent("HELLO", "pid" => @pid, "ppid" => Process.ppid,
                            "sid" => Process.getsid(0), "pgid" => Process.getpgrp, "fd_map_version" => 1)
        @hello_sent = true
      end

      def receive_parent
        return unless @parent_channel

        @parent_channel.read_frames.each do |frame|
          raise ProtocolError if @terminal_started

          case frame["type"]
          when "CONFIG" then accept_configuration(frame)
          when "CANCEL"
            raise ProtocolError if frame["cleanup_deadline_ns"] > @hard_cleanup_deadline_ns

            @cancel_received = true
            fail!(frame["reason_code"], cutoff: frame["cleanup_deadline_ns"], from_parent: true)
          else receive_command(frame)
          end
        end
        if @parent_channel.eof? && !@parent_eof_handled
          @parent_eof_handled = true
          fail!("parent_lost")
        end
      end

      def accept_configuration(frame)
        raise ProtocolError if @configuration || @failed || !@hello_sent
        unless frame["role"] == @role && frame["run_deadline_ns"] == @run_deadline_ns &&
               frame["hard_cleanup_deadline_ns"] == @hard_cleanup_deadline_ns && launch_allowed?
          raise ProtocolError
        end

        cwd = frame.fetch("cwd")
        raise ProtocolError unless File.directory?(cwd) && File.realpath(cwd) == cwd

        # Helper-local only; never alter a Fastlane/capture caller's cwd.
        Dir.chdir(cwd)
        raise ProtocolError unless Dir.pwd == cwd

        @configuration = frame
      end

      def flush_parent
        return unless @parent_channel

        @parent_channel.flush(deadline_ns: effective_deadline_ns, launch_allowed: method(:launch_allowed?))
        fail!("deadline") if @parent_channel.launch_vetoed? && !@failed
      rescue Exception => error
        fail!(NativeUploadProcess.reason_for(error), error: error)
        close_lease(@parent_channel.writer)
        @cleanup_unknown = true
      end

      def close_lease(lease)
        return true unless lease
        return true if lease.process_lifetime? || lease.state == :closed || lease.state == :not_acquired
        return false if @close_attempted[lease.object_id]

        @close_attempted[lease.object_id] = true
        lease.close_once
        unless lease.state == :closed || lease.state == :not_acquired
          @cleanup_unknown = true
          fail!("io")
          return false
        end
        true
      rescue Exception => error
        @cleanup_unknown = true
        fail!(NativeUploadProcess.reason_for(error), error: error)
        false
      end

      def close_data_copies
        return false if @creator_acquisition && !@settled[@creator_acquisition.object_id]

        %i[validator_stdin validator_stdout validator_stderr].map { |name| close_lease(@roles[name]) }.all?
      end

      def own_resources_settled?(excluding_status: true)
        return false if @cleanup_unknown || @slots.any? { |slot| slot.start_attempted? && !slot.joined? }
        return false unless @acquisitions.all? { |acquisition| @settled[acquisition.object_id] == true }

        @acquisitions.all? do |acquisition|
          acquisition.resources.values.all? do |lease|
            next true if lease.process_lifetime? || (excluding_status && lease.equal?(@roles[:status]))

            lease.state == :closed || lease.state == :not_acquired
          end
        end
      end

      def child_record(child, acquisition, attempt_entered:, launch_closed:)
        if child && child.receipt
          receipt = child.receipt
          return { "state" => "reaped", "pid" => receipt.pid,
                   "status_kind" => receipt.status_kind.to_s, "status_code" => receipt.status_code }.freeze
        end
        if launch_closed && ((!attempt_entered && acquisition.nil?) || (acquisition && acquisition.not_attempted?))
          return { "state" => "not_attempted" }.freeze
        end

        { "state" => "unknown" }.freeze
      end

      def prepare_terminal_io
        close_data_copies
        close_lease(@roles[:control])
      end

      def start_terminal(frame, exit_code:, signal_generation:)
        raise LifecycleError if @terminal_started

        @terminal_started = true
        @terminal_signal_generation = signal_generation
        @terminal_frame = NativeUploadProcess.freeze_value(frame)
        @intended_exit = exit_code
        unless @parent_channel && !@parent_channel.write_failed?
          @terminal_complete = true
          @intended_exit = 1
          return
        end
        @parent_channel.queue(frame)
      end

      def abandon_terminal
        # There is no scoped-cleanup field in RELEASED. Do not send a terminal
        # acknowledgement when the helper's pre-terminal obligations are not
        # positively settled; actual exit1/status EOF remain UNKNOWN evidence.
        @terminal_started = @terminal_complete = @terminal_poisoned = true
        @terminal_signal_generation = @signal_generation
        @intended_exit = 1
      end

      def mark_pending_unknown
        @acquisitions.each do |acquisition|
          next if @settled[acquisition.object_id] == true

          acquisition.mark_unknown!
          @cleanup_unknown = true
        end
      end

      def finish_local_tail
        mark_pending_unknown
        # The final status writer is intentionally not claimed in FINAL's
        # scoped cleanup. Its close and this process's actual exit are outer
        # obligations, and any tail failure vetoes a prior exit-zero offer.
        @acquisitions.each do |acquisition|
          next unless @settled[acquisition.object_id] == true

          acquisition.resources.each_value { |lease| close_lease(lease) }
        end
        !@cleanup_unknown && @terminal_complete && @parent_channel && !@parent_channel.pending?
      end
    end

    # C is the only owner of K's consuming wait. It deliberately keeps K
    # unwaited while even a signal-0 request to the original G remains possible.
    class Custodian < Role
      attr_reader :keeper, :group

      def initialize(**arguments)
        super(role: "custodian", **arguments)
        @keeper_attempt_entered = false
        @keeper_launch_closed = false
        @keeper = @group = @keeper_channel = nil
        @keeper_handoff = false
        @keeper_hello = @moved = @validator_status = @released = nil
        @admitted = @run_forwarded = @commit_received = false
        @cleanup_started = @group_routes_retired = false
        @group_kill_attempted = @keeper_kill_attempted = false
        @cancel_sent = @release_requested = @keeper_wait_broken = false
        @keeper_receipt = nil
      end

      # Public, narrow regression seam. A real WNOHANG nil permits another
      # exact wait; it NEVER makes the original numeric group route usable.
      def poll_keeper
        return @keeper_receipt if @keeper_receipt
        return nil if !@keeper || @keeper_wait_broken
        return nil if NativeUploadProcess.monotonic_ns >= effective_deadline_ns
        unless @group_routes_retired && (!@group || @group.retired?) &&
               @creator_slot&.joined? && @settled[@creator_acquisition.object_id]
          raise LifecycleError
        end

        @keeper.retire_numeric!
        @keeper_receipt = @keeper.poll_wait
        if @keeper_receipt && (@keeper_receipt.status_kind.to_s != "exit" || @keeper_receipt.status_code != 0)
          settled_failure = @keeper_receipt.status_kind.to_s == "exit" && @keeper_receipt.status_code == 2
          @cleanup_unknown = true unless settled_failure
          fail!("lifecycle")
        end
        @keeper_receipt
      rescue Exception => error
        @keeper_wait_broken = true
        @cleanup_unknown = true
        fail!(NativeUploadProcess.reason_for(error), error: error)
        nil
      end

      protected

      def establish_position!
        raise LifecycleError unless Process.ppid == @parent_pid && Process.getsid(0) == @inherited_session_id

        returned = Process.setsid
        unless returned == @pid && Process.getsid(0) == @pid && Process.getpgrp == @pid
          raise LifecycleError
        end
        @session_id = @pid
      end

      def close_descendant_launch!
        @keeper_launch_closed = true
        super
      end

      def receive_command(frame)
        case frame["type"]
        when "ADMIT"
          unless @configuration && !@admitted && !@keeper_launch_closed && launch_allowed?
            raise ProtocolError
          end
          @admitted = true
          start_keeper_creator
        when "RUN"
          unless @keeper_hello && @parent_channel.written?("RESERVED") && !@run_forwarded &&
                 !@cleanup_started && @group && !@group.retired? && launch_allowed?
            raise ProtocolError
          end
          @run_forwarded = true
          @keeper_channel.queue("v" => VERSION, "type" => "RUN")
        when "COMMIT"
          unless @validator_status && @validator_status["status_kind"] == "exit" &&
                 @validator_status["status_code"].zero? && @parent_channel.written?("STATUS") &&
                 !@commit_received && launch_allowed?
            raise ProtocolError
          end
          @commit_received = true
        else raise ProtocolError
        end
      end

      def start_keeper_creator
        @keeper_attempt_entered = true
        @creator_slot, @creator_acquisition = new_creator
        acquisition = @creator_acquisition
        @creator_slot.start do
          control_read, = NativeUploadProcess.native.pipe(acquisition, read_role: :keeper_control_read,
                                                         write_role: :keeper_control_write)
          _, status_write = NativeUploadProcess.native.pipe(acquisition, read_role: :keeper_status_read,
                                                           write_role: :keeper_status_write)
          argv = NativeUploadProcess.helper_argv(
            role: "keeper", parent_context: { parent_pid: @pid, session_id: @session_id },
            deadlines: { run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_cleanup_deadline_ns },
          )
          sources = [@roles.fetch(:null_stdin), @roles.fetch(:null_stdout), @roles.fetch(:null_stderr),
                     control_read, status_write, @roles.fetch(:validator_stdin),
                     @roles.fetch(:validator_stdout), @roles.fetch(:validator_stderr)]
          spec = NativeUploadProcess.native::SpawnSpec.new(
            executable: argv.first, argv: argv, env: NativeUploadProcess.helper_environment, fd_sources: sources,
          )
          NativeUploadProcess.native.create(acquisition, spec)
        end
      end

      def settle_keeper_creator
        return if !@creator_slot || @keeper_handoff

        @creator_slot.admit! if @creator_slot.publication_ready? && launch_allowed?
        return unless poll_creator(@creator_slot, @creator_acquisition)

        @keeper_launch_closed = true
        @keeper_handoff = true
        @keeper = @creator_acquisition.child
        unless @settled[@creator_acquisition.object_id]
          @cleanup_unknown = true
          fail!("creation")
          return
        end
        resources = @creator_acquisition.resources
        close_lease(resources[:keeper_control_read])
        close_lease(resources[:keeper_status_write])
        unless @keeper
          resources.each_value { |lease| close_lease(lease) }
          fail!("creation")
          return
        end
        raise LifecycleError if [@pid, @parent_pid].include?(@keeper.pid)

        reader, writer = resources.values_at(:keeper_status_read, :keeper_control_write)
        unless reader && reader.state == :open && writer && writer.state == :open
          raise LifecycleError, "io"
        end
        @keeper_channel = Channel.new(reader: reader, writer: writer, incoming: :k_to_c,
                                      outgoing: :c_to_k, nsig: NativeUploadProcess.nsig)
        if launch_allowed?
          @keeper_channel.queue(@configuration.merge("role" => "keeper"))
        end
      end

      def receive_keeper
        return unless @keeper_channel

        @keeper_channel.read_frames.each do |frame|
          raise ProtocolError if @released

          case frame["type"]
          when "HELLO" then accept_keeper_hello(frame)
          when "MOVED" then accept_moved(frame)
          when "STATUS" then accept_validator_status(frame)
          when "RELEASED" then accept_released(frame)
          else raise ProtocolError
          end
        end
        if @keeper_channel.eof?
          fail!("protocol") unless @released && @release_requested
          close_lease(@keeper_channel.reader)
        end
      rescue Exception => error
        fail!(NativeUploadProcess.reason_for(error), error: error)
        @cleanup_unknown = true
        close_lease(@keeper_channel.reader) if @keeper_channel&.read_failed?
      end

      def accept_keeper_hello(frame)
        unless @keeper && @keeper.state == :running && !@keeper.numeric_retired? && !@keeper_hello &&
               frame["pid"] == @keeper.pid && frame["ppid"] == @pid && frame["sid"] == @pid &&
               frame["pgid"] == @keeper.pid && Process.getsid(@keeper.pid) == @pid
          raise ProtocolError
        end
        actual_group = Process.getpgid(@keeper.pid)
        raise ProtocolError unless [@keeper.pid, @pid].include?(actual_group)

        @keeper_hello = frame
        @group = GroupLease.new(keeper: @keeper, group_id: @keeper.pid, session_id: @pid,
                                deadline: method(:effective_deadline_ns))
        # A helper may have detected failure and moved before its HELLO was
        # read. Its bound HELLO still records original G, and the actual K still
        # pins that number, but current C-group membership is cleanup-only.
        fail!("lifecycle") if actual_group != @keeper.pid && !@failed
        close_data_copies
        if launch_allowed?
          send_parent("RESERVED", "keeper_pid" => @keeper.pid, "group_id" => @group.id, "session_id" => @pid)
        end
      end

      def accept_moved(frame)
        unless @group && !@group.retired? && @keeper_hello && !@moved &&
               @keeper_channel.written?("RUN") && frame["group_id"] == @group.id &&
               frame["keeper_pgid"] == @pid && ![@pid, @parent_pid, @keeper.pid].include?(frame["validator_pid"]) &&
               Process.getsid(@keeper.pid) == @pid && Process.getpgid(@keeper.pid) == @pid
          raise ProtocolError
        end
        @moved = frame
        if launch_allowed?
          send_parent("READY", "validator_pid" => frame["validator_pid"],
                              "group_id" => @group.id, "keeper_pgid" => @pid)
        end
      end

      def accept_validator_status(frame)
        unless @moved && !@validator_status && frame["validator_pid"] == @moved["validator_pid"]
          raise ProtocolError
        end

        @validator_status = frame
        @cleanup_started = true # Not gated on COMMIT, stdout EOF or stderr EOF.
        note_validator_failure unless frame["status_kind"] == "exit" && frame["status_code"].zero?
        if launch_allowed?
          send_parent("STATUS", "validator_pid" => frame["validator_pid"],
                               "status_kind" => frame["status_kind"], "status_code" => frame["status_code"])
        end
      end

      def accept_released(frame)
        record = frame.fetch("validator")
        if !@keeper_channel.write_attempted?("RUN") && record["state"] != "not_attempted"
          raise ProtocolError
        end
        if record["state"] == "reaped"
          raise ProtocolError if [@pid, @parent_pid, @keeper.pid].include?(record["pid"])
          raise ProtocolError if @moved && record["pid"] != @moved["validator_pid"]
        elsif @moved && record["state"] == "not_attempted"
          raise ProtocolError
        end
        if @validator_status
          expected = { "state" => "reaped", "pid" => @validator_status["validator_pid"],
                       "status_kind" => @validator_status["status_kind"], "status_code" => @validator_status["status_code"] }
          raise ProtocolError unless record == expected
        end
        @released = frame
        # An early failed RELEASED is useful accounting, not evidence that the
        # success protocol or C's release grant occurred.
        fail!("lifecycle") unless @release_requested && @validator_status
        @cleanup_started = true
      end

      def send_keeper_cancel
        return unless @failed && @keeper_channel && !@cancel_sent && !@released
        return if @keeper_channel.write_failed? || @keeper_channel.writer.state != :open

        @cancel_sent = true
        @keeper_channel.queue("v" => VERSION, "type" => "CANCEL",
                              "reason_code" => @failure_reason || "cancelled",
                              "cleanup_deadline_ns" => effective_deadline_ns)
      end

      def flush_keeper
        return unless @keeper_channel

        @keeper_channel.flush(deadline_ns: effective_deadline_ns, launch_allowed: method(:launch_allowed?))
        fail!("cancelled") if @keeper_channel.launch_vetoed? && !@failed
      rescue Exception => error
        fail!(NativeUploadProcess.reason_for(error), error: error)
        close_lease(@keeper_channel.writer)
        @cleanup_unknown = true
      end

      def near_cutoff?
        effective_deadline_ns - NativeUploadProcess.monotonic_ns <= 4 * POLL_NS
      end

      def keeper_outside_group?
        return false unless @keeper && @keeper.state == :running && !@keeper.numeric_retired?

        Process.getsid(@keeper.pid) == @pid && Process.getpgid(@keeper.pid) == @pid
      rescue Errno::ESRCH
        false
      end

      def cleanup_group
        return if @group_routes_retired
        return if @creator_slot && !@keeper_handoff

        unless @group
          if !@keeper || @keeper_channel&.eof? || @keeper_channel&.read_failed? || near_cutoff?
            # Missing original HELLO is NOT an invented group-absence receipt.
            @group_routes_retired = true
          end
          return
        end
        return if NativeUploadProcess.monotonic_ns >= effective_deadline_ns

        if keeper_outside_group?
          present = @group.absent? ? false : @group.request(0)
          if present && !@group_kill_attempted
            @group_kill_attempted = true
            present = @group.request("KILL")
          end
          if !present || @group.absent?
            @group.retire!(absent: true)
            @group_routes_retired = true
            return
          end
        elsif near_cutoff? && !@group_kill_attempted
          # Last-resort failure cleanup may include K itself. This cannot
          # become successful absence accounting merely because kill returned.
          @group_kill_attempted = true
          @group.request("KILL")
        end
        if near_cutoff?
          @group.retire!(absent: @group.absent?)
          @group_routes_retired = true
          @cleanup_unknown = true unless @group.absent?
          fail!("deadline") unless @group.absent?
        end
      end

      def release_keeper
        return unless @group_routes_retired && @group && @group.retired? && @keeper_channel && !@release_requested
        return if @keeper_channel.write_failed? || @keeper_channel.writer.state != :open || @keeper_channel.eof?

        @release_requested = true
        @keeper_channel.queue("v" => VERSION, "type" => "GROUP_RETIRED", "group_id" => @group.id,
                              "absent" => @group.absent?)
        @keeper_channel.queue("v" => VERSION, "type" => "RELEASE")
      end

      def last_resort_keeper_kill
        return unless @keeper && !@keeper_kill_attempted && @group_routes_retired &&
                      @keeper.state == :running && @keeper.receipt.nil? && !@keeper.numeric_retired? &&
                      NativeUploadProcess.monotonic_ns < effective_deadline_ns

        @keeper_kill_attempted = true
        result = Process.kill("KILL", @keeper.pid)
        raise LifecycleError unless result == 1
      rescue Errno::ESRCH
        nil
      end

      def step
        settle_keeper_creator
        receive_keeper
        @cleanup_started = true if @failed
        if @cleanup_started
          close_descendant_launch!
          send_keeper_cancel
          cleanup_group
          release_keeper
        end
        flush_keeper
        if @cleanup_started && @group_routes_retired && @keeper
          if @keeper_channel&.eof? || @keeper_channel&.read_failed? || near_cutoff?
            if !@keeper_channel&.eof? && near_cutoff? && !@keeper.numeric_retired?
              fail!("deadline")
              last_resort_keeper_kill
            end
            poll_keeper
          end
        end
        finish_if_ready if @cleanup_started
      end

      def terminal_records
        keeper_record = child_record(@keeper, @creator_acquisition, attempt_entered: @keeper_attempt_entered,
                                     launch_closed: @keeper_launch_closed)
        if keeper_record["state"] == "not_attempted"
          return [keeper_record, { "state" => "not_attempted" }.freeze, { "state" => "not_created" }.freeze]
        end

        validator_record = if @released
                             @released.fetch("validator")
                           elsif @validator_status
                             # STATUS came from the actual bound K endpoint
                             # after K's genuine wait. A missing later RELEASED
                             # invalidates K cleanup, not this earlier V receipt.
                             { "state" => "reaped", "pid" => @validator_status["validator_pid"],
                               "status_kind" => @validator_status["status_kind"],
                               "status_code" => @validator_status["status_code"] }.freeze
                           else
                             { "state" => "unknown" }.freeze
                           end
        [keeper_record, validator_record,
         @group ? @group.record : { "state" => "unknown" }.freeze]
      end

      def finish_if_ready
        return unless @group_routes_retired
        return if @creator_slot && !@keeper_handoff
        return if @keeper && !@keeper_receipt && !@keeper_wait_broken
        if @keeper_channel && !@keeper_channel.eof? && !@keeper_channel.read_failed? && !@keeper_wait_broken
          return
        end
        # Anchor BEFORE deriving the terminal facts, never after an intervening
        # callback has changed the epoch of an already-derived result.
        signal_generation = @signal_generation
        keeper_record, validator_record, group_record = terminal_records
        zero_validator = validator_record["state"] == "reaped" && validator_record["status_kind"] == "exit" &&
                         validator_record["status_code"].zero?
        if !@failed && zero_validator && !@commit_received
          return # Cleanup is already complete; only acceptance waits for O.
        end

        # One final current cancellation/deadline/control gate before the offer.
        receive_parent
        tick!
        prepare_terminal_io
        close_keeper_io
        confirmed = own_resources_settled? && records_confirmed?(keeper_record, validator_record, group_record)
        outcome = "failed"
        if !@failed && confirmed && keeper_record["state"] == "reaped" && keeper_record["status_kind"] == "exit" &&
           keeper_record["status_code"].zero? && validator_record["state"] == "reaped" &&
           validator_record["status_kind"] == "exit" && @validator_status && @moved &&
           @parent_channel.written?("READY") && @parent_channel.written?("STATUS")
          outcome = validator_record["status_code"].zero? && @commit_received ? "ok" : "rejected"
        end
        frame = { "v" => VERSION, "type" => "FINAL", "outcome" => outcome,
                  "cleanup" => confirmed ? "confirmed" : "unknown", "keeper" => keeper_record,
                  "validator" => validator_record, "group" => group_record }
        exit_code = outcome == "failed" ? (confirmed ? 2 : 1) : 0
        start_terminal(frame, exit_code: exit_code, signal_generation: signal_generation)
      end

      def terminal_offer_settled?
        return false unless @group_routes_retired && @terminal_frame.fetch("type") == "FINAL" &&
                            @terminal_frame.fetch("cleanup") == "confirmed"

        original = @terminal_frame.values_at("keeper", "validator", "group")
        terminal_records == original && records_confirmed?(*original) &&
          @intended_exit == (@terminal_frame.fetch("outcome") == "failed" ? 2 : 0)
      end

      def records_confirmed?(keeper_record, validator_record, group_record)
        if keeper_record["state"] == "not_attempted"
          return validator_record["state"] == "not_attempted" && group_record["state"] == "not_created"
        end

        keeper_record["state"] == "reaped" && keeper_record["status_kind"] == "exit" &&
          [0, 2].include?(keeper_record["status_code"]) && %w[reaped not_attempted].include?(validator_record["state"]) &&
          group_record["state"] == "retired" && group_record["absent"] && @released &&
          @keeper_channel && @keeper_channel.eof?
      end

      def close_keeper_io
        return unless @creator_acquisition && @settled[@creator_acquisition.object_id]

        @creator_acquisition.resources.each_value { |lease| close_lease(lease) }
      end

      def seal_at_cutoff
        close_descendant_launch!
        if @group && !@group.retired?
          @group.retire!(absent: @group.absent?)
        end
        @group_routes_retired = true
        @cleanup_unknown = true
        mark_pending_unknown
        prepare_terminal_io
        close_keeper_io
        return if @terminal_started

        keeper_record, validator_record, group_record = terminal_records
        start_terminal({ "v" => VERSION, "type" => "FINAL", "outcome" => "failed", "cleanup" => "unknown",
                         "keeper" => keeper_record, "validator" => validator_record, "group" => group_record },
                       exit_code: 1, signal_generation: @signal_generation)
        # No extension to write this frame. A missing terminal at the original
        # cutoff is an outer failure, never permission to renew cleanup time.
      end
    end

    # K's actual own PID reserves its original G throughout this interpreter's
    # life. K waits only for its actual V. It never creates a fake Child for
    # itself or asks C to reap before C's group routes are permanently retired.
    class Keeper < Role
      attr_reader :validator

      def initialize(**arguments)
        super(role: "keeper", **arguments)
        @validator_attempt_entered = false
        @validator_launch_closed = false
        @validator = @validator_receipt = nil
        @validator_handoff = @validator_wait_broken = false
        @run_received = @moved_to_parent = @status_sent = false
        @moved_frame = nil
        @group_created = @self_group_retired = @self_group_absent = false
        @group_kill_attempted = false
        @group_retirement_received = @group_retirement_absent = @release_received = false
      end

      # This separate fallback seam is reserved by THIS executing process,
      # not a guessed PID, group-membership snapshot, or borrowed child lease.
      def request_group(signal)
        unless (signal == 0 || signal == "KILL") && @group_created && !@self_group_retired &&
               !@self_group_absent && Process.pid == @pid && Process.getsid(0) == @inherited_session_id &&
               NativeUploadProcess.monotonic_ns < effective_deadline_ns
          raise LifecycleError
        end

        result = Process.kill(signal, -@pid)
        raise LifecycleError unless result == 1

        true
      rescue Errno::ESRCH
        @self_group_absent = true
        false
      end

      protected

      def establish_position!
        unless Process.ppid == @parent_pid && Process.getsid(0) == @inherited_session_id &&
               @inherited_session_id == @parent_pid
          raise LifecycleError
        end

        Process.setpgid(0, 0)
        unless Process.getsid(0) == @parent_pid && Process.getpgrp == @pid
          raise LifecycleError
        end
        @session_id = @parent_pid
        @group_created = true
      end

      def close_descendant_launch!
        @validator_launch_closed = true
        super
      end

      def receive_command(frame)
        case frame["type"]
        when "RUN"
          unless @configuration && !@run_received && !@validator_launch_closed &&
                 !@self_group_retired && !@group_retirement_received && !@release_received &&
                 Process.getpgrp == @pid && launch_allowed?
            raise ProtocolError
          end
          @run_received = true
          start_validator_creator
        when "GROUP_RETIRED"
          unless @group_created && frame["group_id"] == @pid && !@group_retirement_received
            raise ProtocolError
          end
          if frame["absent"] && (!@moved_to_parent || !@validator_launch_closed ||
                                 (@creator_acquisition && !@settled[@creator_acquisition.object_id]))
            raise ProtocolError
          end
          close_descendant_launch!
          @self_group_retired = true
          @group_retirement_received = true
          @group_retirement_absent = frame["absent"]
          fail!("lifecycle", from_parent: true) unless frame["absent"]
        when "RELEASE"
          raise ProtocolError unless @group_retirement_received && !@release_received

          @release_received = true
        else raise ProtocolError
        end
      end

      def start_validator_creator
        @validator_attempt_entered = true
        @creator_slot, @creator_acquisition = new_creator
        acquisition = @creator_acquisition
        @creator_slot.start do
          argv = @configuration.fetch("validator_argv")
          spec = NativeUploadProcess.native::SpawnSpec.new(
            executable: argv.first, argv: argv, env: @configuration.fetch("validator_env"),
            fd_sources: [@roles.fetch(:validator_stdin), @roles.fetch(:validator_stdout), @roles.fetch(:validator_stderr)],
          )
          NativeUploadProcess.native.create(acquisition, spec)
        end
      end

      def settle_validator_creator
        return if !@creator_slot || @validator_handoff

        @creator_slot.admit! if @creator_slot.publication_ready? && launch_allowed?
        return unless poll_creator(@creator_slot, @creator_acquisition)

        @validator_launch_closed = true
        @validator_handoff = true
        @validator = @creator_acquisition.child
        unless @settled[@creator_acquisition.object_id]
          @cleanup_unknown = true
          fail!("creation")
          return
        end
        close_data_copies
        fail!("creation") unless @validator
        if @validator
          raise LifecycleError if [@pid, @parent_pid].include?(@validator.pid)
        end
        move_to_parent_group
        if @validator && launch_allowed?
          @moved_frame = { "validator_pid" => @validator.pid, "group_id" => @pid, "keeper_pgid" => @parent_pid }.freeze
          send_parent("MOVED", @moved_frame)
        end
      end

      def move_to_parent_group
        return if @moved_to_parent
        return unless @group_created
        if @creator_acquisition && !@settled[@creator_acquisition.object_id]
          raise LifecycleError
        end
        unless @validator_launch_closed && Process.getsid(0) == @parent_pid && Process.getpgrp == @pid
          raise LifecycleError
        end

        Process.setpgid(0, @parent_pid)
        unless Process.getsid(0) == @parent_pid && Process.getpgrp == @parent_pid
          raise LifecycleError
        end
        @moved_to_parent = true
      end

      def poll_validator
        return if !@validator || @validator_receipt || @validator_wait_broken
        return unless @creator_slot&.joined? && @settled[@creator_acquisition.object_id]
        return if NativeUploadProcess.monotonic_ns >= effective_deadline_ns

        @validator.retire_numeric!
        @validator_receipt = @validator.poll_wait
        if @validator_receipt && (@validator_receipt.status_kind.to_s != "exit" || !@validator_receipt.status_code.zero?)
          note_validator_failure
        end
      rescue Exception => error
        @validator_wait_broken = true
        @cleanup_unknown = true
        fail!(NativeUploadProcess.reason_for(error), error: error)
      end

      def publish_validator_status
        return unless @validator_receipt && @moved_frame && @parent_channel.written?("MOVED") && !@status_sent && launch_allowed?

        @status_sent = true
        send_parent("STATUS", "validator_pid" => @validator_receipt.pid,
                             "status_kind" => @validator_receipt.status_kind.to_s,
                             "status_code" => @validator_receipt.status_code)
      end

      def cleanup_group
        return unless @failed && @group_created && !@self_group_retired
        return if NativeUploadProcess.monotonic_ns >= effective_deadline_ns

        if @moved_to_parent
          present = @self_group_absent ? false : request_group(0)
          if present && !@group_kill_attempted
            @group_kill_attempted = true
            present = request_group("KILL")
          end
          @self_group_retired = true unless present
        elsif effective_deadline_ns - NativeUploadProcess.monotonic_ns <= 4 * POLL_NS && !@group_kill_attempted
          # A still-unresolved spawn must not be moved into C's group. On
          # parent loss/failure, kill THIS original group, possibly including
          # this K. The resulting nonzero exit can never assert finality.
          @group_kill_attempted = true
          request_group("KILL")
        end
      end

      def step
        settle_validator_creator
        if @failed && !@creator_slot
          close_descendant_launch!
          close_data_copies
          move_to_parent_group
        end
        poll_validator
        publish_validator_status
        cleanup_group
        finish_if_ready
      end

      def validator_record
        child_record(@validator, @creator_acquisition, attempt_entered: @validator_attempt_entered,
                     launch_closed: @validator_launch_closed)
      end

      def finish_if_ready
        return if @creator_slot && !@validator_handoff
        signal_generation = @signal_generation # Before deriving this offer's facts.
        record = validator_record
        return if @validator && !@validator_receipt && !@validator_wait_broken

        if @release_received
          return unless @self_group_retired
        elsif @failed && (@local_failure || @parent_lost)
          return if @group_created && !(@self_group_retired && @self_group_absent)
        else
          return
        end

        receive_parent
        tick!
        close_descendant_launch!
        prepare_terminal_io
        confirmed = own_resources_settled? && %w[reaped not_attempted].include?(record["state"])
        group_confirmed = @group_retirement_absent || (@self_group_retired && @self_group_absent) || !@group_created
        unless confirmed && group_confirmed
          abandon_terminal
          return
        end
        cooperative = @release_received && @group_retirement_received && @group_retirement_absent &&
                      !@local_failure && !@parent_lost && confirmed
        start_terminal({ "v" => VERSION, "type" => "RELEASED", "validator" => record },
                       exit_code: cooperative ? 0 : 2, signal_generation: signal_generation)
      end

      def terminal_offer_settled?
        return false unless @terminal_frame.fetch("type") == "RELEASED"

        record = @terminal_frame.fetch("validator")
        return false unless record == validator_record && %w[reaped not_attempted].include?(record.fetch("state"))

        group_confirmed = @group_retirement_absent || (@self_group_retired && @self_group_absent) || !@group_created
        cooperative = @release_received && @group_retirement_received && @group_retirement_absent &&
                      !@local_failure && !@parent_lost
        group_confirmed && @intended_exit == (cooperative ? 0 : 2)
      end

      def seal_at_cutoff
        close_descendant_launch!
        @self_group_retired = true
        @cleanup_unknown = true
        mark_pending_unknown
        prepare_terminal_io
        return if @terminal_started

        start_terminal({ "v" => VERSION, "type" => "RELEASED", "validator" => validator_record },
                       exit_code: 1, signal_generation: @signal_generation)
      end
    end

    HELPER_FLAGS = %w[
      --disable=rubyopt,gems,did_you_mean,error_highlight,syntax_suggest,rjit,yjit
      --external-encoding=UTF-8
      --internal-encoding=UTF-8
    ].freeze
    HELPER_ENVIRONMENT = { "LANG" => "C", "LC_ALL" => "C", "TZ" => "UTC" }.freeze

    def self.helper_environment
      HELPER_ENVIRONMENT
    end

    def self.helper_argv(role:, parent_context:, deadlines:)
      raise ProtocolError unless %w[custodian keeper].include?(role)
      unless parent_context.instance_of?(Hash) && parent_context.keys.sort == %i[parent_pid session_id] &&
             deadlines.instance_of?(Hash) && deadlines.keys.sort == %i[hard_cleanup_deadline_ns run_deadline_ns]
        raise ProtocolError
      end
      Protocol.pid!(parent_context[:parent_pid])
      Protocol.pid!(parent_context[:session_id])
      Protocol.time!(deadlines[:run_deadline_ns])
      Protocol.time!(deadlines[:hard_cleanup_deadline_ns])
      unless deadlines[:hard_cleanup_deadline_ns].between?(deadlines[:run_deadline_ns], deadlines[:run_deadline_ns] + CLEANUP_GRACE_NS)
        raise ProtocolError
      end
      ruby = File.realpath(RbConfig.ruby)
      helper = File.realpath(__FILE__)
      Protocol.absolute!(ruby)
      Protocol.absolute!(helper)
      raise LifecycleError unless File.file?(ruby) && File.executable?(ruby) && File.file?(helper)

      freeze_value([ruby, *HELPER_FLAGS, "--", helper, role, parent_context[:parent_pid].to_s,
                    parent_context[:session_id].to_s, deadlines[:run_deadline_ns].to_s,
                    deadlines[:hard_cleanup_deadline_ns].to_s])
    rescue IOError, SystemCallError
      raise LifecycleError, "creation"
    end

    def self.helper_main(argv)
      unless argv.instance_of?(Array) && argv.length == 5 && argv.all? { |item| item.instance_of?(String) } &&
             %w[custodian keeper].include?(argv.first) && argv.drop(1).all? { |item| item.match?(/\A[1-9][0-9]{0,18}\z/) }
        return 1
      end

      parent_pid, inherited_session_id, run_deadline_ns, hard_cleanup_deadline_ns = argv.drop(1).map { |item| Integer(item, 10) }
      Protocol.pid!(parent_pid)
      Protocol.pid!(inherited_session_id)
      Protocol.time!(run_deadline_ns)
      Protocol.time!(hard_cleanup_deadline_ns)
      unless hard_cleanup_deadline_ns.between?(run_deadline_ns, run_deadline_ns + CLEANUP_GRACE_NS) &&
             run_deadline_ns <= monotonic_ns + MAX_SECONDS * 1_000_000_000
        return 1
      end

      klass = argv.first == "custodian" ? Custodian : Keeper
      owner = klass.new(parent_pid: parent_pid, inherited_session_id: inherited_session_id,
                        run_deadline_ns: run_deadline_ns, hard_cleanup_deadline_ns: hard_cleanup_deadline_ns)
      owner.seal_exit_handoff(owner.run)
    rescue Exception
      1
    end
  end
end

# NativeUploadProcess fixed executable entrypoint.
if $PROGRAM_NAME == __FILE__
  Process.exit!(MobileReleaseKit::NativeUploadProcess.helper_main(ARGV))
end
