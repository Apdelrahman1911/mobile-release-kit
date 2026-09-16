# frozen_string_literal: true

require "json"
require_relative "store_document"
require_relative "store_lane_resources"
require_relative "native_process_spawn"

module MobileReleaseKit
  # Explicit six-lane boundary. No at_exit, background worker, process owner,
  # pathname adoption, cleanup deletion or automatic Fastlane installation.
  # Actual process/group/EOF finality remains the original Python C/A/W owner.
  module StoreLaneRuntime
    LANES = %w[android_internal_upload android_external_promote android_production_draft
               ios_testflight_internal ios_testflight_external ios_app_store_submit].freeze
    PREFIX = "MOBILE_RELEASE_STORE_LANE_"
    PRIVATE_KEYS = %w[NONCE ROOT ROOT_ID CLOCK RUN_DEADLINE_NS HARD_DEADLINE_NS].map { |key| PREFIX + key }.freeze
    MAX_TIME = (1 << 63) - 1
    MAX_ID = (1 << 64) - 1
    RUN_NS = 3_600_000_000_000
    CLEANUP_NS = 3_000_000_000
    private_constant :LANES, :PREFIX, :PRIVATE_KEYS, :MAX_TIME, :MAX_ID, :RUN_NS, :CLEANUP_NS

    class Error < StandardError
      attr_reader :reason
      def initialize(reason)
        super("Store lane completion is unconfirmed; retain original evidence")
        @reason = reason
      end
    end

    # Capture/admit before optional Fastlane behavior loads. This is the normal
    # documented Ruby exit! API, not an FFI exit or status-only finality proof.
    class ExitBoundary
      def initialize
        @pid, @thread = Process.pid, Thread.current
        @exit = Process.method(:exit!)
        unless RUBY_ENGINE == "ruby" && RUBY_VERSION == "3.3.12" &&
               @exit.receiver.equal?(Process) && @exit.owner.equal?(Process.singleton_class) &&
               @exit.name == :exit! && @exit.source_location.nil? && @exit.arity == -1
          raise Error.new(:exit_api)
        end
      end

      def origin!
        raise Error.new(:foreign_origin) unless @pid == Process.pid && @thread.equal?(Thread.current)
      end

      def exit_status!(status)
        origin!
        raise Error.new(:exit_status) unless status.instance_of?(Integer) && [0, 75, 76].include?(status)
        @exit.call(status)
        raise Error.new(:exit_returned) # The admitted built-in never returns.
      end
    end
    private_constant :ExitBoundary

    def self.capture_exit_boundary!
      if @exit_boundary
        @exit_boundary.origin!
      else
        @exit_boundary = ExitBoundary.new
      end
      true
    end

    def self.current_runtime!
      raise Error.new(:runtime_missing) unless @runtime
      @runtime.origin!
      @runtime
    end

    def self.run_upload!(lane, &body)
      raise Error.new(:exit_not_captured) unless @exit_boundary
      @exit_boundary.origin!
      if @runtime
        @runtime.mark_unknown!(Error.new(:runtime_reused))
        Thread.handle_interrupt(Exception => :never) { @exit_boundary.exit_status!(76) }
      end
      @runtime = Runtime.new(@exit_boundary) # Root before admission/effects.
      @runtime.run!(lane, &body)
    end

    class Runtime
      attr_reader :first_primary

      def initialize(exit_boundary)
        raise Error.new(:exit_owner) unless exit_boundary.instance_of?(ExitBoundary)
        @exit_boundary = exit_boundary
        @pid, @thread = Process.pid, Thread.current
        @state, @unknown = :reserved, false
        @secondary_errors, @cleanup_errors = [], []
      end

      def origin!
        raise Error.new(:foreign_origin) unless @pid == Process.pid && @thread.equal?(Thread.current)
        @exit_boundary.origin!
      end

      def resources
        origin!
        raise Error.new(:resources_missing) unless @resources
        @resources
      end

      def invocation
        origin!
        raise Error.new(:invocation_missing) unless @invocation
        @invocation
      end

      def binding
        origin!
        raise Error.new(:binding_missing) unless @binding
        @binding
      end

      def xml_template
        origin!
        raise Error.new(:bridges_not_admitted) unless @bridges_installed && @xml_template
        @xml_template
      end

      def secondary_errors
        origin!
        @secondary_errors.dup.freeze
      end

      def cleanup_errors
        origin!
        @cleanup_errors.dup.freeze
      end

      def mark_unknown!(error, cleanup: false)
        origin!
        Thread.handle_interrupt(Exception => :never) do
          @unknown = true
          retain_error(@invocation.first_primary) if @invocation&.first_primary && @first_primary.nil?
          retain_error(error, cleanup: cleanup)
          @invocation&.mark_unknown!(error, cleanup: cleanup)
          @invocation&.cleanup_errors&.each { |item| retain_error(item, cleanup: true) }
        end
      end

      def install_fastlane_bridges!
        origin!
        begin
          raise Error.new(:bridge_reused) unless @state == :running && !@bridges_attempted
          @bridges_attempted = true
          require_relative "store_lane_fastlane_bridges"
          @xml_template = StoreLaneFastlaneBridges.install!(self)
          @bridges_installed = true
          true
        rescue Exception => error # rubocop:disable Lint/RescueException
          mark_unknown!(error)
          raise
        end
      end

      def require_active!
        origin!
        raise Error.new(:inactive_runtime) unless @state == :running && @bridges_installed && !@unknown
        @invocation.require_upload_continuation!
        check_environment!
        require_time!
        true
      rescue Exception => error # rubocop:disable Lint/RescueException
        mark_unknown!(error)
        raise
      end

      def run!(lane)
        origin!
        raise Error.new(:unregistered_runtime) unless StoreLaneRuntime.instance_variable_get(:@runtime).equal?(self)
        raise Error.new(:runtime_reused) unless @state == :reserved
        @state = :admitting
        # This surrounding rescue spans admission, the lane, both publishers,
        # all closes and the last check. SystemExit(0/75) is never an admission.
        begin
          Thread.handle_interrupt(Exception => :never) do
            begin
              Thread.handle_interrupt(Exception => :immediate) do
                admit!(lane)
                @state = :running
                begin
                  yield self
                  @lane_returned = true
                rescue StandardError => error
                  # A genuinely ordinary lane error may have a settled failed
                  # terminal. Original unknown latches remain authoritative.
                  @lane_error = error
                  retain_error(@invocation.first_primary) if @invocation.first_primary && @first_primary.nil?
                  retain_error(error)
                end
                raise Error.new(:bridges_not_admitted) unless @bridges_installed
                @state = :finishing
                check_environment!
                @invocation.seal_uploads!
                @resources.finish!
                raise Error.new(:unsettled_lane) unless @invocation.uploads_sealed_and_retired?
                document = @invocation.store_document_result
                unless @lane_error || document
                  @lane_error = Error.new(:document_missing)
                  retain_error(@lane_error)
                end
                @status = @lane_error ? 75 : 0
                frame = terminal_fields(document)
                @publisher = TerminalPublication.new(invocation: @invocation, binding: @binding,
                  fields: frame, fchdir: @fchdir)
                @publisher.publish!
              end
              # Deliver anything pending, then make the final active check.
              # The already-proved terminal has no cleanup/callback tail.
              Thread.handle_interrupt(Exception => :immediate) { require_completion! }
              @state = :complete
              @exit_boundary.exit_status!(@status)
            rescue Exception => error # rubocop:disable Lint/RescueException
              mark_unknown!(error)
              raise
            ensure
              # The actual exit! never unwinds. A non-exception throw/return
              # from optional code is nevertheless UNKNOWN and exits76.
              unless @state == :complete
                mark_unknown!(Error.new(:nonlocal_completion)) unless @unknown
                finish_unknown!
              end
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          mark_unknown!(error)
          finish_unknown!
        end
      end

      private

      def retain_error(error, cleanup: false)
        @first_primary ||= error
        if !error.equal?(@first_primary) && @secondary_errors.length < 8 && !@secondary_errors.any? { |item| item.equal?(error) }
          @secondary_errors << error
        end
        if cleanup && @cleanup_errors.length < 8 && !@cleanup_errors.any? { |item| item.equal?(error) }
          @cleanup_errors << error
        end
      end

      def require_time!
        raise Error.new(:deadline) unless NativeProcessSpawn.monotonic_ns < @binding.fetch("run_deadline_ns")
      end

      def absolute!(value)
        unless value.instance_of?(String) && value.encoding.ascii_compatible? && value.dup.force_encoding(Encoding::UTF_8).valid_encoding? &&
               value.bytesize.between?(1, 4_096) && value.start_with?(File::SEPARATOR) && !value.start_with?("//") &&
               !value.match?(/[\x00-\x1f\x7f]/) && File.expand_path(value) == value && value.split(File::SEPARATOR).length <= 64
          raise Error.new(:path)
        end
        value.dup.freeze
      end

      def decimal!(value, minimum: 0, maximum: MAX_TIME)
        raise Error.new(:integer) unless value.instance_of?(String) && value.match?(/\A(?:0|[1-9][0-9]{0,19})\z/)
        number = Integer(value, 10)
        raise Error.new(:integer) unless number.between?(minimum, maximum)
        number
      end

      def admit!(lane)
        raise Error.new(:lane) unless lane.instance_of?(String) && LANES.include?(lane)
        @environment = ENV.to_h.transform_values { |value| value.dup.freeze }.freeze
        env = @environment
        unless env.keys.select { |key| key.start_with?(PREFIX) }.sort == PRIVATE_KEYS.sort &&
               env["MOBILE_RELEASE_OPERATION"] == lane && %w[prepare execute].include?(env["MOBILE_RELEASE_STORE_MODE"])
          raise Error.new(:environment)
        end
        nonce = env.fetch(PREFIX + "NONCE")
        raise Error.new(:nonce) unless nonce.match?(/\A[0-9a-f]{32}\z/)
        root = absolute!(env.fetch(PREFIX + "ROOT"))
        output = absolute!(env.fetch("MOBILE_RELEASE_STORE_RECEIPT_PATH"))
        raise Error.new(:output_scope) if output == root || output.start_with?(root + File::SEPARATOR)
        root_id = env.fetch(PREFIX + "ROOT_ID").split(":", -1)
        raise Error.new(:root_identity) unless root_id.length == 2
        device = decimal!(root_id.fetch(0), maximum: MAX_ID)
        inode = decimal!(root_id.fetch(1), minimum: 1, maximum: MAX_ID)
        clock = NativeProcessSpawn.monotonic_domain
        raise Error.new(:clock) unless env.fetch(PREFIX + "CLOCK") == clock
        run = decimal!(env.fetch(PREFIX + "RUN_DEADLINE_NS"), minimum: 1)
        hard = decimal!(env.fetch(PREFIX + "HARD_DEADLINE_NS"), minimum: 1)
        now = NativeProcessSpawn.monotonic_ns
        raise Error.new(:deadline) unless now < run && run <= now + RUN_NS && hard - run == CLEANUP_NS
        tmp = File.join(root, "tmp")
        raise Error.new(:temporary_scope) unless %w[TMPDIR TMP TEMP].all? { |key| env[key] == tmp }
        raise Error.new(:cwd) unless Dir.pwd == File.join(root, "runner") && File.realpath(Dir.pwd) == Dir.pwd
        unless RUBY_ENGINE == "ruby" && RUBY_VERSION == "3.3.12" &&
               File.const_defined?(:NOFOLLOW) && File.const_defined?(:NONBLOCK) && Dir.respond_to?(:fchdir)
          raise Error.new(:runtime_api)
        end
        @fchdir = Dir.method(:fchdir)
        raise Error.new(:directory_api) unless @fchdir.owner.equal?(Dir.singleton_class) && @fchdir.source_location.nil? && @fchdir.arity == 1
        app_id, key_id = env["MOBILE_RELEASE_ASC_APP_ID"], env["MOBILE_RELEASE_ASC_KEY_ID"]
        if lane.start_with?("ios_")
          raise Error.new(:app_id) unless app_id.instance_of?(String) && app_id.bytesize <= 64 && app_id.match?(/\A[1-9][0-9]*\z/)
          raise Error.new(:key_id) unless key_id.instance_of?(String) && key_id.bytesize <= 64 && key_id.match?(/\A[A-Za-z0-9]+\z/)
        end
        artifact = env["MOBILE_RELEASE_IOS_IPA_PATH"]
        artifact = absolute!(artifact) if artifact
        @binding = {"lane" => lane.dup.freeze, "mode" => env.fetch("MOBILE_RELEASE_STORE_MODE"),
          "nonce" => nonce, "root" => root, "root_device" => device, "root_inode" => inode,
          "output" => output, "clock" => clock, "run_deadline_ns" => run, "hard_deadline_ns" => hard,
          "shell_home" => env["HOME"] == File.join(root, "home"), "macos" => clock == "darwin-uptime-raw-v1",
          "app_id" => app_id, "key_id" => key_id, "artifact" => artifact}.freeze
        @invocation = StoreLaneLifetime::Invocation.new(lane: lane, nonce: [nonce].pack("H*"),
          output: output, mode: @binding.fetch("mode"), run_deadline_ns: run)
        StoreLaneLifetime.activate!(@invocation)
        @resources = StoreLaneResources::Inventory.new(invocation: @invocation, binding: @binding)
        @invocation.bind_resources!(@resources)
        @resources.admit!
      end

      def check_environment!
        keys = PRIVATE_KEYS + %w[MOBILE_RELEASE_OPERATION MOBILE_RELEASE_STORE_MODE MOBILE_RELEASE_STORE_RECEIPT_PATH
          MOBILE_RELEASE_ASC_APP_ID MOBILE_RELEASE_ASC_KEY_ID MOBILE_RELEASE_IOS_IPA_PATH TMPDIR TMP TEMP HOME]
        raise Error.new(:environment_changed) unless keys.all? { |key| ENV[key] == @environment[key] }
      end

      def terminal_fields(document)
        receipt = if @status.zero?
                    raise Error.new(:document_missing) unless document
                    document.fetch("identity").merge("size" => document.fetch("size"), "sha256" => document.fetch("sha256")).freeze
                  end
        {"version" => 1, "nonce" => @binding.fetch("nonce"), "lane" => @binding.fetch("lane"),
         "mode" => @binding.fetch("mode"), "output" => @binding.fetch("output"), "clock" => @binding.fetch("clock"),
         "run_deadline_ns" => @binding.fetch("run_deadline_ns"), "hard_deadline_ns" => @binding.fetch("hard_deadline_ns"),
         "outcome" => @status.zero? ? "success" : "failed", "launches_closed" => true,
         "adapter_settled" => true, "nested_settled" => true, "receipt" => receipt,
         "inventory" => @resources.inventory}.freeze
      end

      def require_completion!
        origin!
        check_environment!
        unless !@unknown && @state == :finishing && @publisher&.completed? &&
               @invocation.uploads_sealed_and_retired? && @resources.sealed_and_retired? &&
               ((@status == 0 && @lane_returned && @lane_error.nil? && @first_primary.nil?) ||
                (@status == 75 && @lane_error.is_a?(StandardError) && @first_primary.equal?(@lane_error)))
          raise Error.new(:completion)
        end
        require_time! # Last active check; only selecting/calling captured exit follows.
      end

      def finish_unknown!
        origin!
        Thread.handle_interrupt(Exception => :never) do
          @unknown, @state = true, :unknown
          begin
            @publisher&.close_independent!
          rescue Exception => error # rubocop:disable Lint/RescueException
            mark_unknown!(error, cleanup: true)
          ensure
            begin
              @resources&.close_independent!
            rescue Exception => error # rubocop:disable Lint/RescueException
              mark_unknown!(error, cleanup: true)
            end
          end
          @exit_boundary.exit_status!(76)
        end
      end
    end

    class TerminalPublication
      MAX_BYTES = 65_536
      private_constant :MAX_BYTES

      def initialize(invocation:, binding:, fields:, fchdir:)
        @invocation, @binding, @fields, @fchdir = invocation, binding, fields, fchdir
        @root, @writer = StoreLaneResources::FileSlot.new, StoreLaneResources::FileSlot.new
        @state = :reserved
      end

      def completed?
        @invocation.origin!
        @state == :completed && !@invocation.unknown? && @root.retired? && @writer.retired?
      end

      def publish!
        @invocation.origin!
        raise Error.new(:terminal_reused) unless @state == :reserved
        @state, body_returned = :publishing, false
        begin
          Thread.handle_interrupt(Exception => :never) do
            begin
              begin
                Thread.handle_interrupt(Exception => :immediate) do
                  write_body!
                  body_returned = true
                end
              rescue Exception => error # rubocop:disable Lint/RescueException
                fail!(error)
              ensure
                fail!(Error.new(:terminal_nonlocal)) unless body_returned || @invocation.unknown?
                close_independent!
              end
              Thread.handle_interrupt(Exception => :immediate) do
                raise Error.new(:terminal_unretired) unless body_returned && !@invocation.unknown? && @root.retired? && @writer.retired?
                require_time!
                verify_cwd!
                verify_name!("terminal.part", links: 1, revision: @written_revision)
                raise Error.new(:terminal_link_return) unless File.link("terminal.part", "terminal.json") == 0
                # Only the actual successful link return can reach postchecks.
                linked = verify_name!("terminal.part", links: 2, revision: @written_revision, link_change: true)
                verify_name!("terminal.json", links: 2, revision: linked)
                verify_cwd!
                require_time!
              end
              @state = :completed
              return self
            rescue Exception => error # rubocop:disable Lint/RescueException
              fail!(error)
              raise
            ensure
              fail!(Error.new(:terminal_nonlocal)) unless @state == :completed || @invocation.unknown?
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          fail!(error)
          @invocation.raise_unknown!
        end
      end

      def close_independent!
        @invocation.origin!
        Thread.handle_interrupt(Exception => :never) do
          begin
            close_one!(@writer)
          ensure
            close_one!(@root)
          end
        end
      end

      private

      def close_one!(slot)
        failure = nil
        begin
          slot.close_once
        rescue Exception => error # rubocop:disable Lint/RescueException
          failure = error
        ensure
          slot.close_errors.each { |error| fail!(error, cleanup: true) }
          fail!(failure, cleanup: true) if failure
        end
      end

      def fail!(error, cleanup: false)
        @state = :failed
        @invocation.mark_unknown!(error, cleanup: cleanup)
      end

      def require_time!
        raise Error.new(:deadline) unless NativeProcessSpawn.monotonic_ns < @binding.fetch("run_deadline_ns")
      end

      def verify_cwd!
        original = @binding.fetch("root")
        current, named = File.stat("."), File.lstat(original)
        unless current.directory? && named.directory? && !named.symlink? &&
               StoreLaneResources.identity(current) == @root_identity &&
               StoreLaneResources.identity(named) == @root_identity && File.realpath(original) == original
          raise Error.new(:terminal_root_changed)
        end
      end

      def verify_name!(name, links:, revision:, link_change: false)
        value = File.lstat(name)
        actual = StoreLaneResources.revision(value)
        expected = link_change ? revision.first(2) : revision
        observed = link_change ? actual.first(2) : actual
        unless value.file? && !value.symlink? && value.nlink == links &&
               StoreLaneResources.identity(value) == @writer_identity && value.size == @payload.bytesize && observed == expected
          raise Error.new(:terminal_entry_changed)
        end
        actual
      end

      def write_body!
        require_time!
        root_path = @binding.fetch("root")
        @root.acquire(root_path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        original, named = @root.io.stat, File.lstat(root_path)
        unless original.directory? && named.directory? && !named.symlink? && original.uid == Process.euid &&
               (original.mode & 0o7777) == 0o700 && original.dev == @binding.fetch("root_device") &&
               original.ino == @binding.fetch("root_inode") && StoreLaneResources.identity(original) == StoreLaneResources.identity(named)
          raise Error.new(:terminal_root_identity)
        end
        @root_identity = StoreLaneResources.identity(original)
        # No block: no implicit restoration FD or path-based fallback exists.
        raise Error.new(:directory_return) unless @fchdir.call(@root.io.fileno) == 0
        verify_cwd!
        file = @writer.acquire("terminal.part", File::RDWR | File::CREAT | File::EXCL | File::NOFOLLOW | File::NONBLOCK, 0o600)
        file.binmode
        value = file.stat
        unless value.file? && value.dev == original.dev && value.uid == Process.euid &&
               (value.mode & 0o7777) == 0o600 && value.nlink == 1 && value.size.zero?
          raise Error.new(:terminal_writer_identity)
        end
        @writer_identity = StoreLaneResources.identity(value)
        @payload = (JSON.generate(@fields.merge("terminal_identity" => @writer_identity)) + "\n").b.freeze
        raise Error.new(:terminal_size) unless @payload.bytesize.between?(1, MAX_BYTES)
        offset = 0
        while offset < @payload.bytesize
          require_time!
          count = file.write(@payload.byteslice(offset..))
          raise Error.new(:terminal_write_progress) unless count.instance_of?(Integer) && count.positive? && count <= @payload.bytesize - offset
          offset += count
        end
        file.flush
        file.fsync
        descriptor = file.stat
        @written_revision = StoreLaneResources.revision(descriptor)
        unless descriptor.file? && descriptor.nlink == 1 && StoreLaneResources.identity(descriptor) == @writer_identity &&
               descriptor.size == @payload.bytesize && file.pread(MAX_BYTES, 0) == @payload &&
               StoreLaneResources.revision(file.stat) == @written_revision
          raise Error.new(:terminal_writer_changed)
        end
        verify_name!("terminal.part", links: 1, revision: @written_revision)
        verify_cwd!
      end
    end
    private_constant :TerminalPublication
  end
end
