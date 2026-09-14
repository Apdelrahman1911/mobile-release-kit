# frozen_string_literal: true

require "rbconfig"

module MobileReleaseKit
  # Private native-upload implementation, not a general command runner. Import
  # performs no FFI call, FD acquisition, signal inspection, task start or wait.
  # The supported embedding keeps SIGCHLD waitable and never steals our exact
  # children. A policy snapshot cannot police a hostile in-process reaper.
  module NativeProcessSpawn
    RUBY_RELEASE = "3.3.12"
    FIDDLE_RELEASE = "1.1.2"
    MAX_PID = (1 << 31) - 1
    MAX_TIME = (1 << 63) - 1
    MAX_VALUE = 8 * 1_024
    MAX_COLLECTION = 64 * 1_024
    CLEANUP_GRACE_NS = 5_000_000_000
    ACCESS = %i[read write readwrite].freeze
    KINDS = %i[pipe null file].freeze
    CODES = %w[abi runtime origin symbol spec launch deadline state io fd busy native
               waitability spawn wait join close unknown].freeze

    class Error < StandardError
      attr_reader :code, :errno

      def initialize(code = "native", errno: nil, original_error: nil)
        @code = CODES.include?(code) ? code.dup.freeze : "native"
        @errno = errno if errno.instance_of?(Integer) && errno.between?(0, 4_095)
        @original_error = original_error
        super("native process #{@code} failure")
      end

      private

      attr_reader :original_error
    end

    # Process-wide custody, not a PID/FD discovery service. UNKNOWN is absorbing:
    # roots survive caller unwind/GC and no later capture silently reuses this
    # interpreter. Known closes may still finish without reopening admission.
    @custody_lock = Mutex.new
    @retained = {}
    @fd_claims = {}
    @poisoned = false

    class << self
      def monotonic_ns
        Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      end

      def deep_freeze(value)
        case value
        when Hash then value.each { |key, item| key.freeze; deep_freeze(item) }
        when Array then value.each { |item| deep_freeze(item) }
        end
        value.freeze
      end

      # This SAME closed record supplies the actual Fiddle function declarations,
      # container allocation sizes, field offsets and FD/wait constants below.
      # The test-only C reporter compares it with actual public platform headers.
      def declared_abi
        os = RbConfig::CONFIG.fetch("host_os")
        family = if os.match?(/\Alinux/) && !RUBY_PLATFORM.include?("musl")
                   "linux-glibc"
                 elsif os.match?(/\Adarwin/)
                   "darwin"
                 else
                   raise Error.new("abi")
                 end
        architecture = case RbConfig::CONFIG.fetch("host_cpu")
                       when "x86_64" then "x86_64"
                       when "aarch64", "arm64" then "arm64"
                       else raise Error.new("abi")
                       end
        raise Error.new("abi") unless [1].pack("I") == "\x01\x00\x00\x00".b

        linux = family == "linux-glibc"
        function = ->(args, variadic = false) { { "return" => "int", "args" => args, "variadic" => variadic } }
        pointer_slot = { "kind" => "pointer_slot", "size" => 8, "align" => 8, "fields" => {} }
        deep_freeze({
          "schema" => "mrk-native-process-abi-v1", "family" => family,
          "architecture" => architecture, "byteorder" => "little",
          "scalars" => {
            "pointer" => { "size" => 8, "align" => 8 }, "int" => { "size" => 4, "align" => 4 },
            "short" => { "size" => 2, "align" => 2 }, "long" => { "size" => 8, "align" => 8 },
            "pid_t" => { "size" => 4, "align" => 4, "signed" => true },
          },
          "sigaction" => {
            "size" => linux ? 152 : 16, "align" => 8,
            "fields" => {
              "handler" => { "offset" => 0, "size" => 8 },
              "mask" => { "offset" => 8, "size" => linux ? 128 : 4 },
              "flags" => { "offset" => linux ? 136 : 12, "size" => 4 },
              "restorer" => linux ? { "offset" => 144, "size" => 8 } : nil,
            },
          },
          "file_actions" => linux ? {
            "kind" => "struct", "size" => 80, "align" => 8,
            "fields" => { "allocated" => { "offset" => 0, "size" => 4 },
                          "used" => { "offset" => 4, "size" => 4 },
                          "actions" => { "offset" => 8, "size" => 8 },
                          "pad" => { "offset" => 16, "size" => 64 } },
          } : pointer_slot,
          "spawn_attributes" => linux ? nil : pointer_slot,
          "constants" => {
            "SIG_IGN" => 1, "SA_NOCLDWAIT" => linux ? 2 : 32,
            "SIGCHLD" => linux ? 17 : 20, "NSIG" => linux ? 65 : 32,
            "F_DUPFD_CLOEXEC" => linux ? 1_030 : 67, "F_GETFD" => 1, "F_GETFL" => 3,
            "FD_CLOEXEC" => 1, "O_RDONLY" => 0, "O_WRONLY" => 1, "O_RDWR" => 2, "O_ACCMODE" => 3,
            "POSIX_SPAWN_CLOEXEC_DEFAULT" => linux ? nil : 16_384,
          },
          "functions" => {
            "fcntl" => function.call(%w[int int], true), "close" => function.call(%w[int]),
            "sigaction" => function.call(%w[int pointer pointer]),
            "posix_spawn" => function.call(%w[pointer pointer pointer pointer pointer pointer]),
            "posix_spawn_file_actions_init" => function.call(%w[pointer]),
            "posix_spawn_file_actions_destroy" => function.call(%w[pointer]),
            "posix_spawn_file_actions_adddup2" => function.call(%w[pointer int int]),
            "posix_spawn_file_actions_addclosefrom_np" => linux ? function.call(%w[pointer int]) : nil,
            "posix_spawnattr_init" => linux ? nil : function.call(%w[pointer]),
            "posix_spawnattr_destroy" => linux ? nil : function.call(%w[pointer]),
            "posix_spawnattr_setflags" => linux ? nil : function.call(%w[pointer short]),
            "posix_spawnattr_getflags" => linux ? nil : function.call(%w[pointer pointer]),
          },
        })
      end

      def nsig
        declared_abi.fetch("constants").fetch("NSIG")
      end

      def runtime_info
        reusable!
        raise Error.new("runtime") unless RUBY_ENGINE == "ruby" && RUBY_VERSION == RUBY_RELEASE

        abi = declared_abi
        origin = fiddle_origin!
        require origin.fetch(:features).fetch("fiddle")
        check_loaded_fiddle!(origin)
        raise Error.new("runtime") unless Fiddle::VERSION == FIDDLE_RELEASE

        deep_freeze({
          "schema" => "mrk-native-process-runtime-v1", "ruby_engine" => RUBY_ENGINE.dup,
          "ruby_version" => RUBY_VERSION.dup, "fiddle_version" => Fiddle::VERSION.dup,
          "family" => abi.fetch("family"), "architecture" => abi.fetch("architecture"),
          "ruby_executable" => File.realpath(RbConfig.ruby), "origin" => origin.fetch(:kind),
          "ruby_library_root" => origin.fetch(:library), "native_extension_roots" => origin.fetch(:extensions),
          "fiddle_features" => origin.fetch(:features), "gemfile" => origin.fetch(:gemfile),
        })
      rescue Error, Interrupt, SystemExit
        raise
      rescue LoadError, StandardError => error
        raise Error.new("runtime", original_error: error), cause: nil
      end

      # No child, signal mutation, runtime install or library-search subprocess.
      # Bundler is admitted only at the installed/source tooling's own Gemfile;
      # an arbitrary same-version gem or caller $LOAD_PATH is not a trust root.
      def admit_runtime!
        info = runtime_info
        abi = declared_abi
        { "pointer" => "VOIDP", "int" => "INT", "short" => "SHORT", "long" => "LONG" }.each do |name, type|
          scalar = abi.fetch("scalars").fetch(name)
          unless Fiddle.const_get("SIZEOF_#{type}") == scalar.fetch("size") &&
                 Fiddle.const_get("ALIGN_#{type}") == scalar.fetch("align")
            raise Error.new("abi")
          end
        end
        raise Error.new("abi") unless Fiddle.const_defined?(:TYPE_VARIADIC, false)

        # Public glibc capability marker, resolved only, never invoked. Alongside
        # the mandatory closefrom symbol this rejects unsupported Linux libc.
        Fiddle::Handle::DEFAULT["gnu_get_libc_version"] if abi.fetch("family") == "linux-glibc"
        abi.fetch("functions").each do |name, declaration|
          build_function(name, declaration) if declaration
        end
        info
      rescue Error, Interrupt, SystemExit
        raise
      rescue LoadError, StandardError => error
        raise Error.new("runtime", original_error: error), cause: nil
      end

      private

      def canonical_file(path)
        raise Error.new("origin") unless path.instance_of?(String) && path.start_with?(File::SEPARATOR)

        real = File.realpath(path)
        raise Error.new("origin") unless File.file?(real)

        real
      end

      def fiddle_origin!
        library = File.realpath(RbConfig::CONFIG.fetch("rubylibdir"))
        extensions = [File.realpath(RbConfig::CONFIG.fetch("rubyarchdir"))]
        kind, gemfile = "default", nil
        if defined?(Bundler)
          expected = canonical_file(File.expand_path("../Gemfile", __dir__))
          gemfile = canonical_file(Bundler.default_gemfile.to_s)
          raise Error.new("origin") unless gemfile == expected && Bundler::VERSION == "4.0.16"

          locked = Bundler.locked_gems.specs.select { |spec| spec.name == "fiddle" }
          selected = Gem.loaded_specs.fetch("fiddle")
          active = Bundler.load.specs.select { |spec| spec.name == "fiddle" }
          unless locked.length == 1 && active.length == 1 && locked.first.version.to_s == FIDDLE_RELEASE &&
                 selected.version.to_s == FIDDLE_RELEASE && active.first.version.to_s == FIDDLE_RELEASE &&
                 active.first.default_gem? == selected.default_gem?
            raise Error.new("origin")
          end
          paths_agree = if selected.default_gem?
                          # A default spec's full_gem_path is expanded metadata,
                          # not necessarily an existing directory in a prebuilt
                          # core-only runtime. It never supplies an allowed root.
                          File.expand_path(active.first.full_gem_path) == File.expand_path(selected.full_gem_path)
                        else
                          File.realpath(active.first.full_gem_path) == File.realpath(selected.full_gem_path)
                        end
          raise Error.new("origin") unless paths_agree

          # The checked lock is a rubygems.org package, never a path/git override.
          source = locked.first.source
          unless source.is_a?(Bundler::Source::Rubygems) &&
                 source.remotes.length == 1 && source.remotes.first.to_s.match?(/\Ahttps:\/\/rubygems\.org\/?\z/)
            raise Error.new("origin")
          end
          unless selected.default_gem?
            library = File.realpath(File.join(selected.full_gem_path, "lib"))
            extensions = [library, File.realpath(selected.extension_dir)].uniq
          end
          kind = "bundle"
        elsif defined?(Gem) && Gem.loaded_specs.key?("fiddle") && !Gem.loaded_specs.fetch("fiddle").default_gem?
          raise Error.new("origin")
        end
        extension = RbConfig::CONFIG.fetch("DLEXT")
        raise Error.new("origin") unless %w[so bundle].include?(extension)

        expected = {
          "fiddle" => [File.join(library, "fiddle.rb")],
          "version" => [File.join(library, "fiddle/version.rb")],
          "function" => [File.join(library, "fiddle/function.rb")],
          "closure" => [File.join(library, "fiddle/closure.rb")],
          "extension" => extensions.map { |root| File.join(root, "fiddle.#{extension}") },
        }
        features = {}
        expected.each do |key, candidates|
          allowed = candidates.select { |path| File.file?(path) }.map { |path| canonical_file(path) }.uniq
          raise Error.new("origin") if allowed.empty?

          relative = key == "fiddle" ? "fiddle.rb" : (key == "extension" ? "fiddle.#{extension}" : "fiddle/#{key}.rb")
          loaded = loaded_fiddle_feature(relative)
          if loaded.empty?
            # Internal requires in fiddle.rb use the ordinary loader. Check its
            # FIRST existing candidate before executing it; never edit LOAD_PATH.
            candidate = $LOAD_PATH.lazy.map { |root| File.expand_path(relative, root) }.find { |path| File.file?(path) }
            path = canonical_file(candidate)
            raise Error.new("origin") unless allowed.include?(path)
          else
            raise Error.new("origin") unless loaded.length == 1 && allowed.include?(loaded.first)

            path = loaded.first
          end
          features[key] = path
        end
        { kind: kind, library: library, extensions: extensions, features: features, gemfile: gemfile }
      end

      def loaded_fiddle_feature(relative)
        $LOADED_FEATURES.select { |path| path == relative || path.end_with?("/#{relative}") }
                        .map { |path| canonical_file(path) }
      end

      def check_loaded_fiddle!(origin)
        origin.fetch(:features).each do |key, path|
          relative = key == "fiddle" ? "fiddle.rb" : (key == "extension" ? File.basename(path) : "fiddle/#{key}.rb")
          raise Error.new("origin") unless loaded_fiddle_feature(relative) == [path]
        end
        actual = {
          "fiddle" => Fiddle.method(:last_error).source_location,
          "version" => Fiddle.const_source_location(:VERSION),
          "function" => Fiddle::Function.instance_method(:to_proc).source_location,
          "closure" => Fiddle::Closure::BlockCaller.instance_method(:call).source_location,
        }
        actual.each do |key, location|
          unless location && canonical_file(location.first) == origin.fetch(:features).fetch(key)
            raise Error.new("origin")
          end
        end
        unless Fiddle::Function.instance_method(:call).source_location.nil? &&
               Fiddle::Pointer.method(:malloc).source_location.nil?
          raise Error.new("origin")
        end
      end

      def build_function(name, declaration)
        types = { "pointer" => Fiddle::TYPE_VOIDP, "int" => Fiddle::TYPE_INT, "short" => Fiddle::TYPE_SHORT }
        args = declaration.fetch("args").map { |type| types.fetch(type) }
        args << Fiddle::TYPE_VARIADIC if declaration.fetch("variadic")
        Fiddle::Function.new(Fiddle::Handle::DEFAULT[name], args, types.fetch(declaration.fetch("return")),
                             Fiddle::Function::DEFAULT, name: name, need_gvl: false)
      end

      def retain(record)
        @custody_lock.synchronize { @retained[record.object_id] = record }
      end

      def forget(record)
        @custody_lock.synchronize { @retained.delete(record.object_id) }
      end

      def poison(record)
        @custody_lock.synchronize do
          @retained[record.object_id] = record
          @poisoned = true
        end
      end

      def reusable!
        raise Error.new("unknown") if @custody_lock.synchronize { @poisoned }
      end

      def claim_fd!(fd, lease)
        @custody_lock.synchronize do
          raise Error.new("fd") if @fd_claims.key?(fd)

          @fd_claims[fd] = lease
        end
      end

      def release_fd!(fd, lease)
        @custody_lock.synchronize do
          raise Error.new("fd") unless @fd_claims[fd].equal?(lease)

          @fd_claims.delete(fd)
        end
      end

      def valid_time!(value)
        raise Error.new("spec") unless value.instance_of?(Integer) && value.between?(1, MAX_TIME)
      end

      def role!(role)
        unless role.instance_of?(Symbol) && role.to_s.match?(/\A[a-z][a-z0-9_]{0,63}\z/)
          raise Error.new("spec")
        end
      end
    end

    class SpawnSpec
      attr_reader :executable, :argv, :env, :fd_sources

      def initialize(executable:, argv:, env:, fd_sources:)
        @executable = string(executable)
        unless @executable.start_with?(File::SEPARATOR) && !@executable.match?(/[\x00-\x1f\x7f]/)
          raise Error.new("spec")
        end
        raise Error.new("spec") unless argv.instance_of?(Array) && argv.length.between?(1, 64)

        @argv = argv.map { |value| string(value, empty: true) }.freeze
        raise Error.new("spec") unless @argv.first == @executable && @argv.sum { |value| value.bytesize + 1 } <= MAX_COLLECTION
        raise Error.new("spec") unless env.instance_of?(Hash) && env.length <= 64

        @env = env.to_h do |key, value|
          name = string(key)
          raise Error.new("spec") unless name.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)

          [name, string(value, empty: true)]
        end.freeze
        raise Error.new("spec") if @env.sum { |key, value| key.bytesize + value.bytesize + 2 } > MAX_COLLECTION
        unless fd_sources.instance_of?(Array) && [3, 8].include?(fd_sources.length) &&
               fd_sources.all? { |source| source.instance_of?(IOLease) }
          raise Error.new("spec")
        end
        expected = fd_sources.length == 8 ? %i[read write write read write read write write] : %i[read write write]
        fd_sources.zip(expected).each do |source, access|
          raise Error.new("spec") unless source.access == access
        end
        @fd_sources = fd_sources.dup.freeze # The actual leases, not FD-number copies.
        freeze
      end

      private

      def string(value, empty: false)
        unless value.instance_of?(String) && value.bytesize <= MAX_VALUE &&
               (empty || !value.empty?) && !value.include?("\0") &&
               value.dup.force_encoding(Encoding::UTF_8).valid_encoding?
          raise Error.new("spec")
        end
        value.dup.freeze
      end
    end

    # Published before acquisition. The original IO remains the sole close
    # owner; a non-owning wrapper of its number never proves the original close.
    class IOLease
      attr_reader :role, :access, :kind, :io, :close_error

      def initialize(acquisition:, role:, access:, kind:, process_lifetime: false)
        NativeProcessSpawn.__send__(:role!, role)
        raise Error.new("spec") unless ACCESS.include?(access) && KINDS.include?(kind)

        @acquisition, @role, @access, @kind = acquisition, role, access, kind
        @process_lifetime = process_lifetime
        @lock = Mutex.new
        @state = :unattempted
        @io = @fd = @close_error = nil
        @fd_claimed = false
        @borrowers = {}
      end

      def state
        @lock.synchronize { @state }
      end

      def process_lifetime?
        @process_lifetime
      end

      def close_once
        Thread.handle_interrupt(Exception => :never) do
          @lock.synchronize do
            raise Error.new("state") if @process_lifetime
            return true if %i[closed not_acquired].include?(@state)
            raise(@close_error || Error.new("unknown")) if %i[closing unknown].include?(@state)
            raise Error.new("busy") unless @borrowers.empty?
            raise Error.new("state") unless @state == :open

            @state = :closing # Numeric/IO route retires before the actual call.
          end
          begin
            raise Error.new("fd") unless @io.fileno == @fd
            raise Error.new("io") unless @io.autoclose? == true && @io.pid.nil?

            returned = @io.close
            raise Error.new("close") unless returned.nil?

            NativeProcessSpawn.__send__(:release_fd!, @fd, self)
            @lock.synchronize { @state = :closed }
            @acquisition.__send__(:maybe_forget!)
            true
          rescue Exception => error
            @acquisition.__send__(:record_error!, error, cleanup: true)
            @lock.synchronize { @close_error ||= error; @state = :unknown }
            @acquisition.mark_unknown!(error)
            raise # In particular preserve an actual injected IO close exception.
          end
        end
      end

      private

      def acquiring!
        @lock.synchronize do
          raise Error.new("state") unless @state == :unattempted

          @state = :acquiring
        end
      end

      def publish!(actual)
        raise Error.new("io") unless actual.is_a?(IO)

        @lock.synchronize do
          raise Error.new("state") unless @state == :acquiring

          @io = actual # Root the returned IO before any validation can fail.
          unless @process_lifetime || (actual.autoclose? == true && actual.pid.nil?)
            # autoclose:false IO#close only closes wrapper metadata on MRI;
            # an IO.popen owner additionally has an implicit consuming waiter.
            raise Error.new("io")
          end
          observed = actual.fileno
          raise Error.new("fd") if @fd_claimed && observed != @fd

          @fd = observed
          raise Error.new("fd") unless @fd.instance_of?(Integer) && @fd.between?(@process_lifetime ? 0 : 3, MAX_PID)

          unless @fd_claimed
            NativeProcessSpawn.__send__(:claim_fd!, @fd, self)
            @fd_claimed = true
          end
          @state = :open
        end
      end

      def claim_inherited!(fd)
        @lock.synchronize do
          raise Error.new("state") unless @state == :acquiring && !@fd_claimed

          # Check existing ownership BEFORE constructing another owning wrapper
          # of an inherited number. Never re-adopt a source in a new acquisition.
          NativeProcessSpawn.__send__(:claim_fd!, fd, self)
          @fd, @fd_claimed = fd, true
        end
      end

      def unknown!(error)
        @lock.synchronize { @state = :unknown unless @state == :closed }
        @acquisition.mark_unknown!(error)
      end

      def seal_unattempted!
        @lock.synchronize { @state = :not_acquired if @state == :unattempted }
      end

      def borrow!(acquisition)
        @lock.synchronize do
          raise Error.new("fd") unless @state == :open && @io.fileno == @fd

          @borrowers[acquisition.object_id] = acquisition
          @fd
        end
      end

      def release_borrow!(acquisition)
        @lock.synchronize { @borrowers.delete(acquisition.object_id) }
      end

      def descriptor
        @lock.synchronize do
          raise Error.new("fd") unless @state == :open && @io.fileno == @fd

          @fd
        end
      end
    end

    # Each native call/heap/FD slot exists in the acquisition before its call.
    # No native pointer or raw duplicate has an automatic cleanup ensure.
    class NativeCall
      attr_accessor :state, :result, :errno
      attr_reader :function, :arguments

      def initialize(function, arguments)
        @function, @arguments = function, arguments.freeze
        @state, @result, @errno = :unattempted, nil, nil
      end
    end
    private_constant :NativeCall

    class NativeBuffer
      attr_reader :pointer, :state

      def initialize(acquisition, size, alignment)
        @acquisition, @size, @alignment = acquisition, size, alignment
        @pointer, @state = nil, :unattempted
      end

      def allocate!
        Thread.handle_interrupt(Exception => :never) do
          @acquisition.__send__(:check_creation!)
          @state = :allocating
          @pointer = Fiddle::Pointer.malloc(@size, Fiddle::RUBY_FREE)
          raise Error.new("abi") unless @pointer.to_i.positive? && (@pointer.to_i % @alignment).zero?

          @pointer[0, @size] = "\0".b * @size
          @state = :open
        end
        self
      rescue Exception => error
        @state = :unknown unless @state == :unattempted
        @acquisition.mark_unknown!(error) if @state == :unknown
        raise
      end

      def free_once!
        return true if %i[unattempted freed].include?(@state)
        return false unless @state == :open

        Thread.handle_interrupt(Exception => :never) do
          @state = :freeing
          returned = @pointer.call_free
          raise Error.new("close") unless returned.nil? && @pointer.freed?

          @state = :freed
        end
        true
      rescue Exception => error
        @state = :unknown
        @acquisition.__send__(:record_error!, error, cleanup: true)
        @acquisition.mark_unknown!(error)
        false
      end
    end
    private_constant :NativeBuffer

    class NativeContainer
      attr_reader :buffer, :state

      def initialize(acquisition, buffer, prefix)
        @acquisition, @buffer, @prefix = acquisition, buffer, prefix
        @state = :unattempted
      end

      def initialize!
        @state = :initializing
        call = @acquisition.__send__(:native_call!, "#{@prefix}_init", @buffer.pointer)
        @state = call.result == 0 ? :initialized : :failed
        raise Error.new("native", errno: call.result) unless @state == :initialized

        self
      rescue Exception => error
        if @state == :initializing
          @state = :unknown
          @acquisition.mark_unknown!(error)
        end
        raise
      end

      def change!(suffix, *arguments)
        raise Error.new("state") unless @state == :initialized

        @state = :changing
        call = @acquisition.__send__(:native_call!, "#{@prefix}_#{suffix}", @buffer.pointer, *arguments)
        @state = :initialized
        raise Error.new("native", errno: call.result) unless call.result == 0

        call
      rescue Exception => error
        if @state == :changing
          @state = :unknown
          @acquisition.mark_unknown!(error)
        end
        raise
      end

      def destroy_once!
        return true if %i[unattempted failed destroyed].include?(@state)
        return false unless @state == :initialized

        Thread.handle_interrupt(Exception => :never) do
          @state = :destroying
          call = @acquisition.__send__(:native_call!, "#{@prefix}_destroy", @buffer.pointer, cleanup: true)
          raise Error.new("close", errno: call.result) unless call.result == 0

          @state = :destroyed
        end
        true
      rescue Exception => error
        @state = :unknown
        @acquisition.__send__(:record_error!, error, cleanup: true)
        @acquisition.mark_unknown!(error)
        false
      end
    end
    private_constant :NativeContainer

    class NativeFD
      attr_reader :fd, :state

      def initialize(acquisition, source)
        @acquisition, @source = acquisition, source
        @fd, @state = nil, :unattempted
      end

      def duplicate!
        Thread.handle_interrupt(Exception => :never) do
          @acquisition.__send__(:check_creation!)
          @state = :acquiring
          call = @acquisition.__send__(:native_call!, "fcntl", @source.__send__(:descriptor),
                                       @acquisition.__send__(:constant, "F_DUPFD_CLOEXEC"), Fiddle::TYPE_INT, 8)
          if call.result == -1
            @state = :not_acquired
            raise Error.new("fd", errno: call.errno)
          end
          unless call.result.instance_of?(Integer) && call.result.between?(8, MAX_PID)
            raise Error.new("fd") # Never close an unproved low/aliased number.
          end
          NativeProcessSpawn.__send__(:claim_fd!, call.result, self)
          @fd = call.result
          @state = :open
          @acquisition.__send__(:validate_duplicate!, self, @source)
        end
        self
      rescue Exception => error
        if @state == :acquiring
          @state = :unknown
          @acquisition.mark_unknown!(error)
        end
        raise
      end

      def close_once!
        return true if %i[unattempted not_acquired closed].include?(@state)
        return false unless @state == :open

        Thread.handle_interrupt(Exception => :never) do
          @state = :closing
          call = @acquisition.__send__(:native_call!, "close", @fd, cleanup: true)
          raise Error.new("close", errno: call.errno) unless call.result == 0

          NativeProcessSpawn.__send__(:release_fd!, @fd, self)
          @state = :closed
        end
        true
      rescue Exception => error
        @state = :unknown
        @acquisition.__send__(:record_error!, error, cleanup: true)
        @acquisition.mark_unknown!(error)
        false
      end
    end
    private_constant :NativeFD

    class Acquisition
      attr_reader :owner_slot, :run_deadline_ns, :hard_cleanup_deadline_ns, :resources

      def initialize(owner_slot:, run_deadline_ns:, hard_cleanup_deadline_ns:)
        unless defined?(NativeUploadProcess::TaskSlot) && owner_slot.instance_of?(NativeUploadProcess::TaskSlot)
          raise Error.new("spec")
        end
        NativeProcessSpawn.__send__(:valid_time!, run_deadline_ns)
        NativeProcessSpawn.__send__(:valid_time!, hard_cleanup_deadline_ns)
        unless hard_cleanup_deadline_ns.between?(run_deadline_ns, run_deadline_ns + CLEANUP_GRACE_NS) &&
               run_deadline_ns <= owner_slot.run_deadline_ns && hard_cleanup_deadline_ns <= owner_slot.hard_cleanup_deadline_ns
          raise Error.new("spec")
        end
        @owner_slot, @run_deadline_ns, @hard_cleanup_deadline_ns = owner_slot, run_deadline_ns, hard_cleanup_deadline_ns
        @lock = Mutex.new
        @resources, @buffers, @containers, @functions = {}, {}, {}, {}
        @calls, @duplicates, @borrows, @io_returns, @wrappers = [], [], [], [], []
        @abi = @handle = @creator_thread = @child = @first_error = nil
        @cleanup_errors = []
        @state, @launch = :configuring, :closed
        @child_attempted = @create_entered = @creator_joined = @creator_absent = @finished = @finishing = false
        NativeProcessSpawn.__send__(:retain, self)
      end

      def state
        @lock.synchronize { @state }
      end

      def child
        @lock.synchronize { @child }
      end

      def first_error
        @lock.synchronize { @first_error }
      end

      def cleanup_errors
        @lock.synchronize { @cleanup_errors.dup.freeze }
      end

      def child_attempted?
        @lock.synchronize { @child_attempted }
      end

      def launch_closed?
        @lock.synchronize { @launch != :open }
      end

      def launch_retired?
        @lock.synchronize { @launch == :retired }
      end

      def not_attempted?
        @lock.synchronize do
          (@creator_joined || @creator_absent) && @finished && @launch == :retired && !@child_attempted && @state != :unknown
        end
      end

      def close_launch!
        @lock.synchronize { @launch = :retired }
        true
      end

      def mark_unknown!(error = nil)
        record_error!(error) if error
        nil
      ensure
        # Even a failure of the common recorder cannot discard native custody.
        @lock.synchronize { @state, @launch = :unknown, :retired }
        NativeProcessSpawn.__send__(:poison, self)
      end

      # Native-return settlement is NOT a task join. Only the original slot's
      # genuine joined thread authorizes destruction/free/duplicate close and
      # release of borrowed sources. Original endpoint IOs are NEVER closed here.
      def finish_creation!(creator_slot:)
        close_launch!
        unless creator_slot.equal?(@owner_slot)
          error = Error.new("join")
          mark_unknown!(error)
          raise error
        end
        creator_slot.close_launch!
        # This is a DISTINCT positive no-start proof, never a manufactured join.
        # close_launch! and start_attempted? use the same TaskSlot lifecycle lock:
        # after retirement no racing start can cross the Thread.new attempt gate.
        if !creator_slot.start_attempted? && creator_slot.thread.nil? &&
           @creator_thread.nil? && !@create_entered && !@child_attempted && @child.nil? &&
           @resources.empty? && @buffers.empty? && @containers.empty? && @functions.empty? &&
           @calls.empty? && @duplicates.empty? && @borrows.empty? && @io_returns.empty? && @wrappers.empty? && @abi.nil?
          @resources.freeze
          @lock.synchronize do
            @creator_absent = @finished = true
            @state = :settled unless %i[failed unknown].include?(@state)
          end
          maybe_forget!
          return state != :unknown
        end
        unless creator_slot.joined? &&
               creator_slot.thread.instance_of?(Thread) &&
               (@creator_thread.nil? || @creator_thread.equal?(creator_slot.thread))
          error = Error.new("join")
          mark_unknown!(error)
          raise error
        end
        @lock.synchronize { @creator_joined = true }
        return state != :unknown if @finished

        @lock.synchronize do
          raise Error.new("join") if @finishing

          @finishing = true
        end
        Thread.handle_interrupt(Exception => :never) do
          @resources.freeze # Same published object, now irreversibly complete.
          @resources.each_value do |lease|
            lease.__send__(:seal_unattempted!)
            lease.__send__(:unknown!, Error.new("io")) if lease.state == :acquiring
          end
          unsafe_buffers = []
          @containers.each_value do |container|
            unless container.destroy_once!
              unsafe_buffers << container.buffer
              mark_unknown!(Error.new("native"))
            end
          end
          @duplicates.reverse_each { |duplicate| mark_unknown!(Error.new("fd")) unless duplicate.close_once! }
          @buffers.each_value do |buffer|
            mark_unknown!(Error.new("native")) unless unsafe_buffers.include?(buffer) || buffer.free_once!
          end
          mark_unknown!(Error.new("native")) if @calls.any? { |call| %i[in_flight unknown].include?(call.state) }
          mark_unknown!(Error.new("io")) if @wrappers.any? { |wrapper| wrapper.fetch(:state) != :closed }
          # Once the ACTUAL creator has joined, no function can use a source,
          # even if an uncertain return remains retained/UNKNOWN forever.
          @borrows.each { |source| source.__send__(:release_borrow!, self) }
          @borrows.clear
          @lock.synchronize do
            @finished = true
            @state = :settled unless %i[failed unknown].include?(@state)
          end
        end
        maybe_forget!
        state != :unknown
      rescue Exception => error
        record_error!(error, cleanup: true)
        mark_unknown!(error)
        raise
      end

      private

      def check_creation!
        NativeProcessSpawn.__send__(:reusable!)
        @owner_slot.check_creation!
        unless @owner_slot.thread.equal?(Thread.current) && NativeProcessSpawn.monotonic_ns < @run_deadline_ns
          raise Error.new("deadline")
        end
        @lock.synchronize do
          raise Error.new("launch") if @launch == :retired || @state == :unknown || @finished
          raise Error.new("state") if @creator_thread && !@creator_thread.equal?(Thread.current)

          @creator_thread ||= Thread.current
          @launch = :open
        end
        true
      rescue Exception => error
        record_error!(error)
        close_launch!
        raise
      end

      def record_error!(error, cleanup: false)
        error = error.__send__(:original_error) || error if error.is_a?(Error)
        reason = case error
                 when Interrupt, SystemExit then "cancelled"
                 when IOError, SystemCallError then "io"
                 when Error then error.code == "deadline" ? "deadline" : "creation"
                 else "lifecycle"
                 end
        Thread.handle_interrupt(Exception => :never) do
          begin
            # The original TaskSlot shares the capture's actual FailureRecord,
            # even AFTER this creator joined. Record there FIRST, not in a
            # private error latch that a later caller Interrupt could overtake.
            # Never hold an acquisition/lease lock across this callback.
            @owner_slot.cancel!(error: error, reason_code: reason)
          rescue Exception => recording_error
            @lock.synchronize do
              @state, @launch = :unknown, :retired
              @cleanup_errors << recording_error unless @cleanup_errors.any? { |item| item.equal?(recording_error) }
            end
            NativeProcessSpawn.__send__(:poison, self)
          ensure
            @lock.synchronize do
              @first_error ||= error
              @cleanup_errors << error if cleanup && !@cleanup_errors.any? { |item| item.equal?(error) }
            end
          end
        end
        error
      end

      def fail_creation!(error)
        record_error!(error)
        @lock.synchronize do
          @launch = :retired
          @state = :failed unless @state == :unknown
        end
      end

      def runtime!
        return if @abi

        check_creation!
        NativeProcessSpawn.admit_runtime!
        @abi = NativeProcessSpawn.declared_abi
        @handle = Fiddle::Handle::DEFAULT
        @abi.fetch("functions").each do |name, declaration|
          next unless declaration

          check_creation!
          # The variadic fcntl Function is PRIVATE to this creator record. Fiddle
          # mutates its CIF for every call; never share it across concurrent tasks.
          @functions[name] = NativeProcessSpawn.__send__(:build_function, name, declaration)
        end
      rescue Error => error
        # Public standalone admission diagnostics stay fixed-code. The owned
        # creator's first-error channel still receives the actual caught object.
        original = error.__send__(:original_error)
        raise original if original

        raise
      end

      def constant(name)
        @abi.fetch("constants").fetch(name)
      end

      def native_call!(name, *arguments, cleanup: false)
        function = @functions.fetch(name)
        call = NativeCall.new(function, arguments)
        @calls << call
        Thread.handle_interrupt(Exception => :never) do
          check_creation! unless cleanup
          raise Error.new("join") if cleanup && !@creator_joined
          if cleanup && NativeProcessSpawn.monotonic_ns >= [@hard_cleanup_deadline_ns, @owner_slot.cleanup_deadline_ns].min
            raise Error.new("deadline")
          end

          call.state = :in_flight
          call.result = function.call(*arguments)
          call.errno = Fiddle.last_error # Immediate thread-local errno, not message.
          call.state = :returned
        end
        call
      rescue Exception => error
        if call && call.state == :in_flight
          call.state = :unknown
          mark_unknown!(error)
        end
        record_error!(error, cleanup: cleanup)
        raise
      end

      def reserve_io!(role:, access:, kind:, process_lifetime: false)
        check_creation!
        raise Error.new("state") if @create_entered || @resources.key?(role)

        lease = IOLease.new(acquisition: self, role: role, access: access, kind: kind, process_lifetime: process_lifetime)
        @resources[role] = lease
        lease
      end

      def buffer!(name, size, alignment = 8)
        check_creation!
        raise Error.new("state") if @buffers.key?(name)

        buffer = NativeBuffer.new(self, size, alignment)
        @buffers[name] = buffer
        buffer.allocate!
      end

      def container!(name, prefix)
        layout = @abi.fetch(name)
        storage = buffer!(name, layout.fetch("size"), layout.fetch("align"))
        container = NativeContainer.new(self, storage, prefix)
        @containers[name] = container
        container.initialize!
      end

      def fd_facts!(fd, io, access, kind, cloexec: true)
        flags = native_call!("fcntl", fd, constant("F_GETFD"))
        mode = native_call!("fcntl", fd, constant("F_GETFL"))
        raise Error.new("fd", errno: flags.errno) if flags.result == -1
        raise Error.new("fd", errno: mode.errno) if mode.result == -1

        expected = constant({ read: "O_RDONLY", write: "O_WRONLY", readwrite: "O_RDWR" }.fetch(access))
        unless flags.result.instance_of?(Integer) && mode.result.instance_of?(Integer) &&
               (mode.result & constant("O_ACCMODE")) == expected &&
               (!cloexec || (flags.result & constant("FD_CLOEXEC")) == constant("FD_CLOEXEC"))
          raise Error.new("fd")
        end
        facts = io.stat
        case kind
        when :pipe then raise Error.new("fd") unless facts.pipe?
        when :null
          null = File.stat(File::NULL)
          unless facts.chardev? && [facts.dev, facts.ino, facts.rdev] == [null.dev, null.ino, null.rdev]
            raise Error.new("fd")
          end
        when :file then raise Error.new("fd") unless facts.file?
        else raise Error.new("fd")
        end
        [facts.dev, facts.ino, facts.rdev, facts.ftype].freeze
      end

      def validate_io!(lease)
        fd_facts!(lease.__send__(:descriptor), lease.io, lease.access, lease.kind)
      end

      def validate_duplicate!(duplicate, source)
        # This wrapper is explicitly NON-owning. On admitted MRI its close only
        # retires wrapper metadata; the NativeFD performs the real public close.
        slot = { io: nil, state: :unattempted }
        @wrappers << slot
        slot[:state] = :acquiring
        slot[:io] = IO.for_fd(duplicate.fd, { read: "r", write: "w", readwrite: "r+" }.fetch(source.access), autoclose: false)
        slot[:state] = :open
        expected = validate_io!(source)
        actual = fd_facts!(duplicate.fd, slot.fetch(:io), source.access, source.kind)
        raise Error.new("fd") unless actual == expected

        slot[:state] = :closing
        returned = slot.fetch(:io).close
        raise Error.new("close") unless returned.nil?

        slot[:state] = :closed
      rescue Exception => error
        slot[:state] = :unknown if slot
        mark_unknown!(error)
        raise
      end

      def prepare_sources!(spec)
        runtime!
        spec.fd_sources.each do |source|
          check_creation!
          unless @borrows.any? { |item| item.equal?(source) }
            @borrows << source # Publish custody BEFORE borrowing can enter.
            source.__send__(:borrow!, self)
          end
          validate_io!(source)
          duplicate = NativeFD.new(self, source)
          @duplicates << duplicate
          duplicate.duplicate!
        end
      end

      def prepare_spawn!(spec)
        prepare_sources!(spec)
        actions = container!("file_actions", "posix_spawn_file_actions")
        @duplicates.each_with_index { |duplicate, destination| actions.change!("adddup2", duplicate.fd, destination) }
        if @abi.fetch("family") == "linux-glibc"
          actions.change!("addclosefrom_np", spec.fd_sources.length) # LAST action.
        else
          attributes = container!("spawn_attributes", "posix_spawnattr")
          flags = constant("POSIX_SPAWN_CLOEXEC_DEFAULT")
          attributes.change!("setflags", flags)
          flag_storage = buffer!("attribute_flags", @abi.fetch("scalars").fetch("short").fetch("size"), 2)
          attributes.change!("getflags", flag_storage.pointer)
          raise Error.new("abi") unless flag_storage.pointer[0, 2].unpack1("s<") == flags
        end
        strings = [["executable", spec.executable]] + spec.argv.each_with_index.map { |value, index| ["argv_#{index}", value] } +
                  spec.env.map.with_index { |(key, value), index| ["env_#{index}", "#{key}=#{value}"] }
        strings.each do |name, value|
          storage = buffer!(name, value.bytesize + 1)
          storage.pointer[0, value.bytesize + 1] = value.b + "\0".b
        end
        { "argv" => spec.argv.length, "env" => spec.env.length }.each do |name, count|
          vector = buffer!(name, (count + 1) * @abi.fetch("scalars").fetch("pointer").fetch("size"))
          addresses = Array.new(count) { |index| @buffers.fetch("#{name}_#{index}").pointer.to_i } << 0
          vector.pointer[0, (count + 1) * 8] = addresses.pack("Q<*")
        end
        buffer!("pid", @abi.fetch("scalars").fetch("pid_t").fetch("size"), 4)
        @lock.synchronize { @state = :initialized unless @state == :unknown }
      end

      def waitability!
        runtime!
        layout = @abi.fetch("sigaction")
        name = "sigaction_#{@buffers.length}"
        storage = buffer!(name, layout.fetch("size"), layout.fetch("align"))
        call = native_call!("sigaction", constant("SIGCHLD"), 0, storage.pointer)
        raise Error.new("waitability", errno: call.errno) unless call.result == 0

        handler = layout.fetch("fields").fetch("handler")
        flags = layout.fetch("fields").fetch("flags")
        observed_handler = storage.pointer[handler.fetch("offset"), handler.fetch("size")].unpack1("Q<")
        observed_flags = storage.pointer[flags.fetch("offset"), flags.fetch("size")].unpack1("L<")
        if observed_handler == constant("SIG_IGN") || (observed_flags & constant("SA_NOCLDWAIT")) != 0
          raise Error.new("waitability")
        end
        true
      end

      def spawn!(spec)
        raise Error.new("spec") unless spec.instance_of?(SpawnSpec)

        check_creation!
        raise Error.new("state") if @create_entered

        @create_entered = true
        prepare_spawn!(spec)
        waitability! # Read-only admission immediately before EVERY native spawn.
        Thread.handle_interrupt(Exception => :never) do
          check_creation!
          @lock.synchronize { @child_attempted = true; @state = :attempting }
          call = native_call!("posix_spawn", @buffers.fetch("pid").pointer, @buffers.fetch("executable").pointer,
                              @containers.fetch("file_actions").buffer.pointer,
                              @containers["spawn_attributes"]&.buffer&.pointer || 0,
                              @buffers.fetch("argv").pointer, @buffers.fetch("env").pointer)
          if call.result != 0
            error = Error.new("spawn", errno: call.result)
            mark_unknown!(error) # Native startup may itself have created/reaped.
            raise error
          end
          pid = @buffers.fetch("pid").pointer[0, 4].unpack1("l<")
          raise Error.new("spawn") unless pid.instance_of?(Integer) && pid.between?(1, MAX_PID)

          actual = Child.__send__(:new, self, pid)
          @lock.synchronize do
            @child = actual # Owner can recover it if the Ruby return is lost.
            @state = :pid_published unless @state == :unknown
          end
        end
        child
      rescue Exception => error
        mark_unknown!(error) if child_attempted? && child.nil?
        fail_creation!(error)
        raise
      ensure
        close_launch! if @create_entered
      end

      def maybe_forget!
        finished, current_state, attempted, actual = @lock.synchronize { [@finished, @state, @child_attempted, @child] }
        complete = finished && current_state != :unknown && (!attempted || actual&.state == :reaped)
        return unless complete && @resources.values.all? { |lease| %i[closed not_acquired].include?(lease.state) }

        NativeProcessSpawn.__send__(:forget, self)
      end
    end

    class WaitReceipt
      attr_reader :pid, :status_kind, :status_code, :raw_status

      def initialize(pid, status, nsig)
        unless status.instance_of?(Process::Status) && status.pid == pid && pid.instance_of?(Integer) && pid.between?(1, MAX_PID)
          raise Error.new("wait")
        end
        @pid, @raw_status = pid, status
        if status.exited? && status.exitstatus.instance_of?(Integer) && status.exitstatus.between?(0, 255)
          @status_kind, @status_code = "exit", status.exitstatus
        elsif status.signaled? && status.termsig.instance_of?(Integer) && status.termsig.between?(1, nsig - 1)
          @status_kind, @status_code = "signal", status.termsig
        else
          raise Error.new("wait")
        end
        freeze
      end
      private_class_method :new
    end

    class Child
      attr_reader :pid

      def initialize(acquisition, pid)
        @acquisition, @pid = acquisition, pid
        @lock = Mutex.new
        @state, @receipt = :running, nil
        @numeric_retired = false
        @wait_owner = nil
      end
      private_class_method :new

      def state
        @lock.synchronize { @state }
      end

      def receipt
        @lock.synchronize { @receipt }
      end

      def retire_numeric!
        @lock.synchronize { @numeric_retired = true }
        true
      end

      def numeric_retired?
        @lock.synchronize { @numeric_retired }
      end

      # There is deliberately NO signal/probe API and no background waiter.
      # Helper G routing has its separate permanent retirement before a K poll.
      def poll_wait
        Thread.handle_interrupt(Exception => :never) do
          @lock.synchronize do
            return @receipt if @state == :reaped
            raise Error.new("unknown") if %i[wait_in_flight unknown].include?(@state)
            unless @acquisition.instance_variable_get(:@creator_joined) && @acquisition.launch_retired? &&
                   (@wait_owner.nil? || @wait_owner.equal?(Thread.current))
              raise Error.new("wait")
            end
            @wait_owner ||= Thread.current
            @numeric_retired = true
            @state = :wait_in_flight # BEFORE the first potentially consuming call.
          end
          begin
            returned = Process.waitpid2(@pid, Process::WNOHANG)
            if returned.nil?
              @lock.synchronize { @state = :pollable }
              return nil # ONLY a genuine return of nil permits another poll.
            end
            unless returned.instance_of?(Array) && returned.length == 2 &&
                   returned.first.instance_of?(Integer) && returned.first == @pid
              raise Error.new("wait")
            end
            genuine = WaitReceipt.__send__(:new, @pid, returned.last, NativeProcessSpawn.nsig)
            @lock.synchronize { @receipt = genuine; @state = :reaped }
            @acquisition.__send__(:maybe_forget!)
            genuine
          rescue Exception => error
            @lock.synchronize { @state = :unknown; @numeric_retired = true }
            @acquisition.mark_unknown!(error)
            raise
          end
        end
      end
    end

    class << self
      def create(acquisition, spec)
        raise Error.new("spec") unless acquisition.instance_of?(Acquisition)

        acquisition.__send__(:spawn!, spec)
      end

      def admit_waitability!(acquisition)
        raise Error.new("spec") unless acquisition.instance_of?(Acquisition)

        acquisition.__send__(:waitability!)
      rescue Exception => error
        acquisition.__send__(:fail_creation!, error) if acquisition.instance_of?(Acquisition)
        raise
      end

      def pipe(acquisition, read_role:, write_role:)
        raise Error.new("spec") unless acquisition.instance_of?(Acquisition) && read_role != write_role

        acquisition.__send__(:runtime!)
        reader = acquisition.__send__(:reserve_io!, role: read_role, access: :read, kind: :pipe)
        writer = acquisition.__send__(:reserve_io!, role: write_role, access: :write, kind: :pipe)
        Thread.handle_interrupt(Exception => :never) do
          acquisition.__send__(:check_creation!)
          reader.__send__(:acquiring!)
          writer.__send__(:acquiring!)
          # Both slots are in resources before this call. Root the WHOLE returned
          # pair before validating either member, even if our Array return is lost.
          pair = IO.pipe
          acquisition.instance_variable_get(:@io_returns) << pair
          unless pair.instance_of?(Array) && pair.length == 2
            raise Error.new("io")
          end
          reader.__send__(:publish!, pair.first)
          writer.__send__(:publish!, pair.last)
          [reader, writer].each do |lease|
            lease.io.binmode
            acquisition.__send__(:validate_io!, lease)
          end
        end
        [reader, writer].freeze
      rescue Exception => error
        [reader, writer].compact.each { |lease| lease.__send__(:unknown!, error) if lease.state == :acquiring }
        acquisition.__send__(:fail_creation!, error) if acquisition.instance_of?(Acquisition)
        raise
      end

      def null(acquisition, access:, role:)
        raise Error.new("spec") unless acquisition.instance_of?(Acquisition) && %i[read write].include?(access)

        acquisition.__send__(:runtime!)
        lease = acquisition.__send__(:reserve_io!, role: role, access: access, kind: :null)
        Thread.handle_interrupt(Exception => :never) do
          acquisition.__send__(:check_creation!)
          lease.__send__(:acquiring!)
          actual = File.open(File::NULL, access == :read ? "rb" : "wb")
          acquisition.instance_variable_get(:@io_returns) << actual
          lease.__send__(:publish!, actual)
          acquisition.__send__(:validate_io!, lease)
        end
        lease
      rescue Exception => error
        lease.__send__(:unknown!, error) if lease && lease.state == :acquiring
        acquisition.__send__(:fail_creation!, error) if acquisition.instance_of?(Acquisition)
        raise
      end

      # Only a trusted helper's fixed inherited map, not foreign-FD adoption.
      # 0..2 retain their actual interpreter objects for process lifetime. Never
      # explicitly close those numbers and let MRI hit a later reused descriptor.
      def adopt_fd(acquisition, fd:, role:, access:, kind:)
        unless acquisition.instance_of?(Acquisition) && fd.instance_of?(Integer) && fd.between?(0, 7)
          raise Error.new("spec")
        end
        expected = %i[read write write read write read write write].fetch(fd)
        raise Error.new("spec") unless access == expected && (fd < 3 ? kind == :null : %i[pipe null].include?(kind))

        acquisition.__send__(:runtime!)
        lease = acquisition.__send__(:reserve_io!, role: role, access: access, kind: kind, process_lifetime: fd < 3)
        Thread.handle_interrupt(Exception => :never) do
          acquisition.__send__(:check_creation!)
          lease.__send__(:acquiring!)
          lease.__send__(:claim_inherited!, fd)
          actual = if fd < 3
                     [STDIN, STDOUT, STDERR].fetch(fd)
                   else
                     IO.for_fd(fd, access == :read ? "rb" : "wb", autoclose: true)
                   end
          acquisition.instance_variable_get(:@io_returns) << actual
          raise Error.new("fd") unless actual.fileno == fd

          lease.__send__(:publish!, actual)
          # These are THIS helper's owned role FDs, never caller/foreign flags.
          actual.close_on_exec = true
          actual.binmode
          acquisition.__send__(:validate_io!, lease)
        end
        lease
      rescue Exception => error
        lease.__send__(:unknown!, error) if lease && lease.state == :acquiring
        acquisition.__send__(:fail_creation!, error) if acquisition.instance_of?(Acquisition)
        raise
      end

      # The caller has ALREADY positively acquired this actual IO/File and hands
      # its sole explicit close ownership to this lease. This does not claim to
      # prove the caller's earlier acquisition from a guessed FD or nil slot.
      def lease_io(acquisition, io:, role:, access:, kind:)
        raise Error.new("spec") unless acquisition.instance_of?(Acquisition) && io.is_a?(IO)

        acquisition.__send__(:runtime!)
        lease = acquisition.__send__(:reserve_io!, role: role, access: access, kind: kind)
        Thread.handle_interrupt(Exception => :never) do
          acquisition.__send__(:check_creation!)
          lease.__send__(:acquiring!)
          lease.__send__(:publish!, io)
          acquisition.__send__(:validate_io!, lease)
        end
        lease
      rescue Exception => error
        lease.__send__(:unknown!, error) if lease && lease.state == :acquiring
        acquisition.__send__(:fail_creation!, error) if acquisition.instance_of?(Acquisition)
        raise
      end
    end
  end
end
