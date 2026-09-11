# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "rbconfig"
require "tmpdir"

# One fixed optional installation-prefix switch, not a runtime command runner.
# Installed controls load BOTH actual installed files; an absent member fails.
flag = ARGV.index("--installed-tooling-root")
if flag
  raise "duplicate installed tooling switch" unless ARGV.count("--installed-tooling-root") == 1
  prefix = ARGV.fetch(flag + 1)
  raise "absolute installed prefix required" unless prefix.start_with?(File::SEPARATOR)
  prefix = File.realpath(prefix)
  raise "canonical installed prefix required" unless ARGV.fetch(flag + 1) == prefix
  ARGV.slice!(flag, 2)
  tooling = File.join(prefix, "share", "mobile-release-kit", "fastlane")
else
  tooling = File.realpath(File.expand_path("../../fastlane", __dir__))
end
%w[native_process_spawn.rb native_upload_process.rb].each do |name|
  path = File.join(tooling, name)
  raise "missing exact native tooling member" unless File.file?(path) && File.realpath(path) == path
  require path
end

class NativeProcessSpawnTests < Minitest::Test
  Native = MobileReleaseKit::NativeProcessSpawn
  Helper = MobileReleaseKit::NativeUploadProcess
  RETAINED = {}
  FALL_THROUGH = Object.new.freeze
  FAKE_PID = 12_345

  class UnexpectedNativeCall < StandardError; end
  class InjectedFailure < StandardError; end

  def setup
    flunk "earlier native fixture retained UNKNOWN custody; new fixture work forbidden" unless RETAINED.empty?
  end

  # Every fake-only selector replaces ALL process/FD/FFI acquisition boundaries.
  # These objects model return/publication seams; they are never native evidence.
  FakeStat = Struct.new(:dev, :ino, :rdev, :ftype) do
    def pipe? = ftype == "fifo"
    def chardev? = ftype == "characterSpecial"
    def file? = ftype == "file"
  end

  class FakeIO < IO
    attr_reader :close_calls
    attr_accessor :close_hook, :attached_pid, :owning

    def initialize(backend, fd, owning: true)
      @backend, @descriptor, @owning = backend, fd, owning
      @closed, @close_calls, @attached_pid = false, 0, nil
    end

    def fileno
      raise IOError, "fake closed IO" if @closed
      @descriptor
    end

    def stat = @backend.fds.fetch(fileno).fetch(:stat)
    def binmode = self
    def autoclose? = @owning
    def pid = @attached_pid
    def closed? = @closed
    def close_on_exec? = (@backend.fds.fetch(fileno).fetch(:flags) & 1) == 1
    def close_on_exec=(value)
      @backend.fds.fetch(fileno)[:flags] = value ? 1 : 0
    end

    def close
      @close_calls += 1
      @close_hook.call(self) if @close_hook
      @backend.fds.delete(@descriptor) if @owning
      @closed = true
      nil
    end
  end

  module FakeFiddle
    VERSION = "1.1.2"
    TYPE_VOIDP, TYPE_INT, TYPE_SHORT, TYPE_VARIADIC = 1, 4, 3, 9
    TYPE_UINT, TYPE_USHORT = -TYPE_INT, -TYPE_SHORT
    RUBY_FREE = 99
    SIZEOF_VOIDP = ALIGN_VOIDP = SIZEOF_LONG = ALIGN_LONG = 8
    SIZEOF_INT = ALIGN_INT = 4
    SIZEOF_SHORT = ALIGN_SHORT = 2
    class << self
      attr_accessor :backend, :last_error
    end

    class Handle
      DEFAULT = new
      def [](name)
        FakeFiddle.backend.symbols << name
        name
      end
    end

    class Function
      DEFAULT = 2
      attr_reader :arguments, :return_type, :abi, :name

      def initialize(pointer, arguments, return_type, abi = DEFAULT, name:, need_gvl:)
        @pointer, @arguments, @return_type, @abi, @name = pointer, arguments, return_type, abi, name
        @need_gvl = need_gvl
        FakeFiddle.backend.functions << self
      end

      def need_gvl? = @need_gvl
      def call(*args) = FakeFiddle.backend.call(self, args)
      def to_proc = method(:call).to_proc
    end

    class Pointer
      attr_reader :free_calls

      def self.malloc(size, free)
        raise UnexpectedNativeCall unless free == RUBY_FREE
        value = new(size)
        FakeFiddle.backend.pointers << value
        FakeFiddle.backend.malloc_hook&.call(value)
        value
      end

      def initialize(size)
        @bytes = "\0".b * size
        @address = (object_id + 1) * 16
        @freed, @free_calls = false, 0
      end

      def to_i = @address
      def [](offset, length) = @bytes.byteslice(offset, length)
      def []=(offset, length, value)
        raise UnexpectedNativeCall if @freed || value.bytesize != length
        @bytes[offset, length] = value
      end
      def freed? = @freed
      def call_free
        @free_calls += 1
        raise InjectedFailure, "fake double free" if @freed
        @freed = true
        nil
      end
    end
  end

  class FakeBackend
    attr_reader :abi, :fds, :calls, :symbols, :functions, :pointers
    attr_accessor :pipe_hook, :open_hook, :malloc_hook, :handler, :signal_handler, :signal_flags

    def initialize(abi)
      @abi = abi
      @fds, @calls, @symbols, @functions, @pointers = {}, [], [], [], []
      @next_fd, @next_ino = 20, 100
      @signal_handler, @signal_flags = 0, 0
    end

    def null_stat = FakeStat.new(1, 2, 3, "characterSpecial")

    def make_io(access:, kind:, flags: 1, stat: nil, fd: nil)
      fd ||= (@next_fd += 1)
      stat ||= kind == :null ? null_stat : FakeStat.new(1, @next_ino += 1, 0, kind == :pipe ? "fifo" : "file")
      raise UnexpectedNativeCall, "fake FD collision" if @fds.key?(fd)
      @fds[fd] = { access: access, kind: kind, flags: flags, stat: stat }
      FakeIO.new(self, fd)
    end

    def pipe
      return @pipe_hook.call if @pipe_hook
      stat = FakeStat.new(1, @next_ino += 1, 0, "fifo")
      [make_io(access: :read, kind: :pipe, stat: stat), make_io(access: :write, kind: :pipe, stat: stat)]
    end

    def open(path, mode)
      return @open_hook.call(path, mode) if @open_hook
      raise UnexpectedNativeCall, "fake non-null open" unless path == File::NULL
      make_io(access: mode.start_with?("r") ? :read : :write, kind: :null)
    end

    def wrapper(fd, _mode, autoclose:)
      @fds.fetch(fd)
      FakeIO.new(self, fd, owning: autoclose)
    end

    def call(function, args)
      @calls << [function.name, args.dup, function]
      FakeFiddle.last_error = 0
      if @handler
        result = @handler.call(function.name, args, function)
        return result unless result.equal?(FALL_THROUGH)
      end
      constants = @abi.fetch("constants")
      case function.name
      when "fcntl"
        fd, command, *variable = args
        facts = @fds.fetch(fd)
        case command
        when constants.fetch("F_GETFD") then facts.fetch(:flags)
        when constants.fetch("F_GETFL")
          { read: 0, write: 1, readwrite: 2 }.fetch(facts.fetch(:access))
        when constants.fetch("F_DUPFD_CLOEXEC")
          raise UnexpectedNativeCall, "wrong variadic duplication ABI" unless variable == [FakeFiddle::TYPE_INT, 8]
          duplicate = (@next_fd += 1)
          @fds[duplicate] = facts.merge(flags: 1)
          duplicate
        else raise UnexpectedNativeCall, "forbidden fcntl fallback"
        end
      when "close"
        raise UnexpectedNativeCall, "unowned fake close" unless @fds.delete(args.fetch(0))
        0
      when "sigaction"
        signal, action, output = args
        raise UnexpectedNativeCall, "signal mutation in fake production call" unless signal == constants.fetch("SIGCHLD") && action == 0
        layout = @abi.fetch("sigaction").fetch("fields")
        output[layout.fetch("handler").fetch("offset"), 8] = [@signal_handler].pack("Q<")
        output[layout.fetch("flags").fetch("offset"), 4] = [@signal_flags].pack("L<")
        0
      when "posix_spawn"
        args.fetch(0)[0, 4] = [FAKE_PID].pack("l<")
        0
      when "posix_spawnattr_getflags"
        args.fetch(1)[0, 2] = [constants.fetch("POSIX_SPAWN_CLOEXEC_DEFAULT")].pack("s<")
        0
      else
        raise UnexpectedNativeCall, "unknown fake native function" unless @abi.fetch("functions")[function.name]
        0
      end
    end
  end

  def test_spawn_spec_copies_bounded_strings_and_actual_lease_references
    with_fake_native do |acq, _slot, _backend|
      leases = fake_stdio(acq)
      executable = +"/fixture/ruby"
      argv = [executable.dup, +"argument"]
      environment = { +"LANG" => +"C" }
      spec = Native::SpawnSpec.new(executable: executable, argv: argv, env: environment, fd_sources: leases)
      executable.replace("/other")
      argv.last.replace("changed")
      environment.fetch("LANG").replace("changed")
      assert_equal "/fixture/ruby", spec.executable
      assert_equal ["/fixture/ruby", "argument"], spec.argv
      assert_equal({ "LANG" => "C" }, spec.env)
      assert spec.frozen?
      assert spec.argv.all?(&:frozen?)
      assert spec.env.keys.all?(&:frozen?)
      assert spec.env.values.all?(&:frozen?)
      assert spec.fd_sources.frozen?
      leases.each_with_index { |lease, index| assert_same lease, spec.fd_sources.fetch(index) }
      assert_raises(FrozenError) { spec.argv << "late" }
      assert_raises(FrozenError) { spec.env["NEW"] = "late" }
    end
  end

  def test_spawn_spec_rejects_unbounded_untyped_and_nonabsolute_values
    with_fake_native do |acq, _slot, _backend|
      leases = fake_stdio(acq)
      base = { executable: "/fixture/ruby", argv: ["/fixture/ruby"], env: {}, fd_sources: leases }
      mutations = [
        { executable: "ruby" }, { executable: "/bad\npath" }, { executable: "/bad\0path" },
        { argv: [] }, { argv: ["/different"] }, { argv: ["/fixture/ruby"] * 65 },
        { argv: ["/fixture/ruby", "x" * 8_193] }, { argv: ["/fixture/ruby", "\xff".b] },
        { env: { "A=B" => "value" } }, { env: { "KEY" => nil } },
        { env: (1..65).to_h { |index| ["V#{index}", "x"] } },
        { fd_sources: leases.map { |lease| lease.io.fileno } }, { fd_sources: leases.first(2) },
      ]
      mutations.each { |delta| assert_raises(Native::Error) { Native::SpawnSpec.new(**base.merge(delta)) } }
      assert_raises(Native::Error) { Native::SpawnSpec.new(**base.merge(argv: ["/fixture/ruby", *("x" * 8_192).then { |value| [value] * 8 }])) }
      assert_raises(ArgumentError) { Native::SpawnSpec.new(**base, cwd: "/tmp") }
      assert_raises(ArgumentError) { Native::SpawnSpec.new(**base, pgroup: true) }
    end
  end

  def test_spawn_spec_rejects_wrong_destination_access_modes
    with_fake_native do |acq, _slot, _backend|
      sources = fake_stdio(acq)
      assert_raises(Native::Error) { fake_spec(sources.rotate) }
      helper_sources = sources + [sources.first, sources.last, sources.first, sources.last, sources.last]
      assert_equal 8, fake_spec(helper_sources).fd_sources.length
      helper_sources[3] = sources.last
      assert_raises(Native::Error) { fake_spec(helper_sources) }
    end
  end

  def test_declared_abi_is_closed_data_and_nsig_is_platform_bound
    linux, darwin = abi_for("linux-glibc"), abi_for("darwin")
    assert_equal %w[architecture byteorder constants family file_actions functions scalars schema sigaction spawn_attributes], linux.keys.sort
    assert_equal 65, linux.fetch("constants").fetch("NSIG")
    assert_equal 32, darwin.fetch("constants").fetch("NSIG")
    assert_equal 80, linux.fetch("file_actions").fetch("size")
    assert_equal 152, linux.fetch("sigaction").fetch("size")
    assert_nil linux.fetch("spawn_attributes")
    assert_equal "pointer_slot", darwin.fetch("file_actions").fetch("kind")
    assert_equal 8, darwin.fetch("spawn_attributes").fetch("size")
    assert_equal 16, darwin.fetch("sigaction").fetch("size")
    assert linux.frozen?
    assert linux.fetch("functions").values.compact.all?(&:frozen?)
    assert_raises(FrozenError) { linux.fetch("constants")["NSIG"] = 999 }
    Signal.stub(:list, -> { raise UnexpectedNativeCall }) do
      Native.stub(:declared_abi, darwin) { assert_equal 32, Native.nsig }
    end
  end

  def test_fiddle_declarations_use_true_variadic_private_functions_without_gvl
    with_fake_native do |acq, _slot, backend|
      acq.__send__(:runtime!)
      fcntl = acq.instance_variable_get(:@functions).fetch("fcntl")
      assert_equal [FakeFiddle::TYPE_INT, FakeFiddle::TYPE_INT, FakeFiddle::TYPE_VARIADIC], fcntl.arguments
      assert_equal [FakeFiddle::TYPE_VOIDP] * 6, acq.instance_variable_get(:@functions).fetch("posix_spawn").arguments
      assert backend.functions.none?(&:need_gvl?)
      second, = fake_acquisition
      second.__send__(:runtime!)
      refute_same fcntl, second.instance_variable_get(:@functions).fetch("fcntl")
      assert_equal fcntl.arguments, second.instance_variable_get(:@functions).fetch("fcntl").arguments
      assert_empty backend.calls
    end
  end

  def test_runtime_info_is_metadata_only_before_explicit_capability_admission
    with_fake_native do |_acq, _slot, backend|
      origin = { kind: "default", library: "/trusted/lib", extensions: ["/trusted/arch"], gemfile: nil,
                 features: %w[fiddle version function closure extension].to_h { |name| [name, "/trusted/#{name}"] } }
      observed = []
      patch(Native, :fiddle_origin!) { origin }
      patch(Native, :require) { |path| observed << [:require, path]; true }
      patch(Native, :check_loaded_fiddle!) { |value| observed << [:check, value]; true }
      patch(File, :realpath) { |path| path }
      replace_constant(Object, :RUBY_VERSION, "3.3.12")
      replace_constant(Object, :RUBY_ENGINE, "ruby")
      info = Native.runtime_info
      assert_equal "mrk-native-process-runtime-v1", info.fetch("schema")
      assert_equal "1.1.2", info.fetch("fiddle_version")
      assert_equal %w[closure extension fiddle function version], info.fetch("fiddle_features").keys.sort
      assert_equal "default", info.fetch("origin")
      assert_nil info.fetch("gemfile")
      assert info.frozen?
      assert_equal %i[require check], observed.map(&:first)
      assert_empty backend.symbols
      assert_empty backend.functions
      assert_empty backend.calls
    end
  end

  def test_explicit_runtime_admission_rejects_scalar_or_variadic_mismatch_before_binding
    admission = Native.method(:admit_runtime!)
    %i[scalar variadic].each do |defect|
      with_fake_native do |_acq, _slot, backend|
        patch(Native, :runtime_info) { {}.freeze }
        if defect == :scalar
          replace_constant(FakeFiddle, :SIZEOF_INT, 8)
        else
          replace_constant(FakeFiddle, :TYPE_VARIADIC, FALL_THROUGH)
        end
        error = assert_raises(Native::Error) { admission.call }
        assert_equal "abi", error.code
        assert_empty backend.symbols
        assert_empty backend.functions
        assert_empty backend.calls
      end
    end
  end

  def test_missing_public_symbol_has_no_search_or_spawn_fallback
    admission = Native.method(:admit_runtime!)
    with_fake_native do |acq, _slot, backend|
      patch(Native, :runtime_info) { {}.freeze }
      failure = InjectedFailure.new("missing public symbol")
      original = FakeFiddle::Handle::DEFAULT.method(:[])
      patch(FakeFiddle::Handle::DEFAULT, :[]) do |name|
        raise failure if name == "fcntl"
        original.call(name)
      end
      error = assert_raises(Native::Error) { admission.call }
      assert_same failure, error.__send__(:original_error)
      assert_equal "runtime", error.code
      assert_empty backend.calls
      refute acq.child_attempted?
    end
  end

  def test_runtime_origin_rejects_first_load_path_shadow_without_loading_it
    with_fake_native do |_acq, _slot, backend|
      without_bundle_origin do
        config = RbConfig::CONFIG.method(:fetch)
        patch(RbConfig::CONFIG, :fetch) do |key, *rest|
          { "rubylibdir" => "/trusted/lib", "rubyarchdir" => "/trusted/arch", "DLEXT" => "so" }.fetch(key) { config.call(key, *rest) }
        end
        patch(File, :realpath) { |path| path }
        patch(File, :file?) { |_path| true }
        patch(Native, :loaded_fiddle_feature) { |_relative| [] }
        old = $LOAD_PATH.dup
        begin
          $LOAD_PATH.replace(["/foreign", "/trusted/lib", "/trusted/arch"])
          error = assert_raises(Native::Error) { Native.__send__(:fiddle_origin!) }
          assert_equal "origin", error.code
        ensure
          $LOAD_PATH.replace(old)
        end
      end
      assert_empty backend.calls
      assert_empty backend.symbols
    end
  end

  def test_runtime_origin_rejects_foreign_preloaded_features
    with_fake_native do |_acq, _slot, _backend|
      without_bundle_origin do
        patch(File, :realpath) { |path| path }
        patch(File, :file?) { |_path| true }
        patch(Native, :loaded_fiddle_feature) { |_relative| ["/foreign/fiddle.rb"] }
        assert_raises(Native::Error) { Native.__send__(:fiddle_origin!) }
      end
    end
  end

  def test_bundler_default_spec_metadata_does_not_require_an_untrusted_gem_directory
    with_fake_native do |_acq, _slot, backend|
      origin = fake_bundle_origin(active_default: true, selected_default: true,
                                  active_path: "/absent/fiddle-1.1.2", selected_path: "/absent/fiddle-1.1.2")
      assert_equal "bundle", origin.fetch(:kind)
      assert_equal "/trusted/lib", origin.fetch(:library)
      assert_equal ["/trusted/arch"], origin.fetch(:extensions)
      assert origin.fetch(:features).values.all? { |path| path.start_with?("/trusted/") }
      assert_empty backend.calls
      assert_empty backend.symbols
    end
  end

  def test_bundler_default_parity_and_selected_spec_path_mismatch_are_rejected
    [[false, "/absent/fiddle-1.1.2"], [true, "/different/fiddle-1.1.2"]].each do |default, path|
      with_fake_native do |_acq, _slot, backend|
        assert_raises(Native::Error) do
          fake_bundle_origin(active_default: default, selected_default: true,
                             active_path: path, selected_path: "/absent/fiddle-1.1.2")
        end
        assert_empty backend.calls
        assert_empty backend.symbols
      end
    end
  end

  def test_initial_closed_and_nil_child_are_not_no_attempt_receipts
    with_fake_native do |acq, _slot, _backend|
      assert acq.launch_closed?
      refute acq.launch_retired?
      refute acq.not_attempted?
      refute acq.child_attempted?
      assert_nil acq.child
      acq.close_launch!
      refute acq.not_attempted?
    end
  end

  def test_positive_never_started_creator_is_retired_without_inventing_a_join
    # No fake native boundary is needed: an untouched real TaskSlot must not
    # enter Thread.new at all. Its explicit start-attempt bit is the proof.
    cutoff = Native.monotonic_ns + 1_000_000_000
    slot = Helper::TaskSlot.new(run_deadline_ns: cutoff, hard_cleanup_deadline_ns: cutoff + 5_000_000_000)
    acq = Native::Acquisition.new(owner_slot: slot, run_deadline_ns: cutoff, hard_cleanup_deadline_ns: cutoff + 5_000_000_000)
    Thread.stub(:new, ->(*) { raise UnexpectedNativeCall, "forbidden task acquisition" }) do
      refute slot.start_attempted?
      refute slot.joined?
      assert acq.finish_creation!(creator_slot: slot)
      assert acq.not_attempted?
      assert acq.launch_retired?
      refute slot.joined?
      assert_nil slot.thread
      assert_raises(Helper::LifecycleError) { slot.start { flunk "retired start entered body" } }
      refute slot.start_attempted?
      assert_empty acq.resources
    end
  end

  def test_attempted_unpublished_thread_cannot_take_never_started_branch
    with_fake_native do |_acq, _slot, _backend|
      acq, slot = fake_acquisition(unpublished: true)
      assert slot.start_attempted?
      assert_nil slot.thread
      refute slot.joined?
      assert_raises(Native::Error) { acq.finish_creation!(creator_slot: slot) }
      assert_equal :unknown, acq.state
      refute acq.not_attempted?
      refute slot.joined?
      assert Native.instance_variable_get(:@retained).value?(acq)
    end
  end

  def test_finish_requires_same_original_join_not_native_return_settlement
    with_fake_native do |acq, slot, backend|
      spec = fake_spec(fake_stdio(acq))
      child = Native.create(acq, spec)
      assert_equal :pid_published, acq.state
      assert_equal FAKE_PID, child.pid
      refute slot.joined?
      error = assert_raises(Native::Error) { acq.finish_creation!(creator_slot: slot) }
      assert_equal "join", error.code
      assert_equal :unknown, acq.state
      assert_empty backend.calls.select { |name, _args, _function| name.end_with?("_destroy") || name == "close" }
      assert backend.pointers.none?(&:freed?)
      other, other_slot = fake_acquisition
      other_slot.instance_variable_set(:@joined, true)
      assert_raises(Native::Error) { other.finish_creation!(creator_slot: slot) }
    end
  end

  def test_finish_destroys_native_resources_once_but_never_original_endpoints
    with_fake_native do |acq, slot, backend|
      sources = fake_stdio(acq)
      acq.__send__(:prepare_spawn!, fake_spec(sources))
      originals = sources.map(&:io)
      assert originals.none?(&:closed?)
      slot.instance_variable_set(:@joined, true)
      assert acq.finish_creation!(creator_slot: slot)
      assert acq.not_attempted?
      assert originals.none?(&:closed?)
      assert acq.resources.frozen?
      assert backend.pointers.all?(&:freed?)
      closes = backend.calls.count { |name, _args, _function| name == "close" }
      destroys = backend.calls.count { |name, _args, _function| name.end_with?("_destroy") }
      assert_equal 3, closes
      assert_equal 1, destroys
      assert acq.finish_creation!(creator_slot: slot)
      assert_equal closes, backend.calls.count { |name, _args, _function| name == "close" }
      sources.each(&:close_once)
      assert originals.all?(&:closed?)
      refute Native.instance_variable_get(:@retained).value?(acq)
    end
  end

  def test_pipe_pair_slots_are_published_before_acquisition_and_recoverable_after_lost_return
    with_fake_native do |acq, _slot, backend|
      actual_pair = nil
      backend.pipe_hook = lambda do
        assert_equal %i[acquiring acquiring], acq.resources.values.map(&:state)
        assert acq.resources.values.all? { |lease| lease.io.nil? }
        stat = FakeStat.new(1, 222, 0, "fifo")
        actual_pair = [backend.make_io(access: :read, kind: :pipe, stat: stat), backend.make_io(access: :write, kind: :pipe, stat: stat)]
      end
      error = InjectedFailure.new("after actual pipe return")
      assert_raises(InjectedFailure) do
        Native.pipe(acq, read_role: :read_end, write_role: :write_end)
        raise error # Caller loses the returned Array, NOT the published pair.
      end
      assert_same actual_pair.first, acq.resources.fetch(:read_end).io
      assert_same actual_pair.last, acq.resources.fetch(:write_end).io
      assert_equal %i[open open], acq.resources.values.map(&:state)
      assert_same actual_pair, acq.instance_variable_get(:@io_returns).first
      acq.resources.each_value(&:close_once)
    end
  end

  def test_lost_pipe_or_null_acquisition_result_is_unknown_not_empty
    %i[pipe null].each do |kind|
      with_fake_native do |acq, slot, backend|
        error = IOError.new("unpublished IO result")
        hook = ->(*) { raise error }
        kind == :pipe ? backend.pipe_hook = hook : backend.open_hook = hook
        raised = assert_raises(IOError) do
          if kind == :pipe
            Native.pipe(acq, read_role: :reader, write_role: :writer)
          else
            Native.null(acq, access: :read, role: :null)
          end
        end
        assert_same error, raised
        assert_same error, acq.first_error
        assert_same error, slot.first_error
        assert_equal :unknown, acq.state
        assert acq.resources.values.all? { |lease| lease.state == :unknown && lease.io.nil? }
        refute acq.not_attempted?
        slot.instance_variable_set(:@joined, true)
        refute acq.finish_creation!(creator_slot: slot)
        assert_raises(Native::Error) { Native.__send__(:reusable!) }
      end
    end
  end

  def test_unused_unattempted_slot_is_not_acquired_only_after_actual_creator_settlement
    with_fake_native do |acq, slot, _backend|
      lease = acq.__send__(:reserve_io!, role: :reserved, access: :read, kind: :pipe)
      assert_equal :unattempted, lease.state
      assert_nil lease.io
      refute acq.not_attempted?
      slot.instance_variable_set(:@joined, true)
      assert acq.finish_creation!(creator_slot: slot)
      assert_equal :not_acquired, lease.state
      assert lease.close_once
      assert_nil lease.io
      assert acq.not_attempted?
    end
  end

  def test_nonowning_or_popen_io_cannot_become_an_explicit_close_owner
    %i[nonowning popen].each do |kind|
      with_fake_native do |acq, _slot, backend|
        io = backend.make_io(access: :write, kind: :file)
        kind == :nonowning ? io.owning = false : io.attached_pid = FAKE_PID
        assert_raises(Native::Error) { Native.lease_io(acq, io: io, role: :output, access: :write, kind: :file) }
        lease = acq.resources.fetch(:output)
        assert_same io, lease.io
        assert_equal :unknown, lease.state
        assert_equal 0, io.close_calls
        assert_raises(Native::Error) { lease.close_once }
        assert_equal 0, io.close_calls
        refute acq.not_attempted?
      end
    end
  end

  def test_close_once_rechecks_real_close_ownership_and_never_retries_a_raw_number
    with_fake_native do |acq, _slot, _backend|
      lease = Native.null(acq, access: :write, role: :output)
      lease.io.owning = false
      assert_raises(Native::Error) { lease.close_once }
      assert_equal :unknown, lease.state
      assert_equal 0, lease.io.close_calls
      assert_raises(Native::Error) { lease.close_once }
      assert_equal 0, lease.io.close_calls
    end
  end

  def test_close_error_retires_before_call_preserves_identity_and_rejects_retry
    with_fake_native do |acq, slot, backend|
      lease = Native.null(acq, access: :write, role: :output)
      failure = IOError.new("actual close object")
      lease.io.close_hook = lambda do |_io|
        assert_equal :closing, lease.state
        raise failure
      end
      raised = assert_raises(IOError) { lease.close_once }
      assert_same failure, raised
      assert_same failure, lease.close_error
      assert_same failure, acq.first_error
      assert_same failure, slot.first_error
      assert_equal :unknown, lease.state
      assert_same failure, assert_raises(IOError) { lease.close_once }
      assert_equal 1, lease.io.close_calls
      assert_empty backend.calls.select { |name, _args, _function| name == "close" }
    end
  end

  def test_native_error_records_to_shared_failure_before_later_caller_interrupt
    with_fake_native do |acq, slot, _backend|
      failure = InjectedFailure.new("earlier native error")
      later = Interrupt.new("later caller cancellation")
      acq.__send__(:record_error!, failure)
      slot.cancel!(error: later, reason_code: "cancelled")
      assert_same failure, slot.first_error
      assert_same failure, acq.first_error
      assert slot.cancelled?
    end
  end

  def test_post_join_close_uses_the_same_original_shared_failure_record
    with_fake_native do |acq, slot, _backend|
      lease = Native.null(acq, access: :write, role: :output)
      slot.instance_variable_set(:@joined, true)
      assert acq.finish_creation!(creator_slot: slot)
      failure = SystemExit.new(43, "close interruption")
      lease.io.close_hook = ->(_io) { raise failure }
      assert_same failure, assert_raises(SystemExit) { lease.close_once }
      slot.cancel!(error: Interrupt.new("later caller"), reason_code: "cancelled")
      assert_same failure, slot.first_error
      assert_equal 43, slot.first_error.status
      assert_same failure, lease.close_error
    end
  end

  def test_recorder_failure_still_retains_unknown_custody_and_original_error
    with_fake_native do |acq, slot, _backend|
      original = IOError.new("actual acquisition error")
      secondary = InjectedFailure.new("shared recorder failed")
      patch(slot, :cancel!) { |**_args| raise secondary }
      acq.mark_unknown!(original)
      assert_same original, acq.first_error
      assert_includes acq.cleanup_errors, secondary
      assert_equal :unknown, acq.state
      assert Native.instance_variable_get(:@retained).value?(acq)
      assert_raises(Native::Error) { Native.__send__(:reusable!) }
    end
  end

  def test_borrowed_source_cannot_close_but_opposite_control_writer_can
    with_fake_native do |acq, slot, _backend|
      reader, writer = Native.pipe(acq, read_role: :reader, write_role: :writer)
      output = Native.null(acq, access: :write, role: :output)
      acq.__send__(:prepare_sources!, fake_spec([reader, output, output]))
      assert_raises(Native::Error) { reader.close_once }
      assert_equal :open, reader.state
      assert_equal 0, reader.io.close_calls
      assert writer.close_once
      assert_equal :closed, writer.state
      slot.instance_variable_set(:@joined, true)
      assert acq.finish_creation!(creator_slot: slot)
      assert reader.close_once
      assert output.close_once
    end
  end

  def test_cross_acquisition_borrow_keeps_the_original_single_close_owner
    with_fake_native do |source_acq, source_slot, _backend|
      sources = fake_stdio(source_acq)
      source_slot.instance_variable_set(:@joined, true)
      assert source_acq.finish_creation!(creator_slot: source_slot)
      child_acq, child_slot = fake_acquisition
      child_acq.__send__(:prepare_sources!, fake_spec(sources))
      assert_empty child_acq.resources
      sources.each { |source| assert_raises(Native::Error) { source.close_once } }
      child_slot.instance_variable_set(:@joined, true)
      assert child_acq.finish_creation!(creator_slot: child_slot)
      sources.each { |source| assert source.close_once }
      assert sources.all? { |source| source.io.close_calls == 1 }
    end
  end

  def test_process_lifetime_stdio_never_has_an_explicit_close_route
    with_fake_native do |acq, _slot, _backend|
      lease = acq.__send__(:reserve_io!, role: :stdio, access: :read, kind: :null, process_lifetime: true)
      assert lease.process_lifetime?
      assert_raises(Native::Error) { lease.close_once }
      assert_equal :unattempted, lease.state
      assert_raises(Native::Error) { Native.adopt_fd(acq, fd: 8, role: :foreign, access: :read, kind: :pipe) }
    end
  end

  def test_duplicate_errno_has_no_nonatomic_fallback_or_child_attempt
    with_fake_native do |acq, slot, backend|
      spec = fake_spec(fake_stdio(acq))
      command = backend.abi.fetch("constants").fetch("F_DUPFD_CLOEXEC")
      backend.handler = lambda do |name, args, _function|
        if name == "fcntl" && args[1] == command
          FakeFiddle.last_error = 22
          -1
        else
          FALL_THROUGH
        end
      end
      error = assert_raises(Native::Error) { Native.create(acq, spec) }
      assert_equal "fd", error.code
      assert_equal 22, error.errno
      refute acq.child_attempted?
      assert_nil acq.child
      assert_empty backend.calls.select { |name, _args, _function| name == "posix_spawn" }
      assert backend.calls.select { |name, _args, _function| name == "fcntl" }.all? { |_name, args, _function| [1, 3, command].include?(args[1]) }
      slot.instance_variable_set(:@joined, true)
      assert acq.finish_creation!(creator_slot: slot)
      assert acq.not_attempted?
    end
  end

  def test_low_or_aliased_duplicate_is_never_closed_as_a_proven_owned_number
    [2, :source].each do |result|
      with_fake_native do |acq, slot, backend|
        sources = fake_stdio(acq)
        command = backend.abi.fetch("constants").fetch("F_DUPFD_CLOEXEC")
        backend.handler = lambda do |name, args, _function|
          name == "fcntl" && args[1] == command ? (result == :source ? args.first : result) : FALL_THROUGH
        end
        assert_raises(Native::Error) { Native.create(acq, fake_spec(sources)) }
        assert_equal :unknown, acq.state
        slot.instance_variable_set(:@joined, true)
        refute acq.finish_creation!(creator_slot: slot)
        assert_empty backend.calls.select { |name, _args, _function| name == "close" }
        assert sources.none? { |source| source.io.closed? }
      end
    end
  end

  def test_missing_duplicate_return_is_absorbing_unknown_and_blocks_new_launch
    with_fake_native do |acq, slot, backend|
      command = backend.abi.fetch("constants").fetch("F_DUPFD_CLOEXEC")
      spec = fake_spec(fake_stdio(acq))
      failure = InjectedFailure.new("lost native return")
      backend.handler = lambda do |name, args, _function|
        raise failure if name == "fcntl" && args[1] == command
        FALL_THROUGH
      end
      assert_same failure, assert_raises(InjectedFailure) { Native.create(acq, spec) }
      assert_equal :unknown, acq.state
      refute acq.child_attempted?
      refute acq.not_attempted?
      other, = fake_acquisition
      assert_raises(Native::Error) { Native.null(other, access: :read, role: :new_source) }
      slot.instance_variable_set(:@joined, true)
      refute acq.finish_creation!(creator_slot: slot)
      assert_equal :unknown, acq.state
    end
  end

  def test_duplicate_close_failure_is_once_only_with_private_roots_retained
    with_fake_native do |acq, slot, backend|
      acq.__send__(:prepare_sources!, fake_spec(fake_stdio(acq)))
      failure = InjectedFailure.new("lost close return")
      backend.handler = lambda do |name, _args, _function|
        raise failure if name == "close"
        FALL_THROUGH
      end
      slot.instance_variable_set(:@joined, true)
      refute acq.finish_creation!(creator_slot: slot)
      count = backend.calls.count { |name, _args, _function| name == "close" }
      refute acq.finish_creation!(creator_slot: slot)
      assert_equal count, backend.calls.count { |name, _args, _function| name == "close" }
      assert_includes acq.cleanup_errors, failure
      assert Native.instance_variable_get(:@retained).value?(acq)
    end
  end

  def test_native_init_and_action_errors_are_not_errno_or_child_receipts
    %w[posix_spawn_file_actions_init posix_spawn_file_actions_adddup2].each do |function|
      with_fake_native do |acq, slot, backend|
        spec = fake_spec(fake_stdio(acq))
        backend.handler = ->(name, _args, _fn) { name == function ? 12 : FALL_THROUGH }
        error = assert_raises(Native::Error) { Native.create(acq, spec) }
        assert_equal 12, error.errno
        refute acq.child_attempted?
        slot.instance_variable_set(:@joined, true)
        assert acq.finish_creation!(creator_slot: slot)
        assert acq.not_attempted?
        expected = function.end_with?("_init") ? 0 : 1
        assert_equal expected, backend.calls.count { |name, _args, _fn| name == "posix_spawn_file_actions_destroy" }
      end
    end
  end

  def test_lost_native_init_or_destroy_retains_container_storage_without_retry
    %i[init destroy].each do |phase|
      with_fake_native do |acq, slot, backend|
        spec = fake_spec(fake_stdio(acq))
        failure = InjectedFailure.new("uncertain #{phase}")
        function = "posix_spawn_file_actions_#{phase}"
        backend.handler = lambda do |name, _args, _fn|
          raise failure if name == function
          FALL_THROUGH
        end
        if phase == :init
          assert_same failure, assert_raises(InjectedFailure) { Native.create(acq, spec) }
        else
          acq.__send__(:prepare_spawn!, spec)
        end
        container = acq.instance_variable_get(:@containers).fetch("file_actions")
        slot.instance_variable_set(:@joined, true)
        refute acq.finish_creation!(creator_slot: slot)
        refute container.buffer.pointer.freed?
        assert_equal :unknown, container.state
        count = backend.calls.count { |name, _args, _fn| name == function }
        refute acq.finish_creation!(creator_slot: slot)
        assert_equal count, backend.calls.count { |name, _args, _fn| name == function }
      end
    end
  end

  def test_linux_actions_are_exact_destinations_then_one_final_closefrom
    [3, 8].each do |count|
      with_fake_native(family: "linux-glibc") do |acq, _slot, backend|
        sources = fake_stdio(acq)
        sources += [sources.first, sources.last, sources.first, sources.last, sources.last] if count == 8
        Native.create(acq, fake_spec(sources))
        actions = backend.calls.select { |name, _args, _fn| name.start_with?("posix_spawn_file_actions_add") }
        assert_equal ["posix_spawn_file_actions_adddup2"] * count + ["posix_spawn_file_actions_addclosefrom_np"], actions.map(&:first)
        assert_equal (0...count).to_a, actions.first(count).map { |_name, args, _fn| args.fetch(2) }
        assert actions.first(count).all? { |_name, args, _fn| args.fetch(1) >= 8 }
        assert_equal count, actions.last[1].fetch(1)
        spawn_args = backend.calls.find { |name, _args, _fn| name == "posix_spawn" }.fetch(1)
        assert_equal 0, spawn_args.fetch(3)
      end
    end
  end

  def test_darwin_uses_pointer_slots_and_exact_public_cloexec_getter
    with_fake_native(family: "darwin") do |acq, _slot, backend|
      Native.create(acq, fake_spec(fake_stdio(acq)))
      assert_equal 8, backend.abi.fetch("file_actions").fetch("size")
      assert_equal 8, backend.abi.fetch("spawn_attributes").fetch("size")
      assert_equal [16_384], backend.calls.select { |name, _args, _fn| name == "posix_spawnattr_setflags" }.map { |_name, args, _fn| args.fetch(1) }
      assert_equal 1, backend.calls.count { |name, _args, _fn| name == "posix_spawnattr_getflags" }
      assert_empty backend.calls.select { |name, _args, _fn| name.include?("closefrom") }
      refute_equal 0, backend.calls.find { |name, _args, _fn| name == "posix_spawn" }[1][3]
    end
  end

  def test_read_only_sigchld_rejects_ignore_and_nocldwait_before_spawn
    %i[ignore no_cld_wait].each do |policy|
      with_fake_native do |acq, slot, backend|
        policy == :ignore ? backend.signal_handler = 1 : backend.signal_flags = backend.abi.fetch("constants").fetch("SA_NOCLDWAIT")
        error = assert_raises(Native::Error) { Native.create(acq, fake_spec(fake_stdio(acq))) }
        assert_equal "waitability", error.code
        refute acq.child_attempted?
        assert_nil acq.child
        assert_empty backend.calls.select { |name, _args, _fn| name == "posix_spawn" }
        assert backend.calls.select { |name, _args, _fn| name == "sigaction" }.all? { |_name, args, _fn| args.fetch(1) == 0 }
        slot.instance_variable_set(:@joined, true)
        assert acq.finish_creation!(creator_slot: slot)
        assert acq.not_attempted?
      end
    end
  end

  def test_spawn_attempt_and_native_roots_exist_before_call_and_child_before_return
    with_fake_native do |acq, _slot, backend|
      spec = fake_spec(fake_stdio(acq))
      backend.handler = lambda do |name, args, _fn|
        if name == "posix_spawn"
          assert acq.child_attempted?
          assert_equal :attempting, acq.state
          assert_nil acq.child
          assert_equal 6, args.length
          assert args.values_at(0, 1, 2, 4, 5).all? { |pointer| pointer.instance_of?(FakeFiddle::Pointer) && !pointer.freed? }
          assert backend.pointers.none?(&:freed?)
        end
        FALL_THROUGH
      end
      child = Native.create(acq, spec)
      assert_same child, acq.child
      assert acq.launch_retired?
      assert_equal :running, child.state
      refute child.numeric_retired?
    end
  end

  def test_late_native_return_publishes_cleanup_child_without_reopening_admission
    with_fake_native do |acq, slot, backend|
      spec = fake_spec(fake_stdio(acq))
      backend.handler = lambda do |name, _args, _fn|
        if name == "posix_spawn"
          acq.close_launch!
          slot.close_launch!
        end
        FALL_THROUGH
      end
      child = Native.create(acq, spec)
      assert_same child, acq.child
      assert acq.launch_retired?
      assert_raises(Native::Error) { Native.create(acq, spec) }
      assert_equal 1, backend.calls.count { |name, _args, _fn| name == "posix_spawn" }
      refute acq.not_attempted?
    end
  end

  def test_spawn_errno_or_lost_return_is_not_a_no_attempt_or_reaped_receipt
    %i[errno lost].each do |kind|
      with_fake_native do |acq, slot, backend|
        spec = fake_spec(fake_stdio(acq))
        failure = InjectedFailure.new("lost spawn return")
        backend.handler = lambda do |name, _args, _fn|
          if name == "posix_spawn"
            raise failure if kind == :lost
            2
          else
            FALL_THROUGH
          end
        end
        assert_raises(kind == :lost ? InjectedFailure : Native::Error) { Native.create(acq, spec) }
        assert acq.child_attempted?
        assert_nil acq.child
        assert_equal :unknown, acq.state
        refute acq.not_attempted?
        slot.instance_variable_set(:@joined, true)
        refute acq.finish_creation!(creator_slot: slot)
      end
    end
  end

  def test_first_wait_retires_numeric_route_before_only_genuine_nil_allows_repoll
    with_fake_native do |acq, slot, _backend|
      child = Native.create(acq, fake_spec(fake_stdio(acq)))
      slot.instance_variable_set(:@joined, true)
      acq.finish_creation!(creator_slot: slot)
      count = 0
      @wait_handler = lambda do |pid, flags|
        count += 1
        assert_equal FAKE_PID, pid
        assert_equal Process::WNOHANG, flags
        assert child.numeric_retired?
        assert_equal :wait_in_flight, child.state
        nil
      end
      assert_nil child.poll_wait
      assert_equal :pollable, child.state
      assert_nil child.poll_wait
      assert_equal 2, count
      assert child.numeric_retired?
      assert_nil child.receipt
    end
  end

  def test_wait_exception_or_bad_return_is_unknown_with_no_numeric_retry
    [Errno::ECHILD.new, Errno::EINTR.new, InjectedFailure.new("lost wait publication"), [FAKE_PID + 1, 0], [FAKE_PID, 0], false].each do |outcome|
      with_fake_native do |acq, slot, _backend|
        child = Native.create(acq, fake_spec(fake_stdio(acq)))
        slot.instance_variable_set(:@joined, true)
        acq.finish_creation!(creator_slot: slot)
        calls = 0
        @wait_handler = lambda do |_pid, _flags|
          calls += 1
          raise outcome if outcome.is_a?(Exception)
          outcome
        end
        expected_error = outcome.is_a?(Exception) ? outcome.class : Native::Error
        error = assert_raises(expected_error) { child.poll_wait }
        assert_same outcome, error if outcome.is_a?(Exception)
        assert_equal :unknown, child.state
        assert child.numeric_retired?
        assert_nil child.receipt
        assert_raises(Native::Error) { child.poll_wait }
        assert_equal 1, calls
        assert_equal :unknown, acq.state
      end
    end
  end

  def test_explicit_numeric_retirement_is_irreversible_without_a_wait
    with_fake_native do |acq, _slot, _backend|
      child = Native.create(acq, fake_spec(fake_stdio(acq)))
      refute child.numeric_retired?
      assert child.retire_numeric!
      assert child.numeric_retired?
      assert_equal :running, child.state
      assert child.retire_numeric!
      assert child.numeric_retired?
      assert_nil child.receipt
    end
  end

  # ACTUAL native/no-child controls. CI runs exactly these TWO only after the
  # C public-header record equals declared_abi for this loaded source/wheel.
  def test_public_atomic_cloexec_duplication_uses_independent_creator_functions
    Native.admit_runtime!
    cutoff = Native.monotonic_ns + 3_000_000_000
    contexts = 2.times.map do
      begin_native(cutoff: cutoff) do |acq, context|
        reader, writer = Native.pipe(acq, read_role: :reader, write_role: :writer)
        output = Native.null(acq, access: :write, role: :output)
        context[:sources] = [reader, writer, output]
        context[:original_flags] = context[:sources].map { |lease| [lease.io.fcntl(1), lease.io.fcntl(3)] }
        acq.__send__(:prepare_sources!, Native::SpawnSpec.new(executable: File.realpath(RbConfig.ruby),
          argv: [File.realpath(RbConfig.ruby)], env: {}, fd_sources: [reader, writer, output]))
        context[:dup_fds] = acq.instance_variable_get(:@duplicates).map(&:fd)
        context[:function] = acq.instance_variable_get(:@functions).fetch("fcntl")
        context[:after_flags] = context[:sources].map { |lease| [lease.io.fcntl(1), lease.io.fcntl(3)] }
      end
    end
    contexts.each { |context| join_native(context) }
    refute_same contexts.first.fetch(:function), contexts.last.fetch(:function)
    contexts.each do |context|
      assert_equal context.fetch(:original_flags), context.fetch(:after_flags)
      assert_equal 3, context.fetch(:dup_fds).uniq.length
      assert context.fetch(:dup_fds).all? { |fd| fd >= 8 }
      assert_equal :settled, context.fetch(:acq).state
      assert context.fetch(:acq).not_attempted?
      refute context.fetch(:acq).child_attempted?
      assert_nil context.fetch(:acq).child
      assert context.fetch(:sources).none? { |source| source.io.closed? }
    end
  end

  def test_public_spawn_containers_and_read_only_sigchld_admission
    Native.admit_runtime!
    [3, 8].each do |count|
      context = begin_native do |acq, result|
        sources = native_stdio(acq)
        sources += [sources.first, sources.last, sources.first, sources.last, sources.last] if count == 8
        assert Native.admit_waitability!(acq)
        acq.__send__(:prepare_spawn!, Native::SpawnSpec.new(executable: File.realpath(RbConfig.ruby),
          argv: [File.realpath(RbConfig.ruby)], env: {}, fd_sources: sources))
        assert Native.admit_waitability!(acq)
        result[:containers] = acq.instance_variable_get(:@containers).values.dup
      end
      join_native(context)
      assert context.fetch(:acq).not_attempted?
      assert context.fetch(:containers).all? { |container| container.state == :destroyed }
      assert context.fetch(:containers).all? { |container| container.buffer.pointer.freed? }
      assert_nil context.fetch(:acq).child
    end
  end

  def test_native_exact_wait_returns_original_process_status_and_cached_receipt
    [0, 41].each do |exit_code|
      context = begin_native do |acq, _result|
        sources = native_stdio(acq)
        Native.create(acq, native_spec(sources, "exit #{exit_code}"))
      end
      join_native(context)
      close_originals(context)
      receipt = wait_native(context)
      assert_equal "exit", receipt.status_kind
      assert_equal exit_code, receipt.status_code
      assert_instance_of Process::Status, receipt.raw_status
      assert_equal receipt.pid, receipt.raw_status.pid
      assert receipt.raw_status.exited?
      assert_equal exit_code, receipt.raw_status.exitstatus
      assert receipt.frozen?
      Process.stub(:waitpid2, ->(*) { raise UnexpectedNativeCall, "cached receipt rewaited" }) do
        assert_same receipt, context.fetch(:acq).child.poll_wait
      end
    end
  end

  def test_native_genuine_nil_poll_then_control_eof_gives_terminal_receipt
    context = begin_native do |acq, result|
      reader, writer = Native.pipe(acq, read_role: :control_read, write_role: :control_write)
      output = Native.null(acq, access: :write, role: :output)
      result[:writer] = writer
      Native.create(acq, native_spec([reader, output, output], "STDIN.read; exit 0"))
    end
    join_native(context)
    child = context.fetch(:acq).child
    assert_nil child.poll_wait
    assert_equal :pollable, child.state
    assert child.numeric_retired?
    assert context.fetch(:writer).close_once
    close_originals(context)
    receipt = wait_native(context)
    assert_equal 0, receipt.status_code
    assert_equal "exit", receipt.status_kind
  end

  def test_native_signal_receipt_is_a_genuine_exact_wait_not_a_normalized_integer
    context = begin_native do |acq, _result|
      Native.create(acq, native_spec(native_stdio(acq), 'Signal.trap("TERM", "SYSTEM_DEFAULT"); Process.kill("TERM", Process.pid)'))
    end
    join_native(context)
    close_originals(context)
    receipt = wait_native(context)
    assert_equal "signal", receipt.status_kind
    assert_equal Signal.list.fetch("TERM"), receipt.status_code
    assert receipt.raw_status.signaled?
    assert_same receipt.raw_status, context.fetch(:acq).child.receipt.raw_status
  end

  def test_native_caller_ignore_and_nocldwait_are_rejected_without_creating_a_child
    Native.admit_runtime!
    original = native_signal_snapshot
    assert_waitable_snapshot(original)
    abi = Native.declared_abi
    fields = abi.fetch("sigaction").fetch("fields")
    constants = abi.fetch("constants")
    %i[ignore no_cld_wait].each do |policy|
      changed = original.dup
      if policy == :ignore
        changed[fields.fetch("handler").fetch("offset"), 8] = [constants.fetch("SIG_IGN")].pack("Q<")
      else
        offset = fields.fetch("flags").fetch("offset")
        changed[offset, 4] = [changed.byteslice(offset, 4).unpack1("L<") | constants.fetch("SA_NOCLDWAIT")].pack("L<")
      end
      owned_policy = publish_signal_policy(original)
      begin
        native_install_signal(changed, policy: owned_policy)
        context = begin_native do |acq, result|
          begin
            Native.admit_waitability!(acq)
          rescue Native::Error => error
            result[:rejection] = error
          end
        end
        join_native(context, allow_error: true)
        assert_equal "waitability", context.fetch(:rejection).code
        assert_same context.fetch(:rejection), context.fetch(:slot).first_error
        assert context.fetch(:acq).not_attempted?
        refute context.fetch(:acq).child_attempted?
        assert_nil context.fetch(:acq).child
        assert context.fetch(:acq).instance_variable_get(:@calls).none? { |call| call.function.name == "posix_spawn" }
      ensure
        restore_signal_policy(owned_policy)
      end
    end
  end

  def test_native_nonreaping_custom_sigchld_policy_allows_two_exact_owners_unchanged
    Native.admit_runtime!
    original = native_signal_snapshot
    assert_waitable_snapshot(original)
    notifications = 0
    custom = proc { notifications += 1 } # Deliberately NO consuming wait.
    policy = publish_signal_policy(original, custom: custom)
    begin
      Thread.handle_interrupt(Exception => :never) do
        policy[:ruby_install] = :in_flight
        policy[:old] = Signal.trap("CHLD", custom)
        policy[:ruby_install] = :returned
        policy[:installed] = true
      end
      before = native_signal_snapshot
      cutoff = Native.monotonic_ns + 3_000_000_000
      contexts = 2.times.map do |index|
        begin_native(cutoff: cutoff) do |acq, _result|
          Native.create(acq, native_spec(native_stdio(acq), "exit #{index + 11}"))
        end
      end
      receipts = contexts.map do |context|
        join_native(context)
        close_originals(context)
        wait_native(context)
      end
      assert_equal [11, 12], receipts.map(&:status_code)
      assert_equal 2, receipts.map(&:pid).uniq.length
      receipts.zip(contexts).each do |receipt, context|
        assert_instance_of Process::Status, receipt.raw_status
        assert_equal context.fetch(:acq).child.pid, receipt.raw_status.pid
      end
      assert_equal signal_fields(before), signal_fields(native_signal_snapshot)
      assert_operator notifications, :>=, 1
    ensure
      restore_signal_policy(policy)
    end
  end

  def test_native_public_fifo_open_stall_keeps_foreground_runnable_and_cancels_late_go
    Native.admit_runtime!
    deadline = Native.monotonic_ns + 1_000_000_000
    owned_path = acquire_fixture_fifo
    fifo = owned_path.fetch(:fifo)
    context = nil
    fixture = self
    context = begin_native(cutoff: deadline) do |acq, result|
      context = result # Publish the exact record before any action hook runs.
      result[:fifo_path] = owned_path
      reader, writer = Native.pipe(acq, read_role: :go_read, write_role: :go_write)
      out_read, out_write = Native.pipe(acq, read_role: :output_read, write_role: :output_write)
      err = Native.null(acq, access: :write, role: :error)
      result[:go_writer], result[:output_reader] = writer, out_read
      if Native.declared_abi.fetch("family") == "linux-glibc"
        # Scope the test hook to THIS acquisition and THIS actual container.
        # No process-global method can outlive an unresolved creator/ensure.
        original_container = acq.method(:container!)
        acq.define_singleton_method(:container!) do |name, prefix|
          container = original_container.call(name, prefix)
          if name == "file_actions"
            original_change = container.method(:change!)
            container.define_singleton_method(:change!) do |suffix, *arguments|
              fixture.__send__(:add_fifo_action, acq, self, fifo) if suffix == "addclosefrom_np"
              original_change.call(suffix, *arguments)
            end
          end
          container
        end
        acq.singleton_class.send(:private, :container!)
      else
        original_waitability = acq.method(:waitability!)
        acq.define_singleton_method(:waitability!) do
          fixture.__send__(:add_fifo_action, self, instance_variable_get(:@containers).fetch("file_actions"), fifo)
          original_waitability.call
        end
        acq.singleton_class.send(:private, :waitability!)
      end
      Native.create(acq, native_spec([reader, out_write, err], 'value = STDIN.read; STDOUT.write("GO_EXECUTED") if value == "GO"'))
    end
    while Native.monotonic_ns < deadline
      sleep 0.002
    end
    assert context.fetch(:acq).child_attempted?, "public spawn was not entered before cutoff"
    assert spawn_in_flight?(context)
    refute context.fetch(:slot).joined?
    refute context.fetch(:slot).thread.join(0), "FIFO open did not actually stall the creator"
    context.fetch(:acq).close_launch!
    context.fetch(:slot).cancel!(reason_code: "deadline")
    assert context.fetch(:go_writer).close_once # Opposite, UNBORROWED end.
    assert release_fixture_fifo(context), "no actual pending native FIFO reader"
    join_native(context, allow_error: true)
    assert context.fetch(:slot).cancelled?
    assert_nil context.fetch(:slot).offer
    assert context.fetch(:acq).launch_retired?
    child = context.fetch(:acq).child
    refute_nil child
    close_originals(context, except: [context.fetch(:output_reader)])
    receipt = wait_native(context)
    assert_equal 0, receipt.status_code
    bytes = read_to_eof(context.fetch(:output_reader), context.fetch(:hard))
    assert_equal "".b, bytes, "late GO was accepted"
    assert context.fetch(:output_reader).close_once
  end

  private

  def abi_for(family)
    original = RbConfig::CONFIG.method(:fetch)
    RbConfig::CONFIG.stub(:fetch, lambda { |key, *rest|
      { "host_os" => family == "darwin" ? "darwin25" : "linux-gnu", "host_cpu" => "x86_64" }.fetch(key) { original.call(key, *rest) }
    }) { Native.declared_abi }
  end

  def patch(target, name, &body)
    eigen = target.singleton_class
    own = eigen.instance_methods(false).include?(name) || eigen.private_instance_methods(false).include?(name)
    visibility = eigen.private_method_defined?(name) ? :private : :public
    original = target.method(name)
    @patches << [eigen, name, original, own, visibility]
    Thread.handle_interrupt(Exception => :never) do
      eigen.send(:define_method, name, &body)
      eigen.send(visibility, name)
    end
  end

  def replace_constant(target, name, replacement)
    present = target.const_defined?(name, false)
    original = target.const_get(name, false) if present
    @constants << [target, name, present, original]
    Thread.handle_interrupt(Exception => :never) do
      target.send(:remove_const, name) if present
      target.const_set(name, replacement) unless replacement.equal?(FALL_THROUGH)
    end
  end

  def without_bundle_origin
    replace_constant(Object, :Bundler, FALL_THROUGH) if Object.const_defined?(:Bundler, false)
    patch(Gem, :loaded_specs) { {} } if defined?(Gem)
    yield
  end

  def fake_acquisition(unpublished: false)
    deadline = Native.monotonic_ns + 10_000_000_000
    slot = Helper::TaskSlot.new(run_deadline_ns: deadline, hard_cleanup_deadline_ns: deadline + 5_000_000_000)
    # Simulated task facts ONLY inside a world whose every native boundary is
    # vetoed or fake. These booleans are not offered as actual join evidence.
    slot.instance_variable_set(:@start_attempted, true)
    slot.instance_variable_set(:@thread, unpublished ? nil : Thread.current)
    slot.instance_variable_set(:@returned_thread, unpublished ? nil : Thread.current)
    slot.instance_variable_set(:@launch, :open)
    [Native::Acquisition.new(owner_slot: slot, run_deadline_ns: deadline, hard_cleanup_deadline_ns: deadline + 5_000_000_000), slot]
  end

  def fake_bundle_origin(active_default:, selected_default:, active_path:, selected_path:)
    specification = Struct.new(:name, :version, :full_gem_path, :default_gem, :source) do
      def default_gem? = default_gem
    end
    rubygems = Class.new do
      def remotes = ["https://rubygems.org/"]
    end
    source = Module.new
    source.const_set(:Rubygems, rubygems)
    bundle = Module.new
    bundle.const_set(:Source, source)
    bundle.const_set(:VERSION, "4.0.16")
    actual_path = Native.method(:runtime_info).source_location.fetch(0)
    gemfile = File.expand_path("../Gemfile", File.dirname(actual_path))
    selected = specification.new("fiddle", "1.1.2", selected_path, selected_default, rubygems.new)
    active = specification.new("fiddle", "1.1.2", active_path, active_default, rubygems.new)
    holder = Struct.new(:specs)
    bundle.define_singleton_method(:default_gemfile) { gemfile }
    bundle.define_singleton_method(:locked_gems) { holder.new([selected]) }
    bundle.define_singleton_method(:load) { holder.new([active]) }
    replace_constant(Object, :Bundler, bundle)
    raise "fake origin needs loaded test RubyGems" unless defined?(Gem)
    patch(Gem, :loaded_specs) { { "fiddle" => selected } }
    original_config = RbConfig::CONFIG.method(:fetch)
    patch(RbConfig::CONFIG, :fetch) do |key, *rest|
      { "rubylibdir" => "/trusted/lib", "rubyarchdir" => "/trusted/arch", "DLEXT" => "so" }.fetch(key) { original_config.call(key, *rest) }
    end
    features = %w[fiddle.rb fiddle/version.rb fiddle/function.rb fiddle/closure.rb].to_h { |relative| [relative, "/trusted/lib/#{relative}"] }
    features["fiddle.so"] = "/trusted/arch/fiddle.so"
    patch(File, :realpath) do |path|
      raise Errno::ENOENT, "metadata-only gemdir does not exist" if path.start_with?("/absent/", "/different/")
      path
    end
    patch(File, :file?) { |path| features.value?(path) || path == gemfile }
    patch(Native, :loaded_fiddle_feature) { |relative| [features.fetch(relative)] }
    Native.__send__(:fiddle_origin!)
  end

  def with_fake_native(family: "linux-glibc")
    raise "real unresolved native custody cannot be reset by a fake test" if Native.instance_variable_get(:@poisoned)
    saved = %i[@retained @fd_claims @poisoned].to_h { |name| [name, Native.instance_variable_get(name)] }
    @patches, @constants, @wait_handler = [], [], nil
    abi = abi_for(family)
    backend = FakeBackend.new(abi)
    replace_constant(Object, :Fiddle, FakeFiddle)
    FakeFiddle.backend = backend
    FakeFiddle.last_error = 0
    Native.instance_variable_set(:@retained, {})
    Native.instance_variable_set(:@fd_claims, {})
    Native.instance_variable_set(:@poisoned, false)
    patch(Native, :admit_runtime!) { true }
    patch(Native, :declared_abi) { abi }
    patch(IO, :pipe) { backend.pipe }
    patch(IO, :for_fd) { |fd, mode, **keywords| backend.wrapper(fd, mode, **keywords) }
    patch(File, :open) { |path, mode, **_keywords| backend.open(path, mode) }
    patch(File, :stat) { |_path| backend.null_stat }
    patch(Thread, :new) { |*_args| raise UnexpectedNativeCall, "real thread in fake-only control" }
    fixture = self
    patch(Process, :waitpid2) do |pid, flags|
      handler = fixture.instance_variable_get(:@wait_handler)
      raise UnexpectedNativeCall, "real wait in fake-only control" unless handler
      handler.call(pid, flags)
    end
    %i[spawn fork detach wait wait2 waitpid waitall kill].each do |name|
      patch(Process, name) { |*_args| raise UnexpectedNativeCall, "forbidden process boundary" }
    end
    acq, slot = fake_acquisition
    yield acq, slot, backend
  ensure
    Thread.handle_interrupt(Exception => :never) do
      @patches&.reverse_each do |eigen, name, original, own, visibility|
        if own
          eigen.send(:define_method, name, original)
          eigen.send(visibility, name)
        else
          eigen.send(:remove_method, name)
        end
      end
      @constants&.reverse_each do |target, name, present, original|
        target.send(:remove_const, name) if target.const_defined?(name, false)
        target.const_set(name, original) if present
      end
      saved&.each { |name, value| Native.instance_variable_set(name, value) }
      FakeFiddle.backend = nil
      @patches = @constants = nil
    end
  end

  def fake_stdio(acq)
    [Native.null(acq, access: :read, role: :stdin), Native.null(acq, access: :write, role: :stdout),
     Native.null(acq, access: :write, role: :stderr)]
  end

  def fake_spec(sources)
    Native::SpawnSpec.new(executable: "/fixture/ruby", argv: ["/fixture/ruby"], env: {}, fd_sources: sources)
  end

  def native_stdio(acq)
    [Native.null(acq, access: :read, role: :stdin), Native.null(acq, access: :write, role: :stdout),
     Native.null(acq, access: :write, role: :stderr)]
  end

  def native_spec(sources, script)
    ruby = File.realpath(RbConfig.ruby)
    Native::SpawnSpec.new(executable: ruby, argv: [ruby, *Helper::HELPER_FLAGS, "-e", script],
                         env: Helper.helper_environment, fd_sources: sources)
  end

  def begin_native(cutoff: Native.monotonic_ns + 3_000_000_000, &work)
    hard = cutoff + 5_000_000_000
    slot = Helper::TaskSlot.new(run_deadline_ns: cutoff, hard_cleanup_deadline_ns: hard)
    acq = Native::Acquisition.new(owner_slot: slot, run_deadline_ns: cutoff, hard_cleanup_deadline_ns: hard)
    context = { slot: slot, acq: acq, hard: hard, finish_attempted: false, finish_returned: false }
    @native_contexts ||= []
    @native_contexts << context # BEFORE either task or resource acquisition.
    slot.start { |_owner| work.call(acq, context) }
    assert slot.admit!, "actual creator was not admitted"
    context
  end

  def join_native(context, allow_error: false)
    slot, acq = context.values_at(:slot, :acq)
    assert slot.join_until(deadline_ns: context.fetch(:hard)), "actual creator did not join"
    assert slot.joined?
    assert_nil slot.first_error unless allow_error
    unless context.fetch(:finish_attempted)
      context[:finish_attempted] = true
      result = acq.finish_creation!(creator_slot: slot)
      context[:finish_returned] = result
      assert result, "native creation custody is UNKNOWN"
    end
    assert_empty acq.cleanup_errors
    context
  end

  def close_originals(context, except: [])
    context.fetch(:acq).resources.each_value do |lease|
      next if except.include?(lease) || %i[closed not_acquired].include?(lease.state) || lease.process_lifetime?
      assert_equal :open, lease.state, "unsettled original endpoint"
      assert lease.close_once
      assert_equal :closed, lease.state
    end
  end

  def wait_native(context)
    child = context.fetch(:acq).child
    refute_nil child
    loop do
      receipt = child.poll_wait
      return receipt if receipt
      raise "original exact-child wait deadline exceeded" if Native.monotonic_ns >= context.fetch(:hard)
      sleep 0.002
    end
  end

  def read_to_eof(lease, cutoff)
    bytes = +"".b
    loop do
      returned = lease.io.read_nonblock(1_024, exception: false)
      return bytes if returned.nil?
      if returned == :wait_readable
        raise "owned output EOF deadline exceeded" if Native.monotonic_ns >= cutoff
        sleep 0.002
      else
        bytes << returned
        raise "unexpected unbounded fixture output" if bytes.bytesize > 1_024
      end
    end
  end

  def acquire_fixture_fifo
    record = { directory: nil, directory_identity: nil, directory_state: :unattempted,
               fifo: nil, fifo_identity: nil, fifo_state: :unattempted, errors: [] }
    @owned_paths ||= []
    @owned_paths << record # BEFORE mktmpdir can create an as-yet-unnamed path.
    Thread.handle_interrupt(Exception => :never) do
      record[:directory_state] = :acquiring
      record[:directory] = Dir.mktmpdir("mrk-native-fifo-")
      identity = record[:directory_identity] = File.lstat(record.fetch(:directory))
      assert identity.directory? && identity.uid == Process.euid && (identity.mode & 0o777) == 0o700
      record[:directory_state] = :open
      record[:fifo] = File.join(record.fetch(:directory), "owned.fifo")
      record[:fifo_state] = :acquiring
      assert_equal 0, File.mkfifo(record.fetch(:fifo), 0o600)
      identity = record[:fifo_identity] = File.lstat(record.fetch(:fifo))
      assert identity.pipe? && identity.uid == Process.euid && (identity.mode & 0o777) == 0o600
      record[:fifo_state] = :open
    end
    record
  rescue Exception => error
    if record
      record[:directory_state] = :unknown if record[:directory_state] == :acquiring
      record[:fifo_state] = :unknown if record[:fifo_state] == :acquiring
      record[:errors] << error
    end
    raise
  end

  def fixture_path_identity!(record, member)
    expected = record.fetch(:"#{member}_identity")
    current = File.lstat(record.fetch(member))
    kind = member == :fifo ? current.pipe? : current.directory?
    unless kind && current.uid == Process.euid && [current.dev, current.ino] == [expected.dev, expected.ino]
      raise "owned fixture path identity changed; retained"
    end
    current
  end

  def spawn_in_flight?(context)
    context.fetch(:acq).instance_variable_get(:@calls).any? do |call|
      call.function.name == "posix_spawn" && call.state == :in_flight
    end
  end

  def close_fixture_writer_once(slot)
    return true if %i[unattempted not_acquired closed].include?(slot.fetch(:state))
    raise "uncertain FIFO writer cannot be retried" unless slot.fetch(:state) == :open

    Thread.handle_interrupt(Exception => :never) do
      slot[:state] = :closing # Retire the actual owning IO before its close.
      io = slot.fetch(:io)
      raise "non-owning FIFO writer" unless io.is_a?(File) && io.autoclose? == true && io.pid.nil?
      raise "FIFO writer close did not return" unless io.close.nil?

      slot[:state] = :closed
    end
    true
  rescue Exception => error
    slot[:state] = :unknown if slot[:state] == :closing
    slot[:error] ||= error
    raise
  end

  def release_fixture_fifo(context)
    slot = context[:fifo_writer] ||= { io: nil, state: :unattempted, attempts: 0, error: nil }
    return true if slot.fetch(:state) == :closed
    return close_fixture_writer_once(slot) if slot.fetch(:state) == :open
    raise "uncertain FIFO open cannot be retried" unless %i[unattempted not_acquired].include?(slot.fetch(:state))

    path = context.fetch(:fifo_path)
    raise "unsettled FIFO path acquisition" unless path.fetch(:directory_state) == :open && path.fetch(:fifo_state) == :open
    fixture_path_identity!(path, :directory)
    identity = fixture_path_identity!(path, :fifo)
    loop do
      return false unless spawn_in_flight?(context)
      raise "FIFO cleanup deadline exceeded" if Native.monotonic_ns >= context.fetch(:hard)

      Thread.handle_interrupt(Exception => :never) do
        slot[:state] = :opening
        slot[:attempts] += 1
        begin
          slot[:io] = File.open(path.fetch(:fifo), File::WRONLY | File::NONBLOCK | File::NOFOLLOW)
          slot[:state] = :open
        rescue Errno::ENXIO => error
          # A genuine failed nonblocking open acquired no FD. Preserve attempt
          # history; no missing return/other exception earns this retry branch.
          slot[:last_open_error] = error
          slot[:state] = :not_acquired
        end
      end
      if slot.fetch(:state) == :open
        actual = slot.fetch(:io).stat
        raise "FIFO writer identity changed" unless actual.pipe? && [actual.dev, actual.ino] == [identity.dev, identity.ino]

        close_fixture_writer_once(slot)
        return true # Actual owning writer return proves a pending native reader.
      end
      sleep 0.002
    end
  rescue Exception => error
    slot[:state] = :unknown if slot && slot[:state] == :opening
    slot[:error] ||= error if slot
    raise
  end

  def remove_fixture_fifo(record)
    %i[fifo directory].each do |member|
      state_key = :"#{member}_state"
      next if %i[unattempted removed].include?(record.fetch(state_key))
      raise "uncertain fixture path cannot be removed" unless record.fetch(state_key) == :open

      Thread.handle_interrupt(Exception => :never) do
        fixture_path_identity!(record, :directory) if member == :fifo
        fixture_path_identity!(record, member)
        record[state_key] = :removing
        returned = member == :fifo ? File.unlink(record.fetch(member)) : Dir.rmdir(record.fetch(member))
        raise "fixture removal did not return" unless returned == (member == :fifo ? 1 : 0)

        record[state_key] = :removed
      end
    end
    true
  rescue Exception => error
    %i[fifo_state directory_state].each { |key| record[key] = :unknown if record[key] == :removing }
    record[:errors] << error
    raise
  end

  def fixture_cleanup_step(errors)
    yield
  rescue Exception => error
    errors << error
    false
  end

  def add_fifo_action(acq, container, path)
    return if acq.instance_variable_get(:@fixture_fifo_added)
    acq.instance_variable_set(:@fixture_fifo_added, true)
    family = Native.declared_abi.fetch("family")
    mode_type = family == "darwin" ? Fiddle::TYPE_USHORT : Fiddle::TYPE_UINT
    functions = acq.instance_variable_get(:@functions)
    functions["posix_spawn_file_actions_addopen"] = Fiddle::Function.new(
      Fiddle::Handle::DEFAULT["posix_spawn_file_actions_addopen"],
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, mode_type], Fiddle::TYPE_INT,
      name: "posix_spawn_file_actions_addopen", need_gvl: false)
    storage = acq.__send__(:buffer!, "fixture_fifo_path", path.bytesize + 1)
    storage.pointer[0, path.bytesize + 1] = path.b + "\0".b
    container.change!("addopen", 8, storage.pointer, File::RDONLY, 0)
    if family == "darwin"
      functions["posix_spawn_file_actions_addclose"] = Fiddle::Function.new(
        Fiddle::Handle::DEFAULT["posix_spawn_file_actions_addclose"],
        [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT,
        name: "posix_spawn_file_actions_addclose", need_gvl: false)
      container.change!("addclose", 8)
    end
  end

  def native_signal_snapshot
    context = begin_native do |acq, result|
      acq.__send__(:runtime!)
      abi = Native.declared_abi
      layout = abi.fetch("sigaction")
      storage = acq.__send__(:buffer!, "fixture_signal_snapshot", layout.fetch("size"), layout.fetch("align"))
      call = acq.__send__(:native_call!, "sigaction", abi.fetch("constants").fetch("SIGCHLD"), 0, storage.pointer)
      raise Native::Error.new("waitability", errno: call.errno) unless call.result == 0
      result[:bytes] = storage.pointer[0, layout.fetch("size")].freeze
    end
    join_native(context)
    context.fetch(:bytes)
  end

  def publish_signal_policy(original, custom: nil)
    policy = { original: original, custom: custom, old: nil, displaced: nil,
               ruby_install: :unattempted, ruby_restore: :unattempted,
               installed: false, restored: false, restoration: :unattempted,
               operations: [], error: nil }
    @signal_policies ||= []
    @signal_policies << policy # BEFORE any Ruby/native signal mutation.
    policy
  end

  def assert_waitable_snapshot(bytes)
    abi = Native.declared_abi
    fields, constants = abi.values_at("sigaction", "constants")
    fields = fields.fetch("fields")
    handler = bytes.byteslice(fields.fetch("handler").fetch("offset"), 8).unpack1("Q<")
    flags = bytes.byteslice(fields.fetch("flags").fetch("offset"), 4).unpack1("L<")
    refute_equal constants.fetch("SIG_IGN"), handler, "fixture caller must initially be waitable"
    assert_equal 0, flags & constants.fetch("SA_NOCLDWAIT"), "fixture caller must initially be waitable"
  end

  def restore_signal_policy(policy)
    return true if policy.fetch(:restored)
    return false unless policy.fetch(:installed) # Missing mutation receipt is retained, never guessed/retried.
    raise "signal restoration cannot be retried" unless policy.fetch(:restoration) == :unattempted

    Thread.handle_interrupt(Exception => :never) do
      policy[:restoration] = :in_flight
      if policy.fetch(:custom)
        policy[:ruby_restore] = :in_flight
        policy[:displaced] = Signal.trap("CHLD", policy.fetch(:old))
        policy[:ruby_restore] = :returned
      end
    end
    native_install_signal(policy.fetch(:original), policy: policy, restoring: true)
    assert_equal signal_fields(policy.fetch(:original)), signal_fields(native_signal_snapshot)
    assert_same policy.fetch(:custom), policy.fetch(:displaced) if policy.fetch(:custom)
    policy[:restoration] = :returned
    policy[:restored] = true
    true
  rescue Exception => error
    policy[:restoration] = :unknown
    policy[:error] ||= error
    raise
  end

  def native_install_signal(bytes, policy:, restoring: false)
    # Test-owned disposition mutation only, never a production admission helper.
    # All original pointers/masks/flags come from an actual saved public query.
    operation = { context: nil, call: nil, state: :unattempted, error: nil,
                  purpose: restoring ? :restore : :install }
    policy.fetch(:operations) << operation
    context = begin_native do |acq, result|
      operation[:context] = result
      acq.__send__(:runtime!)
      abi = Native.declared_abi
      layout = abi.fetch("sigaction")
      raise "invalid saved disposition size" unless bytes.bytesize == layout.fetch("size")
      storage = acq.__send__(:buffer!, "fixture_signal_restore", layout.fetch("size"), layout.fetch("align"))
      storage.pointer[0, bytes.bytesize] = bytes
      Thread.handle_interrupt(Exception => :never) do
        operation[:state] = :in_flight
        call = operation[:call] = acq.__send__(:native_call!, "sigaction", abi.fetch("constants").fetch("SIGCHLD"), storage.pointer, 0)
        operation[:state] = :returned
        raise Native::Error.new("waitability", errno: call.errno) unless call.result == 0
      end
    end
    join_native(context)
    assert_equal :returned, operation.fetch(:state)
    policy[:installed] = true unless restoring
    true
  rescue Exception => error
    operation[:state] = :unknown if operation && operation[:state] == :in_flight
    operation[:error] ||= error if operation
    raise
  end

  def signal_fields(bytes)
    abi = Native.declared_abi
    fields = abi.fetch("sigaction").fetch("fields")
    # Compare meaningful signal bits, not libc sigset/structure padding.
    mask_size = (abi.fetch("constants").fetch("NSIG") - 1 + 7) / 8
    [bytes.byteslice(fields.fetch("handler").fetch("offset"), 8),
     bytes.byteslice(fields.fetch("flags").fetch("offset"), 4),
     bytes.byteslice(fields.fetch("mask").fetch("offset"), mask_size)]
  end

  public

  def teardown
    return unless @native_contexts || @owned_paths || @signal_policies
    verified_complete = false
    complete = !@signal_policies || @signal_policies.all? { |policy| policy.fetch(:restored) }
    errors = @fixture_cleanup_errors = []
    begin
      @native_contexts&.reverse_each do |context|
        slot, acq = context.values_at(:slot, :acq)
        fixture_cleanup_step(errors) do
          unless slot.joined?
            acq.close_launch!
            slot.cancel!(reason_code: "lifecycle")
          end
        end
        if context[:fifo_path]
          # Closing the opposite, unborrowed GO writer and releasing only our
          # FIFO can settle a late actual native call. Neither authorizes GO.
          fixture_cleanup_step(errors) do
            writer = context[:go_writer] || acq.resources[:go_write]
            writer.close_once if writer && writer.state == :open
          end
          fixture_cleanup_step(errors) { release_fixture_fifo(context) } if spawn_in_flight?(context)
          fixture_cleanup_step(errors) { close_fixture_writer_once(context.fetch(:fifo_writer)) } if context[:fifo_writer]
        end
        creator_stopped = fixture_cleanup_step(errors) do
          slot.joined? || (!slot.start_attempted? && slot.thread.nil?) || slot.join_until(deadline_ns: context.fetch(:hard))
        end
        if creator_stopped
          fixture_cleanup_step(errors) do
            unless context.fetch(:finish_attempted)
              context[:finish_attempted] = true
              context[:finish_returned] = acq.finish_creation!(creator_slot: slot)
            end
          end
          acq.resources.each_value do |lease|
            fixture_cleanup_step(errors) do
              next if %i[closed not_acquired].include?(lease.state) || lease.process_lifetime?
              assert_equal :open, lease.state, "unsettled original endpoint"
              assert lease.close_once
              assert_equal :closed, lease.state
            end
          end
          # IO/native cleanup uncertainty does not erase the genuine exact
          # Child's wait route after its actual creator join. Account it too.
          fixture_cleanup_step(errors) { wait_native(context) } if slot.joined? && acq.child && %i[running pollable].include?(acq.child.state)
        else
          fixture_cleanup_step(errors) { acq.mark_unknown!(Native::Error.new("join")) }
        end
        actual_finality = slot.joined? || (!slot.start_attempted? && slot.thread.nil? && acq.not_attempted?)
        finalized = context.fetch(:finish_returned) && actual_finality && acq.state != :unknown &&
                    (acq.not_attempted? || acq.child&.state == :reaped) &&
                    acq.resources.values.all? { |lease| %i[closed not_acquired].include?(lease.state) }
        finalized &&= !context[:fifo_writer] || %i[unattempted not_acquired closed].include?(context.fetch(:fifo_writer).fetch(:state))
        complete &&= finalized
      end
      complete &&= !@owned_paths || @owned_paths.all? do |record|
        %i[fifo_state directory_state].all? { |key| %i[unattempted open removed].include?(record.fetch(key)) }
      end
      complete &&= errors.empty?
      if complete
        @owned_paths&.reverse_each do |record|
          complete &&= fixture_cleanup_step(errors) { remove_fixture_fifo(record) }
        end
      end
      raise errors.first unless errors.empty?
      flunk "native fixture retained unresolved own custody; no raw retry or removal" unless complete

      verified_complete = true
    ensure
      # Retain the entire live fixture, including signal policy/callback roots,
      # raw-IO close attempts, partially published temp paths and cleanup errors.
      # This also covers an exception in identity checks or removal itself.
      RETAINED[object_id] = self unless verified_complete
    end
  end
end
