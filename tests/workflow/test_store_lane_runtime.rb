# frozen_string_literal: true

# Filesystem/exception models only. The exact ExitBoundary is intercepted with
# a local throw BEFORE run!, and no Fastlane, Store, child, signal or thread is
# started. These definitions are NOT native exit/group/clock verification.
require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "../../fastlane/store_lane_runtime"
require_relative "store_lane_native_fixture"

class StoreLaneRuntimeTest < Minitest::Test
  RuntimeModule = MobileReleaseKit::StoreLaneRuntime
  Lifetime = MobileReleaseKit::StoreLaneLifetime
  Native = MobileReleaseKit::NativeProcessSpawn
  Publication = MobileReleaseKit::StoreDocument::Publication
  Terminal = RuntimeModule.const_get(:TerminalPublication, false)

  def setup
    @previous_environment, @previous_cwd = ENV.to_h, Dir.pwd
    @previous_runtime = RuntimeModule.instance_variable_get(:@runtime)
    @previous_invocation = Lifetime.instance_variable_get(:@invocation)
    @root = File.realpath(Dir.mktmpdir("mrk-store-runtime-model-"))
    value = File.lstat(@root)
    @root_identity = [value.dev, value.ino]
    @opened, @codes, @case_number = [], [], 0
  end

  def teardown
    Dir.chdir(@previous_cwd)
    ENV.replace(@previous_environment)
    RuntimeModule.instance_variable_set(:@runtime, @previous_runtime)
    Lifetime.instance_variable_set(:@invocation, @previous_invocation)
    assert @opened.all? { |file| file.closed? }, "model left an original product FD open"
    value = File.lstat(@root)
    assert value.directory? && !value.symlink? && [value.dev, value.ino] == @root_identity
    FileUtils.remove_entry(@root) # Exclusive inert fixture, all owned FDs closed.
  end

  def scenario
    @case_number += 1
    base = File.join(@root, "case-#{@case_number}")
    Dir.mkdir(base, 0o700)
    @lane_root, @output = File.join(base, "lane"), File.join(base, "receipt.json")
    [@lane_root, File.join(@lane_root, "tmp"), File.join(@lane_root, "runner")].each { |path| Dir.mkdir(path, 0o700) }
    root_stat = File.stat(@lane_root)
    @deadline = Native.monotonic_ns + 3_600_000_000_000
    ENV.keys.grep(/\AMOBILE_RELEASE_STORE_LANE_/).each { |key| ENV.delete(key) }
    ENV.update("MOBILE_RELEASE_OPERATION" => "android_external_promote", "MOBILE_RELEASE_STORE_MODE" => "prepare",
      "MOBILE_RELEASE_STORE_RECEIPT_PATH" => @output, "MOBILE_RELEASE_STORE_LANE_NONCE" => "a" * 32,
      "MOBILE_RELEASE_STORE_LANE_ROOT" => @lane_root,
      "MOBILE_RELEASE_STORE_LANE_ROOT_ID" => "#{root_stat.dev}:#{root_stat.ino}",
      "MOBILE_RELEASE_STORE_LANE_CLOCK" => Native.monotonic_domain,
      "MOBILE_RELEASE_STORE_LANE_RUN_DEADLINE_NS" => @deadline.to_s,
      "MOBILE_RELEASE_STORE_LANE_HARD_DEADLINE_NS" => (@deadline + 3_000_000_000).to_s,
      "TMPDIR" => File.join(@lane_root, "tmp"), "TMP" => File.join(@lane_root, "tmp"), "TEMP" => File.join(@lane_root, "tmp"))
    ENV.delete("MOBILE_RELEASE_IOS_IPA_PATH")
    Dir.chdir(File.join(@lane_root, "runner"))
    boundary = RuntimeModule.const_get(:ExitBoundary, false).new
    codes = @codes
    boundary.define_singleton_method(:exit_status!) { |status| codes << status; throw :store_runtime_model_exit, status }
    @runtime = RuntimeModule::Runtime.new(boundary)
    RuntimeModule.instance_variable_set(:@runtime, @runtime)
    Lifetime.instance_variable_set(:@invocation, nil)
    # Inert caller model, not acceptance of the pinned Fastlane installer.
    @runtime.define_singleton_method(:install_fastlane_bridges!) do
      @bridges_attempted = @bridges_installed = true
      true
    end
    @runtime
  end

  def observe_files(configure = nil)
    original = File.method(:open)
    wrapper = lambda do |path, *arguments, **keywords|
      file = original.call(path, *arguments, **keywords)
      @opened << file
      role = if path == "terminal.part"
               :terminal_writer
             elsif path == @lane_root && @runtime.instance_variable_get(:@publisher)
               :terminal_root
             else
               :other
             end
      configure&.call(role, file)
      file
    end
    File.stub(:open, wrapper) { yield }
  end

  def run_model(&body)
    catch(:store_runtime_model_exit) do
      @runtime.run!("android_external_promote") do |runtime|
        runtime.install_fastlane_bridges!
        body.call(runtime)
      end
      flunk "explicit boundary unexpectedly returned"
    end
  end

  def document(runtime)
    owner = Publication.new(path: @output, contents: {"fixture" => "original-document"})
    runtime.invocation.reserve_store_document!(owner)
    owner.publish!
    runtime.invocation.record_store_document!(owner)
    owner
  end

  def frame
    JSON.parse(File.binread(File.join(@lane_root, "terminal.json")))
  end

  def test_completed_success_binds_original_document_after_all_original_closes_before_link
    scenario
    links, owner = [], nil
    actual = File.method(:link)
    wrapper = lambda do |source, destination|
      if source == "terminal.part"
        publisher = @runtime.instance_variable_get(:@publisher)
        assert publisher.instance_variable_get(:@root).retired?
        assert publisher.instance_variable_get(:@writer).retired?
        assert @runtime.resources.sealed_and_retired?
      end
      links << [source, destination]
      actual.call(source, destination)
    end
    observe_files do
      File.stub(:link, wrapper) { assert_equal 0, run_model { |runtime| owner = document(runtime) } }
    end
    assert_equal ["terminal.part", "terminal.json"], links.last
    assert_equal "success", frame.fetch("outcome")
    assert_equal owner.result.fetch("sha256"), frame.fetch("receipt").fetch("sha256")
    assert_equal owner.result.fetch("identity").fetch("inode"), frame.fetch("receipt").fetch("inode")
    assert_equal @deadline, frame.fetch("run_deadline_ns")
    assert_empty frame.fetch("inventory")
    %w[terminal.part terminal.json].each do |name|
      stat = File.lstat(File.join(@lane_root, name))
      assert_equal 2, stat.nlink
      assert_equal 0o600, stat.mode & 0o7777
      assert_equal frame.fetch("terminal_identity").fetch("inode"), stat.ino
    end
    assert_raises(RuntimeModule::Error) { @runtime.run!("android_external_promote") {} }
  end

  def test_ordinary_lane_failure_and_missing_document_are_settled75_not_success
    [RuntimeError.new("ordinary synthetic failure"), nil].each do |primary|
      scenario
      code = observe_files { run_model { raise primary if primary } }
      assert_equal 75, code
      assert_equal "failed", frame.fetch("outcome")
      assert_nil frame.fetch("receipt")
      assert_same primary, @runtime.first_primary if primary
      assert @runtime.invocation.uploads_sealed_and_retired?
      assert @runtime.resources.sealed_and_retired?
      refute File.exist?(@output)
    end
  end

  def test_original_interrupt_and_arbitrary_system_exit0_or75_never_authorize_terminal_binding
    [Interrupt.new("model interruption"), SystemExit.new(0), SystemExit.new(75)].each do |primary|
      scenario
      assert_equal 76, observe_files { run_model { raise primary } }
      assert_same primary, @runtime.first_primary
      assert_same primary, @runtime.invocation.first_primary
      refute File.exist?(File.join(@lane_root, "terminal.json"))
      assert @runtime.invocation.unknown?
    end
  end

  def test_swallowed_original_unknown_and_nonlocal_lane_completion_cannot_become_ordinary_failure
    scenario
    original = IOError.new("original swallowed producer error")
    assert_equal 76, observe_files { run_model { |runtime| runtime.invocation.mark_unknown!(original) } }
    assert_same original, @runtime.first_primary
    refute File.exist?(File.join(@lane_root, "terminal.json"))
    scenario
    observed = catch(:foreign_lane_return) do
      observe_files { run_model { throw :foreign_lane_return, :not_a_completion } }
    end
    assert_equal 76, observed
    assert @runtime.invocation.unknown?
  end

  def test_terminal_writer_and_root_close_errors_are_fatal_and_all_independent_closes_are_single_attempt
    %i[terminal_writer terminal_root].each do |fault_role|
      scenario
      primary, closes = IOError.new("returned close failure"), []
      configure = lambda do |role, file|
        next unless %i[terminal_writer terminal_root].include?(role)
        actual = file.method(:close)
        file.define_singleton_method(:close) do
          closes << role
          actual.call
          raise primary if role == fault_role
        end
      end
      assert_equal 76, observe_files(configure) { run_model { |runtime| document(runtime) } }
      assert_equal %i[terminal_writer terminal_root], closes
      assert_same primary, @runtime.first_primary
      assert_includes @runtime.invocation.cleanup_errors, primary
      refute File.exist?(File.join(@lane_root, "terminal.json"))
      assert File.exist?(File.join(@lane_root, "terminal.part"))
    end
  end

  def test_stage_collision_is_preserved_and_missing_writer_acquisition_is_not_adopted
    scenario
    stage = File.join(@lane_root, "terminal.part")
    File.binwrite(stage, "foreign stage")
    original = File.lstat(stage)
    assert_equal 76, observe_files { run_model {} }
    assert_equal "foreign stage", File.binread(stage)
    assert_equal original.ino, File.lstat(stage).ino
    refute File.exist?(File.join(@lane_root, "terminal.json"))
    assert @runtime.invocation.unknown?
  end

  def test_link_collision_replacement_or_lost_success_return_always_preserves_bytes_and_exits76
    %i[before collision after replacement].each do |cut|
      scenario
      primary = IOError.new("synthetic link cut")
      actual = File.method(:link)
      wrapper = lambda do |source, destination|
        raise primary if cut == :before
        File.binwrite(destination, "foreign completion") if cut == :collision
        if cut == :replacement
          File.rename(source, source + ".original")
          File.binwrite(source, "foreign replacement")
        end
        value = actual.call(source, destination)
        raise primary if cut == :after
        value
      end
      observe_files { File.stub(:link, wrapper) { assert_equal 76, run_model {} } }
      refute @runtime.instance_variable_get(:@publisher).completed?
      assert File.exist?(File.join(@lane_root, "terminal.part"))
      if cut == :collision
        assert_equal "foreign completion", File.binread(File.join(@lane_root, "terminal.json"))
      elsif cut == :replacement
        assert_equal "foreign replacement", File.binread(File.join(@lane_root, "terminal.json"))
        assert File.exist?(File.join(@lane_root, "terminal.part.original"))
      elsif cut == :after
        assert_equal "failed", frame.fetch("outcome")
      else
        refute File.exist?(File.join(@lane_root, "terminal.json"))
      end
    end
  end

  def test_postlink_pending_interruption_or_expired_original_deadline_denies_existing_valid_frame
    [Interrupt.new("pending completion interruption"), SystemExit.new(0), SystemExit.new(75)].each do |primary|
      scenario
      @runtime.define_singleton_method(:require_completion!) { raise primary }
      assert_equal 76, observe_files { run_model {} }
      assert File.exist?(File.join(@lane_root, "terminal.json"))
      assert_includes [@runtime.first_primary, *@runtime.secondary_errors], primary
    end
    scenario
    actual = Native.method(:monotonic_ns)
    clock = -> { File.exist?(File.join(@lane_root, "terminal.json")) ? @deadline : actual.call }
    observe_files { Native.stub(:monotonic_ns, clock) { assert_equal 76, run_model {} } }
    assert File.exist?(File.join(@lane_root, "terminal.json"))
    refute @runtime.instance_variable_get(:@publisher).completed?
  end

  def test_changed_environment_or_terminal_root_refuses_before_foreign_publication
    scenario
    assert_equal 76, observe_files { run_model { ENV["TMPDIR"] = @root } }
    refute File.exist?(File.join(@lane_root, "terminal.json"))
    scenario
    configure = lambda do |role, _file|
      next unless role == :terminal_root
      File.rename(@lane_root, @lane_root + ".original")
      Dir.mkdir(@lane_root, 0o700)
      File.binwrite(File.join(@lane_root, "sentinel"), "foreign root")
    end
    assert_equal 76, observe_files(configure) { run_model {} }
    assert_equal "foreign root", File.binread(File.join(@lane_root, "sentinel"))
    refute File.exist?(File.join(@lane_root, "terminal.part"))
  end

  def test_shared_clock_uses_only_fixed_platform_domain_and_no_relative_fallback
    config = RbConfig::CONFIG
    fetch = config.method(:fetch)
    selected = []
    config.stub(:fetch, ->(key, *rest) { key == "host_os" ? "linux-gnu" : fetch.call(key, *rest) }) do
      Process.stub(:clock_gettime, ->(clock, unit) { selected << [clock, unit]; 123 }) do
        assert_equal "linux-monotonic-v1", Native.monotonic_domain
        assert_equal 123, MobileReleaseKit::NativeUploadProcess.monotonic_ns
      end
    end
    assert_equal [[Process::CLOCK_MONOTONIC, :nanosecond]], selected
    config.stub(:fetch, ->(key, *rest) { key == "host_os" ? "unsupported" : fetch.call(key, *rest) }) do
      assert_raises(Native::Error) { Native.monotonic_ns }
    end
    # The native macOS paired-clock gate must run on macOS. No Linux fake clock
    # constant or mocked sample is presented as evidence of that domain.
    binding_entry_handoff_contracts
  end

  def binding_entry_handoff_contracts
    fixture = StoreLaneNativeFixture
    source = File.expand_path("../..", __dir__)
    work = File.join(File.dirname(source), "work")
    value_type = Struct.new(:dev, :uid, :gid, :mode, :kind) do
      def directory? = kind == :directory
      def symlink? = kind == :symlink
    end
    faults = %i[valid legacy_form phase directory_name relative_case source_link parent_link
                root_owner root_mode root_device leaf_owner leaf_group leaf_mode leaf_device leaf_type leaf_link cache environment]
    %w[source wheel].each do |phase|
      faults.each do |fault|
        directory = File.join(work, "store-lane", phase, "binding-capture")
        nodes = {}
        [source, work, File.join(work, "store-lane"), File.dirname(directory), directory].each do |path|
          nodes[path] = value_type.new(5, 0, 0, 0o40755, :directory)
        end
        %w[home tmp gem-cache bundle-config bundle-home].each do |name|
          nodes[File.join(directory, name)] = value_type.new(5, 61001, 61001, 0o40700, :directory)
        end
        changes = {
          root_owner: [directory, :uid, 61001], root_mode: [directory, :mode, 0o40777], root_device: [directory, :dev, 6],
          leaf_owner: [File.join(directory, "tmp"), :uid, 0], leaf_group: [File.join(directory, "tmp"), :gid, 0],
          leaf_mode: [File.join(directory, "tmp"), :mode, 0o40755], leaf_device: [File.join(directory, "tmp"), :dev, 6],
          leaf_type: [File.join(directory, "tmp"), :kind, :file], leaf_link: [File.join(directory, "tmp"), :kind, :symlink]
        }
        if changes.key?(fault)
          path, field, value = changes.fetch(fault)
          nodes.fetch(path)[field] = value
        end
        environment = {"HOME" => File.join(work, "home"), "TMPDIR" => File.join(work, "tmp"),
          "TMP" => File.join(work, "tmp"), "TEMP" => File.join(work, "tmp"),
          "GEM_SPEC_CACHE" => File.join(directory, "gem-cache"), "BUNDLE_APP_CONFIG" => File.join(directory, "bundle-config"),
          "BUNDLE_USER_HOME" => File.join(directory, "bundle-home")}
        environment["BUNDLE_USER_HOME"] = File.join(work, "bundle-home") if fault == :cache
        environment["HOME"] = "/unaccounted/home" if fault == :environment
        before = environment.dup
        prefix = phase == "source" ? source : File.join(work, "wheel-venv")
        modules = phase == "source" ? File.join(source, "src") : File.join(prefix, "lib/python3.11/site-packages")
        arguments = [phase, prefix, source, modules, directory]
        arguments.concat([File.join(work, "wheels/fixed.whl"), "a" * 64]) if phase == "wheel"
        arguments.delete_at(4) if fault == :legacy_form
        arguments[0] = "unknown" if fault == :phase
        arguments[4] = File.join(File.dirname(directory), "case-01") if fault == :directory_name
        arguments[4] = "binding-capture" if fault == :relative_case
        lookup = lambda do |path|
          assert nodes.key?(path), "unexpected binding filesystem lookup #{path}"
          nodes.fetch(path)
        end
        resolve = lambda do |path|
          assert nodes.key?(path), "unexpected binding filesystem lookup #{path}"
          (fault == :source_link && path == source) || (fault == :parent_link && path == File.dirname(directory)) ? path + "-alias" : path
        end
        imports = []
        stopped = RuntimeError.new("first fixture import after binding entry selection")
        importing = lambda do |path|
          imports << path
          assert_equal File.join(source, "tests/workflow/installed_ruby_capture_fixture.rb"), path
          assert_equal File.join(directory, "home"), environment.fetch("HOME")
          assert_equal [File.join(directory, "tmp")] * 3, environment.values_at("TMPDIR", "TMP", "TEMP")
          raise stopped
        end
        File.stub(:lstat, lookup) do
          File.stub(:realpath, resolve) do
            Process.stub(:euid, 61001) do
              Process.stub(:egid, 61001) do
                ENV.stub(:[], ->(key) { environment[key] }) do
                  ENV.stub(:update, ->(values) { environment.update(values) }) do
                    fixture.stub(:require, importing) do
                      if fault == :valid
                        assert_same stopped, assert_raises(RuntimeError) { fixture.binding_record(arguments) }
                        assert_equal 1, imports.length
                        fixture.select_binding_environment(phase, source, directory) # Repeated explicit placement remains valid.
                        assert_equal File.join(directory, "home"), environment.fetch("HOME")
                      else
                        assert_raises(fixture::Failure) { fixture.binding_record(arguments) }
                        assert_equal before, environment
                        assert_empty imports
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
