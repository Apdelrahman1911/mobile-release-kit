# frozen_string_literal: true

# Filesystem/exception models only. The exact ExitBoundary is intercepted with
# a local throw BEFORE run!, and no Fastlane, Store, child, signal or thread is
# started. These definitions are NOT native exit/group/clock verification.
require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "../../fastlane/store_lane_runtime"
require_relative "../../fastlane/ios_upload_validation"
require_relative "store_lane_native_fixture"
require_relative "upload_process_ownership"

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

  def scenario(lane: "android_external_promote", mode: "prepare", observer_model: false)
    @case_number += 1
    base = File.join(@root, "case-#{@case_number}")
    Dir.mkdir(base, 0o700)
    @lane_root, @output = File.join(base, "lane"), File.join(base, "receipt.json")
    [@lane_root, File.join(@lane_root, "tmp"), File.join(@lane_root, "runner")].each { |path| Dir.mkdir(path, 0o700) }
    root_stat = File.stat(@lane_root)
    @deadline = Native.monotonic_ns + 3_600_000_000_000
    ENV.keys.grep(/\AMOBILE_RELEASE_STORE_LANE_/).each { |key| ENV.delete(key) }
    ENV.update("MOBILE_RELEASE_OPERATION" => lane, "MOBILE_RELEASE_STORE_MODE" => mode,
      "MOBILE_RELEASE_STORE_RECEIPT_PATH" => @output, "MOBILE_RELEASE_STORE_LANE_NONCE" => "a" * 32,
      "MOBILE_RELEASE_STORE_LANE_ROOT" => @lane_root,
      "MOBILE_RELEASE_STORE_LANE_ROOT_ID" => "#{root_stat.dev}:#{root_stat.ino}",
      "MOBILE_RELEASE_STORE_LANE_CLOCK" => Native.monotonic_domain,
      "MOBILE_RELEASE_STORE_LANE_RUN_DEADLINE_NS" => @deadline.to_s,
      "MOBILE_RELEASE_STORE_LANE_HARD_DEADLINE_NS" => (@deadline + 3_000_000_000).to_s,
      "TMPDIR" => File.join(@lane_root, "tmp"), "TMP" => File.join(@lane_root, "tmp"), "TEMP" => File.join(@lane_root, "tmp"))
    ENV.delete("MOBILE_RELEASE_IOS_IPA_PATH")
    if lane == "ios_testflight_internal"
      @artifact = File.join(base, "original.ipa")
      File.binwrite(@artifact, "inert original IPA bytes\x00\xff".b)
      ENV.update("MOBILE_RELEASE_IOS_IPA_PATH" => @artifact, "MOBILE_RELEASE_ASC_APP_ID" => "12345",
        "MOBILE_RELEASE_ASC_KEY_ID" => "KEY123")
    end
    Dir.chdir(File.join(@lane_root, "runner"))
    boundary = RuntimeModule.const_get(:ExitBoundary, false).new
    codes = @codes
    unless observer_model
      boundary.define_singleton_method(:exit_status!) { |status| codes << status; throw :store_runtime_model_exit, status }
    end
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

  def observe_files(configure = nil, before_open: nil, owning_closes: false)
    original, assertions = File.method(:open), self
    wrapper = lambda do |path, *arguments, **keywords, &block|
      before_open&.call(path, arguments, keywords, block)
      record_file = lambda do |file|
        @opened << file
        if owning_closes
          close, calls = file.method(:close), 0
          file.define_singleton_method(:close) do
            calls += 1
            assertions.assert_equal 1, calls, "original close was retried"
            assertions.assert_equal true, autoclose?, "original File close was not armed"
            returned = close.call
            assertions.assert_nil returned, "original close did not return nil"
            returned
          end
        end
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
      if block
        original.call(path, *arguments, **keywords) { |file| block.call(record_file.call(file)) }
      else
        record_file.call(original.call(path, *arguments, **keywords))
      end
    end
    File.stub(:open, wrapper) { yield }
  end

  def run_model(&body)
    catch(:store_runtime_model_exit) do
      @runtime.run!(ENV.fetch("MOBILE_RELEASE_OPERATION")) do |runtime|
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

  def bind_runtime_ios_validation(record, expires)
    adapter, native = MobileReleaseKit::IosUploadValidation, MobileReleaseKit::NativeUploadValidation
    type = native.const_get(:CaptureSession, false)
    base = File.dirname(@output)
    config, intent = %w[config.json intent.json].map { |name| File.join(base, name) }
    [config, intent].each { |path| File.write(path, "{}") }
    output = JSON.generate("documentType" => "ios-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64, "ipaSha256" => Digest::SHA256.file(@artifact).hexdigest,
      "ipaSize" => File.size(@artifact), "notBefore" => "2020-01-01T00:00:00Z", "notAfter" => expires.iso8601).freeze
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
        adapter.current!(python: RbConfig.ruby, module_root: File.expand_path("../../src", __dir__),
          app_root: base, config_path: config, intent_path: intent, ipa_path: @artifact,
          intent_sha256: "a" * 64, environment: {}, tooling_directory: File.expand_path("../../fastlane", __dir__))
      end
    end
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
    observe_files(owning_closes: true) do
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

  def test_original_ios_no_send_refusal_is_settled75_but_ambiguous_resource_close_is76
    [false, true].each do |close_fails|
      scenario(lane: "ios_testflight_internal", mode: "execute")
      expected_digest = Digest::SHA256.hexdigest(File.binread(@artifact))
      clock = Time.utc(2026, 9, 16, 12)
      cleanup = IOError.new("synthetic resource close after no-send")
      code = Time.stub(:now, -> { clock }) do
        observe_files(owning_closes: true) do
          run_model do |runtime|
            validation = bind_runtime_ios_validation(runtime.invocation, clock + 1)
            assert_equal expected_digest, validation.fetch("ipaSha256")
            if close_fails
              file = runtime.resources.instance_variable_get(:@handles).first.io
              original = file.method(:close)
              file.define_singleton_method(:close) { original.call; raise cleanup }
            end
            clock += 1
            runtime.invocation.begin_ios_transporter_dispatch!(command: "never-executed", artifact: @artifact)
            flunk "expired original interval passed dispatch admission"
          end
        end
      end
      assert_equal(close_fails ? 76 : 75, code)
      assert_instance_of Lifetime::IosDispatchRefused, @runtime.first_primary
      assert_same @runtime.first_primary, @runtime.invocation.first_primary
      refute File.exist?(@output)
      if close_fails
        assert @runtime.invocation.unknown?
        assert_includes @runtime.invocation.cleanup_errors, cleanup
        refute File.exist?(File.join(@lane_root, "terminal.json"))
      else
        assert_equal "failed", frame.fetch("outcome")
        assert_nil frame.fetch("receipt")
        assert @runtime.invocation.uploads_sealed_and_retired?
        assert @runtime.resources.sealed_and_retired?
        refute @runtime.invocation.unknown?
      end
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
      begin
        raise primary, cause: ArgumentError.new("synthetic original cause")
      rescue IOError => error
        assert_same primary, error
      end
      cause = primary.cause
      configure = lambda do |role, file|
        next unless %i[terminal_writer terminal_root].include?(role)
        actual = file.method(:close)
        file.define_singleton_method(:close) do
          closes << role
          actual.call
          raise primary if role == fault_role
        end
      end
      assert_equal 76, observe_files(configure, owning_closes: true) { run_model { |runtime| document(runtime) } }
      assert_equal %i[terminal_writer terminal_root], closes
      assert_same primary, @runtime.first_primary
      assert_same cause, primary.cause
      assert_includes @runtime.invocation.cleanup_errors, primary
      publisher = @runtime.instance_variable_get(:@publisher)
      failed = publisher.instance_variable_get(fault_role == :terminal_writer ? :@writer : :@root)
      assert_equal 2, failed.close_errors.length
      assert_same primary, failed.close_errors.first
      assert_instance_of IOError, failed.close_errors.last
      failed.close_errors.each { |error| assert_includes @runtime.invocation.cleanup_errors, error }
      assert_includes @opened, failed.io
      refute failed.retired?
      refute publisher.completed?
      snapshot = @runtime.invocation.cleanup_errors
      publisher.close_independent!
      assert_equal %i[terminal_writer terminal_root], closes
      assert_equal snapshot, @runtime.invocation.cleanup_errors
      assert_same publisher, @runtime.instance_variable_get(:@publisher)
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

  def test_native_observer_failure_attribution_is_single_attempt_and_prefinal
    fixture = StoreLaneNativeFixture
    assert_equal %w[success0 ordinary75 nested-ios-success nested-android-success
                    nested-android-inherited-pipe bridge-success bridge-ordinary-error], fixture::EARLY_UNKNOWN_MODES
    %i[before_binding before_resources].each do |cut|
      with_native_observer_model do |observer, probe|
        primary = RuntimeModule::Error.new(cut == :before_binding ? :clock : :resources_missing)
        action = -> { run_model { flunk "early refused runtime entered its lane" } }
        code = if cut == :before_binding
                 Native.stub(:monotonic_domain, -> { raise primary }) { action.call }
               else
                 MobileReleaseKit::StoreLaneResources::Inventory.stub(:new, ->(**_arguments) { raise primary }) { action.call }
               end
        assert_equal 76, code
        assert_same primary, @runtime.first_primary
        assert_nil @runtime.instance_variable_get(:@resources)
        assert_equal(cut == :before_binding, @runtime.instance_variable_get(:@binding).nil?)
        assert_native_observer_minimal(observer, probe, "unknown-exit76", primary)
        assert_equal ["unknown-exit76"], probe.fetch(:stages)
        assert_equal [76], probe.fetch(:forwarded)
      end
    end

    with_native_observer_model(mode: "clock-wrong-label") do |observer, probe|
      ENV["MOBILE_RELEASE_STORE_LANE_CLOCK"] = "unsupported-peer-domain"
      assert_equal 76, run_model { flunk "wrong clock entered lane" }
      assert_equal :clock, @runtime.first_primary.reason
      assert File.zero?(probe.fetch(:path))
      refute observer.instance_variable_get(:@flush_attempted)
      assert_empty probe.fetch(:stages)
      assert_equal 0, probe.fetch(:counts).fetch(:open)
    end

    # One absent primary, one existing primary, then the three distinct ways
    # fallback can itself fail. The restoration cut loses only its return: all
    # original hooks have really been restored before the synthetic exception.
    [[false, :restoration, nil], [true, :provenance, nil], [true, :provenance, :serialization],
     [true, :provenance, :write], [true, :provenance, :close]].each do |ordinary, cut, fault|
      preparation = IOError.new("fixed observer preparation failure")
      with_native_observer_model(fault: fault, preparation: preparation, cut: cut) do |observer, probe|
        first = ordinary ? observer.ordinary : nil
        original = observer.method(:flush)
        observed = []
        flushing = lambda do |stage|
          before = [@runtime.first_primary, @runtime.secondary_errors, @runtime.cleanup_errors]
          begin
            original.call(stage)
          rescue Exception => error # rubocop:disable Lint/RescueException
            observed << error
            assert_same preparation, error
            assert_equal before, [@runtime.first_primary, @runtime.secondary_errors, @runtime.cleanup_errors]
            raise
          end
        end
        code = observer.stub(:flush, flushing) do
          run_model { |runtime| ordinary ? (raise first) : document(runtime) }
        end
        assert_equal 76, code
        assert_equal [preparation], observed
        assert_same(first || preparation, @runtime.first_primary)
        assert_equal ["observer-preparation-failed"], probe.fetch(:stages)
        assert_equal 1, probe.fetch(:restores)
        assert_operator probe.fetch(:counts).fetch(:open), :<=, 1
        assert_operator probe.fetch(:counts).fetch(:close), :<=, 1
        refute File.exist?(File.join(@lane_root, "terminal.json"))
        assert_native_observer_minimal(observer, probe, "observer-preparation-failed", first, preparation) if fault.nil? || fault == :close
        assert File.zero?(probe.fetch(:path)) if %i[serialization write].include?(fault)
        before = probe.fetch(:counts).dup
        observer.unknown_exit76(probe.fetch(:boundary))
        assert_equal before, probe.fetch(:counts)
      end
    end

    # These faults happen only AFTER preparation. In particular no writer
    # failure can select a minimal fallback, reopen, or repeat the original close.
    %i[identity open write flush fsync close].each do |fault|
      with_native_observer_model(mode: "ordinary75", fault: fault) do |observer, probe|
        assert_equal 76, run_model { raise observer.ordinary }
        assert_same observer.ordinary, @runtime.first_primary
        assert_equal ["before-terminal-link"], probe.fetch(:stages)
        assert_equal 1, probe.fetch(:restores)
        counts = probe.fetch(:counts)
        assert_equal 1, counts.fetch(:open)
        assert_equal(fault == :open ? 0 : 1, counts.fetch(:close))
        assert_equal(%i[identity open].include?(fault) ? 0 : 1, counts.fetch(:write))
        assert_equal(%i[identity open write].include?(fault) ? 0 : 1, counts.fetch(:flush))
        assert_equal(%i[identity open write flush].include?(fault) ? 0 : 1, counts.fetch(:fsync))
        before = counts.dup
        assert_raises(fixture::Failure) { observer.flush("unknown-cleanup") }
        observer.unknown_exit76(probe.fetch(:boundary))
        assert_equal before, counts
        assert_equal [76], probe.fetch(:forwarded)
      end
    end

    [false, true].each do |ordinary|
      with_native_observer_model(mode: ordinary ? "ordinary75" : "success0") do |observer, probe|
        original_link = observer.method(:terminal_link)
        link = lambda do |original, arguments|
          forwarding = lambda do |*values|
            assert probe.fetch(:hooks_intact).call
            assert observer.instance_variable_get(:@closed)
            assert probe.fetch(:io).closed?
            probe.fetch(:events) << :terminal_link
            original.call(*values)
          end
          original_link.call(forwarding, arguments)
        end
        completion, assertions = @runtime.method(:require_completion!), self
        @runtime.define_singleton_method(:require_completion!) do
          assertions.assert probe.fetch(:hooks_intact).call
          assertions.assert probe.fetch(:io).closed?
          probe.fetch(:events) << :final_check
          completion.call
        end
        code = observer.stub(:terminal_link, link) do
          run_model { |runtime| ordinary ? (raise observer.ordinary) : document(runtime) }
        end
        assert_equal(ordinary ? 75 : 0, code)
        assert_equal %i[open write flush fsync close terminal_link final_check exit], probe.fetch(:events)
        assert probe.fetch(:hooks_intact).call
        value = JSON.parse(File.binread(probe.fetch(:path)))
        assert_equal "before-terminal-link", value.fetch("stage")
        assert value.fetch("observerRestored") && value.fetch("originalSlotsCovered")
        assert value.fetch("slots").all? { |row| row.fetch("calls") == 1 && row.fetch("returns") == 1 && row.fetch("retired") && row.fetch("closed") }
        refute value.key?("preparationDiagnostic")
      end
    end

    with_native_observer_model do |observer, probe|
      # Prime the real runtime's unknown state, suppressing only this first
      # optional observation. Every boundary call still uses the same local
      # captured throw; the real exit_status! body and class hook are exercised.
      observer.stub(:unknown_exit76, ->(_boundary) {}) do
        Native.stub(:monotonic_domain, -> { raise RuntimeModule::Error.new(:clock) }) do
          assert_equal 76, run_model { flunk "priming failure entered lane" }
        end
      end
      boundary = probe.fetch(:boundary)
      [0, 75].each { |status| assert_equal status, catch(:store_runtime_model_exit) { boundary.exit_status!(status) } }
      assert_equal :exit_status, assert_raises(RuntimeModule::Error) { boundary.exit_status!(76.0) }.reason
      assert_equal 76, catch(:store_runtime_model_exit) { boundary.exit_status!(76) { flunk "unexpected boundary block" } }
      observer.unknown_exit76(Object.new) # Not the captured original boundary.
      foreign = Object.new
      foreign.define_singleton_method(:origin!) { true }
      begin
        RuntimeModule.instance_variable_set(:@runtime, foreign)
        assert_equal 76, catch(:store_runtime_model_exit) { boundary.exit_status!(76) }
      ensure
        RuntimeModule.instance_variable_set(:@runtime, @runtime)
      end
      assert File.zero?(probe.fetch(:path))
      assert_empty probe.fetch(:stages)
      assert_equal 76, catch(:store_runtime_model_exit) { boundary.exit_status!(76) }
      assert_native_observer_minimal(observer, probe, "unknown-exit76", @runtime.first_primary)
      before = probe.fetch(:counts).dup
      assert_equal 76, catch(:store_runtime_model_exit) { boundary.exit_status!(76) }
      observer.unknown_exit76(boundary)
      observer.flush("unknown-cleanup") # A positively closed observation is inert.
      assert_equal before, probe.fetch(:counts)
      assert_equal [76, 0, 75, 76, 76, 76, 76], probe.fetch(:forwarded)
    end
  end

  def with_native_observer_model(mode: "success0", fault: nil, preparation: nil, cut: :provenance)
    fixture = StoreLaneNativeFixture
    previous = [[RuntimeModule, :@runtime], [RuntimeModule, :@exit_boundary], [Lifetime, :@invocation], [fixture, :@observer]].map do |owner, name|
      [owner, name, owner.instance_variable_defined?(name), owner.instance_variable_get(name)]
    end
    environment, cwd, previous_runtime = ENV.to_h, Dir.pwd, @runtime
    targets = [[RuntimeModule.const_get(:ExitBoundary, false), :exit_status!],
      [MobileReleaseKit::StoreLaneResources::FileSlot, :acquire], [Publication.const_get(:Handle, false), :acquire],
      [MobileReleaseKit::StoreLaneResources::Inventory, :close_independent!], [File.singleton_class, :link]]
    originals = targets.map { |target, name| [target, name, target.instance_method(name)] }
    probe = {counts: %i[open write flush fsync close].to_h { |name| [name, 0] }, stages: [], events: [], forwarded: [], restores: 0,
      error: IOError.new("fixed observer writer failure"), hooks_intact: -> { originals.all? { |target, name, original| target.instance_method(name) == original } }}
    scenario(observer_model: true)
    model_runtime = @runtime
    boundary = @runtime.instance_variable_get(:@exit_boundary)
    original_exit = boundary.instance_variable_get(:@exit)
    codes = @codes
    boundary.instance_variable_set(:@exit, lambda do |status|
      probe.fetch(:forwarded) << status
      probe.fetch(:events) << :exit
      codes << status
      throw :store_runtime_model_exit, status
    end)
    RuntimeModule.instance_variable_set(:@exit_boundary, boundary)
    probe[:boundary] = boundary
    path = probe[:path] = File.join(File.dirname(@output), "observation.json")
    File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW | File::NONBLOCK, 0o600) { |file| @opened << file }
    source = File.expand_path("../..", __dir__)
    request = {"mode" => mode, "phase" => "source", "root" => File.dirname(@output), "sourceRoot" => source,
      "diagnostic" => path, "diagnosticIdentity" => fixture.identity(File.lstat(path)),
      "binding" => {"files" => {"fastlane/store_lane_runtime.rb" => {"path" => File.join(source, "fastlane/store_lane_runtime.rb")}}},
      "fixtureFiles" => {"tests/workflow/store_lane_native_fixture.rb" => "model-only-no-source-import"}}
    observer = fixture::Observation.new(request)
    assertions = self
    configure = lambda do |_role, file|
      next unless file.path == path
      probe[:io] = file
      file.singleton_class # Stabilize Method equality before per-file wrappers.
      probe[:io_originals] = %i[stat write flush fsync close].to_h { |name| [name, file.method(name)] }
      if fault == :identity
        stat = file.stat
        different = stat.dup
        different.define_singleton_method(:ino) { stat.ino + 1 }
        file.define_singleton_method(:stat) { different }
      end
      %i[write flush fsync close].each do |name|
        original = file.method(name)
        file.define_singleton_method(name) do |*arguments|
          probe.fetch(:counts)[name] += 1
          probe.fetch(:events) << name
          raise probe.fetch(:error) if fault == name && name != :close
          assertions.assert_equal true, autoclose? if name == :close
          value = original.call(*arguments)
          assertions.assert_nil value if name == :close
          raise probe.fetch(:error) if fault == name # Close return loss, never an unclosed real FD.
          value
        end
      end
    end
    opening = lambda do |entry, arguments, keywords, block|
      next unless entry == path
      assert_equal [File::WRONLY | File::NOFOLLOW | File::NONBLOCK], arguments
      assert keywords.empty? && block.nil?
      probe.fetch(:counts)[:open] += 1
      probe.fetch(:events) << :open
      raise probe.fetch(:error) if fault == :open
    end
    actual_generate, actual_restore = JSON.method(:generate), observer.method(:restore_hooks!)
    generating = lambda do |value, *arguments, **keywords|
      if value.instance_of?(Hash) && value.key?("stage")
        probe.fetch(:stages) << value.fetch("stage")
        raise probe.fetch(:error) if fault == :serialization && value.fetch("stage") == "observer-preparation-failed"
      end
      actual_generate.call(value, *arguments, **keywords)
    end
    restoring = lambda do
      probe[:restores] += 1
      answer = actual_restore.call
      raise preparation if preparation && cut == :restoration
      answer
    end
    provenance = ->(_request) { raise preparation if preparation && cut == :provenance; {} }
    fixture.stub(:product_origins, provenance) do
      fixture.stub(:fastlane_origins, ->(_request) { {} }) do
        observer.stub(:restore_hooks!, restoring) do
          JSON.stub(:generate, generating) do
            observe_files(configure, before_open: opening) do
              fixture.install_observer(observer)
              yield observer, probe
            end
          end
        end
      end
    end
  ensure
    begin
      observer.restore_hooks! if observer && !observer.instance_variable_get(:@restore_attempted)
      assert probe.fetch(:hooks_intact).call if probe
      assert @opened.all?(&:closed?)
    ensure
      begin
        if probe && probe[:io]
          file = probe.fetch(:io)
          probe.fetch(:io_originals).each_key do |name|
            file.singleton_class.send(:remove_method, name) if file.singleton_methods(false).include?(name)
          end
          assert probe.fetch(:io_originals).all? { |name, original| file.method(name) == original }
        end
        if model_runtime && model_runtime.singleton_methods(false).include?(:require_completion!)
          model_runtime.singleton_class.send(:remove_method, :require_completion!)
        end
      ensure
        boundary.instance_variable_set(:@exit, original_exit) if boundary && original_exit
        previous&.each do |owner, name, present, value|
          present ? owner.instance_variable_set(name, value) : (owner.remove_instance_variable(name) if owner.instance_variable_defined?(name))
        end
        @runtime = previous_runtime
        Dir.chdir(cwd) if cwd
        ENV.replace(environment) if environment
      end
    end
  end

  def assert_native_observer_minimal(observer, probe, stage, primary, preparation = nil)
    value = JSON.parse(File.binread(probe.fetch(:path)))
    keys = %w[version mode phase stage primaryDiagnostic]
    keys << "preparationDiagnostic" if preparation
    assert_equal keys.sort, value.keys.sort
    assert_equal stage, value.fetch("stage")
    assert_equal StoreLaneNativeFixture.first_primary_diagnostic(primary, observer.request), value.fetch("primaryDiagnostic")
    category = primary.nil? ? "none" : (primary.instance_of?(RuntimeModule::Error) ? "store-runtime-error" : "ordinary-fixture-error")
    assert_equal category, value.fetch("primaryDiagnostic").fetch("category")
    assert_equal primary.reason.to_s, value.fetch("primaryDiagnostic").fetch("reason") if primary.instance_of?(RuntimeModule::Error)
    if preparation
      assert_equal StoreLaneNativeFixture.first_primary_diagnostic(preparation, observer.request), value.fetch("preparationDiagnostic")
      assert_equal "io-error", value.fetch("preparationDiagnostic").fetch("category")
    end
    assert_equal 1, probe.fetch(:counts).fetch(:open)
    assert_equal 1, probe.fetch(:counts).fetch(:close)
    assert probe.fetch(:io).closed?
    refute_includes File.binread(probe.fetch(:path)), @root
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
