# frozen_string_literal: true

# Exclusive inert filesystem fixtures only. macos:true below exercises a
# structural branch on ordinary files, never native macOS or Store behavior.
require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "../../fastlane/store_lane_runtime"
require_relative "../../fastlane/store_lane_fastlane_bridges"
require_relative "../../fastlane/ios_upload_validation"

class StoreLaneResourcesTest < Minitest::Test
  Resources = MobileReleaseKit::StoreLaneResources
  Lifetime = MobileReleaseKit::StoreLaneLifetime
  Native = MobileReleaseKit::NativeProcessSpawn

  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-store-resources-model-"))
    stat = File.lstat(@root)
    @root_identity = [stat.dev, stat.ino]
    @owners, @case_number = [], 0
  end

  def teardown
    @owners.each do |owner|
      owner.close_independent!
      assert owner.instance_variable_get(:@handles).all? { |slot| slot.io.nil? || slot.io.closed? }
    end
    stat = File.lstat(@root)
    assert stat.directory? && !stat.symlink? && [stat.dev, stat.ino] == @root_identity
    FileUtils.remove_entry(@root) # Test's exclusive root; no native consumers.
  end

  def scenario(macos: false, shell: false)
    @case_number += 1
    @base = File.join(@root, "case-#{@case_number}")
    @lane = File.join(@base, "lane")
    [@base, @lane, File.join(@lane, "runner"), File.join(@lane, "tmp")].each { |path| Dir.mkdir(path, 0o700) }
    if shell
      %w[home home/.appstoreconnect home/.appstoreconnect/private_keys].each { |name| Dir.mkdir(File.join(@lane, name), 0o700) }
    end
    @artifact = File.join(@base, "synthetic.ipa")
    File.binwrite(@artifact, "synthetic artifact bytes\x00\xff".b * 1_024)
    File.chmod(0o600, @artifact)
    stat = File.stat(@lane)
    deadline = Native.monotonic_ns + 3_600_000_000_000
    binding = {"root" => @lane, "root_device" => stat.dev, "root_inode" => stat.ino,
      "shell_home" => shell, "macos" => macos, "app_id" => "12345", "key_id" => "KEY123",
      "artifact" => @artifact, "run_deadline_ns" => deadline}.freeze
    @invocation = Lifetime::Invocation.new(lane: "ios_testflight_internal", mode: "execute", nonce: "n" * 16,
      output: File.join(@base, "receipt.json"), run_deadline_ns: deadline)
    @resources = Resources::Inventory.new(invocation: @invocation, binding: binding)
    @invocation.bind_resources!(@resources)
    @owners << @resources
    @resources.admit!
    @resources
  end

  def completed_inventory
    @invocation.seal_uploads!
    result = @resources.finish!
    assert @resources.sealed_and_retired?
    assert @invocation.uploads_sealed_and_retired?
    result
  end

  def observe_original_closes(configure = nil)
    original, assertions = File.method(:open), self
    wrapper = lambda do |path, *arguments, **keywords|
      file = original.call(path, *arguments, **keywords)
      close, calls = file.method(:close), 0
      file.define_singleton_method(:close) do
        calls += 1
        assertions.assert_equal 1, calls, "original close was retried"
        assertions.assert_equal true, autoclose?, "original File close was not armed"
        returned = close.call
        assertions.assert_nil returned, "original close did not return nil"
        returned
      end
      configure&.call(path, file)
      file
    end
    File.stub(:open, wrapper) { yield }
  end

  def inert_close_slot(fd: 91, pid: nil, arm: nil, close: nil, after: nil, disarm: nil,
                       armed: true, returned: nil, closed: true)
    # Retained state injection tests only the close operation. No File.open,
    # wrapper adoption, numeric-FD operation or native disposal is involved.
    state = {autoclose: false, wrapper: false, descriptor: false, flags: [], closes: 0, close_flags: []}
    io = Object.new
    io.define_singleton_method(:fileno) { fd }
    io.define_singleton_method(:pid) { pid }
    io.define_singleton_method(:autoclose?) { state.fetch(:autoclose) && armed }
    io.define_singleton_method(:autoclose=) do |value|
      state.fetch(:flags) << value
      raise IOError, "synthetic closed-wrapper disarm" if state.fetch(:wrapper)
      if value
        state[:autoclose] = true
        arm&.call
      else
        disarm&.call
        state[:autoclose] = false
      end
      value
    end
    io.define_singleton_method(:closed?) { state.fetch(:wrapper) && closed }
    io.define_singleton_method(:close) do
      state[:closes] += 1
      state.fetch(:close_flags) << state.fetch(:autoclose)
      close&.call
      state[:wrapper] = true
      state[:descriptor] = state.fetch(:autoclose) == true && fd.instance_of?(Integer) && fd >= 3 && pid.nil?
      after&.call
      returned
    end
    slot = Resources::FileSlot.new
    slot.instance_variable_set(:@io, io)
    slot.instance_variable_set(:@state, :open)
    [slot, io, state]
  end

  def close_error(type = IOError)
    error = type == SystemExit ? SystemExit.new(19) : type.new("synthetic original close failure")
    begin
      raise error, cause: ArgumentError.new("synthetic original cause")
    rescue Exception => observed # rubocop:disable Lint/RescueException
      assert_same error, observed
    end
    error
  end

  def pending_close_delivery(error)
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
    assert delivered # Finite synchronous cut, never Thread#raise or a worker.
  end

  def nonlocal_close_return
    yield proc { return :escaped_close_return }
  end

  def test_nonmac_original_generated_inventory_is_exclusive_closed_and_never_deletes_source_or_package
    observe_original_closes do
      scenario
      source = File.binread(@artifact)
      pilot = @resources.create_pilot_root!
      ipa = @resources.copy_package_ipa!(ipa_path: @artifact, package_path: pilot)
      info = File.join(@base, "AppStoreInfo.plist")
      File.binwrite(info, "synthetic plist")
      copied_info = @resources.copy_appstore_info!(source: info, pilot_path: pilot)
      key_dir = @resources.write_api_key!(key_id: "KEY123", contents: "synthetic non-credential key", shell: false)
      @resources.require_upload_inputs!(package_path: pilot, asset_path: @artifact)
      assert @resources.require_ready_for_executor!
      @resources.defer_removal!(pilot)
      @resources.defer_removal!(key_dir)
      rows = completed_inventory
      assert_equal %w[pilot-root package-ipa package-appstore-info key-dir key], rows.map { |row| row.fetch("role") }
      assert_equal Digest::SHA256.hexdigest(source) + ".ipa", File.basename(ipa)
      assert_equal source, File.binread(@artifact)
      assert_equal source, File.binread(ipa)
      assert_equal "synthetic plist", File.binread(copied_info)
      assert File.file?(File.join(key_dir, "AuthKey_KEY123.p8"))
      rows.each { |row| assert_equal(row.fetch("kind") == "directory" ? 0o700 : 0o600, row.fetch("mode")) }
      assert rows.frozen? && rows.all?(&:frozen?)
      assert_raises(Resources::Error) { @resources.create_pilot_root! }
    end
  end

  def test_mac_structural_package_metadata_asset_and_private_shell_key_roles_are_bound_before_dispatch
    scenario(macos: true, shell: true)
    pilot = @resources.create_pilot_root!
    package = @resources.create_package!(pilot_path: pilot, app_id: "12345")
    ipa = @resources.copy_package_ipa!(ipa_path: @artifact, package_path: package)
    attributes = @resources.package_file_attributes!(ipa)
    assert_equal File.size(@artifact), attributes.fetch(:size)
    assert_equal Digest::MD5.hexdigest(File.binread(@artifact)), attributes.fetch(:md5)
    metadata = @resources.write_metadata!(package_path: package, contents: "<synthetic-package/>")
    asset = @resources.copy_upload_asset!(source: @artifact)
    key_dir = @resources.write_api_key!(key_id: "KEY123", contents: "synthetic key", shell: true)
    assert_equal File.join(@lane, "home/.appstoreconnect/private_keys"), key_dir
    assert @resources.require_ready_for_executor!
    rows = completed_inventory
    assert_equal %w[pilot-root package package-ipa package-metadata upload-asset key], rows.map { |row| row.fetch("role") }
    assert_equal "shell-keys", rows.last.fetch("parent")
    assert File.file?(metadata) && File.file?(asset) && File.file?(@artifact)
  end

  def test_pilot_directory_and_key_file_collisions_preserve_foreign_entries_without_adoption
    scenario
    name = File.join(@lane, "tmp", "pilot-#{'a' * 32}")
    Dir.mkdir(name, 0o700)
    File.binwrite(File.join(name, "sentinel"), "foreign pilot")
    SecureRandom.stub(:hex, "a" * 32) { assert_raises(Errno::EEXIST) { @resources.create_pilot_root! } }
    assert @invocation.unknown?
    assert_equal "foreign pilot", File.binread(File.join(name, "sentinel"))
    assert_raises(Resources::Error) { @resources.inventory }
    scenario(shell: true)
    path = File.join(@lane, "home/.appstoreconnect/private_keys/AuthKey_KEY123.p8")
    File.symlink(@artifact, path)
    source = File.binread(@artifact)
    assert_raises(SystemCallError) { @resources.write_api_key!(key_id: "KEY123", contents: "must not overwrite", shell: true) }
    assert File.symlink?(path)
    assert_equal source, File.binread(@artifact)
    assert @invocation.unknown?
  end

  def test_generated_file_replacement_and_parent_replacement_refuse_executor_and_keep_both_originals
    scenario
    pilot = @resources.create_pilot_root!
    ipa = @resources.copy_package_ipa!(ipa_path: @artifact, package_path: pilot)
    File.rename(ipa, ipa + ".original")
    File.binwrite(ipa, "foreign replacement")
    assert_raises(Resources::Error) { @resources.require_ready_for_executor! }
    assert @invocation.unknown?
    assert_equal "foreign replacement", File.binread(ipa)
    assert_equal File.binread(@artifact), File.binread(ipa + ".original")
    scenario
    pilot = @resources.create_pilot_root!
    tmp = File.join(@lane, "tmp")
    File.rename(tmp, tmp + ".original")
    Dir.mkdir(tmp, 0o700)
    File.binwrite(File.join(tmp, "sentinel"), "foreign tmp")
    assert_raises(Resources::Error) { @resources.require_ready_for_executor! }
    assert_equal "foreign tmp", File.binread(File.join(tmp, "sentinel"))
    assert File.directory?(File.join(tmp + ".original", File.basename(pilot)))
  end

  def test_lost_generated_writer_close_latches_original_error_and_closes_other_original_handles_once
    primary, writer, close_calls, pilot = close_error, nil, 0, nil
    cause = primary.cause
    configure = lambda do |path, file|
      if File.dirname(path) == pilot
        writer = file
        close = file.method(:close)
        # The inner original-close observer requires armedtrue and nil
        # BEFORE this after-effect failure. Never retry an uncertain FD.
        file.define_singleton_method(:close) { close_calls += 1; close.call; raise primary, cause: primary.cause }
      end
    end
    observe_original_closes(configure) do
      scenario
      pilot = @resources.create_pilot_root!
      assert_same primary, assert_raises(IOError) { @resources.copy_package_ipa!(ipa_path: @artifact, package_path: pilot) }
      assert writer.closed?
      assert_equal 1, close_calls
      assert_same cause, primary.cause
      assert_same primary, @invocation.first_primary
      slot = @resources.instance_variable_get(:@handles).find { |item| item.io.equal?(writer) }
      assert_same writer, slot.io
      refute slot.retired?
      assert_equal 2, slot.close_errors.length
      assert_same primary, slot.close_errors.first
      assert_instance_of IOError, slot.close_errors.last
      slot.close_errors.each { |error| assert_includes @invocation.cleanup_errors, error }
      assert_raises(Lifetime::LifetimeError) { @resources.require_ready_for_executor! }
      @resources.close_independent!
      assert_equal 1, close_calls
      assert @resources.instance_variable_get(:@handles).all? { |item| item.io.nil? || item.io.closed? }
      assert File.file?(@artifact)
    end

    cuts = %i[before after interrupt system_exit arm arm_throw arm_return arm_unconfirmed
              close_throw close_return disarm_error disarm_throw disarm_return duplicate nonnil closed_unconfirmed
              fd0 fd1 fd2 fd_negative fd_string fd_float popen missing pending pending_after_error]
    cuts.each do |cut|
      primary = close_error(cut == :interrupt ? Interrupt : cut == :system_exit ? SystemExit : IOError)
      pending, secondary, cause = close_error(Interrupt), IOError.new("synthetic independent disarm failure"), primary.cause
      pending_cause = pending.cause
      options = {}
      fail_first = -> { raise primary, cause: primary.cause }
      escape = -> { throw :store_resource_close_nonlocal, :escaped_close }
      observed = nonlocal_close_return do |returning|
        case cut
        when :before, :interrupt, :system_exit, :pending_after_error then options[:close] = fail_first
        when :after then options[:after] = fail_first
        when :arm then options[:arm] = fail_first
        when :arm_throw then options[:arm] = escape
        when :arm_return then options[:arm] = returning
        when :arm_unconfirmed then options[:armed] = false
        when :close_throw then options[:close] = escape
        when :close_return then options[:close] = returning
        when :disarm_error then options[:close], options[:disarm] = fail_first, -> { raise secondary }
        when :disarm_throw then options[:close], options[:disarm] = fail_first, escape
        when :disarm_return then options[:close], options[:disarm] = fail_first, returning
        when :duplicate then options[:close], options[:disarm] = fail_first, fail_first
        when :nonnil then options[:returned] = false
        when :closed_unconfirmed then options[:closed] = false
        when :fd0 then options[:fd] = 0
        when :fd1 then options[:fd] = 1
        when :fd2 then options[:fd] = 2
        when :fd_negative then options[:fd] = -1
        when :fd_string then options[:fd] = "91"
        when :fd_float then options[:fd] = 91.0
        when :popen then options[:pid] = 4141
        end
        options[:disarm] = -> { raise secondary } if cut == :pending_after_error
        slot, io, state = inert_close_slot(**options)
        slot.instance_variable_set(:@io, nil) if cut == :missing
        other, other_io, other_state = inert_close_slot(fd: 92)
        record = Lifetime::Invocation.new(lane: "ios_testflight_internal", nonce: "n" * 16, output: "/model/resources.json")
        inventory = Resources::Inventory.new(invocation: record, binding: {}.freeze)
        inventory.instance_variable_set(:@handles, [other, slot])
        record.bind_resources!(inventory)
        retained = [inventory, slot, io, other, other_io] # No real descriptor/finalizer exists.
        failure = catch(:store_resource_close_nonlocal) do
          assert_raises(Exception) do
            if %i[pending pending_after_error].include?(cut)
              pending_close_delivery(pending) { slot.close_once }
            else
              slot.close_once
            end
          end
        end
        assert_kind_of Exception, failure, "#{cut} escaped the close operation"
        first_is_actual = %i[before after interrupt system_exit arm disarm_error disarm_throw disarm_return duplicate pending_after_error].include?(cut)
        expected = first_is_actual ? primary : cut == :pending ? pending : nil
        expected ? assert_same(expected, failure) : assert_instance_of(Resources::Error, failure)
        assert_same cause, primary.cause
        assert_same pending_cause, pending.cause
        assert_same(cut == :missing ? nil : io, slot.io)
        refute slot.retired?
        refute slot.open?
        errors = slot.close_errors
        assert errors.frozen?
        refute_same errors, slot.close_errors
        assert_same failure, errors.first
        assert_operator errors.length, :<=, 4
        assert_equal errors.map(&:object_id).uniq, errors.map(&:object_id)
        assert_includes errors, secondary if %i[disarm_error pending_after_error].include?(cut)
        assert_includes errors, pending if %i[pending pending_after_error].include?(cut)
        assert_equal 3, errors.length if cut == :pending_after_error
        assert_equal 1, errors.length if cut == :duplicate
        assert_operator errors.length, :>=, 2 if %i[after disarm_throw disarm_return nonnil closed_unconfirmed missing pending pending_after_error].include?(cut)
        no_close = %i[arm arm_throw arm_return arm_unconfirmed fd0 fd1 fd2 fd_negative fd_string fd_float popen missing].include?(cut)
        assert_equal(no_close ? 0 : 1, state.fetch(:closes))
        assert_equal [true], state.fetch(:close_flags) unless no_close
        expected_flags = if cut == :missing then []
                         elsif %i[fd0 fd1 fd2 fd_negative fd_string fd_float popen].include?(cut) then [false]
                         else [true, false]
                         end
        assert_equal expected_flags, state.fetch(:flags)
        effected = %i[after nonnil closed_unconfirmed pending].include?(cut)
        assert_equal effected, state.fetch(:wrapper)
        assert_equal effected, state.fetch(:descriptor)
        snapshot = [state.fetch(:closes), state.fetch(:flags).dup, state.fetch(:close_flags).dup,
                    state.fetch(:autoclose), state.fetch(:wrapper), state.fetch(:descriptor), errors]
        # Repeat guard must still fold the saved disarm errors through the
        # original collector, and cannot skip the other original close.
        assert_nil slot.close_once
        inventory.close_independent!
        assert_equal snapshot, [state.fetch(:closes), state.fetch(:flags), state.fetch(:close_flags),
                                state.fetch(:autoclose), state.fetch(:wrapper), state.fetch(:descriptor), slot.close_errors]
        assert_same failure, record.first_primary
        errors.each { |error| assert_includes record.cleanup_errors, error }
        assert record.unknown?
        assert_equal 1, other_state.fetch(:closes)
        assert other_state.fetch(:descriptor) && other.retired?
        assert_same other_io, other.io
        assert_same inventory, retained.first
        assert_same inventory, record.instance_variable_get(:@resources)
        assert state.fetch(:autoclose) if %i[disarm_error disarm_throw disarm_return duplicate pending_after_error].include?(cut)
        :completed
      end
      assert_equal :completed, observed, "#{cut} nonlocal return escaped independent cleanup"
    end
  end

  def test_pin_reads_missing_document_owner_and_foreign_origin_cannot_supply_success
    scenario
    bytes = File.binread(@artifact)
    assert_equal bytes, @resources.read_pinned_source!(@artifact, Digest::SHA256.hexdigest(bytes))
    assert_raises(Resources::Error) { @resources.read_pinned_source!(@artifact, "0" * 64) }
    assert @invocation.unknown?
    scenario
    assert_raises(Lifetime::LifetimeError) { @invocation.record_store_document!(nil) }
    assert @invocation.unknown?
    slot = Resources::FileSlot.new
    Process.stub(:pid, Process.pid + 1) { assert_raises(Resources::Error) { slot.close_once } }
    assert slot.retired?, "foreign-origin rejection must not mutate original slot state"
  end

  def bind_original_ios_validation(expires)
    adapter, native = MobileReleaseKit::IosUploadValidation, MobileReleaseKit::NativeUploadValidation
    type = native.const_get(:CaptureSession, false)
    config, intent = %w[config.json intent.json].map { |name| File.join(@base, name) }
    [config, intent].each { |path| File.write(path, "{}") }
    output = JSON.generate("documentType" => "ios-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64, "ipaSha256" => Digest::SHA256.file(@artifact).hexdigest,
      "ipaSize" => File.size(@artifact), "notBefore" => "2020-01-01T00:00:00Z", "notAfter" => expires).freeze
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
    Lifetime.stub(:current_invocation, @invocation) do
      type.stub(:new, constructor) do
        adapter.current!(python: RbConfig.ruby, module_root: File.expand_path("../../src", __dir__),
          app_root: @base, config_path: config, intent_path: intent, ipa_path: @artifact,
          intent_sha256: "a" * 64, environment: {}, tooling_directory: File.expand_path("../../fastlane", __dir__))
      end
    end
  end

  def with_bridge_models(expires: "2099-01-01T00:00:00Z", force_package: false)
    # Dependencies are inert local types; do not import Fastlane or invoke a
    # transport command. Restore any prior module after this single model.
    previous = Object.const_get(:FastlaneCore, false) if Object.const_defined?(:FastlaneCore, false)
    Object.send(:remove_const, :FastlaneCore) if previous
    core = Module.new
    Object.const_set(:FastlaneCore, core)
    ui = Module.new
    %i[message success verbose header important].each { |name| ui.define_singleton_method(name) { |*| nil } }
    core.const_set(:UI, ui)
    globals = Module.new
    globals.define_singleton_method(:verbose?) { false }
    core.const_set(:Globals, globals)
    environment = Module.new
    environment.define_singleton_method(:truthy?) { |*| force_package }
    core.const_set(:Env, environment)
    bridge = MobileReleaseKit::StoreLaneFastlaneBridges
    executor = Class.new do
      attr_accessor :behavior
      def build_upload_command(*)
        "inert-command-description-never-executed"
      end
      def execute(*)
        @behavior.call
      end
    end
    executor.prepend(bridge.const_get(:KeyBridge, false))
    core.const_set(:AltoolTransporterExecutor, executor)
    core.const_set(:JavaTransporterExecutor, Class.new)
    core.const_set(:ShellScriptTransporterExecutor, Class.new)
    transporter = Class.new do
      def self.hide_transporter_output?
        true
      end
      def initialize(executor)
        @transporter_executor = executor
        @api_key = {key_id: "KEY123", issuer_id: "synthetic-issuer", key: "synthetic non-credential bytes"}
        @jwt = "synthetic non-credential token"
      end
      def handle_error(*)
        false
      end
    end
    transporter.prepend(bridge.const_get(:TransporterBridge, false))
    core.const_set(:ItunesTransporter, transporter)
    builder = Class.new { attr_accessor :package_path }
    builder.prepend(bridge.const_get(:PackageBridge, false))
    runtime = Object.new
    owner, invocation = @resources, @invocation
    runtime.define_singleton_method(:resources) { owner }
    runtime.define_singleton_method(:invocation) { invocation }
    runtime.define_singleton_method(:binding) { owner.instance_variable_get(:@binding) }
    runtime.define_singleton_method(:xml_template) { '<package><%= @data[:ipa_path] %></package>' }
    runtime.define_singleton_method(:require_active!) { invocation.require_upload_continuation! }
    runtime.define_singleton_method(:mark_unknown!) { |error, cleanup: false| invocation.mark_unknown!(error, cleanup: cleanup) }
    bind_original_ios_validation(expires)
    bridge.stub(:runtime!, runtime) { yield executor.new, transporter, builder.new }
  ensure
    Object.send(:remove_const, :FastlaneCore) if defined?(core) && Object.const_defined?(:FastlaneCore, false) && Object.const_get(:FastlaneCore, false).equal?(core)
    Object.const_set(:FastlaneCore, previous) if previous
  end

  def test_fixed_package_key_and_transporter_bridges_create_before_inert_dispatch_and_never_run_unsafe_cleanup
    [false, true].each do |macos|
      scenario(macos: macos)
      pilot = @resources.create_pilot_root!
      with_bridge_models do |executor, transporter, builder|
        package = builder.generate(app_id: "12345", ipa_path: @artifact, package_path: pilot,
          platform: "ios", app_identifier: "fixture.app", short_version: "1.0.0", bundle_version: "1")
        executor.behavior = lambda do
          assert @resources.require_ready_for_executor!
          assert @resources.instance_variable_get(:@entries).key?("key")
          assert @resources.instance_variable_get(:@entries).key?("package-ipa")
          assert @resources.instance_variable_get(:@entries).key?("upload-asset") if macos
          true
        end
        forbidden = ->(*) { flunk "historical copy/removal path was entered" }
        FileUtils.stub(:rm_rf, forbidden) do
          FileUtils.stub(:cp, forbidden) do
            assert transporter.new(executor).upload(package_path: package, asset_path: @artifact, platform: "ios")
          end
        end
        rows = completed_inventory
        assert rows.any? { |row| row.fetch("role") == "package-metadata" } if macos
        assert File.file?(@artifact) && File.directory?(pilot)
      end
    end
  end

  def test_transporter_ordinary_failure_can_reconcile_but_deferred_request_error_latches_original_primary
    [false, true].each do |cleanup_fails|
      scenario
      pilot = @resources.create_pilot_root!
      with_bridge_models do |executor, transporter, builder|
        package = builder.generate(app_id: "12345", ipa_path: @artifact, package_path: pilot,
          platform: "ios", app_identifier: "fixture.app", short_version: "1.0.0", bundle_version: "1")
        primary, cleanup = IOError.new("ordinary synthetic executor failure"), IOError.new("synthetic deferred request failure")
        executor.behavior = -> { raise primary }
        action = -> { transporter.new(executor).upload(package_path: package, asset_path: @artifact, platform: "ios") }
        if cleanup_fails
          @resources.stub(:defer_removal!, ->(*, **) { raise cleanup }) do
            assert_same primary, assert_raises(IOError, &action)
          end
          assert @invocation.unknown?
          assert_same primary, @invocation.first_primary
          assert_includes @invocation.cleanup_errors, cleanup
        else
          assert_same primary, assert_raises(IOError, &action)
          assert @invocation.require_upload_continuation!
          refute @invocation.unknown?
        end
        assert File.file?(@artifact) && File.directory?(pilot)
      end
    end
  end

  def test_expiry_during_real_package_asset_key_or_final_preparation_never_enters_executor
    [false, true].each do |force_package|
      delays = %i[copy_package_ipa! write_metadata! write_api_key! require_ready_for_executor!]
      delays << :copy_upload_asset! unless force_package
      delays.each do |boundary|
        scenario(macos: true)
        original_bytes = File.binread(@artifact)
        clock = Time.utc(2026, 9, 16, 12)
        expiry = clock + 1
        Time.stub(:now, -> { clock }) do
          with_bridge_models(expires: expiry.iso8601, force_package: force_package) do |executor, transporter, builder|
            executor.behavior = -> { flunk "expired real preparation entered executor" }
            actual = @resources.method(boundary)
            delayed = lambda do |*args, **keywords|
              result = actual.call(*args, **keywords)
              clock = expiry
              result
            end
            error = @resources.stub(boundary, delayed) do
              pilot = @resources.create_pilot_root!
              package = builder.generate(app_id: "12345", ipa_path: @artifact, package_path: pilot,
                platform: "ios", app_identifier: "fixture.app", short_version: "1.0.0", bundle_version: "1")
              assert_raises(Lifetime::IosDispatchRefused) do
                transporter.new(executor).upload(package_path: package, asset_path: @artifact, platform: "ios")
              end
            end
            assert_same error, @invocation.first_primary
            refute @invocation.unknown?
            assert @invocation.require_upload_continuation!
            assert_equal original_bytes, File.binread(@artifact)
            entries = @resources.instance_variable_get(:@entries)
            assert_equal original_bytes, File.binread(entries.fetch("package-ipa").fetch(:path))
            key_dir = File.dirname(entries.fetch("key").fetch(:path))
            assert_includes @resources.instance_variable_get(:@requested), key_dir
            rows = completed_inventory
            assert rows.any? { |row| row.fetch("role") == "package-metadata" }
            assert_empty @invocation.instance_variable_get(:@adapters)
          end
        end
      end
    end
  end
end
