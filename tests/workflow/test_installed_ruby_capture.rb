# frozen_string_literal: true

# These literal inventories are selected separately by the source/wheel gates.
# No skip, copied source runtime, Open3 facade or BOOTSTRAP-only string inspection
# substitutes for actually executing the selected Ruby helpers and installed V.
require_relative "installed_ruby_capture_fixture"

INSTALLED_RUBY_CAPTURE_CONFIGURATION = InstalledRubyCaptureFixture.parse_options!(ARGV)

# The independent fixture collector borrows only this explicitly selected,
# already-loaded primitive/task pair. It must not silently import a checkout
# primitive under a wheel Gemfile. Actual Gate/capture loading still occurs
# ONLY in each fresh fixed driver, from the same selected absolute prefix.
require File.join(INSTALLED_RUBY_CAPTURE_CONFIGURATION.tooling_root, "native_process_spawn.rb")
require File.join(INSTALLED_RUBY_CAPTURE_CONFIGURATION.tooling_root, "native_upload_process.rb")

require "minitest/autorun"

Minitest.after_run { InstalledRubyCaptureFixture.close_negative_installation! }

module InstalledRubyCaptureAssertions
  def assert_source_origin(actual, binding, relative)
    expected = binding.fetch("files").fetch(relative)
    assert_equal %w[line path sha256], actual.keys.sort
    assert_equal expected.fetch("path"), actual.fetch("path")
    assert_equal expected.fetch("sha256"), actual.fetch("sha256")
    assert_kind_of Integer, actual.fetch("line")
    assert_operator actual.fetch("line"), :>, 0
  end

  def assert_actual_origins(record)
    binding = record.fetch("installation")
    observation = record.fetch("captureObservation")
    assert_equal({ "outer" => "measured-loaded-methods", "custodian" => "genuine-fixed-spawn",
                   "keeper" => "source-bound-by-fixed-custodian", "childLocalMeasurement" => false }, record.fetch("originScope"))
    # These are O's actual loaded methods. C's genuine fixed SpawnSpec plus the
    # unchanged installed helper bytes causally bind C->K; the record does NOT
    # pretend that a Method#source_location was measured inside C or K.
    origins = observation.fetch("sourceOrigins")
    assert_equal %w[capture helper spawn], origins.keys.sort
    assert_source_origin(origins.fetch("capture"), binding, "fastlane/native_upload_validation.rb")
    assert_source_origin(origins.fetch("spawn"), binding, "fastlane/native_process_spawn.rb")
    assert_source_origin(origins.fetch("helper"), binding, "fastlane/native_upload_process.rb")
    assert_source_origin(record.fetch("helperArgvOrigin"), binding, "fastlane/native_upload_process.rb")
    record.fetch("adapterOrigins").each_value do |origin|
      assert_source_origin(origin, binding, "fastlane/#{record.fetch('platform')}_upload_validation.rb")
    end
    loaded = %W[
      release_support.rb native_process_spawn.rb native_upload_process.rb
      native_upload_validation.rb #{record.fetch('platform')}_upload_validation.rb
    ].map { |name| File.join(binding.fetch("toolingRoot"), name) }.sort
    assert_equal loaded, record.fetch("loadedProductFeatures")
    if record.fetch("phase") == "wheel"
      assert_equal File.join(binding.fetch("prefix"), "share/mobile-release-kit/fastlane"), binding.fetch("toolingRoot")
      assert InstalledRubyCaptureFixture.inside?(binding.fetch("recordPath"), binding.fetch("prefix"))
      refute InstalledRubyCaptureFixture.inside?(binding.fetch("toolingRoot"), binding.fetch("sourceRoot"))
      refute InstalledRubyCaptureFixture.inside?(binding.fetch("moduleRoot"), binding.fetch("sourceRoot"))
      assert_equal INSTALLED_RUBY_CAPTURE_CONFIGURATION.wheel_sha256, binding.fetch("wheelSha256")
    else
      assert_nil binding.fetch("recordPath")
      assert_equal File.join(binding.fetch("prefix"), "fastlane"), binding.fetch("toolingRoot")
    end

    runtime = record.fetch("runtime")
    assert_equal "ruby", runtime.fetch("rubyEngine")
    assert_equal "3.3.12", runtime.fetch("rubyVersion")
    assert_equal "1.1.2", runtime.fetch("fiddleVersion")
    info = runtime.fetch("runtimeInfo")
    assert_equal "mrk-native-process-runtime-v1", info.fetch("schema")
    assert_equal "ruby", info.fetch("ruby_engine")
    assert_equal "3.3.12", info.fetch("ruby_version")
    assert_equal "1.1.2", info.fetch("fiddle_version")
    assert_equal "default", info.fetch("origin"), "fresh fixed drivers must not inherit a source Bundler installation"
    assert_nil info.fetch("gemfile")
    assert_includes %w[linux-glibc darwin], info.fetch("family")
    assert_includes %w[x86_64 arm64], info.fetch("architecture")
    assert_equal File.realpath(RbConfig.ruby), info.fetch("ruby_executable")
    assert_equal %w[closure extension fiddle function version], info.fetch("fiddle_features").keys.sort
    assert_equal info.fetch("fiddle_features").keys.sort, runtime.fetch("fiddleFiles").keys.sort
    runtime.fetch("fiddleFiles").each do |name, file|
      assert_equal info.fetch("fiddle_features").fetch(name), file.fetch("path")
      assert_equal Digest::SHA256.file(file.fetch("path")).hexdigest, file.fetch("sha256")
      roots = name == "extension" ? info.fetch("native_extension_roots") : [info.fetch("ruby_library_root")]
      assert roots.any? { |root| InstalledRubyCaptureFixture.inside?(file.fetch("path"), root) }
      refute InstalledRubyCaptureFixture.inside?(file.fetch("path"), binding.fetch("sourceRoot"))
      refute InstalledRubyCaptureFixture.inside?(file.fetch("path"), record.fetch("driverCwd"))
    end

    spawn = observation.fetch("custodianSpawn")
    assert_equal info.fetch("ruby_executable"), spawn.fetch("executable")
    argv = spawn.fetch("argv")
    assert_equal 11, argv.length
    assert_equal [info.fetch("ruby_executable"), *InstalledRubyCaptureFixture::RUBY_FLAGS, "--",
                  File.join(binding.fetch("toolingRoot"), "native_upload_process.rb"), "custodian"], argv.first(7)
    assert_equal record.fetch("driverPid").to_s, argv.fetch(7)
    assert_equal record.fetch("driverSid").to_s, argv.fetch(8)
    assert_operator Integer(argv.fetch(9), 10), :>, 0
    assert_equal 5_000_000_000, Integer(argv.fetch(10), 10) - Integer(argv.fetch(9), 10)
    assert_equal({ "LANG" => "C", "LC_ALL" => "C", "TZ" => "UTC" }, spawn.fetch("environment"))
    assert_equal record.fetch("driverCwd"), spawn.fetch("creatorCwd")
    assert_equal %w[null_stdin null_stdout null_stderr control_read status_write stdin_read stdout_write stderr_write], spawn.fetch("fdRoles")
    refute record.fetch("poisonExecuted")
  end

  def assert_capture_finality(record, outcome:)
    assert_equal true, record.fetch("captureInvoked")
    observation = record.fetch("captureObservation")
    assert InstalledRubyCaptureFixture.finalized_capture?(observation),
           "capture lacks an original C receipt, confirmed K/V/G accounting, actual EOF/joins/closes or restored observation"
    final = observation.fetch("final")
    assert_equal outcome, final.fetch("outcome")
    assert_equal false, record.fetch("fallbackUsed"), "independent fixture expiry, not production cleanup, released the streams"
    context = observation.fetch("protocolContext")
    custodian, keeper, validator = observation.fetch("custodian"), final.fetch("keeper"), final.fetch("validator")
    assert_equal({ "v" => 1, "type" => "HELLO", "pid" => custodian.fetch("pid"),
                   "ppid" => record.fetch("driverPid"), "sid" => custodian.fetch("pid"),
                   "pgid" => custodian.fetch("pid"), "fd_map_version" => 1 }, context.fetch("hello"))
    assert_equal({ "v" => 1, "type" => "RESERVED", "keeper_pid" => keeper.fetch("pid"),
                   "group_id" => keeper.fetch("pid"), "session_id" => custodian.fetch("pid") }, context.fetch("reserved"))
    assert_equal observation.fetch("ready"), context.fetch("ready")
    if outcome != "failed" || observation.fetch("ready")
      assert_equal({ "v" => 1, "type" => "READY", "validator_pid" => validator.fetch("pid"),
                     "group_id" => keeper.fetch("pid"), "keeper_pgid" => custodian.fetch("pid") }, observation.fetch("ready"))
      assert_equal true, observation.fetch("stdinCloseReturned")
      events = observation.fetch("events").map { |event| event.fetch("event") }
      assert_equal 1, events.count("ready_before_stdin_close")
      assert_equal 1, events.count("stdin_close_returned")
      assert_operator events.index("ready_before_stdin_close"), :<, events.index("stdin_close_returned")
    end
    assert_actual_origins(record)
    observation
  end

  def assert_validator_contract(record)
    binding, platform = record.values_at("installation", "platform")
    worker = record.fetch("validator")
    assert_kind_of Hash, worker
    final = record.fetch("captureObservation").fetch("final")
    assert_equal final.fetch("validator").fetch("pid"), worker.fetch("pid")
    assert_equal final.fetch("group").fetch("id"), worker.fetch("group")
    assert_equal true, worker.fetch("stdoutOpen")
    assert_equal true, worker.fetch("stderrOpen")
    assert_equal binding.fetch("toolingRoot"), worker.fetch("cwd")
    app = File.join(record.fetch("driverCwd"), "app")
    extension = platform == "ios" ? "ipa" : "aab"
    bootstrap = 'import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("mobile_release.' + platform + '_upload_validation",run_name="__main__")'
    assert_equal ["-I", "-S", "-c", bootstrap, binding.fetch("moduleRoot"), "--app-root", app,
                  "--config-path", File.join(app, "release/mobile-release.json"),
                  "--operation-intent", File.join(app, "intent.json"), "--#{extension}",
                  File.join(app, "candidate.#{extension}"), "--intent-sha256", "a" * 64], worker.fetch("argv")
    environment = worker.fetch("environment").dup
    if (encoding = environment.delete("__CF_USER_TEXT_ENCODING"))
      assert_match(/\A0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+\z/, encoding)
    end
    path = record.fetch("mode") == "poison" ? File.join(record.fetch("driverCwd"), "path-shadow") : "/usr/bin:/bin"
    assert_equal({ "HOME" => app, "PATH" => path, "LANG" => "C", "LC_ALL" => "C" }, environment)
    %w[RUBYOPT RUBYLIB BUNDLE_GEMFILE PYTHONPATH MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64].each do |name|
      refute worker.fetch("environment").key?(name)
    end
  end

  def assert_success(record)
    assert_capture_finality(record, outcome: "ok")
    assert_validator_contract(record)
    result = record.fetch("result")
    assert_equal "value", result.fetch("kind")
    assert_equal @fixture.expected_value, result.fetch("value")
    assert_equal true, result.fetch("frozen")
    validator = record.fetch("captureObservation").fetch("final").fetch("validator")
    assert_equal "exit", validator.fetch("status_kind")
    assert_equal 0, validator.fetch("status_code")
  end

  def assert_missing_helper(helper)
    negative = InstalledRubyCaptureFixture.negative_installation(INSTALLED_RUBY_CAPTURE_CONFIGURATION)
    record = negative.missing_capture(@fixture, helper)
    binding = record.fetch("installation")
    assert_equal INSTALLED_RUBY_CAPTURE_CONFIGURATION.negative_prefix, binding.fetch("prefix")
    refute_equal INSTALLED_RUBY_CAPTURE_CONFIGURATION.prefix, binding.fetch("prefix")
    assert_equal INSTALLED_RUBY_CAPTURE_CONFIGURATION.wheel_sha256, binding.fetch("wheelSha256")
    result = record.fetch("result")
    assert_equal "load-refused", result.fetch("kind"), "missing installed helper loaded a source/app/PATH substitute"
    assert_equal "LoadError", result.fetch("errorClass")
    expected = File.join(binding.fetch("toolingRoot"), helper)
    assert_includes [expected, expected.delete_suffix(".rb")], result.fetch("missingPath")
    assert_equal false, record.fetch("captureInvoked")
    assert_nil record.fetch("captureObservation")
    assert_nil record.fetch("runtime")
    assert_nil record.fetch("adapterOrigins")
    assert_nil record.fetch("validator")
    assert_equal({ "outer" => "load-refusal-only", "custodian" => "not-invoked",
                   "keeper" => "not-invoked", "childLocalMeasurement" => false }, record.fetch("originScope"))
    refute record.fetch("poisonExecuted")
    refute record.fetch("fallbackUsed")
    assert InstalledRubyCaptureFixture.verify_binding!(binding), "helper was not restored after genuine local finality"
    assert InstalledRubyCaptureFixture.verify_binding!(INSTALLED_RUBY_CAPTURE_CONFIGURATION.binding),
           "missing-helper case changed the frozen positive installation"
  end
end

class PackagedRubyCaptureTest < Minitest::Test
  include InstalledRubyCaptureAssertions
  prepend UploadProcessFixture::CaseGuard

  def setup
    @fixture = InstalledRubyCaptureFixture::Case.new(INSTALLED_RUBY_CAPTURE_CONFIGURATION)
  end

  def teardown
    @fixture&.close!
  end

  def test_actual_capture_and_helper_origins_are_bound
    %w[ios android].each do |platform|
      record = @fixture.capture(platform, "help")
      assert_capture_finality(record, outcome: "ok")
      assert_equal "help", record.fetch("result").fetch("kind")
      assert_includes record.fetch("result").fetch("value"), "--operation-intent"
      assert_includes record.fetch("result").fetch("value"), "--intent-sha256"
      assert_nil record.fetch("validator"), "actual Python help must not use the synthetic executable"
    end
  end

  def test_success_through_both_adapters_has_true_finality
    %w[ios android].each { |platform| assert_success(@fixture.capture(platform, "success")) }
  end

  def test_rejection_through_both_adapters_is_private_and_finalized
    %w[ios android].each do |platform|
      record = @fixture.capture(platform, "rejection")
      assert_capture_finality(record, outcome: "rejected")
      assert_validator_contract(record)
      result = record.fetch("result")
      assert_equal %w[errorClass kind message], result.keys.sort
      assert_equal "contract-error", result.fetch("kind")
      assert_equal "MobileReleaseKit::ContractError", result.fetch("errorClass")
      assert_includes result.fetch("message"), "no new upload is authorized"
      refute_includes result.fetch("message"), "fictional"
      validator = record.fetch("captureObservation").fetch("final").fetch("validator")
      assert_equal "exit", validator.fetch("status_kind")
      assert_equal 3, validator.fetch("status_code")
    end
  end

  def test_reaped_validator_descendant_is_cleaned_before_fallback
    %w[ios android].each do |platform|
      record = @fixture.capture(platform, "descendant")
      assert_success(record)
      descendant = record.fetch("descendant")
      assert_kind_of Hash, descendant
      assert_equal true, descendant.fetch("stdoutOpen")
      assert_equal true, descendant.fetch("stderrOpen")
      assert_equal record.fetch("captureObservation").fetch("final").fetch("group").fetch("id"), descendant.fetch("group")
      refute_equal record.fetch("validator").fetch("pid"), descendant.fetch("pid")
      assert_operator record.fetch("elapsed"), :<, InstalledRubyCaptureFixture::FALLBACK_SECONDS
      # No post-reap numeric probe: real accepted G absence while K was reserved,
      # original C wait and BOTH inherited EOFs must precede independent expiry.
      assert_equal false, record.fetch("fallbackUsed")
    end
  end

  def test_independent_stdout_stderr_bounds_preserve_cleanup
    %w[ios android].each do |platform|
      # Exactly64KiB on EACH stream succeeds; a combined64KiB counter is wrong.
      assert_success(@fixture.capture(platform, "split-bounds"))
      %w[stdout-overflow stderr-overflow].each do |mode|
        record = @fixture.capture(platform, mode)
        assert_capture_finality(record, outcome: "failed")
        assert_validator_contract(record)
        result = record.fetch("result")
        assert_equal "contract-error", result.fetch("kind")
        assert_equal "MobileReleaseKit::ContractError", result.fetch("errorClass")
        assert_includes result.fetch("message"), "safety bound"
        refute_includes result.fetch("message"), "fictional-private"
        assert_operator record.fetch("elapsed"), :<, InstalledRubyCaptureFixture::FALLBACK_SECONDS
      end
    end
  end

  def test_source_app_path_and_preload_poison_cannot_replace_helpers
    %w[ios android].each do |platform|
      record = @fixture.capture(platform, "poison")
      assert_success(record)
      assert_equal false, record.fetch("poisonExecuted")
    end
  end
end

class InstalledRubyCaptureMissingHelperTest < Minitest::Test
  include InstalledRubyCaptureAssertions
  prepend UploadProcessFixture::CaseGuard

  def setup
    @fixture = InstalledRubyCaptureFixture::Case.new(INSTALLED_RUBY_CAPTURE_CONFIGURATION)
  end

  def teardown
    @fixture&.close!
  end

  def test_missing_installed_process_helper_refuses_fallback
    assert_missing_helper("native_upload_process.rb")
  end

  def test_missing_installed_spawn_helper_refuses_fallback
    assert_missing_helper("native_process_spawn.rb")
  end
end
