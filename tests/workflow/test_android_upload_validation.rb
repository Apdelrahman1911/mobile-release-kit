# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "rbconfig"
require "json"
require "digest"
require_relative "../../fastlane/android_upload_validation"

class AndroidUploadValidationTest < Minitest::Test
  Gate = MobileReleaseKit::AndroidUploadValidation

  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-upload-gate-"))
    @app = File.join(@root, "app")
    FileUtils.mkdir_p(File.join(@app, "release"))
    @config = File.join(@app, "release/mobile-release.json")
    @intent = File.join(@app, "intent.json")
    @aab = File.join(@app, "candidate.aab")
    File.write(@config, "{}")
    File.write(@intent, "{}")
    File.write(@aab, "bounded synthetic artifact")
    @module_root = File.realpath(File.expand_path("../../src", __dir__))
    @tooling_directory = File.realpath(File.expand_path("../../fastlane", __dir__))
    @capture = File.join(@root, "capture.json")
    @python = File.join(@root, "trusted-test-interpreter")
    @value = {
      "documentType" => "android-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64,
      "aabSha256" => Digest::SHA256.file(@aab).hexdigest, "aabSize" => File.size(@aab),
    }
    interpreter("puts #{JSON.generate(@value).inspect}")
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def interpreter(source)
    # A toolkit-owned fake executable exercises the REAL no-shell spawn, pipe
    # limits, deadline, child cleanup, argv, cwd and environment behavior. It
    # is not an AAB/native-signature fixture or an application hook.
    File.write(@python, <<~RUBY)
      #!#{RbConfig.ruby}
      require "json"
      File.write(#{@capture.inspect}, JSON.generate("argv" => ARGV, "environment" => ENV.to_h, "cwd" => Dir.pwd, "pid" => Process.pid))
      #{source}
    RUBY
    File.chmod(0o700, @python)
  end

  def validate(environment: {}, **overrides)
    Gate.current!(**{
      python: @python, module_root: @module_root, app_root: @app,
      config_path: @config, intent_path: @intent, aab_path: @aab,
      intent_sha256: "a" * 64, environment: environment,
      tooling_directory: @tooling_directory,
    }.merge(overrides))
  end

  def test_real_spawn_has_constant_isolated_argv_no_store_authority_or_app_python_path
    forbidden = %w[
      MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64 MOBILE_RELEASE_IOS_CERTIFICATE_P12_BASE64
      MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64 GH_TOKEN GITHUB_TOKEN
      ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
      GOOGLE_APPLICATION_CREDENTIALS AWS_SESSION_TOKEN AZURE_CLIENT_SECRET
      PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE RUBYOPT BUNDLE_GEMFILE
      MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD MOBILE_RELEASE_ANDROID_KEYSTORE_PATH
      JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS SUPPLY_UPLOAD_MAX_RETRIES
    ].to_h { |name| [name, "fictional-#{name}"] }
    value = validate(environment: forbidden.merge("HOME" => @root, "PATH" => "/usr/bin:/bin", "LANG" => "unexpected", "MOBILE_RELEASE_BUNDLETOOL_JAR" => "/public/pinned.jar", "JAVA_HOME" => "/public/jdk"))
    assert_equal @value, value
    assert value.frozen?
    capture = JSON.parse(File.read(@capture))
    assert_equal ["-I", "-S", "-c", Gate::BOOTSTRAP, @module_root, "--app-root", @app,
                  "--config-path", @config, "--operation-intent", @intent, "--aab", @aab,
                  "--intent-sha256", "a" * 64], capture.fetch("argv")
    assert_equal @tooling_directory, capture.fetch("cwd")
    child_environment = capture.fetch("environment").dup
    # CoreFoundation may initialize this non-authoritative encoding hint inside
    # the child on macOS, after exec received the exact scrubbed environment.
    if (encoding = child_environment.delete("__CF_USER_TEXT_ENCODING"))
      assert_match(/\A0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+\z/, encoding)
    end
    assert_equal({ "HOME" => @root, "PATH" => "/usr/bin:/bin", "LANG" => "C", "LC_ALL" => "C", "MOBILE_RELEASE_BUNDLETOOL_JAR" => "/public/pinned.jar", "JAVA_HOME" => "/public/jdk" }, child_environment)
    forbidden.each_key { |name| refute capture.fetch("environment").key?(name) }
  end

  def test_relative_command_and_app_substitute_module_are_rejected_before_spawn
    assert_raises(MobileReleaseKit::ContractError) { validate(python: "python3") }
    assert_raises(MobileReleaseKit::ContractError) { validate(python: "#{@python}\n-fake") }
    FileUtils.mkdir_p(File.join(@app, "mobile_release"))
    File.write(File.join(@app, "mobile_release/android_upload_validation.py"), "raise RuntimeError('application code')")
    assert_raises(MobileReleaseKit::ContractError) { validate(module_root: @app) }
    refute File.exist?(@capture)
  end

  def test_parent_symlink_and_outside_aab_cannot_reach_validator
    outside = File.join(@root, "outside.aab")
    File.write(outside, "outside bytes")
    File.symlink(outside, File.join(@app, "link.aab"))
    assert_raises(MobileReleaseKit::ContractError) { validate(aab_path: outside) }
    assert_raises(MobileReleaseKit::ContractError) { validate(aab_path: File.join(@app, "link.aab")) }
    refute File.exist?(@capture)
  end

  def test_missing_installed_helper_cannot_fall_back_to_an_application_or_ambient_module
    modules = File.join(@root, "installed/lib/python/site-packages")
    tooling = File.join(@root, "installed/share/mobile-release-kit/fastlane")
    FileUtils.mkdir_p(File.join(modules, "mobile_release"))
    FileUtils.mkdir_p(tooling)
    error = assert_raises(MobileReleaseKit::ContractError) do
      validate(module_root: modules, tooling_directory: tooling, environment: { "PYTHONPATH" => @app })
    end
    assert_includes error.message, "Required file is missing: mobile_release/android_upload_validation.py"
    refute File.exist?(@capture)
  end

  def test_child_failure_does_not_log_its_output_or_treat_it_as_authority
    interpreter('STDOUT.write("fictional-private-profile"); STDERR.write("fictional-Store-secret"); exit 3')
    error = assert_raises(MobileReleaseKit::ContractError) { validate }
    assert_includes error.message, "no new upload is authorized"
    refute_includes error.message, "fictional"
  end

  def test_output_bound_terminates_validation_process
    interpreter('STDOUT.sync = true; STDOUT.write("x" * 70_000); sleep 60')
    error = assert_raises(MobileReleaseKit::ContractError) { validate }
    assert_includes error.message, "safety bound"
    pid = JSON.parse(File.read(@capture)).fetch("pid")
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  end

  def test_private_stderr_is_bounded_and_never_forwarded
    interpreter('STDERR.sync = true; STDERR.write("private-profile" * 6_000); sleep 60')
    error = assert_raises(MobileReleaseKit::ContractError) { validate }
    assert_includes error.message, "safety bound"
    refute_includes error.message, "private-profile"
    pid = JSON.parse(File.read(@capture)).fetch("pid")
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  end

  def test_deadline_terminates_validator_without_authorizing_upload
    interpreter("sleep 60")
    prior = Gate::MAX_SECONDS
    Gate.send(:remove_const, :MAX_SECONDS)
    Gate.const_set(:MAX_SECONDS, 0.25)
    real_spawn = Open3.method(:popen3)
    pid = nil
    error = Open3.stub(:popen3, lambda do |*args, **options, &block|
      real_spawn.call(*args, **options) do |stdin, stdout, stderr, waiter|
        pid = waiter.pid
        block.call(stdin, stdout, stderr, waiter)
      end
    end) { assert_raises(MobileReleaseKit::ContractError) { validate } }
    assert_includes error.message, "timed out"
    refute_nil pid
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  ensure
    Gate.send(:remove_const, :MAX_SECONDS)
    Gate.const_set(:MAX_SECONDS, prior)
  end

  def test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits
    child_record = File.join(@root, "validator-child")
    interpreter("child = fork { sleep 60 }; File.write(#{child_record.inspect}, child.to_s); exit 0")
    prior = Gate::MAX_SECONDS
    Gate.send(:remove_const, :MAX_SECONDS)
    Gate.const_set(:MAX_SECONDS, 3)
    error = assert_raises(MobileReleaseKit::ContractError) { validate }
    assert_includes error.message, "timed out"
    child = Integer(File.read(child_record), 10)
    # An orphaned, killed child can remain a zombie briefly until the OS reaps
    # it. Either absence or zombie proves it cannot keep inspecting files.
    state, status = Open3.capture2("ps", "-o", "stat=", "-p", child.to_s)
    assert !status.success? || state.strip.start_with?("Z"), "validator's inherited-pipe child survived its deadline"
  ensure
    if child
      begin
        Process.kill("KILL", child)
      rescue Errno::ESRCH
        nil
      end
    end
    Gate.send(:remove_const, :MAX_SECONDS)
    Gate.const_set(:MAX_SECONDS, prior)
  end

  def test_incomplete_unknown_duplicate_or_mismatched_result_rejects
    [
      @value.reject { |name, _| name == "aabSize" }, @value.merge("extra" => "untrusted"),
      @value.merge("aabSha256" => "b" * 64), @value.merge("operationIntentSha256" => "b" * 64),
      @value.merge("aabSize" => 0), @value.merge("aabSize" => true),
      @value.merge("schemaVersion" => 2),
    ].each do |value|
      interpreter("puts #{JSON.generate(value).inspect}")
      assert_raises(MobileReleaseKit::ContractError) { validate }
    end
    duplicate = JSON.generate(@value).sub('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')
    interpreter("puts #{duplicate.inspect}")
    assert_raises(MobileReleaseKit::ContractError) { validate }
  end

  def test_aab_change_during_validator_does_not_pass_handoff
    interpreter("File.write(#{@aab.inspect}, 'substituted artifact'); puts #{JSON.generate(@value).inspect}")
    assert_raises(MobileReleaseKit::ContractError) { validate }
  end

  def test_real_python_bootstrap_ignores_app_modules_pythonpath_home_and_sitecustomize
    python = ENV.fetch("MOBILE_RELEASE_TEST_PYTHON", "python3")
    stdout, _stderr, status = Open3.capture3(python, "-I", "-S", "-c", "import sys;print(sys.executable)")
    assert status.success?, "supported Python interpreter is required for the isolation contract"
    executable = stdout.strip
    marker = File.join(@root, "APP_CODE_EXECUTED")
    poison = "open(#{marker.inspect}, 'w').write('unsafe application import')\nraise RuntimeError('app code ran')\n"
    File.write(File.join(@app, "sitecustomize.py"), poison)
    File.write(File.join(@app, "mobile_release.py"), poison)
    File.write(File.join(@app, "unsafe.pth"), "import sitecustomize\n")
    output = Gate.capture_validator(
      { "PYTHONPATH" => @app, "PYTHONHOME" => @app, "PYTHONUSERBASE" => @app, "HOME" => @app },
      [executable, "-I", "-S", "-c", Gate::BOOTSTRAP, @module_root, "--help"], @app,
    )
    assert_includes output, "--operation-intent"
    assert_includes output, "--intent-sha256"
    refute File.exist?(marker), "application Python or site hooks executed inside a Store validator"
  end

  def test_fixed_bootstrap_runs_from_installed_package_layout_without_any_site_startup
    python = ENV.fetch("MOBILE_RELEASE_TEST_PYTHON", "python3")
    stdout, _stderr, status = Open3.capture3(python, "-I", "-S", "-c", "import sys;print(sys.executable)")
    assert status.success?, "supported Python interpreter is required for the installation contract"
    installed_modules = File.join(@root, "prefix/lib/python/site-packages")
    installed_tooling = File.join(@root, "prefix/share/mobile-release-kit/fastlane")
    FileUtils.mkdir_p(installed_modules)
    FileUtils.mkdir_p(installed_tooling)
    FileUtils.cp_r(File.join(@module_root, "mobile_release"), installed_modules)
    marker = File.join(@root, "SITE_CODE_EXECUTED")
    poison = "open(#{marker.inspect}, 'w').write('unexpected site startup')\nraise RuntimeError('site code ran')\n"
    File.write(File.join(installed_modules, "sitecustomize.py"), poison)
    File.write(File.join(installed_modules, "usercustomize.py"), poison)
    File.write(File.join(installed_modules, "unsafe.pth"), "import sitecustomize\n")
    # Data-file tooling and package modules live in different wheel locations.
    # The actual installed CLI supplies this exact module root; -S must not
    # run even that directory's .pth files or import a stale user installation.
    output = Gate.capture_validator(
      { "HOME" => @app, "PYTHONUSERBASE" => @app, "PYTHONPATH" => @app },
      [stdout.strip, "-I", "-S", "-c", Gate::BOOTSTRAP, installed_modules, "--help"],
      installed_tooling,
    )
    assert_includes output, "--operation-intent"
    assert_includes output, "--intent-sha256"
    refute File.exist?(marker)
    # Check the public Ruby boundary also accepts that package/data-file split
    # rather than requiring a source checkout alongside every installed wheel.
    assert_equal @value, validate(module_root: installed_modules, tooling_directory: installed_tooling)
  end
end
