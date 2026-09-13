# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "rbconfig"
require "json"
require "digest"
require_relative "../../fastlane/ios_upload_validation"
require_relative "upload_process_fixture"

class IosUploadValidationTest < Minitest::Test
  Gate = MobileReleaseKit::IosUploadValidation
  include UploadProcessFixture::Contracts
  prepend UploadProcessFixture::CaseGuard

  def setup
    UploadProcessFixture.assert_domain_reusable!
    @root = File.realpath(Dir.mktmpdir("mrk-upload-gate-"))
    @capture_observations = []
    @app = File.join(@root, "app")
    FileUtils.mkdir_p(File.join(@app, "release"))
    @config = File.join(@app, "release/mobile-release.json")
    @intent = File.join(@app, "intent.json")
    @ipa = File.join(@app, "candidate.ipa")
    File.write(@config, "{}")
    File.write(@intent, "{}")
    File.write(@ipa, "bounded synthetic artifact")
    @module_root = File.realpath(File.expand_path("../../src", __dir__))
    @tooling_directory = File.realpath(File.expand_path("../../fastlane", __dir__))
    @capture = File.join(@root, "capture.json")
    @python = File.join(@root, "trusted-test-interpreter")
    @value = {
      "documentType" => "ios-current-upload-validation", "schemaVersion" => 1,
      "operationIntentSha256" => "a" * 64,
      "ipaSha256" => Digest::SHA256.file(@ipa).hexdigest, "ipaSize" => File.size(@ipa),
      "notBefore" => "2020-01-01T00:00:00Z", "notAfter" => "2099-01-01T00:00:00Z",
    }
    interpreter("puts #{JSON.generate(@value).inspect}")
  end

  def teardown
    return unless @root # A refused entry acquired no new fixture directory.

    unresolved_capture = (@capture_observations || []).any? { |item| !(item.finalized? || item.no_producers?) }
    if UploadProcessFixture.cleanup_unresolved?(@root) || unresolved_capture
      warn "Preserve unresolved synthetic process evidence: #{@root}"
      flunk "direct adapter capture did not establish producer finality" if unresolved_capture
      unless UploadProcessFixture.expected_unknown_retention?(@root)
        flunk "adapter fixture retained unexpected process custody"
      end
    else
      FileUtils.remove_entry(@root)
    end
  end

  def interpreter(source)
    UploadProcessFixture.assert_domain_reusable!
    # A toolkit-owned fake executable exercises the REAL no-shell spawn, pipe
    # limits, deadline, child cleanup, argv, cwd and environment behavior. It
    # is not an IPA/native-signature fixture or an application hook.
    File.write(@python, <<~RUBY)
      #!#{RbConfig.ruby}
      require "json"
      File.write(#{@capture.inspect}, JSON.generate("argv" => ARGV, "environment" => ENV.to_h, "cwd" => Dir.pwd, "pid" => Process.pid))
      #{source}
    RUBY
    File.chmod(0o700, @python)
  end

  def validate(environment: {}, **overrides)
    observe_capture do
      Gate.current!(**{
        python: @python, module_root: @module_root, app_root: @app,
        config_path: @config, intent_path: @intent, ipa_path: @ipa,
        intent_sha256: "a" * 64, environment: environment,
        tooling_directory: @tooling_directory,
      }.merge(overrides))
    end
  end

  def process_case(mode)
    with_adapter_failure_diagnostic(platform: "ios", mode: mode) do |optional|
      UploadProcessFixture.run(platform: "ios", root: @root, mode: mode, parameters: {
        python: @python, module_root: @module_root, app_root: @app,
        config_path: @config, intent_path: @intent, ipa_path: @ipa,
        intent_sha256: "a" * 64, tooling_directory: @tooling_directory,
      }, **optional)
    end
  end

  def observe_capture
    UploadProcessFixture.assert_domain_reusable!
    observation = UploadProcessFixture::CaptureObservation.new(
      native: MobileReleaseKit::NativeUploadValidation, root: @root,
    )
    @capture_observations << observation
    observation.observe { yield }
  end

  def assert_capture_finalized(observation)
    refute observation.unknown?, "capture retained uncertain child/task/descriptor custody"
    assert observation.finalized?, "capture returned without genuine waits, EOF, joins and closes"
  end

  def python_executable
    stdout, stderr, status = UploadProcessFixture.capture_command(
      [ENV.fetch("MOBILE_RELEASE_TEST_PYTHON", "python3"), "-I", "-S", "-c", "import sys;print(sys.executable)"],
      seconds: 5,
    )
    assert_equal 0, status, "supported Python interpreter is required for the isolation contract"
    assert_empty stderr
    executable = stdout.strip
    assert executable.start_with?(File::SEPARATOR), "Python discovery did not return an absolute interpreter"
    executable
  end

  def test_real_spawn_has_constant_isolated_argv_no_store_authority_or_app_python_path
    forbidden = %w[
      MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64 MOBILE_RELEASE_IOS_CERTIFICATE_P12_BASE64
      MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64 GH_TOKEN GITHUB_TOKEN
      ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
      GOOGLE_APPLICATION_CREDENTIALS AWS_SESSION_TOKEN AZURE_CLIENT_SECRET
      PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE RUBYOPT BUNDLE_GEMFILE
    ].to_h { |name| [name, "fictional-#{name}"] }
    value = validate(environment: forbidden.merge("HOME" => @root, "PATH" => "/usr/bin:/bin", "LANG" => "unexpected"))
    assert_equal @value, value
    assert value.frozen?
    capture = JSON.parse(File.read(@capture))
    assert_equal ["-I", "-S", "-c", Gate::BOOTSTRAP, @module_root, "--app-root", @app,
                  "--config-path", @config, "--operation-intent", @intent, "--ipa", @ipa,
                  "--intent-sha256", "a" * 64], capture.fetch("argv")
    assert_equal @tooling_directory, capture.fetch("cwd")
    child_environment = capture.fetch("environment").dup
    # CoreFoundation may initialize this non-authoritative encoding hint inside
    # the child on macOS, after exec received the exact scrubbed environment.
    if (encoding = child_environment.delete("__CF_USER_TEXT_ENCODING"))
      assert_match(/\A0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+\z/, encoding)
    end
    assert_equal({ "HOME" => @root, "PATH" => "/usr/bin:/bin", "LANG" => "C", "LC_ALL" => "C" }, child_environment)
    forbidden.each_key { |name| refute capture.fetch("environment").key?(name) }
  end

  def test_relative_command_and_app_substitute_module_are_rejected_before_spawn
    assert_raises(MobileReleaseKit::ContractError) { validate(python: "python3") }
    assert_raises(MobileReleaseKit::ContractError) { validate(python: "#{@python}\n-fake") }
    UploadProcessFixture.assert_domain_reusable!
    FileUtils.mkdir_p(File.join(@app, "mobile_release"))
    File.write(File.join(@app, "mobile_release/ios_upload_validation.py"), "raise RuntimeError('application code')")
    assert_raises(MobileReleaseKit::ContractError) { validate(module_root: @app) }
    refute File.exist?(@capture)
  end

  def test_parent_symlink_and_outside_ipa_cannot_reach_validator
    outside = File.join(@root, "outside.ipa")
    File.write(outside, "outside bytes")
    File.symlink(outside, File.join(@app, "link.ipa"))
    assert_raises(MobileReleaseKit::ContractError) { validate(ipa_path: outside) }
    assert_raises(MobileReleaseKit::ContractError) { validate(ipa_path: File.join(@app, "link.ipa")) }
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
    assert File.file?(@capture), "the real validator never entered"
    # A late numeric PID probe is not child or process-group lifetime authority.
    assert_capture_finalized(@capture_observations.last)
  end

  def test_private_stderr_is_bounded_and_never_forwarded
    interpreter('STDERR.sync = true; STDERR.write("private-profile" * 6_000); sleep 60')
    error = assert_raises(MobileReleaseKit::ContractError) { validate }
    assert_includes error.message, "safety bound"
    refute_includes error.message, "private-profile"
    assert File.file?(@capture), "the real validator never entered"
    assert_capture_finalized(@capture_observations.last)
  end

  def test_incomplete_unknown_duplicate_or_mismatched_result_rejects
    [
      @value.reject { |name, _| name == "notAfter" }, @value.merge("extra" => "untrusted"),
      @value.merge("ipaSha256" => "b" * 64), @value.merge("operationIntentSha256" => "b" * 64),
      @value.merge("ipaSize" => 0), @value.merge("ipaSize" => true),
      @value.merge("schemaVersion" => 2),
    ].each do |value|
      interpreter("puts #{JSON.generate(value).inspect}")
      assert_raises(MobileReleaseKit::ContractError) { validate }
    end
    duplicate = JSON.generate(@value).sub('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')
    interpreter("puts #{duplicate.inspect}")
    assert_raises(MobileReleaseKit::ContractError) { validate }
  end

  def test_ipa_change_during_validator_does_not_pass_handoff
    interpreter("File.write(#{@ipa.inspect}, 'substituted artifact'); puts #{JSON.generate(@value).inspect}")
    assert_raises(MobileReleaseKit::ContractError) { validate }
  end

  def test_final_boundary_checks_both_current_bounds_without_native_rerun
    now = Time.iso8601("2026-09-05T12:00:00Z")
    Time.stub(:now, now) do
      assert Gate.require_current!("notBefore" => now.iso8601, "notAfter" => (now + 1).iso8601)
      assert_raises(MobileReleaseKit::ContractError) { Gate.require_current!("notBefore" => (now - 1).iso8601, "notAfter" => now.iso8601) }
      assert_raises(MobileReleaseKit::ContractError) { Gate.require_current!("notBefore" => (now + 1).iso8601, "notAfter" => (now + 2).iso8601) }
      assert_raises(MobileReleaseKit::ContractError) { Gate.require_current!("notBefore" => now.iso8601, "notAfter" => now.iso8601) }
      assert Gate.require_current!("notBefore" => "2026-09-05T11:59:59.999999Z", "notAfter" => "2026-09-05T12:00:00.000001Z")
    end
    ["2026-02-30T12:00:00Z", "2026-09-05T12:00:60Z", "2026-09-05T12:00:00", "2026-09-05T12:00:00+00:00", 1, nil].each do |value|
      assert_raises(MobileReleaseKit::ContractError) { Gate.require_current!(@value.merge("notBefore" => value)) }
    end
  end

  def test_real_python_bootstrap_ignores_app_modules_pythonpath_home_and_sitecustomize
    executable = python_executable
    marker = File.join(@root, "APP_CODE_EXECUTED")
    poison = "open(#{marker.inspect}, 'w').write('unsafe application import')\nraise RuntimeError('app code ran')\n"
    File.write(File.join(@app, "sitecustomize.py"), poison)
    File.write(File.join(@app, "mobile_release.py"), poison)
    File.write(File.join(@app, "unsafe.pth"), "import sitecustomize\n")
    output = observe_capture do
      Gate.capture_validator(
        { "PYTHONPATH" => @app, "PYTHONHOME" => @app, "PYTHONUSERBASE" => @app, "HOME" => @app },
        [executable, "-I", "-S", "-c", Gate::BOOTSTRAP, @module_root, "--help"], @app,
      )
    end
    assert_includes output, "--operation-intent"
    assert_includes output, "--intent-sha256"
    refute File.exist?(marker), "application Python or site hooks executed inside a Store validator"
  end

  def test_fixed_bootstrap_runs_from_installed_package_layout_without_any_site_startup
    executable = python_executable
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
    # This is a copied Python layout contract, NOT actual installed Ruby capture
    # evidence; test_installed_ruby_capture.rb exercises the real wheel helpers.
    # Data-file tooling and package modules live in different wheel locations.
    # The actual installed CLI supplies this exact module root; -S must not
    # run even that directory's .pth files or import a stale user installation.
    output = observe_capture do
      Gate.capture_validator(
        { "HOME" => @app, "PYTHONUSERBASE" => @app, "PYTHONPATH" => @app },
        [executable, "-I", "-S", "-c", Gate::BOOTSTRAP, installed_modules, "--help"],
        installed_tooling,
      )
    end
    assert_includes output, "--operation-intent"
    assert_includes output, "--intent-sha256"
    refute File.exist?(marker)
    # Check the public Ruby boundary also accepts that package/data-file split
    # rather than requiring a source checkout alongside every installed wheel.
    assert_equal @value, validate(module_root: installed_modules, tooling_directory: installed_tooling)
  end
end
