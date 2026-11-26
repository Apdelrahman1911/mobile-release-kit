# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require "rbconfig"
require "json"
require "digest"
require_relative "../../fastlane/android_upload_validation"
require_relative "upload_process_fixture"

class AndroidUploadValidationTest < Minitest::Test
  Gate = MobileReleaseKit::AndroidUploadValidation
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
    observe_capture do
      Gate.current!(**{
        python: @python, module_root: @module_root, app_root: @app,
        config_path: @config, intent_path: @intent, aab_path: @aab,
        intent_sha256: "a" * 64, environment: environment,
        tooling_directory: @tooling_directory,
      }.merge(overrides))
    end
  end

  def process_case(mode)
    with_adapter_failure_diagnostic(platform: "android", mode: mode) do |optional|
      UploadProcessFixture.run(platform: "android", root: @root, mode: mode, parameters: {
        python: @python, module_root: @module_root, app_root: @app,
        config_path: @config, intent_path: @intent, aab_path: @aab,
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
    UploadProcessFixture.assert_domain_reusable!
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

class AndroidUploadOriginTest < Minitest::Test
  # Stop at the shared origin decision: no native capture or process fixture.
  def test_origin_android_current_adapter_supplies_actual_directory_before_capture
    calls = []
    refusal = ->(**arguments) { calls << arguments; raise MobileReleaseKit::ContractError, "inert origin refusal" }
    MobileReleaseKit::NativeUploadValidation.stub(:module_origin!, refusal) do
      assert_raises(MobileReleaseKit::ContractError) do
        MobileReleaseKit::AndroidUploadValidation.current!(python: RbConfig.ruby, module_root: "/inert/core.zip", app_root: "/inert/app",
          config_path: "release/mobile-release.json", intent_path: "intent.json", aab_path: "candidate.aab", intent_sha256: "a" * 64,
          environment: {}, tooling_directory: "/inert/runtime/store/tooling/fastlane")
      end
    end
    assert_equal 1, calls.length
    assert_equal "android", calls[0].fetch(:platform)
    assert_equal File.realpath(File.expand_path("../../fastlane", __dir__)), calls[0].fetch(:adapter_directory)
    assert_equal "/inert/core.zip", calls[0].fetch(:module_root)
  end
end

class AndroidLocalUploadInputTest < Minitest::Test
  # Real tiny paths, source admission and result policy; no validator process.
  Gate = MobileReleaseKit::AndroidUploadValidation

  def with_inputs
    Dir.mktmpdir("mrk-local-current-") do |root|
      root = File.realpath(root)
      FileUtils.mkdir_p(File.join(root, "release"))
      %w[release/mobile-release.json intent.json app-release.aab].each do |name|
        File.binwrite(File.join(root, name), "inert current input")
      end
      yield({python: RbConfig.ruby, module_root: File.expand_path("../../src", __dir__), app_root: root,
        config_path: "release/mobile-release.json", intent_path: "intent.json", aab_path: "app-release.aab",
        intent_sha256: "a" * 64, environment: {"PATH" => "/usr/bin:/bin", "LANG" => "unsafe-locale",
          "GOOGLE_APPLICATION_CREDENTIALS" => "secret-sentinel", "PYTHONPATH" => "untrusted",
          "MOBILE_RELEASE_ORIGIN" => "local-desktop", "GITHUB_TOKEN" => "secret-sentinel"},
        tooling_directory: File.expand_path("../../fastlane", __dir__)})
    end
  end

  def test_local_and_ci_fixed_arguments_share_admission_capture_and_result_policy
    with_inputs do |inputs|
      artifact = File.join(inputs.fetch(:app_root), inputs.fetch(:aab_path))
      result = {"documentType" => "android-current-upload-validation", "schemaVersion" => 1,
        "operationIntentSha256" => inputs.fetch(:intent_sha256), "aabSize" => File.size(artifact),
        "aabSha256" => Digest::SHA256.file(artifact).hexdigest}
      original_reserve = MobileReleaseKit::StoreLaneLifetime.method(:reserve_current_validation!)
      reservations = []
      reserve = ->(**request) { reservations << request; original_reserve.call(**request) }
      [:current!, :current_local!].each do |entry|
        flag = entry == :current! ? "--operation-intent" : "--local-operation-intent"
        captures = []
        capture = lambda do |environment, argv, tooling, **limits|
          captures << [environment, argv, tooling, limits]
          assert_equal({"PATH" => "/usr/bin:/bin", "LANG" => "C", "LC_ALL" => "C"}, environment)
          assert_equal [RbConfig.ruby, "-I", "-S", "-c", Gate::BOOTSTRAP, inputs.fetch(:module_root),
            "--app-root", inputs.fetch(:app_root), "--config-path", File.join(inputs.fetch(:app_root), "release/mobile-release.json"),
            flag, File.join(inputs.fetch(:app_root), "intent.json"), "--aab", artifact,
            "--intent-sha256", inputs.fetch(:intent_sha256)], argv
          assert_equal inputs.fetch(:tooling_directory), tooling
          assert_equal 3_600, limits.fetch(:max_seconds)
          assert_equal 65_536, limits.fetch(:max_output_bytes)
          assert_nil limits.fetch(:store_binding)
          JSON.generate(result)
        end
        MobileReleaseKit::StoreLaneLifetime.stub(:reserve_current_validation!, reserve) do
          MobileReleaseKit::NativeUploadValidation.stub(:capture, capture) do
            assert_equal result, Gate.public_send(entry, **inputs)
          end
        end
        assert_equal 1, captures.length
        reservation = reservations.last
        assert_equal "current-android", reservation.fetch(:role)
        assert_same Gate, reservation.fetch(:adapter)
        assert_equal captures[0][0], reservation.fetch(:environment)
        assert_equal captures[0][1], reservation.fetch(:argv)
        assert_equal artifact, reservation.fetch(:artifact)
      end
      assert_equal 2, reservations.length
      refute Gate.respond_to?(:current_input!)
      # Even a syntactically successful child cannot hand off substituted bytes.
      MobileReleaseKit::NativeUploadValidation.stub(:capture, ->(*) {
        File.binwrite(artifact, "changed bytes")
        JSON.generate(result)
      }) do
        assert_raises(MobileReleaseKit::ContractError) { Gate.current_local!(**inputs) }
      end
    end
  end

  def test_local_current_binding_failure_is_not_retired_as_success
    with_inputs do |inputs|
      calls = []
      binding = Object.new
      binding.define_singleton_method(:fail_unless_retired!) { |error| calls << [:failed, error] }
      binding.define_singleton_method(:finish_call!) { calls << [:finish] }
      binding.define_singleton_method(:accept_result!) { |**_| raise "must not accept a failed capture" }
      failure = MobileReleaseKit::ContractError.new("inert joined refusal")
      MobileReleaseKit::StoreLaneLifetime.stub(:reserve_current_validation!, binding) do
        MobileReleaseKit::NativeUploadValidation.stub(:capture, ->(*args, **kw) {
          assert_same binding, kw.fetch(:store_binding)
          raise failure
        }) do
          assert_same failure, assert_raises(MobileReleaseKit::ContractError) { Gate.current_local!(**inputs) }
        end
      end
      assert_equal [[:failed, failure], [:finish]], calls
    end
  end

  def selected_invocation(digest, local: true)
    lifetime = MobileReleaseKit::StoreLaneLifetime
    invocation = lifetime::Invocation.new(lane: "android_internal_upload", nonce: "n"*16,
      output: "/inert/result.json", mode: "execute",
      run_deadline_ns: MobileReleaseKit::NativeUploadProcess.monotonic_ns + 90_000_000_000)
    # Runtime's real original-resource admission has separate composed tests.
    # This boundary tests the exact existing Invocation, not a minted grant.
    invocation.instance_variable_set(:@local_execution, {digest: digest}.freeze) if local
    raw = MobileReleaseKit.canonical_json({"schemaVersion"=>1,"toolchain"=>{"inert"=>true},
      "runDeadlineNs"=>(invocation.run_deadline_ns-5_000_000_000).to_s,
      "hardDeadlineNs"=>invocation.run_deadline_ns.to_s}).freeze
    invocation.define_singleton_method(:local_current_validation_request) do |adapter:|
      raise lifetime::LifetimeError unless adapter.equal?(MobileReleaseKit::AndroidUploadValidation) && local
      raw
    end
    [invocation,raw]
  end

  def test_registered_request_is_forwarded_from_same_invocation_without_credentials
    with_inputs do |inputs|
      invocation,raw = selected_invocation(inputs.fetch(:intent_sha256))
      failure = MobileReleaseKit::ContractError.new("inert capture boundary")
      seen=[]
      MobileReleaseKit::StoreLaneLifetime.stub(:current_invocation,invocation) do
        MobileReleaseKit::NativeUploadValidation.stub(:capture, ->(env,argv,tooling,**kw) {
          seen << kw.fetch(:store_binding)
          assert_equal ["--local-registered-tools-json",raw], argv[-2,2]
          assert_equal 1,argv.count("--local-operation-intent")
          refute_includes argv,"--operation-intent"
          refute_includes env.values,"secret-sentinel"
          binding=seen.last
          assert_same invocation,binding.instance_variable_get(:@invocation)
          assert_equal [invocation.run_deadline_ns-5_000_000_000,invocation.run_deadline_ns],binding.instance_variable_get(:@deadlines)
          raise failure
        }) do
          assert_same failure,assert_raises(MobileReleaseKit::ContractError){Gate.current_local!(**inputs)}
        end
      end
      assert_equal 1,seen.length
      assert invocation.unknown?
      refute seen.first.retired?
    end
  end

  def test_registered_nomination_digest_and_origin_are_one_use_exactly_bound
    digest="a"*64
    variations=[:good,:json,:digest,:argv_digest,:ci_flag,:missing_flag,:duplicate,:no_local]
    variations.each do |variation|
      invocation,raw=selected_invocation(digest,local:variation != :no_local)
      argv=["/inert/python","--local-operation-intent","/inert/intent.json",
        "--intent-sha256",digest,"--local-registered-tools-json",raw]
      request={role:"current-android",adapter:Gate,environment:{"LANG"=>"C"},argv:argv,
        tooling_directory:"/inert/tooling",intent_sha256:digest,artifact:"/inert/app-release.aab"}
      case variation
      when :json then argv[-1]=raw+" "
      when :digest then request[:intent_sha256]="b"*64
      when :argv_digest then argv[4]="b"*64
      when :ci_flag then argv[1]="--operation-intent"
      when :missing_flag then argv.slice!(-2,2)
      when :duplicate then argv.unshift("--local-registered-tools-json")
      end
      if variation==:good
        binding=invocation.reserve_current_validation!(**request)
        refute binding.retired?
        assert_raises(MobileReleaseKit::StoreLaneLifetime::LifetimeError){invocation.reserve_current_validation!(**request)}
      else
        assert_raises(MobileReleaseKit::StoreLaneLifetime::LifetimeError){invocation.reserve_current_validation!(**request)}
        assert_nil invocation.instance_variable_get(:@nested)
      end
      assert invocation.unknown?
    end
  end
end
