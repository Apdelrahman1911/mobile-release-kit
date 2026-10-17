# frozen_string_literal: true

require_relative "release_support"
require_relative "native_upload_validation"

module MobileReleaseKit
  module AndroidUploadValidation
    ENVIRONMENT_NAMES = %w[
      CI HOME JAVA_HOME LANG LC_ALL LC_CTYPE PATH RUNNER_TEMP SYSTEMROOT
      TEMP TMP TMPDIR TZ MOBILE_RELEASE_BUNDLETOOL_JAR
    ].freeze
    RESULT_KEYS = %w[documentType schemaVersion operationIntentSha256 aabSha256 aabSize].freeze
    BOOTSTRAP = 'import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("mobile_release.android_upload_validation",run_name="__main__")'.freeze
    MAX_OUTPUT_BYTES = 64 * 1024
    MAX_SECONDS = 3_600

    module_function

    def current!(python:, module_root:, app_root:, config_path:, intent_path:, aab_path:, intent_sha256:, environment:, tooling_directory:)
      current_input!(python: python, module_root: module_root, app_root: app_root,
        config_path: config_path, intent_path: intent_path, aab_path: aab_path,
        intent_sha256: intent_sha256, environment: environment, tooling_directory: tooling_directory,
        intent_argument: "--operation-intent")
    end

    def current_local!(python:, module_root:, app_root:, config_path:, intent_path:, aab_path:, intent_sha256:, environment:, tooling_directory:)
      current_input!(python: python, module_root: module_root, app_root: app_root,
        config_path: config_path, intent_path: intent_path, aab_path: aab_path,
        intent_sha256: intent_sha256, environment: environment, tooling_directory: tooling_directory,
        intent_argument: "--local-operation-intent")
    end

    def current_input!(python:, module_root:, app_root:, config_path:, intent_path:, aab_path:, intent_sha256:, environment:, tooling_directory:, intent_argument:)
      unless python.is_a?(String) && python.start_with?(File::SEPARATOR) && !python.match?(/[\x00-\x1f\x7f]/) && File.file?(python) && File.executable?(python)
        raise ContractError, "Current AAB validation requires the toolkit's absolute Python interpreter"
      end
      unless intent_sha256.is_a?(String) && intent_sha256.match?(/\A[0-9a-f]{64}\z/)
        raise ContractError, "Current AAB validation requires the authenticated intent digest"
      end
      trusted_module_root = NativeUploadValidation.module_origin!(python: python, module_root: module_root,
        tooling_directory: tooling_directory, adapter_directory: __dir__, platform: "android")
      config = MobileReleaseKit.safe_path(app_root, config_path)
      intent = MobileReleaseKit.safe_path(app_root, intent_path)
      aab = MobileReleaseKit.safe_path(app_root, aab_path)
      argv = [
        python, "-I", "-S", "-c", BOOTSTRAP, trusted_module_root,
        "--app-root", File.realpath(app_root), "--config-path", config,
        intent_argument, intent, "--aab", aab, "--intent-sha256", intent_sha256,
      ]
      if intent_argument == "--local-operation-intent" && (invocation = StoreLaneLifetime.current_invocation)
        request = invocation.local_current_validation_request(adapter: self)
        argv.concat(["--local-registered-tools-json", request])
      end
      clean = environment.to_h.select { |name, value| ENVIRONMENT_NAMES.include?(name) && !value.to_s.empty? }
      clean.merge!("LANG" => "C", "LC_ALL" => "C")
      binding = StoreLaneLifetime.reserve_current_validation!(role: "current-android", adapter: self,
        environment: clean, argv: argv, tooling_directory: tooling_directory,
        intent_sha256: intent_sha256, artifact: aab)
      output = capture_validator(clean, argv, tooling_directory, store_binding: binding)
      binding ? binding.accept_result!(adapter: self, output: output) :
        validated_result(output, intent_sha256: intent_sha256, artifact: aab)
    rescue Exception => error # rubocop:disable Lint/RescueException
      binding&.fail_unless_retired!(error)
      raise
    ensure
      binding&.finish_call!
    end

    private_class_method :current_input!

    def validated_result(output, intent_sha256:, artifact:)
      value = MobileReleaseKit.strict_json(output, label: "current AAB validation result")
      unless value.is_a?(Hash) && value.keys.sort == RESULT_KEYS.sort && value["documentType"] == "android-current-upload-validation" &&
             value["schemaVersion"].instance_of?(Integer) && value["schemaVersion"] == 1 && value["operationIntentSha256"] == intent_sha256 &&
             value["aabSize"].is_a?(Integer) && value["aabSize"].positive? && value["aabSize"] == File.size(artifact) &&
             value["aabSha256"].is_a?(String) && value["aabSha256"].match?(/\A[0-9a-f]{64}\z/) &&
             File.file?(artifact) && !File.symlink?(artifact) && File.realpath(artifact) == artifact &&
             value["aabSha256"] == Digest::SHA256.file(artifact).hexdigest
        raise ContractError, "Current AAB validation returned incomplete or mismatched evidence"
      end
      value.each_value(&:freeze)
      value.freeze
    end

    def capture_validator(environment, argv, tooling_directory, store_binding: nil)
      NativeUploadValidation.capture(
        environment, argv, tooling_directory,
        max_seconds: MAX_SECONDS, max_output_bytes: MAX_OUTPUT_BYTES, label: "Current AAB",
        failure_message: "Current AAB signing/identity validation failed; no new upload is authorized (inspect the original AAB with credential-free preflight)",
        store_binding: store_binding,
      )
    end

    private_class_method :validated_result
  end
end
