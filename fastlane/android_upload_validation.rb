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
      unless python.is_a?(String) && python.start_with?(File::SEPARATOR) && !python.match?(/[\x00-\x1f\x7f]/) && File.file?(python) && File.executable?(python)
        raise ContractError, "Current AAB validation requires the toolkit's absolute Python interpreter"
      end
      unless intent_sha256.is_a?(String) && intent_sha256.match?(/\A[0-9a-f]{64}\z/)
        raise ContractError, "Current AAB validation requires the authenticated intent digest"
      end
      unless module_root.is_a?(String) && module_root.start_with?(File::SEPARATOR) &&
             !module_root.match?(/[\x00-\x1f\x7f]/) && !File.symlink?(module_root) && File.directory?(module_root)
        raise ContractError, "Current AAB validation requires the pinned toolkit module root"
      end
      trusted_module_root = File.realpath(module_root)
      source_root = File.expand_path("../src", tooling_directory)
      if File.directory?(File.join(source_root, "mobile_release")) && trusted_module_root != File.realpath(source_root)
        raise ContractError, "Current AAB validation module differs from the pinned source checkout"
      end
      module_file = MobileReleaseKit.safe_path(trusted_module_root, "mobile_release/android_upload_validation.py")
      raise ContractError, "Pinned current-upload validator module is missing" unless File.file?(module_file)
      config = MobileReleaseKit.safe_path(app_root, config_path)
      intent = MobileReleaseKit.safe_path(app_root, intent_path)
      aab = MobileReleaseKit.safe_path(app_root, aab_path)
      argv = [
        python, "-I", "-S", "-c", BOOTSTRAP, trusted_module_root,
        "--app-root", File.realpath(app_root), "--config-path", config,
        "--operation-intent", intent, "--aab", aab, "--intent-sha256", intent_sha256,
      ]
      clean = environment.to_h.select { |name, value| ENVIRONMENT_NAMES.include?(name) && !value.to_s.empty? }
      clean.merge!("LANG" => "C", "LC_ALL" => "C")
      value = MobileReleaseKit.strict_json(capture_validator(clean, argv, tooling_directory), label: "current AAB validation result")
      unless value.is_a?(Hash) && value.keys.sort == RESULT_KEYS.sort && value["documentType"] == "android-current-upload-validation" &&
             value["schemaVersion"] == 1 && value["operationIntentSha256"] == intent_sha256 &&
             value["aabSize"].is_a?(Integer) && value["aabSize"].positive? && value["aabSize"] == File.size(aab) &&
             value["aabSha256"].is_a?(String) && value["aabSha256"].match?(/\A[0-9a-f]{64}\z/) &&
             File.file?(aab) && !File.symlink?(aab) && File.realpath(aab) == aab &&
             value["aabSha256"] == Digest::SHA256.file(aab).hexdigest
        raise ContractError, "Current AAB validation returned incomplete or mismatched evidence"
      end
      value.freeze
    end

    def capture_validator(environment, argv, tooling_directory)
      NativeUploadValidation.capture(
        environment, argv, tooling_directory,
        max_seconds: MAX_SECONDS, max_output_bytes: MAX_OUTPUT_BYTES, label: "Current AAB",
        failure_message: "Current AAB signing/identity validation failed; no new upload is authorized (inspect the original AAB with credential-free preflight)",
      )
    end
  end
end
