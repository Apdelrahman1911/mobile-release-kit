# frozen_string_literal: true

require "time"
require_relative "release_support"
require_relative "native_upload_validation"

module MobileReleaseKit
  # This gate launches only the already-running toolkit's Python interpreter,
  # supplied by Python's Store adapter, never a command from application config.
  # The result is a private, same-process validity window, NOT an attestation.
  module IosUploadValidation
    ENVIRONMENT_NAMES = %w[
      CI DEVELOPER_DIR HOME JAVA_HOME LANG LC_ALL LC_CTYPE PATH RUNNER_TEMP
      SDKROOT SYSTEMROOT TEMP TMP TMPDIR TZ
    ].freeze
    RESULT_KEYS = %w[documentType schemaVersion operationIntentSha256 ipaSha256 ipaSize notBefore notAfter].freeze
    BOOTSTRAP = 'import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("mobile_release.ios_upload_validation",run_name="__main__")'.freeze
    MAX_OUTPUT_BYTES = 64 * 1024
    MAX_SECONDS = 3_600

    module_function

    def current!(python:, module_root:, app_root:, config_path:, intent_path:, ipa_path:, intent_sha256:, environment:, tooling_directory:)
      unless python.is_a?(String) && python.start_with?(File::SEPARATOR) && !python.match?(/[\x00-\x1f\x7f]/) && File.file?(python) && File.executable?(python)
        raise ContractError, "Current IPA validation requires the toolkit's absolute Python interpreter"
      end
      unless intent_sha256.is_a?(String) && intent_sha256.match?(/\A[0-9a-f]{64}\z/)
        raise ContractError, "Current IPA validation requires the authenticated intent digest"
      end
      unless module_root.is_a?(String) && module_root.start_with?(File::SEPARATOR) &&
             !module_root.match?(/[\x00-\x1f\x7f]/) && !File.symlink?(module_root) && File.directory?(module_root)
        raise ContractError, "Current IPA validation requires the pinned toolkit module root"
      end
      trusted_module_root = File.realpath(module_root)
      source_root = File.expand_path("../src", tooling_directory)
      if File.directory?(File.join(source_root, "mobile_release")) && trusted_module_root != File.realpath(source_root)
        raise ContractError, "Current IPA validation module differs from the pinned source checkout"
      end
      module_file = MobileReleaseKit.safe_path(trusted_module_root, "mobile_release/ios_upload_validation.py")
      raise ContractError, "Pinned current-upload validator module is missing" unless File.file?(module_file)
      config = MobileReleaseKit.safe_path(app_root, config_path)
      intent = MobileReleaseKit.safe_path(app_root, intent_path)
      ipa = MobileReleaseKit.safe_path(app_root, ipa_path)
      argv = [
        # -I excludes cwd/PYTHONPATH/user site; -S also excludes site/.pth code.
        # Only this fixed literal bootstrap can insert a module directory, and
        # that directory comes from the actual pinned CLI's __file__, not any
        # application input or inherited Python environment.
        python, "-I", "-S", "-c", BOOTSTRAP, trusted_module_root,
        "--app-root", File.realpath(app_root), "--config-path", config,
        "--operation-intent", intent, "--ipa", ipa, "--intent-sha256", intent_sha256,
      ]
      clean = environment.to_h.select { |name, value| ENVIRONMENT_NAMES.include?(name) && !value.to_s.empty? }
      clean.merge!("LANG" => "C", "LC_ALL" => "C")
      output = capture_validator(clean, argv, tooling_directory)
      value = MobileReleaseKit.strict_json(output, label: "current IPA validation result")
      unless value.is_a?(Hash) && value.keys.sort == RESULT_KEYS.sort && value["documentType"] == "ios-current-upload-validation" &&
             value["schemaVersion"] == 1 && value["operationIntentSha256"] == intent_sha256 &&
             value["ipaSize"].is_a?(Integer) && value["ipaSize"].positive? && value["ipaSize"] == File.size(ipa) &&
             value["ipaSha256"].is_a?(String) && value["ipaSha256"].match?(/\A[0-9a-f]{64}\z/) &&
             value["ipaSha256"] == Digest::SHA256.file(ipa).hexdigest
        raise ContractError, "Current IPA validation returned incomplete or mismatched evidence"
      end
      require_current!(value)
      value.freeze
    end

    def require_current!(value)
      before, after = %w[notBefore notAfter].map do |name|
        date = value.fetch(name)
        unless date.is_a?(String) && date.match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\z/)
          raise ContractError, "Current IPA validation returned an invalid UTC signing interval"
        end
        time = Time.iso8601(date)
        # Ruby normalizes invalid calendar dates; round-trip the non-fractional
        # part rather than accepting a fictional February 30 or leap second.
        unless time.utc.strftime("%Y-%m-%dT%H:%M:%S") == date.split(/[.Z]/, 2).first
          raise ContractError, "Current IPA validation returned an invalid UTC signing interval"
        end
        time
      end
      now = Time.now.utc
      unless before < after && before <= now && now < after
        raise ContractError, "IPA signing/profile eligibility expired before upload; preserve the original candidate and reconcile accepted Store state instead of re-signing"
      end
      true
    rescue KeyError, ArgumentError
      raise ContractError, "Current IPA validation returned an invalid UTC signing interval"
    end

    def capture_validator(environment, argv, tooling_directory)
      NativeUploadValidation.capture(
        environment, argv, tooling_directory,
        max_seconds: MAX_SECONDS, max_output_bytes: MAX_OUTPUT_BYTES, label: "Current IPA",
        failure_message: "Current IPA signing/profile validation failed; no new upload is authorized (inspect the original IPA with credential-free preflight)",
      )
    end
  end
end
