# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"

module MobileReleaseKit
  class ContractError < StandardError; end

  class DuplicateRejectingHash < Hash
    def []=(key, value)
      raise ContractError, "Duplicate JSON key: #{key}" if key?(key)

      super
    end
  end

  COMMENT_PREFIXES = ["#", "//", ";"].freeze

  def self.required_environment(environ, name, strip:)
    raw = environ[name]
    missing = raw.nil? || (strip ? raw.strip.empty? : raw.empty?)
    raise ContractError, "Missing protected environment value: #{name}" if missing

    strip ? raw.strip : raw
  end

  def self.closed_tester_assignment?(testers)
    groups = testers.respond_to?(:google_groups) ? testers.google_groups : nil
    Array(groups).any? { |group| group.is_a?(String) && !group.strip.empty? }
  end

  def self.manual_app_store_release?(version)
    release_type = version.respond_to?(:release_type) ? version.release_type.to_s.upcase : ""
    earliest = if version.respond_to?(:earliest_release_date)
                 version.earliest_release_date.to_s.strip
               else
                 ""
               end
    release_type == "MANUAL" && earliest.empty?
  end

  def self.deep_sort(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
        result[key] = deep_sort(value.fetch(source))
      end
    when Array
      value.map { |item| deep_sort(item) }
    when Float
      raise ContractError, "Floating-point values are forbidden in operation evidence"
    else
      value
    end
  end

  def self.canonical_json(value)
    JSON.generate(deep_sort(value))
  end

  def self.strict_json(text, label: "JSON")
    # DuplicateRejectingHash is a parser sentinel, not the state-machine's
    # mutable value type. Retaining it through nested `dup` calls would reject
    # legitimate before -> target field updates after loading a sealed intent.
    # The pinned JSON parser optimizes Hash subclasses and may bypass []=;
    # its explicit duplicate-key option is therefore required as well.
    deep_sort(JSON.parse(text, object_class: DuplicateRejectingHash, allow_duplicate_key: false))
  rescue JSON::ParserError, EncodingError => e
    raise ContractError, "#{label} is invalid UTF-8 JSON: #{e.class}"
  end

  def self.operation_intent(root, path)
    safe = safe_path(root, path)
    unless File.file?(safe) && !File.symlink?(safe) && File.size(safe) <= 2 * 1024 * 1024
      raise ContractError, "Operation intent must be a bounded regular file"
    end
    document = strict_json(File.read(safe, encoding: "UTF-8"), label: "Operation intent")
    integrity = document["integrity"]
    unless integrity.is_a?(Hash) && integrity.keys.sort == %w[algorithm sha256] &&
           integrity["algorithm"] == "sha256" &&
           integrity["sha256"].to_s.match?(/\A[a-f0-9]{64}\z/)
      raise ContractError, "Operation intent integrity is invalid"
    end
    payload = document.reject { |key, _value| key == "integrity" }
    actual = Digest::SHA256.hexdigest(canonical_json(payload))
    raise ContractError, "Operation intent integrity mismatch" unless secure_equal(actual, integrity["sha256"])
    unless payload["documentType"] == "store-operation-intent" && payload["schemaVersion"] == 1
      raise ContractError, "Operation intent document type/schemaVersion is invalid"
    end
    [payload, integrity.fetch("sha256")]
  end

  def self.execution_authority(environ)
    raw = required_environment(environ, "MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON", strip: true)
    value = strict_json(raw, label: "Execution authority")
    expected = %w[
      attempt callerPath event headSha ref reusableCommit reusablePath
      reusableRepository runId workflow
    ]
    raise ContractError, "Execution authority fields are invalid" unless value.keys.sort == expected.sort
    value
  end

  def self.hmac_commitment(domain, value, environ)
    key_text = required_environment(
      environ,
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
      strip: false,
    )
    key = Base64.strict_decode64(key_text)
    raise ContractError, "Operation commitment key must be exactly 32 bytes" unless key.bytesize == 32
    unless domain.match?(/\A[a-z0-9-]{1,64}\z/)
      raise ContractError, "Operation commitment domain is invalid"
    end
    OpenSSL::HMAC.hexdigest(
      "SHA256",
      key,
      "mobile-release-kit:hmac:v1:#{domain}:#{canonical_json(value)}",
    )
  rescue ArgumentError
    raise ContractError, "Operation commitment key must be canonical base64"
  ensure
    key&.replace("\0" * key.bytesize)
  end

  def self.secure_equal(left, right)
    return false unless left.is_a?(String) && right.is_a?(String) && left.bytesize == right.bytesize

    OpenSSL.fixed_length_secure_compare(left, right)
  end

  def self.safe_path(root, path, must_exist: true)
    resolved_root = File.realpath(root)
    candidate = File.expand_path(path, resolved_root)
    unless candidate == resolved_root || candidate.start_with?(resolved_root + File::SEPARATOR)
      raise ContractError, "Path escapes the application repository"
    end

    present = File.exist?(candidate) || File.symlink?(candidate)
    raise ContractError, "Required file is missing: #{path}" if must_exist && !present

    # For an output that does not exist yet, resolving its closest existing
    # ancestor prevents a committed directory symlink from redirecting writes.
    probe = candidate
    unless present
      probe = File.dirname(probe) until File.exist?(probe) || File.symlink?(probe)
    end
    resolved_probe = File.realpath(probe)
    unless resolved_probe == resolved_root || resolved_probe.start_with?(resolved_root + File::SEPARATOR)
      raise ContractError, "Path resolves outside the application repository"
    end

    candidate
  rescue SystemCallError
    raise ContractError, "Path cannot be resolved safely: #{path}"
  end

  def self.release_version(path, name_key:, build_key:)
    raise ContractError, "Version source must not be a symlink" if File.symlink?(path)
    unless File.file?(path) && File.size(path) <= 64 * 1024
      raise ContractError, "Version source is missing or unexpectedly large"
    end

    values = {}
    File.foreach(path, encoding: "UTF-8") do |line|
      stripped = line.strip
      next if stripped.empty? || COMMENT_PREFIXES.any? { |prefix| stripped.start_with?(prefix) }

      key, value = stripped.split("=", 2)
      raise ContractError, "Malformed version line in #{path}" if value.nil?

      key = key.strip
      value = value.strip
      unless key.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*\z/)
        raise ContractError, "Invalid version key: #{key}"
      end
      raise ContractError, "Duplicate version key: #{key}" if values.key?(key)
      if value.empty? || ["$", "`"].any? { |token| value.include?(token) }
        raise ContractError, "Unsafe or empty version value: #{key}"
      end
      if (value.start_with?('"') && value.end_with?('"')) ||
         (value.start_with?("'") && value.end_with?("'"))
        value = value[1...-1]
      end
      raise ContractError, "Unsafe or empty version value: #{key}" if value.empty?

      values[key] = value
    end

    marketing = values[name_key].to_s
    build_text = values[build_key].to_s
    raise ContractError, "Marketing version is missing" if marketing.empty?
    unless marketing.match?(/\A[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?\z/)
      raise ContractError, "Marketing version must use dotted numeric form"
    end
    unless build_text.match?(/\A[1-9]\d*\z/)
      raise ContractError, "Build number must be a positive integer"
    end
    build = Integer(build_text, 10)
    unless build.between?(1, 2_100_000_000)
      raise ContractError, "Build number must be between 1 and 2100000000"
    end

    { marketing: marketing, build: build }
  rescue ArgumentError, Encoding::InvalidByteSequenceError, Encoding::UndefinedConversionError
    raise ContractError, "Version source must be valid UTF-8 key/value text"
  end
end
