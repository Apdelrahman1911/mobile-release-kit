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
  ANDROID_NOTE_LIMIT = 500
  ANDROID_NOTE_MAX_BYTES = 4 * ANDROID_NOTE_LIMIT
  ANDROID_NOTE_LOCALE = /\A[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?\z/
  # Python's Unicode whitespace set, not Ruby's ASCII-only String#strip / \s.
  NOTE_WHITESPACE = "\\u0009-\\u000d\\u001c-\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"
  NOTE_NON_WHITESPACE = Regexp.new("[^#{NOTE_WHITESPACE}]")
  NOTE_PLACEHOLDER = /(?<![a-z0-9_])(?:todo|tbd|changeme)(?![a-z0-9_])|example\.(?:com|org)|<[^>]+>|\{\{[^}]+\}\}/
  NOTE_SECRET = Regexp.new(
    "-----begin [a-z0-9 ]*private key-----|akia[0-9a-z]{16}|" \
    "[\"'](?:client_secret|private_key|private_key_id)[\"'][#{NOTE_WHITESPACE}]*:[#{NOTE_WHITESPACE}]*[\"'][^\"']{8,}|" \
    "(?:password|api[_ -]?key|secret)[#{NOTE_WHITESPACE}]*[:=][#{NOTE_WHITESPACE}]*[^#{NOTE_WHITESPACE}]{8,}",
  )

  def self.validate_android_release_note(text)
    raise ContractError, "Android release notes must be UTF-8 text" unless text.is_a?(String)
    text = text.dup.force_encoding(Encoding::UTF_8)
    raise ContractError, "Android release notes must be UTF-8 text" unless text.valid_encoding?
    if !NOTE_NON_WHITESPACE.match?(text) || text.include?("\0")
      raise ContractError, "Android release notes must contain non-whitespace text without NUL"
    end
    if text.length > ANDROID_NOTE_LIMIT
      raise ContractError, "Android release notes exceed the 500-character limit (including whitespace)"
    end
    # A validation-only, single-character map matches the explicit Python policy.
    # Native Ruby /i and \b differ for dotted/dotless I and combining marks.
    view = text.tr("ABCDEFGHIJKLMNOPQRSTUVWXYZ\u0130\u0131\u017f\u212a", "abcdefghijklmnopqrstuvwxyziisk")
    raise ContractError, "Android release notes contain an unresolved placeholder" if NOTE_PLACEHOLDER.match?(view)
    raise ContractError, "Android release notes contain possible secret material" if NOTE_SECRET.match?(view)
    text
  end

  def self.validate_android_note_scope(languages, version_code)
    unless languages.is_a?(Array) && languages.length.between?(1, 250) && languages.uniq == languages &&
           languages.all? { |language| language.is_a?(String) && ANDROID_NOTE_LOCALE.match?(language) }
      raise ContractError, "Android release notes require a unique nonempty configured locale set"
    end
    unless version_code.is_a?(Integer) && version_code.between?(1, 2_100_000_000)
      raise ContractError, "Android release notes require the authoritative positive build number"
    end
  end

  def self.android_release_notes(root, metadata_path:, languages:, version_code:)
    validate_android_note_scope(languages, version_code)
    root = File.realpath(root)
    metadata_path = File.expand_path(metadata_path, root)
    languages.sort.map do |language|
      directory = safe_path(root, File.join(metadata_path, language, "changelogs"))
      # safe_path enforces containment; reject even in-root component symlinks
      # before inspecting exact/default presence below the locale directory.
      current = root
      directory.delete_prefix(root + File::SEPARATOR).split(File::SEPARATOR).each do |part|
        current = File.join(current, part)
        unless File.lstat(current).directory? && !File.lstat(current).symlink?
          raise ContractError, "Android release note directories must be regular, not symlinks"
        end
      end
      exact = File.join(directory, "#{version_code}.txt")
      present = begin
        File.lstat(exact)
        true
      rescue Errno::ENOENT
        false
      end
      selected = present ? exact : File.join(directory, "default.txt")
      path = safe_path(root, selected)
      raise ContractError, "Android release note paths must not traverse symlinks" if File.lstat(path).symlink?
      text = File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
        unless file.stat.file? && file.stat.size <= ANDROID_NOTE_MAX_BYTES
          raise ContractError, "Android release notes must be a bounded regular file: #{language}"
        end
        raw = file.read(ANDROID_NOTE_MAX_BYTES + 1) || ""
        if raw.bytesize > ANDROID_NOTE_MAX_BYTES
          raise ContractError, "Android release notes exceed the bounded UTF-8 file size: #{language}"
        end
        validate_android_release_note(raw)
      end
      { "language" => language, "text" => text }
    end
  rescue SystemCallError, IOError
    raise ContractError, "Required Android release notes must be readable regular UTF-8 files for every locale"
  end

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
