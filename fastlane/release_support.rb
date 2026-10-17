# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require "time"

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
    payload, digest = sealed_operation_document(document)
    unless payload["documentType"] == "store-operation-intent" && payload["schemaVersion"] == 1 &&
           payload.keys.sort == CI_INTENT_FIELDS.sort
      raise ContractError, "Operation intent document type/schemaVersion/fields are invalid"
    end
    [payload, digest]
  end

  def self.sealed_operation_document(document)
    raise ContractError, "Operation intent must be an object" unless document.is_a?(Hash)
    integrity = document["integrity"]
    unless integrity.is_a?(Hash) && integrity.keys.sort == %w[algorithm sha256] &&
           integrity["algorithm"] == "sha256" &&
           integrity["sha256"].to_s.match?(/\A[a-f0-9]{64}\z/)
      raise ContractError, "Operation intent integrity is invalid"
    end
    payload = document.reject { |key, _value| key == "integrity" }
    actual = Digest::SHA256.hexdigest(canonical_json(payload))
    raise ContractError, "Operation intent integrity mismatch" unless secure_equal(actual, integrity["sha256"])
    [payload, integrity.fetch("sha256")]
  end

  CI_INTENT_FIELDS = %w[documentType schemaVersion stage platform tooling repository candidateSource
    operationSource authorizedBy confirmation application version destination configuration artifacts
    signing predecessors storePrecondition privateStateCommitments createdAt].freeze
  LOCAL_INTENT_FIELDS = (CI_INTENT_FIELDS - %w[repository authorizedBy] +
    %w[origin project operationId candidateSha256 preparedBy]).freeze
  LOCAL_AUTHORITY_FIELDS = %w[schemaVersion origin purpose project operationId candidateSha256
    authorizationId source assignment confirmationSha256 intentSha256].freeze
  LOCAL_STAGE_LANES = {
    ["android", "candidate"] => "android_internal_upload",
    ["android", "external-testing"] => "android_external_promote",
    ["android", "production-submit"] => "android_production_draft",
    ["ios", "candidate"] => "ios_testflight_internal",
    ["ios", "external-testing"] => "ios_testflight_external",
    ["ios", "production-submit"] => "ios_app_store_submit",
  }.freeze
  LOCAL_PROJECT_FIELDS = %w[projectLocator projectBinding projectId keyId keyRevision].freeze
  LOCAL_BRANCH = /\A(?!\/)(?!.*(?:\.\.|\/\/|@\{|\\|[ ~^:?*\[]))(?!.*[.\/]$).+\z/

  # DATA only: neither this public record nor its hash proves original custody,
  # native consent, journal authentication or that any Store request dispatched.
  def self.local_need(value)
    raise ContractError, "Invalid local Store intent or authority DATA" unless value
  end

  def self.local_keys(value, keys)
    local_need(value.instance_of?(Hash) && value.keys.sort == keys.sort)
    value
  end

  def self.local_hex(value, size)
    value.instance_of?(String) && /\A[0-9a-f]{#{size}}\z/.match?(value)
  end

  def self.local_uuid(value)
    value.instance_of?(String) && /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/.match?(value)
  end

  def self.local_project(value)
    local_keys(value, LOCAL_PROJECT_FIELDS)
    local_need(%w[projectLocator projectBinding].all? { |k| local_hex(value[k], 64) } &&
      %w[projectId keyId].all? { |k| local_uuid(value[k]) } && value["keyRevision"].instance_of?(Integer) && value["keyRevision"] == 1)
  end

  def self.local_source(value)
    local_keys(value, %w[commit tree ref])
    ref = value["ref"]
    local_need(%w[commit tree].all? { |k| local_hex(value[k], 40) } && ref.instance_of?(String) &&
      ref.length <= 266 && ref.start_with?("refs/heads/") && ref.each_codepoint.all? { |c| c >= 32 && c != 127 } &&
      LOCAL_BRANCH.match?(ref.delete_prefix("refs/heads/")))
  end

  def self.local_json(content, maximum)
    local_need(content.instance_of?(String) && content.bytesize.between?(1, maximum))
    text = content.dup.force_encoding(Encoding::UTF_8)
    local_need(text.valid_encoding? && !text.start_with?("\uFEFF"))
    value = deep_sort(JSON.parse(text, object_class: DuplicateRejectingHash,
      allow_duplicate_key: false, max_nesting: 65))
    local_need(value.instance_of?(Hash))
    value
  end

  def self.local_stage_lane(platform, stage)
    local_need(platform.instance_of?(String) && stage.instance_of?(String))
    LOCAL_STAGE_LANES.fetch([platform, stage]) { local_need(false) }
  end

  def self.local_authority_data(value, purpose:, platform: "android", stage: "candidate")
    local_stage_lane(platform, stage)
    local_need(stage == "candidate" || %w[prepare execute].include?(purpose))
    extra = stage != "candidate" && platform == "ios"
    local_keys(value, LOCAL_AUTHORITY_FIELDS + (extra ? ["supplementalAssignments"] : []))
    local_need(%w[prepare execute recover].include?(purpose) && value["purpose"] == purpose &&
      value["origin"] == "local-desktop" && value["schemaVersion"].instance_of?(Integer) && value["schemaVersion"] == 1)
    local_project(value["project"])
    local_source(value["source"])
    local_need(%w[operationId authorizationId].all? { |k| local_uuid(value[k]) } &&
      %w[candidateSha256 confirmationSha256].all? { |k| local_hex(value[k], 64) })
    row = local_keys(value["assignment"], %w[kind recordId expectedRevision contextRevision])
    local_need(%w[android ios].include?(platform) && (platform != "ios" || %w[prepare execute recover].include?(purpose)) &&
      row["kind"] == (platform == "android" ? "google-service-account" : "asc-p8") && local_hex(row["recordId"], 32) &&
      %w[expectedRevision contextRevision].all? { |k| row[k].instance_of?(Integer) && row[k].between?(1, 2**32 - 2) })
    if extra
      additions = value["supplementalAssignments"]
      local_need(additions.instance_of?(Array) && [2, 3].include?(additions.length))
      kinds = %w[apple-review-contact operation-commitment] + (additions.length == 3 ? ["apple-review-demo"] : [])
      records = [row["recordId"]]
      additions.zip(kinds).each do |item, kind|
        local_keys(item, %w[kind recordId expectedRevision contextRevision])
        local_need(item["kind"] == kind && local_hex(item["recordId"], 32) && !records.include?(item["recordId"]) &&
          item["contextRevision"] == row["contextRevision"] && item["contextRevision"].instance_of?(Integer) &&
          item["expectedRevision"].instance_of?(Integer) && item["expectedRevision"].between?(1, 2**32 - 2))
        records << item["recordId"]
      end
    end
    local_need(purpose == "prepare" ? value["intentSha256"].nil? : local_hex(value["intentSha256"], 64))
    value
  end

  # The expected digest must come from an independently admitted original, NOT
  # the adjacent carrier. Python's shared validator owns full platform policy;
  # Ruby checks exact bytes/domain/identity before existing lane/state checks.
  # No current lane dispatches here and no ambient-origin switch exists.
  def self.local_operation_intent(content, expected_sha256:, platform: "android", stage: "candidate")
    local_need(local_hex(expected_sha256, 64))
    document = local_json(content, 2 * 1024 * 1024)
    payload, digest = sealed_operation_document(document)
    local_need(secure_equal(digest, expected_sha256))
    lane = local_stage_lane(platform, stage)
    local_keys(payload, LOCAL_INTENT_FIELDS + (stage == "candidate" ? [] : ["candidateOperationId"]))
    local_need(payload["documentType"] == "local-store-operation-intent" && payload["schemaVersion"].instance_of?(Integer) &&
      payload["schemaVersion"] == 1 && payload["origin"] == "local-desktop" && payload["stage"] == stage && %w[android ios].include?(platform) && payload["platform"] == platform)
    local_project(payload["project"])
    local_need(local_uuid(payload["operationId"]) && local_hex(payload["candidateSha256"], 64))
    %w[candidateSource operationSource].each { |k| local_source(payload[k]) }
    local_need(payload["candidateSource"] == payload["operationSource"]) unless stage == "production-submit"
    prepared = local_authority_data(payload["preparedBy"], purpose: "prepare", platform: platform, stage: stage)
    local_need(%w[project operationId candidateSha256].all? { |k| prepared[k] == payload[k] } &&
      prepared["source"] == payload["operationSource"] && payload["confirmation"].instance_of?(String) &&
      prepared["confirmationSha256"] == Digest::SHA256.hexdigest(payload["confirmation"]))
    if stage == "candidate"
      local_need(payload["predecessors"] == {} && payload["privateStateCommitments"] == {})
    else
      local_need(local_uuid(payload["candidateOperationId"]) && payload["candidateOperationId"] != payload["operationId"])
      keys = %w[candidateManifestSha256 candidateReceiptSha256] + (stage == "production-submit" ? ["externalReceiptSha256"] : [])
      previous = local_keys(payload["predecessors"], keys)
      local_need(previous.values.all? { |digest| local_hex(digest, 64) } && previous["candidateManifestSha256"] == payload["candidateSha256"])
      local_need(payload["storePrecondition"].instance_of?(Hash) && payload["storePrecondition"]["operation"] == lane &&
        payload["storePrecondition"]["platform"] == platform)
      local_need(payload["privateStateCommitments"] == {}) if platform == "android"
    end
    local_ios_intent_artifacts(payload, stage: stage) if platform == "ios"
    [payload, digest]
  rescue ContractError, JSON::ParserError, EncodingError, ArgumentError, TypeError, KeyError
    raise ContractError, "Invalid local Store intent or authority DATA"
  end

  def self.local_execution_authority(content, intent_content:, expected_intent_sha256:, purpose:, platform: "android", stage: "candidate")
    local_need(%w[execute recover].include?(purpose))
    intent, digest = local_operation_intent(intent_content, expected_sha256: expected_intent_sha256, platform: platform, stage: stage)
    value = local_authority_data(local_json(content, 8 * 1024), purpose: purpose, platform: platform, stage: stage)
    prepared = intent.fetch("preparedBy")
    local_need(value["intentSha256"] == digest && value["authorizationId"] != prepared["authorizationId"] &&
      %w[project operationId candidateSha256 source assignment confirmationSha256].all? { |k| value[k] == prepared[k] } &&
      value["supplementalAssignments"] == prepared["supplementalAssignments"])
    value
  rescue ContractError, JSON::ParserError, EncodingError, ArgumentError, TypeError, KeyError
    raise ContractError, "Invalid local Store intent or authority DATA"
  end

  # Fixed local DATA refusal-key preparation only. No current marker/Store
  # owner calls this; it cannot prove original custody or a previous dispatch.
  # Full platform intent/receipt policy still belongs to the shared Python body.
  def self.local_execution_attempt_key(intent_content:, authority_content:, expected_intent_sha256:, purpose:, platform: "android", stage: "candidate")
    authority = local_execution_authority(authority_content, intent_content: intent_content,
      expected_intent_sha256: expected_intent_sha256, purpose: purpose, platform: platform, stage: stage)
    raw = canonical_json(authority).b
    local_need(raw.bytesize <= 8 * 1024)
    lane = local_stage_lane(platform, stage).b
    Digest::SHA256.hexdigest("mrk-local-store-attempt-v1\0".b + [expected_intent_sha256].pack("H*") +
      [raw.bytesize].pack("N") + raw + [lane.bytesize].pack("C") + lane)
  rescue ContractError, JSON::ParserError, EncodingError, ArgumentError, TypeError, KeyError
    raise ContractError, "Invalid local Store receipt or attempt DATA"
  end

  # Closed local-only archive grammar. The hash commits to canonical inventory
  # rows under mrk-local-ios-archive-inventory/1\0, NEVER to ZIP/file bytes.
  # Full shared platform/Store precondition policy remains Python's obligation.
  def self.local_ios_intent_artifacts(payload, stage: "candidate")
    artifacts = payload["artifacts"]
    local_need(artifacts.instance_of?(Array) && artifacts.length == 4)
    row = local_keys(artifacts.last, %w[logicalName platform kind directory entries bytes sha256])
    local_need(row["logicalName"] == "ios-archive" && row["platform"] == "ios" && row["kind"] == "xcarchive" &&
      row["directory"] == "archive.xcarchive" && row["entries"].instance_of?(Integer) && row["entries"].between?(1, 100_000) &&
      row["bytes"].instance_of?(Integer) && row["bytes"].between?(1, 8 << 30) && local_hex(row["sha256"], 64))
    ipa = artifacts.first.instance_of?(Hash) && artifacts.first["fileName"]
    local_need(ipa.instance_of?(String) && ipa.bytesize.between?(1, 255) && ipa.end_with?(".ipa") &&
      !ipa.match?(/[\x00-\x1f\x7f\/\\:]/))
    specs = [["ios-ipa", "ios", "ipa", ipa, 4 << 30],
      ["store-metadata", "shared", "metadata", "store-metadata.zip", 512 << 20],
      ["validation-report", "shared", "validation-report", "validation-report.json", 65536]]
    artifacts.first(3).zip(specs).each do |file, (name, os, kind, filename, maximum)|
      local_keys(file, %w[logicalName platform kind fileName size sha256 architectures])
      local_need(file["logicalName"] == name && file["platform"] == os && file["kind"] == kind && file["fileName"] == filename &&
        file["size"].instance_of?(Integer) && file["size"].between?(1, maximum) && local_hex(file["sha256"], 64) &&
        file["architectures"].instance_of?(Array) && file["architectures"].all? { |v| v.instance_of?(String) && /\A[A-Za-z0-9_.-]+\z/.match?(v) } &&
        file["architectures"].uniq == file["architectures"])
    end
    local_need(payload["signing"].instance_of?(Array) && payload["signing"].length == 1)
    signing = local_keys(payload["signing"].first, %w[platform kind certificateSha256 teamId profileUuid profileExpiresAt])
    local_need(signing["platform"] == "ios" && signing["kind"] == "apple-distribution" && local_hex(signing["certificateSha256"], 64) &&
      signing["teamId"].instance_of?(String) && /\A[A-Z0-9]{10}\z/.match?(signing["teamId"]) &&
      signing["profileUuid"].instance_of?(String) && /\A[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\z/.match?(signing["profileUuid"]))
    local_timestamp(signing["profileExpiresAt"])
    precondition = payload["storePrecondition"]
    local_need(precondition.instance_of?(Hash) && precondition["snapshot"].instance_of?(Hash))
    if stage == "candidate"
      snapshot = local_keys(precondition["snapshot"], %w[canonicalization appStoreAppId serverObservedAt build])
      local_need(snapshot["canonicalization"] == "mrk-apple-operation-v1" && snapshot["build"].nil? &&
        payload["application"].instance_of?(Hash) && snapshot["appStoreAppId"] == payload["application"]["storeAppId"] &&
        payload["destination"] == {"channel" => "testflight-internal"})
    else
      snapshot = precondition["snapshot"]
      local_need(snapshot["canonicalization"] == "mrk-apple-operation-v1" && snapshot["build"].instance_of?(Hash) &&
        payload["application"].instance_of?(Hash) && snapshot["appStoreAppId"] == payload["application"]["storeAppId"])
      destination = stage == "external-testing" ? {"channel" => "testflight-external"} : {"channel" => "app-store-review", "automaticRelease" => false}
      local_need(payload["destination"] == destination)
    end
  end

  def self.local_timestamp(value)
    local_need(value.instance_of?(String) && /\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/.match?(value))
    local_need(Time.iso8601(value).utc.iso8601 == value)
  end

  # Explicit iOS receipt DATA, not called by a lane/dispatcher. Independent
  # intent+authority comparisons are mandatory; recover purpose is not supported.
  def self.local_ios_execution_receipt(content, intent_content:, authority_content:, expected_intent_sha256:)
    intent, digest = local_operation_intent(intent_content, expected_sha256: expected_intent_sha256, platform: "ios")
    authority = local_execution_authority(authority_content, intent_content: intent_content,
      expected_intent_sha256: expected_intent_sha256, purpose: "execute", platform: "ios")
    value = local_keys(local_json(content, 65536), %w[documentType schemaVersion origin project operationId candidateSha256
      operationIntentSha256 preparedBy executedBy operation platform appIdentity marketingVersion buildNumber observedAt result state
      appStoreAppId buildResourceId processingState autoNotifyEnabled])
    local_need(value["documentType"] == "local-store-execution-receipt" && value["schemaVersion"].instance_of?(Integer) &&
      value["schemaVersion"] == 1 && value["origin"] == "local-desktop" && value["operation"] == "ios_testflight_internal" && value["platform"] == "ios")
    local_project(value["project"])
    local_authority_data(value["preparedBy"], purpose: "prepare", platform: "ios")
    local_authority_data(value["executedBy"], purpose: "execute", platform: "ios")
    local_need(%w[project operationId candidateSha256 preparedBy].all? { |key| value[key] == intent[key] } &&
      value["operationIntentSha256"] == digest && value["executedBy"] == authority && value["appIdentity"] == intent.dig("application", "id") &&
      value["marketingVersion"] == intent.dig("version", "marketing") && value["buildNumber"].instance_of?(Integer) &&
      value["buildNumber"] == intent.dig("version", "build") && %w[accepted reconciled].include?(value["result"]) &&
      value["appStoreAppId"] == intent.dig("application", "storeAppId") && value["buildResourceId"].instance_of?(String) &&
      !value["buildResourceId"].strip.empty? && value["buildResourceId"].length <= 255 && value["processingState"] == "VALID" &&
      value["autoNotifyEnabled"] == false && %w[processed available-to-testers].include?(value["state"]))
    local_timestamp(value["observedAt"])
    value
  rescue ContractError, JSON::ParserError, EncodingError, ArgumentError, TypeError, KeyError
    raise ContractError, "Invalid local Store receipt or attempt DATA"
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
