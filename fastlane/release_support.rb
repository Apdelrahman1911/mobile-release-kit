# frozen_string_literal: true

module MobileReleaseKit
  class ContractError < StandardError; end

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
