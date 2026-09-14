# frozen_string_literal: true

# Test-only actual source/wheel capture. This file never loads product code on
# import. The fixed fresh driver loads ONLY the selected absolute installation;
# the fake validator is a separate executable, not a replacement spawn/helper.
require "json"
require "csv"
require "base64"
require "digest"
require "fileutils"
require "rbconfig"
require "tmpdir"
require "uri"
require_relative "upload_process_fixture"

module InstalledRubyCaptureFixture
  VERSION = 1
  MAX_FILE_BYTES = 1_048_576
  MAX_RECORD_BYTES = 32_768
  DRIVER_SECONDS = 20
  FALLBACK_SECONDS = 8
  STREAM_BYTES = 65_536
  RUBY_FLAGS = %w[
    --disable=rubyopt,gems,did_you_mean,error_highlight,syntax_suggest,rjit,yjit
    --external-encoding=UTF-8
    --internal-encoding=UTF-8
  ].freeze
  RUBY_FILES = %w[
    release_support.rb native_process_spawn.rb native_upload_process.rb
    native_upload_validation.rb ios_upload_validation.rb android_upload_validation.rb
  ].freeze
  PYTHON_FILES = %w[
    mobile_release/__init__.py mobile_release/ios_upload_validation.py
    mobile_release/android_upload_validation.py mobile_release/_native_process.py
    mobile_release/_profile_process.py
  ].freeze
  MISSING_HELPERS = %w[native_upload_process.rb native_process_spawn.rb].freeze
  CAPTURE_LEASE_ROLES = %w[
    control_read control_write status_read status_write stdin_read stdin_write
    stdout_read stdout_write stderr_read stderr_write null_stdin null_stdout null_stderr
  ].freeze
  MODES = %w[help success rejection descendant split-bounds stdout-overflow stderr-overflow poison missing-helper].freeze
  SOURCE_SELECTOR = '/\APackagedRubyCaptureTest#/'.freeze
  WHEEL_SELECTOR = '/\A(?:PackagedRubyCaptureTest|InstalledRubyCaptureMissingHelperTest)#/'.freeze

  class Failure < StandardError; end

  module_function

  def clock
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def check(condition, message)
    raise Failure, message unless condition
  end

  def remaining(deadline, maximum)
    left = deadline - clock
    check(left.positive?, "original installed-capture deadline expired")
    [left, maximum].min
  end

  def canonical(path, directory: false)
    check(path.is_a?(String) && path.start_with?(File::SEPARATOR) &&
          !path.match?(/[\x00-\x1f\x7f]/), "capture path is not absolute and bounded")
    check(path.bytesize <= 4_096 && File.realpath(path) == path && !File.symlink?(path),
          "capture path is not its canonical entry")
    check(directory ? File.directory?(path) : File.file?(path), "capture entry has the wrong type")
    path
  end

  def inside?(path, root)
    path == root || path.start_with?(root + File::SEPARATOR)
  end

  def read_json(path, limit: MAX_RECORD_BYTES)
    bytes = File.binread(path, limit + 1)
    check(bytes.bytesize <= limit, "oversized installed-capture fixture record")
    JSON.parse(bytes, max_nesting: 24)
  end

  def write_json(path, value)
    bytes = JSON.generate(value)
    check(bytes.bytesize <= MAX_RECORD_BYTES, "oversized installed-capture fixture request")
    File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |io| io.write(bytes) }
  end

  def file_binding(path)
    canonical(path)
    stat = File.lstat(path)
    check(stat.file? && stat.nlink == 1 && stat.size <= MAX_FILE_BYTES, "invalid bound runtime file")
    { "path" => path, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => stat.size,
      "device" => stat.dev, "inode" => stat.ino, "mode" => stat.mode, "uid" => stat.uid, "gid" => stat.gid }
  end

  def source_hashes(root)
    RUBY_FILES.to_h { |name| ["fastlane/#{name}", file_binding(File.join(root, "fastlane", name)).fetch("sha256")] }
      .merge(PYTHON_FILES.to_h { |name| ["src/#{name}", file_binding(File.join(root, "src", name)).fetch("sha256")] })
  end

  # RECORD is read from the actual pip installation. Neither a copied Python
  # layout nor a module imported from the checkout establishes this binding.
  def installed_layout(prefix, source, wheel: nil, wheel_sha256: nil)
    candidates = Dir.glob(File.join(prefix, "lib", "python[0-9]*", "site-packages", "mobile_release_kit-*.dist-info", "RECORD"))
    check(candidates.length == 1, "actual installed distribution RECORD is missing or ambiguous")
    record = canonical(candidates.fetch(0))
    check(inside?(record, prefix), "installed RECORD escaped its exact prefix")
    modules = canonical(File.dirname(File.dirname(record)), directory: true)
    rows = CSV.parse(File.binread(record, MAX_FILE_BYTES + 1))
    check(File.size(record) <= MAX_FILE_BYTES && rows.length.between?(1, 2_048) &&
          rows.all? { |row| row.length == 3 && row.first.is_a?(String) &&
            row.drop(1).all? { |part| part.nil? || part.is_a?(String) } } &&
          rows.map(&:first).uniq.length == rows.length, "invalid installed RECORD inventory")
    entries = rows.to_h { |name, digest, size| [File.expand_path(name, modules), [digest.to_s, size.to_s]] }
    check(entries.length == rows.length && entries.keys.all? { |path| inside?(path, prefix) },
          "installed RECORD has an ambiguous or outside-prefix entry")
    tooling = canonical(File.join(prefix, "share/mobile-release-kit/fastlane"), directory: true)
    expected = source_hashes(source)
    bindings = RUBY_FILES.to_h { |name| ["fastlane/#{name}", file_binding(File.join(tooling, name))] }
      .merge(PYTHON_FILES.to_h { |name| ["src/#{name}", file_binding(File.join(modules, name))] })
    bindings.each do |name, item|
      check(inside?(item.fetch("path"), prefix) && item.fetch("sha256") == expected.fetch(name),
            "installed runtime bytes differ from the checked source")
      encoded = Base64.urlsafe_encode64([item.fetch("sha256")].pack("H*"), padding: false)
      check(entries[item.fetch("path")] == ["sha256=#{encoded}", item.fetch("bytes").to_s],
            "actual installed runtime differs from RECORD")
    end
    direct_url = nil
    if wheel
      direct_url = canonical(File.join(File.dirname(record), "direct_url.json"))
      receipt = read_json(direct_url)
      url = URI.parse(receipt.fetch("url"))
      archive = receipt.fetch("archive_info")
      check(url.scheme == "file" && (url.host.nil? || url.host.empty?) &&
            File.realpath(URI::DEFAULT_PARSER.unescape(url.path)) == wheel &&
            archive.fetch("hashes").fetch("sha256") == wheel_sha256,
            "negative installation is not from the original checked wheel")
      check(!archive.key?("hash") || archive.fetch("hash") == "sha256=#{wheel_sha256}",
            "installed wheel archive hash fields disagree")
    end
    { "prefix" => prefix, "toolingRoot" => tooling, "moduleRoot" => modules,
      "sourceRoot" => source, "files" => bindings, "recordPath" => record,
      "recordSha256" => Digest::SHA256.file(record).hexdigest,
      "directUrlPath" => direct_url, "wheelSha256" => wheel_sha256 }
  end

  def source_layout(prefix, source)
    tooling = canonical(File.join(prefix, "fastlane"), directory: true)
    modules = canonical(File.join(prefix, "src"), directory: true)
    expected = source_hashes(source)
    bindings = RUBY_FILES.to_h { |name| ["fastlane/#{name}", file_binding(File.join(tooling, name))] }
      .merge(PYTHON_FILES.to_h { |name| ["src/#{name}", file_binding(File.join(modules, name))] })
    check(bindings.all? { |name, item| item.fetch("sha256") == expected.fetch(name) }, "selected source runtime differs from the checked source")
    { "prefix" => prefix, "toolingRoot" => tooling, "moduleRoot" => modules,
      "sourceRoot" => source, "files" => bindings, "recordPath" => nil,
      "recordSha256" => nil, "directUrlPath" => nil, "wheelSha256" => nil }
  end

  def verify_binding!(binding, missing: nil)
    binding.fetch("files").each do |name, expected|
      path = expected.fetch("path")
      if name == "fastlane/#{missing}"
        check(!File.exist?(path) && !File.symlink?(path), "missing-helper case did not remove exactly its helper")
      else
        check(file_binding(path) == expected, "selected runtime entry changed during actual capture")
      end
    end
    if binding.fetch("recordPath")
      check(Digest::SHA256.file(binding.fetch("recordPath")).hexdigest == binding.fetch("recordSha256"),
            "installed RECORD changed during actual capture")
    end
    true
  end

  def reaped_record?(record)
    record.is_a?(Hash) && record.keys.sort == %w[pid state status_code status_kind] &&
      record["state"] == "reaped" && record["pid"].is_a?(Integer) && record["pid"].positive? &&
      %w[exit signal].include?(record["status_kind"]) && record["status_code"].is_a?(Integer) &&
      record["status_code"].between?(record["status_kind"] == "exit" ? 0 : 1, 255)
  end

  # Deletion requires the observed physical facts, not just production/session
  # boolean offers. This predicate covers these real V-created cases only;
  # absent helpers use a distinct pre-capture load refusal, never a guessed
  # no-producers variant manufactured from a missing session publication.
  def finalized_capture?(observation)
    return false unless observation.is_a?(Hash) && observation["version"] == 1 &&
                        observation["finalized"] == true && observation["settled"] == true &&
                        observation["noProducers"] == false && observation["unknown"] == false &&
                        observation["hooksRestored"] == true && observation["observerErrors"] == []
    final = observation["final"]
    return false unless final.is_a?(Hash) && final.keys.sort == %w[cleanup group keeper outcome type v validator] &&
                        final["v"] == 1 && final["type"] == "FINAL" && final["cleanup"] == "confirmed" &&
                        %w[ok rejected failed].include?(final["outcome"])
    custodian, keeper, validator = observation["custodian"], final["keeper"], final["validator"]
    # Terminal2 is the explicit settled-failure convention. Default/helper1 or
    # a helper signal is never finality, even with a claimed confirmed frame.
    return false unless [custodian, keeper, validator].all? { |child| reaped_record?(child) } &&
                        [custodian, keeper, validator].map { |child| child["pid"] }.uniq.length == 3 &&
                        custodian["status_kind"] == "exit" &&
                        custodian["status_code"] == (final["outcome"] == "failed" ? 2 : 0) &&
                        keeper["status_kind"] == "exit" &&
                        (final["outcome"] == "failed" ? [0, 2] : [0]).include?(keeper["status_code"])
    return false unless final["group"] == { "state" => "retired", "id" => keeper["pid"], "absent" => true }
    tasks, leases, streams = observation.values_at("tasks", "leases", "streams")
    return false unless tasks.is_a?(Array) && tasks.map { |task| task["role"] }.sort == %w[capture creator] &&
                        tasks.all? { |task| task["startAttempted"] == true && task["finished"] == true &&
                          task["joined"] == true && task["actualJoinObserved"] == true && task["unresolved"] == false }
    return false unless leases.is_a?(Array) && leases.map { |lease| lease["role"] }.sort == CAPTURE_LEASE_ROLES.sort &&
                        leases.all? { |lease| lease["state"] == "closed" && lease["closed"] == true &&
                          lease["actualCloseObserved"] == true && lease["closeError"].nil? }
    streams == { "stdoutEOF" => true, "stderrEOF" => true, "statusEOF" => true, "actualEOFObserved" => true }
  end

  class Configuration
    attr_reader :phase, :prefix, :source_root, :tooling_root, :python, :wheel, :wheel_sha256,
                :deadline, :binding, :negative_prefix

    def initialize(options)
      @phase = options.fetch("phase")
      InstalledRubyCaptureFixture.check(%w[source wheel].include?(@phase), "unknown actual-capture phase")
      @prefix = InstalledRubyCaptureFixture.canonical(options.fetch("prefix"), directory: true)
      @source_root = InstalledRubyCaptureFixture.canonical(options.fetch("source-root"), directory: true)
      @tooling_root = InstalledRubyCaptureFixture.canonical(options.fetch("tooling-root"), directory: true)
      @python = InstalledRubyCaptureFixture.canonical(options.fetch("python"))
      InstalledRubyCaptureFixture.check(File.executable?(@python), "actual phase Python is not executable")
      @deadline = Float(options.fetch("deadline"))
      InstalledRubyCaptureFixture.check(@deadline.finite?, "original capture deadline is not finite")
      InstalledRubyCaptureFixture.remaining(@deadline, DRIVER_SECONDS)
      if @phase == "wheel"
        @wheel = InstalledRubyCaptureFixture.canonical(options.fetch("wheel"))
        InstalledRubyCaptureFixture.check(@wheel.end_with?(".whl") && File.size(@wheel) <= 64 * 1_024 * 1_024,
                                         "checked wheel is not a bounded wheel file")
        @wheel_sha256 = Digest::SHA256.file(@wheel).hexdigest
        InstalledRubyCaptureFixture.check(!InstalledRubyCaptureFixture.inside?(@prefix, @source_root),
                                         "wheel capture must execute outside the checkout")
        @binding = InstalledRubyCaptureFixture.installed_layout(@prefix, @source_root, wheel: @wheel, wheel_sha256: @wheel_sha256)
        @negative_prefix = InstalledRubyCaptureFixture.canonical(options.fetch("negative-prefix"), directory: true)
        InstalledRubyCaptureFixture.check(!InstalledRubyCaptureFixture.inside?(@negative_prefix, @prefix) &&
                                         !InstalledRubyCaptureFixture.inside?(@prefix, @negative_prefix) &&
                                         !InstalledRubyCaptureFixture.inside?(@negative_prefix, @source_root),
                                         "negative installation must have its own disjoint prefix")
      else
        InstalledRubyCaptureFixture.check(!options.key?("wheel") && !options.key?("negative-prefix"),
                                         "source capture cannot consume wheel/negative-prefix arguments")
        @binding = InstalledRubyCaptureFixture.source_layout(@prefix, @source_root)
      end
      InstalledRubyCaptureFixture.check(@binding.fetch("toolingRoot") == @tooling_root,
                                       "selected tooling is not the actual phase prefix")
    end
  end

  def parse_options!(arguments)
    keys = %w[phase prefix source-root tooling-root python deadline wheel]
    options, minitest = {}, []
    until arguments.empty?
      argument = arguments.shift
      if argument.start_with?("--capture-")
        key = argument.delete_prefix("--capture-")
        check(keys.include?(key) && !options.key?(key) && !arguments.empty?, "invalid or duplicate capture option")
        options[key] = arguments.shift
      elsif argument == "--negative-prefix"
        check(!options.key?("negative-prefix") && !arguments.empty?, "invalid or duplicate negative-prefix option")
        options["negative-prefix"] = arguments.shift
      else
        minitest << argument
      end
    end
    check((keys - ["wheel"]).all? { |key| options.key?(key) }, "actual-capture phase binding is incomplete")
    expected = options.fetch("phase") == "source" ? SOURCE_SELECTOR : WHEEL_SELECTOR
    check(minitest == ["--verbose", "--name", expected], "actual-capture gate requires its exact literal class selector")
    arguments.concat(minitest)
    Configuration.new(options)
  end

  # Only explicitly created private fixture directories are removable. Failed
  # driver publication, EOF, capture finality or identity verification retains
  # the entire tree; no finalizer/blanket cleanup follows a failed assertion.
  class Case
    attr_reader :root, :expected_value

    def initialize(configuration)
      UploadProcessFixture.assert_domain_reusable!
      @configuration = configuration
      @root = File.realpath(Dir.mktmpdir("mrk-installed-ruby-"))
      File.chmod(0o700, @root)
      stat = UploadProcessFixture.owned_fixture_directory(@root)
      @identity = [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode]
      @safe, @serial, @closed = true, 0, false
      InstalledRubyCaptureFixture.check(!InstalledRubyCaptureFixture.inside?(@root, configuration.source_root),
                                       "actual-capture scratch must be outside the checkout")
    end

    def safe?
      @safe && !UploadProcessFixture.cleanup_unresolved?(@root)
    end

    def capture(platform, mode, binding: @configuration.binding, missing: nil)
      InstalledRubyCaptureFixture.check(safe? && !@closed, "uncertain fixture cannot be reused")
      InstalledRubyCaptureFixture.check(%w[ios android].include?(platform) && MODES.include?(mode), "unknown fixed capture case")
      InstalledRubyCaptureFixture.check((mode == "missing-helper") == MISSING_HELPERS.include?(missing), "invalid missing-helper case")
      InstalledRubyCaptureFixture.verify_binding!(binding, missing: missing)
      @serial += 1
      directory = File.join(@root, "case-#{@serial}")
      FileUtils.mkdir_p(File.join(directory, "app/release"), mode: 0o700)
      app = File.join(directory, "app")
      %w[release/mobile-release.json intent.json].each { |name| File.write(File.join(app, name), "{}") }
      extension = platform == "ios" ? "ipa" : "aab"
      artifact = File.join(app, "candidate.#{extension}")
      File.write(artifact, "bounded synthetic #{platform} artifact")
      @expected_value = {
        "documentType" => "#{platform}-current-upload-validation", "schemaVersion" => 1,
        "operationIntentSha256" => "a" * 64, "#{extension}Sha256" => Digest::SHA256.file(artifact).hexdigest,
        "#{extension}Size" => File.size(artifact),
      }
      @expected_value.merge!("notBefore" => "2020-01-01T00:00:00Z", "notAfter" => "2099-01-01T00:00:00Z") if platform == "ios"
      request_path = File.join(directory, "request.json")
      validator = File.join(directory, "trusted-validator")
      File.write(validator, <<~RUBY)
        #!#{File.realpath(RbConfig.ruby)}
        require #{File.realpath(__FILE__).inspect}
        exit! InstalledRubyCaptureFixture.validator(#{request_path.inspect})
      RUBY
      File.chmod(0o700, validator)
      request = { "version" => VERSION, "phase" => @configuration.phase, "platform" => platform, "mode" => mode,
                  "root" => directory, "binding" => binding, "python" => @configuration.python,
                  "deadline" => @configuration.deadline, "value" => @expected_value,
                  "validator" => validator, "missingHelper" => missing }
      InstalledRubyCaptureFixture.write_json(request_path, request)
      @safe = false # Publish uncertainty BEFORE an owned driver can be created.
      stdout, stderr, status = UploadProcessFixture.capture_command(
        [File.realpath(RbConfig.ruby), *RUBY_FLAGS, "--", File.realpath(__FILE__), "driver", request_path],
        seconds: InstalledRubyCaptureFixture.remaining(@configuration.deadline, DRIVER_SECONDS),
        environment: UploadProcessFixture.driver_environment(directory), cwd: directory,
        root: @root, deadline: @configuration.deadline,
      )
      # The shared collector returns only after its original wait, BOTH actual
      # pipe EOFs, creator joins and closes. Printed JSON alone proves none of it.
      InstalledRubyCaptureFixture.check(status == 0 && stderr.empty? && stdout.bytesize <= MAX_RECORD_BYTES,
                                       "actual installed-capture driver failed")
      record = JSON.parse(stdout, max_nesting: 24)
      InstalledRubyCaptureFixture.check(record.fetch("version") == VERSION && record.fetch("phase") == @configuration.phase &&
                                       record.fetch("platform") == platform && record.fetch("mode") == mode &&
                                       record.fetch("driverCwd") == directory && record.fetch("installation") == binding,
                                       "actual installed-capture driver record is not this case")
      observation = record.fetch("captureObservation")
      missing_path = missing && File.join(binding.fetch("toolingRoot"), missing)
      result = record.fetch("result")
      load_refused = mode == "missing-helper" && result.fetch("kind") == "load-refused" &&
                     result.fetch("errorClass") == "LoadError" &&
                     [missing_path, missing_path.delete_suffix(".rb")].include?(result.fetch("missingPath")) &&
                     record.fetch("captureInvoked") == false && observation.nil?
      @safe = load_refused || InstalledRubyCaptureFixture.finalized_capture?(observation)
      InstalledRubyCaptureFixture.check(safe?, "actual capture retained uncertain producer custody")
      InstalledRubyCaptureFixture.verify_binding!(binding, missing: missing)
      record
    end

    def close!
      return if @closed
      unless safe?
        warn "Preserve unresolved actual installed-Ruby fixture: #{@root}"
        raise Failure, "actual installed-Ruby fixture finality is unresolved"
      end
      stat = UploadProcessFixture.owned_fixture_directory(@root)
      InstalledRubyCaptureFixture.check([stat.dev, stat.ino, stat.uid, stat.gid, stat.mode] == @identity,
                                       "actual installed-Ruby scratch identity changed")
      FileUtils.remove_entry(@root)
      @closed = true
    end
  end

  class NegativeInstallation
    def initialize(configuration)
      @configuration = configuration
      InstalledRubyCaptureFixture.check(configuration.phase == "wheel", "missing helpers require a real wheel installation")
      # The controller installed the SAME wheel in a distinct original Session
      # capture, then waited for true domain finality/idle and bound this prefix.
      # There is no installer subprocess or prefix impersonation inside Minitest.
      @root = configuration.negative_prefix
      stat = UploadProcessFixture.owned_fixture_directory(@root)
      @identity = [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode]
      InstalledRubyCaptureFixture.check(Digest::SHA256.file(@configuration.wheel).hexdigest == @configuration.wheel_sha256,
                                       "original checked wheel changed before negative installation")
      @binding = InstalledRubyCaptureFixture.installed_layout(
        @root, @configuration.source_root, wheel: @configuration.wheel, wheel_sha256: @configuration.wheel_sha256,
      )
      @safe, @held = true, nil
    end

    def missing_capture(fixture, helper)
      InstalledRubyCaptureFixture.check(@safe && @held.nil? && MISSING_HELPERS.include?(helper),
                                       "negative installation is not exclusively ready")
      InstalledRubyCaptureFixture.verify_binding!(@binding)
      original = File.join(@binding.fetch("toolingRoot"), helper)
      held = File.join(@root, "held-#{helper}")
      @held = [original, held] # Keep the restoration obligation before mutation.
      @safe = false
      File.rename(original, held)
      record = fixture.capture("ios", "missing-helper", binding: @binding, missing: helper)
      @safe = fixture.safe?
      record
    ensure
      if @held && @safe && fixture.safe?
        File.rename(@held.last, @held.first)
        @held = nil
        InstalledRubyCaptureFixture.verify_binding!(@binding)
      end
      # UNKNOWN never restores/mutates a helper that a late producer may use.
    end

    def close!
      unless @safe && @held.nil? && !UploadProcessFixture.cleanup_unresolved?(@root)
        warn "Preserve unresolved actual negative wheel installation: #{@root}"
        raise Failure, "negative wheel installation finality is unresolved"
      end
      stat = UploadProcessFixture.owned_fixture_directory(@root)
      InstalledRubyCaptureFixture.check([stat.dev, stat.ino, stat.uid, stat.gid, stat.mode] == @identity,
                                       "negative installation scratch identity changed")
      InstalledRubyCaptureFixture.verify_binding!(@binding)
      # Only the outside controller removes this prefix, after the whole
      # Minitest original capture is final and Session.ensure_idle succeeds.
    end
  end

  def negative_installation(configuration)
    unless @negative_installation
      @negative_installation = NegativeInstallation.new(configuration)
    end
    @negative_installation
  end

  def close_negative_installation!
    @negative_installation&.close!
  end

  def method_origin(method)
    path, line = method.source_location
    check(path && line.is_a?(Integer) && line.positive?, "actual method has no source origin")
    item = file_binding(File.realpath(path))
    { "path" => item.fetch("path"), "line" => line, "sha256" => item.fetch("sha256") }
  end

  def runtime_record
    info = MobileReleaseKit::NativeProcessSpawn.runtime_info
    { "rubyEngine" => RUBY_ENGINE, "rubyVersion" => RUBY_VERSION, "fiddleVersion" => Fiddle::VERSION,
      "runtimeInfo" => info,
      "fiddleFiles" => info.fetch("fiddle_features").transform_values { |path| file_binding(path) } }
  end

  def install_poison(request)
    root = request.fetch("root")
    marker = File.join(root, "POISON_EXECUTED")
    poison = "File.write(#{marker.inspect}, 'fixture poison executed'); raise 'fixture poison must not load'\n"
    directories = %w[app source-shadow path-shadow].map { |name| File.join(root, name) }
    directories.each do |directory|
      FileUtils.mkdir_p(directory, mode: 0o700)
      RUBY_FILES.each { |name| File.write(File.join(directory, name), poison) }
    end
    preload = File.join(root, "app/preload.rb")
    File.write(preload, poison)
    %w[ruby native_upload_process.rb native_process_spawn.rb python3].each do |name|
      path = File.join(root, "path-shadow", name)
      File.write(path, "#!#{File.realpath(RbConfig.ruby)}\n#{poison}")
      File.chmod(0o700, path)
    end
    # These are test inputs in the already-started driver, never a replacement
    # helper bootstrap. The real helper's fixed argv/environment must ignore them.
    ENV["RUBYOPT"] = "-r#{preload}"
    ENV["RUBYLIB"] = directories.join(File::PATH_SEPARATOR)
    ENV["BUNDLE_GEMFILE"] = File.join(root, "app/Gemfile")
    ENV["MOBILE_RELEASE_TOOLING_ROOT"] = request.fetch("binding").fetch("sourceRoot")
    ENV["PATH"] = directories.last
    $LOAD_PATH.unshift(*directories, File.join(request.fetch("binding").fetch("sourceRoot"), "fastlane"))
  end

  def driver(request_path)
    request = read_json(request_path)
    check(request.fetch("version") == VERSION && MODES.include?(request.fetch("mode")), "invalid fixed capture driver request")
    root, binding = request.values_at("root", "binding")
    canonical(root, directory: true)
    check(Dir.pwd == root && !inside?(root, binding.fetch("sourceRoot")), "actual driver did not enter outside the checkout")
    remaining(request.fetch("deadline"), DRIVER_SECONDS)
    missing = request.fetch("missingHelper")
    verify_binding!(binding, missing: missing)
    check(!defined?(MobileReleaseKit::NativeUploadValidation), "driver already imported a capture from another origin")
    install_poison(request) if %w[poison missing-helper].include?(request.fetch("mode"))
    record = { "version" => VERSION, "phase" => request.fetch("phase"), "platform" => request.fetch("platform"),
               "mode" => request.fetch("mode"), "driverCwd" => Dir.pwd, "driverPid" => Process.pid,
               "driverSid" => Process.getsid(0),
               "installation" => binding, "captureInvoked" => false, "captureObservation" => nil,
               "runtime" => nil, "adapterOrigins" => nil,
               "originScope" => { "outer" => "measured-loaded-methods", "custodian" => "genuine-fixed-spawn",
                                  "keeper" => "source-bound-by-fixed-custodian", "childLocalMeasurement" => false } }
    begin
      require File.join(binding.fetch("toolingRoot"), "#{request.fetch('platform')}_upload_validation.rb")
    rescue LoadError => error
      # Missing helpers are deliberately tested before any capture invocation.
      # A LoadError in unrelated stdlib/test code is NOT the expected negative.
      check(request.fetch("mode") == "missing-helper", "actual installed Gate could not load")
      expected = File.join(binding.fetch("toolingRoot"), missing)
      check([expected, expected.delete_suffix(".rb")].include?(error.path), "missing-helper test failed on an unrelated import")
      record["result"] = { "kind" => "load-refused", "errorClass" => error.class.name, "missingPath" => error.path }
      record["originScope"] = { "outer" => "load-refusal-only", "custodian" => "not-invoked",
                                "keeper" => "not-invoked", "childLocalMeasurement" => false }
      record["poisonExecuted"] = File.exist?(File.join(root, "POISON_EXECUTED"))
      record["validator"] = nil
      record["descendant"] = nil
      record["fallbackUsed"] = false
      verify_binding!(binding, missing: missing)
      return record
    end
    gate = request.fetch("platform") == "ios" ? MobileReleaseKit::IosUploadValidation : MobileReleaseKit::AndroidUploadValidation
    record["adapterOrigins"] = { "current" => method_origin(gate.method(:current!)), "capture" => method_origin(gate.method(:capture_validator)) }
    record["helperArgvOrigin"] = method_origin(MobileReleaseKit::NativeUploadProcess.method(:helper_argv))
    observation = UploadProcessFixture::CaptureObservation.new(native: MobileReleaseKit::NativeUploadValidation, root: root)
    app = File.join(root, "app")
    environment = { "HOME" => app, "PATH" => "/usr/bin:/bin", "LANG" => "fictional-language",
                    "RUBYOPT" => ENV["RUBYOPT"].to_s, "RUBYLIB" => ENV["RUBYLIB"].to_s,
                    "BUNDLE_GEMFILE" => ENV["BUNDLE_GEMFILE"].to_s, "PYTHONPATH" => app,
                    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64" => "fictional-private-capture-secret" }
    environment["PATH"] = File.join(root, "path-shadow") if request.fetch("mode") == "poison"
    record["captureInvoked"] = true
    started = clock
    begin
      value = observation.observe do
        if request.fetch("mode") == "help"
          gate.capture_validator(
            environment.select { |name, _| %w[HOME PATH].include?(name) }.merge("LANG" => "C", "LC_ALL" => "C"),
            [request.fetch("python"), "-I", "-S", "-c", gate::BOOTSTRAP, binding.fetch("moduleRoot"), "--help"],
            binding.fetch("toolingRoot"),
          )
        else
          extension = request.fetch("platform") == "ios" ? "ipa" : "aab"
          gate.current!(**{
            python: request.fetch("validator"), module_root: binding.fetch("moduleRoot"), app_root: app,
            config_path: File.join(app, "release/mobile-release.json"), intent_path: File.join(app, "intent.json"),
            "#{extension}_path".to_sym => File.join(app, "candidate.#{extension}"),
            intent_sha256: "a" * 64, environment: environment, tooling_directory: binding.fetch("toolingRoot"),
          })
        end
      end
      record["result"] = { "kind" => request.fetch("mode") == "help" ? "help" : "value", "value" => value, "frozen" => value.frozen? }
    rescue MobileReleaseKit::ContractError => error
      record["result"] = { "kind" => "contract-error", "errorClass" => error.class.name, "message" => error.message }
    end
    record["elapsed"] = clock - started
    record["captureObservation"] = observation.snapshot
    record["runtime"] = runtime_record
    record["validator"] = File.file?(File.join(root, "validator.json")) ? read_json(File.join(root, "validator.json")) : nil
    record["descendant"] = File.file?(File.join(root, "descendant.json")) ? read_json(File.join(root, "descendant.json")) : nil
    record["fallbackUsed"] = File.exist?(File.join(root, "fallback.json"))
    record["poisonExecuted"] = File.exist?(File.join(root, "POISON_EXECUTED"))
    record["loadedProductFeatures"] = $LOADED_FEATURES.select { |path| RUBY_FILES.include?(File.basename(path)) }.map { |path| File.realpath(path) }.sort
    verify_binding!(binding, missing: missing)
    record
  end

  def fallback_wait(request)
    cutoff = [clock + FALLBACK_SECONDS, request.fetch("deadline")].min
    sleep [cutoff - clock, 0].max
    write_json(File.join(request.fetch("root"), "fallback.json"), { "kind" => "independent-worker-expiry" })
  end

  def validator(request_path)
    request = read_json(request_path)
    root, mode = request.values_at("root", "mode")
    write_json(File.join(root, "validator.json"), {
      "argv" => ARGV, "environment" => ENV.to_h, "cwd" => Dir.pwd, "pid" => Process.pid,
      "group" => Process.getpgrp, "stdoutOpen" => !STDOUT.closed?, "stderrOpen" => !STDERR.closed?,
    })
    value = JSON.generate(request.fetch("value"))
    STDOUT.sync = STDERR.sync = true
    case mode
    when "rejection"
      STDOUT.write("fictional-private-profile")
      STDERR.write("fictional-private-capture-secret")
      3
    when "stdout-overflow"
      STDOUT.write("x" * (STREAM_BYTES + 1))
      fallback_wait(request)
      4
    when "stderr-overflow"
      STDOUT.write(value)
      STDERR.write("fictional-private-capture-secret" * 3_000)
      fallback_wait(request)
      4
    when "split-bounds"
      STDOUT.write(value.rjust(STREAM_BYTES))
      STDERR.write("d" * STREAM_BYTES)
      0
    when "descendant"
      # The only extra worker is born INSIDE the real V after exec. Its local
      # readiness pipe is never added to production's pre-exec descriptor map.
      ready_read, ready_write = IO.pipe
      fork do
        ready_read.close
        Signal.trap("TERM", "IGNORE")
        write_json(File.join(root, "descendant.json"), {
          "pid" => Process.pid, "group" => Process.getpgrp, "stdoutOpen" => !STDOUT.closed?,
          "stderrOpen" => !STDERR.closed?, "readyAt" => clock,
        })
        ready_write.write("R")
        ready_write.close
        fallback_wait(request)
        exit! 0
      end
      ready_write.close
      check(IO.select([ready_read], nil, nil, remaining(request.fetch("deadline"), 5)) && ready_read.read(1) == "R",
            "real descendant did not acknowledge inherited capture streams")
      ready_read.close
      STDOUT.write(value)
      0 # K genuinely reaps V while the orphan still holds BOTH real pipes.
    else
      check(%w[success poison missing-helper].include?(mode), "unknown fixed validator mode")
      STDOUT.write(value)
      0
    end
  end
end

if $PROGRAM_NAME == __FILE__
  File.umask(0o077)
  begin
    InstalledRubyCaptureFixture.check(ARGV.length == 2 && ARGV.first == "driver", "unknown fixed installed-capture entrypoint")
    record = InstalledRubyCaptureFixture.driver(ARGV.last)
    output = JSON.generate(record)
    InstalledRubyCaptureFixture.check(output.bytesize <= InstalledRubyCaptureFixture::MAX_RECORD_BYTES, "oversized actual capture observation")
    STDOUT.write(output)
    STDOUT.write("\n")
  rescue StandardError, LoadError => error
    # No native/private child diagnostics are relayed by this outer driver.
    warn "Actual installed-Ruby fixture failed: #{error.class.name}"
    exit 1
  end
end
