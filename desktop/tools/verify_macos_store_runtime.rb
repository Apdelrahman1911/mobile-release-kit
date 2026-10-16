# frozen_string_literal: true

# Offline build-component smoke. No Store requests, credentials or execution grant.
require "rbconfig"
require "find"
require "open3"

# These build-only filesystem operations never run when the helper is imported.
module StoreRuntimeComponent
  OPTIONAL_APP = "vendor/terminal-notifier/terminal-notifier.app"

  def self.remove_optional_notifier(root, specs)
    selected = specs.select { |spec| spec.name == "terminal-notifier" }
    raise ArgumentError, "Expected exactly terminal-notifier 2.0.0" unless selected.length == 1 && selected.first.version.to_s == "2.0.0"
    root = File.realpath(root)
    expected = File.join(root, "bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0")
    gem = File.realpath(selected.first.full_gem_path)
    raise ArgumentError, "Notifier is outside this private build" unless gem == expected
    app = File.join(gem, OPTIONAL_APP)
    info = File.lstat(app)
    raise ArgumentError, "Notifier payload is not the original owned directory" unless info.directory? && info.uid == Process.euid && File.realpath(app) == app
    # Keep its wrapper, notices and gem metadata. Only the optional native app
    # is excluded; none of MRK's eight fixed lanes invokes notification/notify.
    ["lib/terminal-notifier.rb", "vendor/terminal-notifier/LICENSE.md", "vendor/terminal-notifier/Ruby/LICENSE"].each do |relative|
      path = File.join(gem, relative)
      raise ArgumentError, "Notifier wrapper/license is missing" unless File.lstat(path).file? && File.realpath(path) == path
    end
    require "fileutils"
    FileUtils.remove_entry_secure(app)
  end

  def self.verify(root, architecture, mode)
    root = File.realpath(root)
    abort "Unsupported target" unless %w[arm64 x86_64].include?(architecture)
    abort "Unsupported mode" unless %w[default bundle].include?(mode)
    abort "Ruby mismatch" unless RUBY_VERSION == "3.3.12" && RUBY_ENGINE == "ruby"
    cpu = RbConfig::CONFIG.fetch("host_cpu")
    abort "Ruby architecture mismatch" unless (cpu == architecture || cpu == "aarch64" && architecture == "arm64")
    abort "Not Darwin" unless RbConfig::CONFIG.fetch("host_os").start_with?("darwin")
    %w[rubylibdir rubyarchdir].each do |name|
      abort "Ruby relocation escaped component" unless File.realpath(RbConfig::CONFIG.fetch(name)).start_with?(root + "/")
    end
    abort "Ruby executable escaped component" unless File.realpath(RbConfig.ruby) == File.join(root, "bin/ruby")
    require File.join(root, "tooling/fastlane/native_process_spawn.rb")
    MobileReleaseKit::NativeProcessSpawn.admit_runtime!
    require "openssl"
    require "psych"
    require "json"
    require "zlib"
    abort "OpenSSL mismatch" unless OpenSSL::OPENSSL_LIBRARY_VERSION.start_with?("OpenSSL 3.5.8 ")
    abort "JSON smoke failed" unless JSON.parse(JSON.generate({ "ok" => true })) == { "ok" => true }
    abort "YAML smoke failed" unless Psych.safe_load("ok: true\n") == { "ok" => true }
    abort "Zlib smoke failed" unless Zlib::Inflate.inflate(Zlib::Deflate.deflate("offline")) == "offline"
    ca = File.binread(File.join(root, "ca.pem"))
    abort "CA size mismatch" unless ca.bytesize.between?(1, 512 * 1024)
    certificates = ca.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
    abort "CA bundle is empty" if certificates.empty?
    store = OpenSSL::X509::Store.new
    certificates.each { |pem| store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
    context = OpenSSL::SSL::SSLContext.new
    context.cert_store = store
    context.verify_mode = OpenSSL::SSL::VERIFY_PEER
    context.verify_hostname = true
    if mode == "bundle"
      require "bundler"
      abort "Bundler mismatch" unless Bundler::VERSION == "4.0.16"
      require "fastlane"
      abort "Fastlane mismatch" unless Fastlane::VERSION == "2.235.0"
      # Same fixed-Fastfile parsing used by run_lane.rb --validate; no lane runs.
      Fastlane::FastFile.new(File.join(root, "tooling/fastlane/Fastfile"))
      %w[google/apis/androidpublisher_v3 google/cloud/storage bigdecimal nkf fiddle].each { |feature| require feature }
      abort "Fiddle mismatch" unless Fiddle::VERSION == "1.1.2"
      notices = Bundler.load.specs.map do |spec|
        "#{spec.name} #{spec.version}: #{spec.licenses.join(', ')}"
      end.sort.join("\n") + "\n"
      # Descriptive metadata only; license texts remain in the installed gems.
      File.write(File.join(root, "licenses/locked-gem-licenses.txt"), notices)
    end

    total = 0
    files = 0
    native_files = 0
    mach_magic = ["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"]
    Find.find(root) do |path|
      info = File.lstat(path)
      abort "Nonordinary component entry: #{path.delete_prefix(root + '/')}" unless info.directory? || info.file?
      next if info.directory?
      files += 1
      total += info.size
      abort "Store component exceeds 512 MiB" if total > 512 * 1024 * 1024
      next unless mach_magic.include?(File.binread(path, 4).unpack1("H*"))
      native_files += 1
      arches, status = Open3.capture2e("/usr/bin/lipo", "-archs", path)
      abort "Native component does not support #{architecture}: #{path.delete_prefix(root + '/')}" unless status.success? && arches.split.include?(architecture)
      libraries, status = Open3.capture2e("/usr/bin/otool", "-L", path)
      abort "Cannot inspect component linkage" unless status.success?
      libraries.each_line do |line|
        next unless line.match?(/\A\s+/)
        dependency = line.strip.split(" (compatibility version", 2).first
        abort "Non-system dylib dependency: #{dependency}" unless dependency.start_with?("/usr/lib/", "/System/Library/")
      end
    end
    abort "Missing native Ruby" if native_files.zero?
    puts "Offline #{mode} smoke: #{files} files, #{total} bytes, #{native_files} native images; TLS handshake/signing/app integration not verified."
  end
end

if $PROGRAM_NAME == __FILE__
  abort "Expected root, architecture and default|bundle|trim-notifier mode" unless ARGV.length == 3
  root, architecture, mode = ARGV
  if mode == "trim-notifier"
    abort "Unsupported runtime" unless RUBY_VERSION == "3.3.12" && %w[arm64 x86_64].include?(architecture)
    require "bundler"
    abort "Bundler mismatch" unless Bundler::VERSION == "4.0.16"
    StoreRuntimeComponent.remove_optional_notifier(root, Bundler.load.specs)
  else
    StoreRuntimeComponent.verify(root, architecture, mode)
  end
end
