# frozen_string_literal: true

# Offline build-component smoke. No Store requests, credentials or execution grant.
require "rbconfig"
require "find"
require "open3"

# These build-only filesystem operations never run when the helper is imported.
module StoreRuntimeComponent
  OPTIONAL_APP = "vendor/terminal-notifier/terminal-notifier.app"
  MACH_MAGICS = %w[feedface cefaedfe feedfacf cffaedfe cafebabe bebafeca cafebabf bfbafeca].freeze

  # Consumer smoke after the authenticated build-object projection and signing.
  # Read-only, no Store lane, no gem installation, no notice regeneration.
  def self.projected_smoke(root, architecture)
    abort "Unsupported runtime" unless RUBY_VERSION == "3.3.12" && %w[arm64 x86_64].include?(architecture)
    abort "Runtime architecture differs" unless RbConfig::CONFIG.fetch("host_cpu") == architecture
    root = File.realpath(root)
    require "bundler"
    require "fastlane"
    require "digest/crc32"
    abort "Bundler mismatch" unless Bundler::VERSION == "4.0.16"
    abort "Fastlane mismatch" unless Fastlane::VERSION == "2.235.0"
    abort "CRC32 native extension missing" unless Digest::CRC32.instance_method(:update).source_location.nil?
    loaded = $LOADED_FEATURES.select { |name| name.end_with?("/digest/crc32/crc32_ext.bundle") }
    abort "CRC32 extension escaped runtime" unless loaded.length == 1 && File.realpath(loaded.first).start_with?(root + "/")
    abort "CRC32 result differs" unless Digest::CRC32.hexdigest("123456789") == "cbf43926"
    apple_crypto_smoke
    Fastlane::FastFile.new(File.join(root, "tooling/fastlane/Fastfile"))
    puts "Projected signed runtime: native CRC32, Apple P256 crypto and Fastlane require/parse passed; no lane or Store request."
  end

  # Exercise the bundled OpenSSL APIs used by Apple credential validation.
  # Generated test material stays in memory; never read or print a user's key.
  def self.apple_crypto_smoke
    require "openssl"
    key = OpenSSL::PKey::EC.generate("prime256v1")
    public_key = OpenSSL::PKey.read(key.public_to_der)
    raise "Apple P256 public key unexpectedly private" if public_key.private?
    message = "Mobile Release Kit offline Apple crypto check"
    [key.private_to_pem, key.private_to_der].each do |encoded|
      parsed = OpenSSL::PKey.read(encoded)
      raise "Apple P256 parsing failed" unless parsed.is_a?(OpenSSL::PKey::EC) && parsed.private? &&
        parsed.group.curve_name == "prime256v1" && parsed.check_key
      signature = parsed.sign("SHA256", message)
      raise "Apple P256 signature verification failed" unless public_key.verify("SHA256", signature, message)
      raise "Apple P256 changed-message verification passed" if public_key.verify("SHA256", signature, message + "changed")
    end
    true
  end

  def self.native_image?(path)
    # File.binread(path, length) returns nil at EOF for an empty ordinary file.
    # Empty gem resources are valid DATA, not native images or a read failure.
    MACH_MAGICS.include?(File.binread(path, 4).to_s.unpack1("H*"))
  end

  def self.install_headers(root, headers, config = RbConfig::CONFIG)
    lexical_root = File.expand_path(root)
    root = File.realpath(root)
    headers = File.realpath(headers)
    destination = File.expand_path(config.fetch("rubyhdrdir"))
    destination = root + destination.delete_prefix(lexical_root) if destination.start_with?(lexical_root + "/")
    raise ArgumentError, "Ruby header destination escaped copied runtime" unless destination.start_with?(root + "/")
    directory = lambda do |path|
      info = File.lstat(path)
      raise ArgumentError, "Ruby header directory is not an owned ordinary directory" unless info.directory? && info.uid == Process.euid && (info.mode & 0o022).zero?
    end
    directory.call(root)
    current = root
    destination.delete_prefix(root + "/").split("/").each do |part|
      current = File.join(current, part)
      directory.call(current) # Generated headers installed by the base must exist.
    end
    total = count = 0
    Find.find(headers) do |path|
      info = File.lstat(path)
      if info.directory?
        directory.call(path)
        next
      end
      relative = path.delete_prefix(headers + "/")
      raise ArgumentError, "Unexpected common Ruby header" unless info.file? && info.nlink == 1 && info.uid == Process.euid && relative.end_with?(".h", ".hpp")
      count += 1
      total += info.size
      raise ArgumentError, "Ruby headers exceed assembly bounds" if count > 2048 || total > 16 * 1024 * 1024
      target = File.join(destination, relative)
      parent = destination
      relative.split("/")[0...-1].each do |part|
        parent = File.join(parent, part)
        Dir.mkdir(parent, 0o755) unless File.exist?(parent) || File.symlink?(parent)
        directory.call(parent)
      end
      File.open(path, File::RDONLY | File::NOFOLLOW) do |input|
        bytes = input.read(info.size + 1)
        raise ArgumentError, "Ruby header source changed" unless bytes.bytesize == info.size && input.stat.ino == info.ino && input.stat.dev == info.dev
        if File.exist?(target) || File.symlink?(target)
          existing = File.lstat(target)
          raise ArgumentError, "Existing Ruby header differs" unless existing.file? && existing.uid == Process.euid && existing.nlink == 1 && existing.size == bytes.bytesize && File.binread(target) == bytes
        else
          File.open(target, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o644) { |output| output.write(bytes) }
        end
      end
    end
    %w[ruby.h ruby/ruby.h ruby/version.h].each do |relative|
      raise ArgumentError, "Incomplete common Ruby headers" unless File.file?(File.join(destination, relative))
    end
    puts "Installed common Ruby headers for offline extension assembly; generated architecture headers preserved."
  end

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
    directories = 0
    max_relative_bytes = 0
    native_files = 0
    Find.find(root) do |path|
      info = File.lstat(path)
      abort "Nonordinary component entry: #{path.delete_prefix(root + '/')}" unless info.directory? || info.file?
      if info.directory?
        directories += 1 unless path == root
        next
      end
      files += 1
      max_relative_bytes = [max_relative_bytes, path.delete_prefix(root + "/").bytesize].max
      total += info.size
      abort "Store component exceeds 512 MiB" if total > 512 * 1024 * 1024
      next unless native_image?(path)
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
    puts "Offline #{mode} smoke: #{files} files, #{directories} directories, #{total} bytes, #{native_files} native images, max relative path #{max_relative_bytes} bytes; TLS handshake/signing/app integration not verified."
  end
end

if $PROGRAM_NAME == __FILE__
  abort "Expected root, architecture and component mode" unless ARGV.length == (ARGV[2] == "headers" ? 4 : 3)
  root, architecture, mode = ARGV
  if mode == "projected-smoke"
    StoreRuntimeComponent.projected_smoke(root, architecture)
  elsif mode == "headers"
    abort "Unsupported runtime" unless RUBY_VERSION == "3.3.12" && %w[arm64 x86_64].include?(architecture)
    StoreRuntimeComponent.install_headers(root, ARGV[3])
  elsif mode == "trim-notifier"
    abort "Unsupported runtime" unless RUBY_VERSION == "3.3.12" && %w[arm64 x86_64].include?(architecture)
    require "bundler"
    abort "Bundler mismatch" unless Bundler::VERSION == "4.0.16"
    StoreRuntimeComponent.remove_optional_notifier(root, Bundler.load.specs)
  else
    StoreRuntimeComponent.verify(root, architecture, mode)
  end
end
