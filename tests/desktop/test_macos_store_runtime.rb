# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "fileutils"
require_relative "../../desktop/tools/verify_macos_store_runtime"

class MacOSStoreRuntimeTest < Minitest::Test
  Spec = Struct.new(:name, :version, :full_gem_path)

  def test_native_image_detection_handles_empty_gem_resources_without_hiding_read_errors
    Dir.mktmpdir("mrk-store-magic-") do |root|
      file = File.join(root, "ordinary-data")
      ["", "x", "xy", "xyz", "plain text"].each do |bytes|
        File.binwrite(file, bytes)
        refute StoreRuntimeComponent.native_image?(file)
      end
      %w[feedface cefaedfe feedfacf cffaedfe cafebabe bebafeca cafebabf bfbafeca].each do |magic|
        File.binwrite(file, [magic].pack("H*") + "synthetic header only")
        assert StoreRuntimeComponent.native_image?(file)
      end
      File.unlink(file)
      assert_raises(Errno::ENOENT) { StoreRuntimeComponent.native_image?(file) }
    end
  end

  def fixture(root)
    gem = File.join(root, "bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0")
    app = File.join(gem, StoreRuntimeComponent::OPTIONAL_APP)
    FileUtils.mkdir_p(File.join(app, "Contents/MacOS"))
    File.write(File.join(app, "Contents/MacOS/terminal-notifier"), "synthetic nonexecutable fixture")
    retained = ["lib/terminal-notifier.rb", "vendor/terminal-notifier/LICENSE.md", "vendor/terminal-notifier/Ruby/LICENSE"]
    retained.each do |path|
      FileUtils.mkdir_p(File.dirname(File.join(gem, path)))
      File.write(File.join(gem, path), "retained fixture")
    end
    [Spec.new("terminal-notifier", "2.0.0", gem), app, retained.map { |path| File.join(gem, path) }]
  end

  def test_only_documented_optional_app_is_removed_and_notices_remain
    Dir.mktmpdir("mrk-store-component-test-") do |root|
      spec, app, retained = fixture(root)
      sentinel = File.join(root, "unrelated-output")
      File.write(sentinel, "keep")
      StoreRuntimeComponent.remove_optional_notifier(root, [spec])
      refute File.exist?(app)
      retained.each { |path| assert_equal "retained fixture", File.read(path) }
      assert_equal "keep", File.read(sentinel)
      assert_raises(Errno::ENOENT) { StoreRuntimeComponent.remove_optional_notifier(root, [spec]) }
    end
  end

  def test_unexpected_version_duplicate_or_outside_gem_is_not_deleted
    Dir.mktmpdir("mrk-store-component-test-") do |root|
      spec, app, = fixture(root)
      [[], [spec, spec], [Spec.new(spec.name, "2.0.1", spec.full_gem_path)]].each do |specs|
        assert_raises(ArgumentError) { StoreRuntimeComponent.remove_optional_notifier(root, specs) }
        assert File.directory?(app)
      end
      Dir.mktmpdir("mrk-store-component-other-") do |other|
        foreign, foreign_app, = fixture(other)
        assert_raises(ArgumentError) { StoreRuntimeComponent.remove_optional_notifier(root, [foreign]) }
        assert File.directory?(foreign_app)
      end
    end
  end

  def test_symlink_and_missing_preserved_notice_refuse_before_deletion
    Dir.mktmpdir("mrk-store-component-test-") do |root|
      spec, app, retained = fixture(root)
      File.unlink(retained.last)
      assert_raises(Errno::ENOENT) { StoreRuntimeComponent.remove_optional_notifier(root, [spec]) }
      assert File.directory?(app)
      File.write(retained.last, "retained fixture")
      moved = app + ".original"
      File.rename(app, moved)
      File.symlink(moved, app)
      assert_raises(ArgumentError) { StoreRuntimeComponent.remove_optional_notifier(root, [spec]) }
      assert File.symlink?(app)
      assert File.directory?(moved)
    end
  end

  def header_fixture(root)
    runtime = File.join(root, "runtime")
    destination = File.join(runtime, "include/ruby-3.3.0")
    headers = File.join(root, "headers")
    FileUtils.mkdir_p(File.join(destination, "fixture-arch/ruby"))
    FileUtils.mkdir_p(File.join(headers, "ruby"))
    %w[ruby.h ruby/ruby.h ruby/version.h].each { |path| File.write(File.join(headers, path), "common header") }
    generated = File.join(destination, "fixture-arch/ruby/config.h")
    File.write(generated, "generated arch header")
    [runtime, headers, destination, generated]
  end

  def test_common_headers_repair_assembly_without_changing_generated_headers
    Dir.mktmpdir("mrk-ruby-headers-") do |root|
      runtime, headers, destination, generated = header_fixture(root)
      config = {"rubyhdrdir" => destination}
      StoreRuntimeComponent.install_headers(runtime, headers, config)
      assert_equal "common header", File.read(File.join(destination, "ruby/ruby.h"))
      assert_equal "generated arch header", File.read(generated)
      StoreRuntimeComponent.install_headers(runtime, headers, config) # Equal existing bytes need no rewrite.
      File.write(File.join(destination, "ruby/ruby.h"), "foreign header")
      assert_raises(ArgumentError) { StoreRuntimeComponent.install_headers(runtime, headers, config) }
      assert_equal "foreign header", File.read(File.join(destination, "ruby/ruby.h"))
    end
  end

  def test_header_copy_never_follows_an_outside_destination_or_link
    Dir.mktmpdir("mrk-ruby-headers-") do |root|
      runtime, headers, destination, generated = header_fixture(root)
      assert_raises(ArgumentError) { StoreRuntimeComponent.install_headers(runtime, headers, {"rubyhdrdir" => root}) }
      File.symlink(headers, File.join(destination, "ruby"))
      assert_raises(ArgumentError) { StoreRuntimeComponent.install_headers(runtime, headers, {"rubyhdrdir" => destination}) }
      assert File.symlink?(File.join(destination, "ruby"))
      assert_equal "generated arch header", File.read(generated)
    end
  end
end
