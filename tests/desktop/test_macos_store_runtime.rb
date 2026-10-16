# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "fileutils"
require_relative "../../desktop/tools/verify_macos_store_runtime"

class MacOSStoreRuntimeTest < Minitest::Test
  Spec = Struct.new(:name, :version, :full_gem_path)

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
end
