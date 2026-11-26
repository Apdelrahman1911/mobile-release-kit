# Pure catalog-to-installed-pinned-supplier contract. No Store client is created,
# no fixture image decoded, and no project or subprocess is invoked.
require "json"
require "digest"
require "minitest/autorun"
require "deliver/app_screenshot"
require "supply"

class MetadataImageCatalogTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)

  def test_catalog_matches_the_actual_pinned_supplier_tables
    bytes = File.binread(File.join(ROOT, "src/mobile_release/api/data/metadata-images-v1.json"))
    assert_operator bytes.bytesize, :<=, 128 * 1024
    catalog = JSON.parse(bytes)
    supplier = catalog.fetch("supplier")
    spec = Gem.loaded_specs.fetch("fastlane")
    assert_equal "2.235.0", spec.version.to_s
    assert_equal spec.version.to_s, supplier.fetch("version")
    assert_includes File.binread(File.join(ROOT, "Gemfile.lock")),
                    "  fastlane (2.235.0) sha256=#{supplier.fetch('gemSha256')}\n"
    supplier.fetch("sourceFiles").each do |row|
      assert_includes ["deliver/lib/deliver/app_screenshot.rb", "supply/lib/supply.rb"], row.fetch("path")
      assert_equal row.fetch("sha256"), Digest::SHA256.file(File.join(spec.full_gem_path, row.fetch("path"))).hexdigest
    end

    rows = catalog.fetch("types")
    assert_equal rows.length, rows.map { |row| [row.fetch("platform"), row.fetch("id")] }.uniq.length
    android = rows.select { |row| row.fetch("platform") == "android" }
    assert_equal Supply::IMAGES_TYPES.sort, android.select { |row| row.fetch("singleton") }.map { |row| row.fetch("id") }.sort
    assert_equal Supply::SCREENSHOT_TYPES.sort, android.reject { |row| row.fetch("singleton") }.map { |row| row.fetch("id") }.sort
    android.each do |row|
      assert_equal [], row.fetch("dimensions")
      # Eight is explicitly MRK's conservative local policy, not a numeric
      # constant invented in the supplier type table.
      assert_equal(row.fetch("singleton") ? 1 : 8, row.fetch("maxCount"))
    end

    expected = Deliver::AppScreenshot::DEVICE_RESOLUTIONS.select do |name, _|
      name.start_with?("APP_IPHONE_", "APP_IPAD_", "APP_WATCH_")
    end
    ios = rows.select { |row| row.fetch("platform") == "ios" }
    assert_equal expected, ios.to_h { |row| [row.fetch("id"), row.fetch("dimensions")] }
    ios.each do |row|
      assert_equal false, row.fetch("singleton")
      assert_equal 10, row.fetch("maxCount")
      assert_equal Deliver::AppScreenshot::FORMATTED_NAMES.fetch(row.fetch("id")), row.fetch("label")
    end
  end
end
