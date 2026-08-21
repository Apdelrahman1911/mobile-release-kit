# frozen_string_literal: true

# This contract intentionally uses only Ruby's standard library so it can run
# inside the exact production Bundle without adding a test framework to the
# Store adapter dependency graph.

require "rubygems"

def assert_contract(condition, message)
  raise message unless condition
end

root = File.expand_path("../..", __dir__)
specification = Gem::Specification.find_by_name("fastlane", "= 2.235.0")
source_path = File.join(specification.full_gem_path, "supply/lib/supply/client.rb")
assert_contract(File.file?(source_path), "locked Supply client source is missing")

source = File.read(source_path, encoding: "UTF-8")
dispatch = source.match(
  /case google_credentials\['type'\](.*?)UI\.verbose\("Fetching a new access token/m,
)
assert_contract(!dispatch.nil?, "Supply credential-type dispatch could not be located")
assert_contract(
  dispatch[1].match?(
    /when "external_account".*Google::Auth::ExternalAccount::Credentials\.make_creds\(json_key_io: service_account_json, scope: self\.class::SCOPE\)/m,
  ),
  "locked Supply does not dispatch external_account JSON to WIF credentials",
)
assert_contract(
  dispatch[1].match?(
    /when "service_account".*Google::Auth::ServiceAccountCredentials\.make_creds/m,
  ),
  "locked Supply no longer supports service-account JSON",
)

fastfile = File.read(File.join(root, "fastlane/Fastfile"), encoding: "UTF-8")
assert_contract(
  fastfile.include?('json_key: required_env("GOOGLE_APPLICATION_CREDENTIALS")'),
  "Fastfile does not pass the exact generated ADC file to Supply",
)

puts "locked Fastlane Supply WIF contract: PASS"
