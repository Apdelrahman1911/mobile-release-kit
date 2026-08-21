# frozen_string_literal: true

# Fastlane does not expose a supported custom-Fastfile CLI option. This tiny
# adapter is the only entry point used by the shared Python tooling: it fixes
# the Fastfile path to this release-kit checkout and rejects arbitrary lanes.

ENV["FASTLANE_HIDE_CHANGELOG"] = "true"
ENV["FASTLANE_OPT_OUT_USAGE"] = "true"
ENV["FASTLANE_SKIP_DOCS"] = "true"
ENV["FASTLANE_SKIP_UPDATE_CHECK"] = "true"

require "fastlane"

FASTFILE = File.realpath(File.join(__dir__, "Fastfile"))
ALLOWED_LANES = %w[
  android_internal_upload
  android_online_preflight
  android_external_promote
  android_production_draft
  ios_testflight_internal
  ios_online_preflight
  ios_testflight_external
  ios_app_store_submit
].freeze

if ARGV == ["--validate"]
  Fastlane::FastFile.new(FASTFILE)
  exit 0
end

abort "usage: bundle exec ruby fastlane/run_lane.rb LANE" unless ARGV.length == 1

lane = ARGV.fetch(0)
abort "unsupported shared Store lane: #{lane}" unless ALLOWED_LANES.include?(lane)

Fastlane::LaneManager.cruise_lane(nil, lane, {}, FASTFILE)
