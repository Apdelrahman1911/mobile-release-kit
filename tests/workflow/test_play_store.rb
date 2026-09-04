# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest/autorun"
require "tmpdir"
require "bundler/setup"
require "fastlane"

require_relative "../../fastlane/play_store"

module MobileReleaseKit
  class PlayStoreHarness < PreservingSupplyUploader
    attr_accessor :metadata_hook

    def upload_apks
      []
    end

    def upload_bundles
      Supply.config[:skip_upload_aab] ? [] : [Supply.config[:version_code]]
    end

    def upload_mapping(_version_codes); end

    def perform_upload_meta(_version_codes, _track_name)
      metadata_hook&.call(self, client)
    end

    def apply_supply_changelogs(release_notes, release, track, track_name)
      upload_changelogs(release_notes, release, track, track_name)
    end
  end
end

class FakePlayClient
  Edit = Struct.new(:id)

  attr_accessor :current_edit, :current_package_name, :commit_behavior, :abort_error,
                :update_transform, :after_update, :post_commit_transform, :readback_error
  attr_reader :commits, :updates, :events, :aborts

  def initialize(tracks = {}, commit_behavior: :success, **named_tracks)
    tracks = named_tracks.transform_keys(&:to_s) if tracks.empty? && !named_tracks.empty?
    @committed = clone_tracks(tracks)
    @pending = nil
    @sequence = 0
    @commit_behavior = commit_behavior
    @commits = []
    @updates = []
    @events = []
    @aborts = 0
  end

  def client
    self
  end

  def begin_edit(package_name:)
    raise "active edit" if current_edit

    @sequence += 1
    raise readback_error if @sequence > 1 && readback_error

    self.current_edit = Edit.new("edit-#{@sequence}")
    self.current_package_name = package_name
    @pending = clone_tracks(@committed)
    @events << [:begin, current_edit.id]
  end

  def tracks(*names)
    selected = names.empty? ? @pending.values : names.filter_map { |name| @pending[name] }
    selected.map { |track| clone_track(track) }
  end

  def update_track(name, track)
    value = clone_track(track)
    value = update_transform.call(name, value) if update_transform
    @pending[name] = clone_track(value)
    @updates << [name, clone_track(value)]
    @events << [:update, name]
    after_update&.call(self, name)
  end

  def mutate_pending(name)
    track = @pending.fetch(name)
    yield track
  end

  def remove_pending_version(name, version_code)
    mutate_pending(name) do |value|
      value.releases = Array(value.releases).reject do |release|
        Array(release.version_codes).map(&:to_i).include?(version_code.to_i)
      end
    end
  end

  def upload_changelogs(track, track_name)
    update_track(track_name, track)
  end

  def validate_current_edit!
    @events << [:validate, current_edit.id]
  end

  def commit_edit(package_name, edit_id, **keywords)
    @events << [:commit, edit_id]
    @commits << [package_name, edit_id, keywords]
    case commit_behavior
    when :success, :lost_success, :timeout_success
      @committed = clone_tracks(@pending)
      @committed = post_commit_transform.call(clone_tracks(@committed)) if post_commit_transform
      raise Google::Apis::ServerError, "response lost after commit" if commit_behavior == :lost_success
      if commit_behavior == :timeout_success
        raise Google::Apis::RequestTimeOutError, "response timed out after commit"
      end
    when :ambiguous_failure
      raise Google::Apis::TransmissionError, "connection lost"
    when :client_failure
      raise Google::Apis::ClientError, "invalid edit"
    when :rate_limit_failure
      raise Google::Apis::RateLimitError, "rate limited"
    when :local_failure
      raise ArgumentError, "local call construction failed"
    when :interrupt
      raise Interrupt, "cancelled"
    else
      raise "unknown fake commit behavior"
    end
  end

  def abort_current_edit
    @aborts += 1
    @events << [:abort, current_edit.id]
    raise abort_error if abort_error

    self.current_edit = nil
    self.current_package_name = nil
    @pending = nil
  end

  def committed_state(name)
    MobileReleaseKit::PreservingSupplyUploader.track_state(@committed[name], name)
  end

  private

  def clone_track(track)
    AndroidPublisher::Track.from_json(track.to_json)
  end

  def clone_tracks(tracks)
    tracks.transform_values { |track| clone_track(track) }
  end
end

class PreservingSupplyUploaderTests < Minitest::Test
  def setup
    @temporary = Dir.mktmpdir("mrk-play-test-")
    @key = File.join(@temporary, "adc.json")
    @aab = File.join(@temporary, "candidate.aab")
    @journal = File.join(@temporary, "play-state.json")
    File.write(@key, "{}\n", mode: "w", perm: 0o600)
    File.write(@aab, "not-a-real-aab", mode: "w", perm: 0o600)
  end

  def teardown
    FileUtils.remove_entry_secure(@temporary) if @temporary && File.directory?(@temporary)
  end

  def release(code, status:, name: nil, fraction: nil, priority: nil, countries: nil)
    AndroidPublisher::TrackRelease.new(
      name: name || "release-#{code}",
      status: status,
      version_codes: Array(code),
      user_fraction: fraction,
      in_app_update_priority: priority,
      country_targeting: countries && AndroidPublisher::CountryTargeting.new(
        countries: countries,
        include_rest_of_world: false,
      ),
      release_notes: [AndroidPublisher::LocalizedText.new(language: "en-US", text: "notes-#{Array(code).first}")],
    )
  end

  def track(name, releases)
    AndroidPublisher::Track.new(track: name, releases: releases)
  end

  def candidate_options(**overrides)
    {
      package_name: "com.example.app",
      json_key: @key,
      aab: @aab,
      track: "internal",
      release_status: "completed",
      version_name: "2.0.0",
      version_code: 200,
      skip_upload_apk: true,
      skip_upload_aab: false,
      metadata_path: @temporary,
      skip_upload_metadata: true,
      skip_upload_changelogs: true,
      skip_upload_images: true,
      skip_upload_screenshots: true,
      changes_not_sent_for_review: false,
      rescue_changes_not_sent_for_review: false,
      timeout: 60,
    }.merge(overrides)
  end

  def promotion_options(destination: "closed", status: "completed", **overrides)
    candidate_options(
      aab: nil,
      track: "internal",
      track_promote_to: destination,
      track_promote_release_status: status,
      skip_upload_aab: true,
      **overrides,
    )
  end

  def run_uploader(options, client, hook: nil)
    Supply.config = MobileReleaseKit::PreservingSupplyUploader.configuration(options)
    uploader = MobileReleaseKit::PlayStoreHarness.new(journal_path: @journal, client: client)
    uploader.metadata_hook = hook
    FastlaneCore::PrintTable.stub(:print_values, nil) { uploader.perform_upload }
    uploader
  end

  def unrelated_releases
    [
      release(10, status: "completed", priority: 2, countries: %w[US CA]),
      release(11, status: "inProgress", fraction: 0.25),
      release(12, status: "halted", fraction: 0.5),
      release(13, status: "draft"),
    ]
  end

  def test_candidate_preserves_every_unrelated_release_and_commits_with_fail_closed_policy
    before_track = track("internal", unrelated_releases)
    before = MobileReleaseKit::PreservingSupplyUploader.track_state(before_track, "internal")
    client = FakePlayClient.new("internal" => before_track)

    uploader = run_uploader(candidate_options, client)

    committed = client.committed_state("internal")
    assert_equal before.fetch("releases"), committed.fetch("releases").reject { |item| item["versionCodes"] == ["200"] }
    target = committed.fetch("releases").find { |item| item["versionCodes"] == ["200"] }
    assert_equal "completed", target.fetch("status")
    assert_equal "mutated", uploader.outcome
    assert_equal "mutation", uploader.state_evidence.fetch(:mode)
    assert_equal uploader.state_evidence.fetch(:unrelatedBeforeSha256), uploader.state_evidence.fetch(:unrelatedCommittedSha256)
    assert_equal 1, client.commits.length
    _package, mutation_edit, keywords = client.commits.fetch(0)
    assert_equal "edit-1", mutation_edit
    assert_equal false, keywords.fetch(:changes_not_sent_for_review)
    assert_equal "ERROR_IF_IN_REVIEW", keywords.fetch(:changes_in_review_behavior)
    assert_equal 0, keywords.fetch(:options).retries
    assert_equal "edit-2", uploader.state_evidence.fetch(:readbackEditId)
    assert File.file?(@journal)
    assert_equal "committed-and-read-back", JSON.parse(File.read(@journal)).fetch("phase")
  end

  def test_promotion_preserves_all_destination_releases_and_complete_source_state
    source = track("internal", [release(200, status: "completed", priority: 4, countries: %w[GB US])])
    destination = track("closed", unrelated_releases)
    source_before = MobileReleaseKit::PreservingSupplyUploader.track_state(source, "internal")
    destination_before = MobileReleaseKit::PreservingSupplyUploader.track_state(destination, "closed")
    client = FakePlayClient.new("internal" => source, "closed" => destination)

    uploader = run_uploader(promotion_options, client)

    assert_equal source_before, client.committed_state("internal")
    committed = client.committed_state("closed")
    assert_equal destination_before.fetch("releases"), committed.fetch("releases").reject { |item| item["versionCodes"] == ["200"] }
    target = committed.fetch("releases").find { |item| item["versionCodes"] == ["200"] }
    assert_equal "completed", target.fetch("status")
    assert_nil target["userFraction"]
    assert_equal uploader.state_evidence.fetch(:sourceBeforeSha256), uploader.state_evidence.fetch(:sourceCommittedSha256)
    assert_equal "retained", uploader.state_evidence.fetch(:sourceTargetTransition)
    assert_equal uploader.state_evidence.fetch(:sourceUnrelatedBeforeSha256),
                 uploader.state_evidence.fetch(:sourceUnrelatedCommittedSha256)
  end

  def test_promotion_accepts_only_automatic_target_deactivation_at_update_or_commit
    %i[update commit].each do |phase|
      source = track(
        "internal",
        [release(150, status: "completed", name: "unrelated-source"), release(200, status: "completed")],
      )
      source_unrelated = MobileReleaseKit::PreservingSupplyUploader.track_state(
        track("internal", [release(150, status: "completed", name: "unrelated-source")]),
        "internal",
      )
      client = FakePlayClient.new("internal" => source, "closed" => track("closed", unrelated_releases))
      if phase == :update
        client.after_update = lambda do |store, name|
          store.remove_pending_version("internal", 200) if name == "closed"
        end
      else
        client.post_commit_transform = lambda do |tracks|
          tracks.fetch("internal").releases.reject! do |item|
            Array(item.version_codes).map(&:to_i).include?(200)
          end
          tracks
        end
      end

      uploader = run_uploader(promotion_options, client)

      assert_equal source_unrelated, client.committed_state("internal"), phase
      assert_equal "deactivated", uploader.state_evidence.fetch(:sourceTargetTransition), phase
      refute_equal uploader.state_evidence.fetch(:sourceBeforeSha256),
                   uploader.state_evidence.fetch(:sourceCommittedSha256), phase
      assert_equal uploader.state_evidence.fetch(:sourceUnrelatedBeforeSha256),
                   uploader.state_evidence.fetch(:sourceUnrelatedCommittedSha256), phase
    end
  end

  def test_source_target_cannot_reappear_and_unrelated_source_changes_are_rejected
    source = track(
      "internal",
      [release(150, status: "completed", name: "unrelated-source"), release(200, status: "completed")],
    )
    reappearing = FakePlayClient.new("internal" => source, "closed" => track("closed", []))
    reappearing.after_update = lambda do |store, name|
      store.remove_pending_version("internal", 200) if name == "closed"
    end
    # The metadata hook runs after the first source observation and simulates an
    # impossible reappearance before the final precommit guard.
    reappear_hook = lambda do |_uploader, store|
      store.mutate_pending("internal") do |value|
        value.releases = Array(value.releases) + [release(200, status: "completed")]
      end
    end
    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(promotion_options, reappearing, hook: reappear_hook)
    end
    assert_match(/reactivated/, error.message)
    assert_empty reappearing.commits

    collateral = FakePlayClient.new("internal" => source, "closed" => track("closed", []))
    collateral.after_update = lambda do |store, name|
      next unless name == "closed"

      store.mutate_pending("internal") { |value| value.releases.first.name = "changed" }
    end
    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(promotion_options, collateral)
    end
    assert_match(/unrelated source-track/, error.message)
    assert_empty collateral.commits
  end

  def test_production_adds_only_non_served_draft
    source = track("closed", [release(200, status: "completed")])
    production = track("production", unrelated_releases)
    before = MobileReleaseKit::PreservingSupplyUploader.track_state(production, "production")
    client = FakePlayClient.new("closed" => source, "production" => production)

    uploader = run_uploader(
      promotion_options(destination: "production", status: "draft", track: "closed"),
      client,
    )

    committed = client.committed_state("production")
    assert_equal before.fetch("releases"), committed.fetch("releases").reject { |item| item["versionCodes"] == ["200"] }
    target = committed.fetch("releases").find { |item| item["versionCodes"] == ["200"] }
    assert_equal "draft", target.fetch("status")
    refute committed.fetch("releases").any? { |item| item["versionCodes"] == ["200"] && item["status"] != "draft" }
    assert_equal "mutated", uploader.outcome
  end

  def test_rejects_wrong_status_multicode_source_and_duplicate_destination
    wrong = FakePlayClient.new("internal" => track("internal", [release(200, status: "draft")]), "closed" => track("closed", []))
    assert_raises(MobileReleaseKit::ContractError) { run_uploader(promotion_options, wrong) }
    assert_empty wrong.commits

    multiple = FakePlayClient.new("internal" => track("internal", [release([199, 200], status: "completed")]), "closed" => track("closed", []))
    assert_raises(MobileReleaseKit::ContractError) { run_uploader(promotion_options, multiple) }
    assert_empty multiple.commits

    duplicate = FakePlayClient.new(
      "internal" => track("internal", [release(200, status: "completed")]),
      "closed" => track("closed", [release(200, status: "completed"), release(200, status: "draft")]),
    )
    assert_raises(MobileReleaseKit::ContractError) { run_uploader(promotion_options, duplicate) }
    assert_empty duplicate.commits
  end

  def test_rejects_silent_collateral_track_update_and_metadata_mutation
    destination = track("closed", unrelated_releases)
    source = track("internal", [release(200, status: "completed")])
    destructive = FakePlayClient.new("internal" => source, "closed" => destination)
    destructive.update_transform = lambda do |_name, value|
      value.releases = [value.releases.last]
      value
    end
    error = assert_raises(MobileReleaseKit::ContractError) { run_uploader(promotion_options, destructive) }
    assert_match(/unrelated|unexpected/, error.message)
    assert_empty destructive.commits

    client = FakePlayClient.new("internal" => source, "closed" => destination)
    hook = lambda do |_uploader, store|
      store.mutate_pending("closed") { |value| value.releases.first.name = "collateral-change" }
    end
    error = assert_raises(MobileReleaseKit::ContractError) { run_uploader(promotion_options, client, hook: hook) }
    assert_match(/unrelated/, error.message)
    assert_empty client.commits
  end

  def test_target_changelog_is_the_only_allowed_track_metadata_delta
    source = track("internal", [release(200, status: "completed")])
    client = FakePlayClient.new("internal" => source, "closed" => track("closed", unrelated_releases))
    hook = lambda do |_uploader, store|
      store.mutate_pending("closed") do |value|
        target = value.releases.find { |item| Array(item.version_codes).map(&:to_i) == [200] }
        target.release_notes = [AndroidPublisher::LocalizedText.new(language: "fr-FR", text: "Nouveautes")]
      end
    end
    assert_equal "mutated", run_uploader(promotion_options, client, hook: hook).outcome

    protected_client = FakePlayClient.new("internal" => source, "closed" => track("closed", unrelated_releases))
    protected_hook = lambda do |_uploader, store|
      store.mutate_pending("closed") do |value|
        target = value.releases.find { |item| Array(item.version_codes).map(&:to_i) == [200] }
        target.in_app_update_priority = 5
      end
    end
    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(promotion_options, protected_client, hook: protected_hook)
    end
    assert_match(/protected target-release field/, error.message)
  end

  def test_inherited_supply_changelog_put_preserves_complete_destination_track
    source = track("internal", [release(200, status: "completed")])
    destination = track("closed", unrelated_releases)
    before = MobileReleaseKit::PreservingSupplyUploader.track_state(destination, "closed")
    client = FakePlayClient.new("internal" => source, "closed" => destination)
    hook = lambda do |uploader, store|
      current = store.tracks("closed").first
      target = current.releases.find { |item| Array(item.version_codes).map(&:to_i) == [200] }
      notes = [AndroidPublisher::LocalizedText.new(language: "fr-FR", text: "Nouveautes")]
      uploader.apply_supply_changelogs(notes, target, current, "closed")
    end

    uploader = run_uploader(promotion_options, client, hook: hook)

    assert_equal 2, client.updates.length
    committed = client.committed_state("closed")
    assert_equal before.fetch("releases"),
                 committed.fetch("releases").reject { |item| item["versionCodes"] == ["200"] }
    target = committed.fetch("releases").find { |item| item["versionCodes"] == ["200"] }
    assert_equal [{ "language" => "fr-FR", "text" => "Nouveautes" }], target.fetch("releaseNotes")
    assert_equal "mutated", uploader.outcome
  end

  def test_empty_destination_is_created_and_missing_source_is_rejected
    candidate = FakePlayClient.new({})
    uploader = run_uploader(candidate_options, candidate)
    assert_equal "mutated", uploader.outcome
    assert_equal ["200"], candidate.committed_state("internal").fetch("releases").first.fetch("versionCodes")

    missing_source = FakePlayClient.new("closed" => track("closed", unrelated_releases))
    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(promotion_options, missing_source)
    end
    assert_match(/exactly once/, error.message)
    assert_empty missing_source.updates
    assert_empty missing_source.commits
  end

  def test_lost_success_and_timeout_are_reconciled_without_a_second_commit
    %i[lost_success timeout_success].each do |behavior|
      client = FakePlayClient.new("internal" => track("internal", unrelated_releases), commit_behavior: behavior)
      uploader = run_uploader(candidate_options, client)
      assert_equal "reconciled", uploader.outcome
      assert_equal 1, client.commits.length
      assert_equal "edit-2", uploader.state_evidence.fetch(:readbackEditId)
    end
  end

  def test_ambiguous_failure_never_retries_or_claims_success
    client = FakePlayClient.new("internal" => track("internal", unrelated_releases), commit_behavior: :ambiguous_failure)
    error = assert_raises(MobileReleaseKit::ContractError) { run_uploader(candidate_options, client) }
    assert_match(/outcome is ambiguous/, error.message)
    assert_equal 1, client.commits.length
    refute client.committed_state("internal").fetch("releases").any? { |item| item["versionCodes"] == ["200"] }
    journal = JSON.parse(File.read(@journal))
    assert_equal "failed", journal.fetch("phase")
    refute_equal "reconciled", journal["outcome"]
    assert_equal "Google::Apis::TransmissionError", journal.dig("failures", "commit")
    assert_equal "MobileReleaseKit::ContractError", journal.dig("failures", "reconciliation")
    assert_equal "MobileReleaseKit::ContractError", journal.dig("failures", "terminal")
    assert journal.dig("destination", "observed")
    phases = journal.fetch("history").map { |entry| entry.fetch("phase") }
    assert_includes phases, "commit-response-ambiguous"
    assert_includes phases, "readback-destination-observed"
    assert_includes phases, "reconciliation-failed"
  end

  def test_local_definitive_and_cancellation_errors_are_never_reconciled
    {
      local_failure: ArgumentError,
      client_failure: Google::Apis::ClientError,
      rate_limit_failure: Google::Apis::RateLimitError,
      interrupt: Interrupt,
    }.each do |behavior, error_class|
      FileUtils.rm_f(@journal)
      client = FakePlayClient.new(
        "internal" => track("internal", unrelated_releases),
        commit_behavior: behavior,
      )
      assert_raises(error_class, behavior) { run_uploader(candidate_options, client) }
      assert_equal 1, client.commits.length, behavior
      assert_equal 1, client.events.count { |event| event.first == :begin }, behavior
      journal = JSON.parse(File.read(@journal))
      expected_phase = behavior == :interrupt ? "cancelled" : "failed"
      assert_equal expected_phase, journal.fetch("phase"), behavior
      refute journal.fetch("failures", {}).key?("commit"), behavior
      refute_equal "reconciled", journal["outcome"], behavior
    end
  end

  def test_ambiguous_readback_failure_retains_original_and_reconciliation_errors
    client = FakePlayClient.new(
      "internal" => track("internal", unrelated_releases),
      commit_behavior: :lost_success,
    )
    client.readback_error = Google::Apis::TransmissionError.new("readback unavailable")

    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(candidate_options, client)
    end

    assert_match(/outcome is ambiguous/, error.message)
    journal = JSON.parse(File.read(@journal))
    assert_equal "Google::Apis::ServerError", journal.dig("failures", "commit")
    assert_equal "Google::Apis::TransmissionError", journal.dig("failures", "reconciliation")
    assert_equal "MobileReleaseKit::ContractError", journal.dig("failures", "terminal")
    phases = journal.fetch("history").map { |entry| entry.fetch("phase") }
    assert_includes phases, "commit-response-ambiguous"
    assert_includes phases, "reconciliation-failed"
  end

  def test_post_commit_mismatch_fails_without_repair_or_second_commit
    client = FakePlayClient.new("internal" => track("internal", unrelated_releases))
    client.post_commit_transform = lambda do |tracks|
      tracks.fetch("internal").releases.first.name = "concurrent-console-change"
      tracks
    end
    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(candidate_options, client)
    end
    assert_match(/differs from the validated edit/, error.message)
    assert_equal 1, client.commits.length
    assert_equal 1, client.updates.length
    journal = JSON.parse(File.read(@journal))
    observed_names = journal.dig("destination", "observed", "releases").map { |item| item["name"] }
    assert_includes observed_names, "concurrent-console-change"
  end

  def test_post_commit_source_mismatch_is_retained_in_journal
    source = track(
      "internal",
      [release(150, status: "completed", name: "unrelated-source"), release(200, status: "completed")],
    )
    client = FakePlayClient.new("internal" => source, "closed" => track("closed", []))
    client.post_commit_transform = lambda do |tracks|
      tracks.fetch("internal").releases.first.name = "collateral-source-change"
      tracks
    end

    error = assert_raises(MobileReleaseKit::ContractError) do
      run_uploader(promotion_options, client)
    end

    assert_match(/unrelated source-track/, error.message)
    journal = JSON.parse(File.read(@journal))
    observed_names = journal.dig("source", "observed", "releases").map { |item| item["name"] }
    assert_includes observed_names, "collateral-source-change"
  end

  def test_definitive_error_is_preserved_when_cleanup_also_fails
    client = FakePlayClient.new("internal" => track("internal", unrelated_releases), commit_behavior: :client_failure)
    client.abort_error = RuntimeError.new("cleanup failure")
    error = assert_raises(Google::Apis::ClientError) { run_uploader(candidate_options, client) }
    assert_match(/invalid edit/, error.message)
    assert_equal 1, client.commits.length
  end

  def test_successful_commit_cleanup_failure_retains_verified_state
    client = FakePlayClient.new("internal" => track("internal", unrelated_releases))
    client.abort_error = RuntimeError.new("readback cleanup failure")

    error = assert_raises(RuntimeError) { run_uploader(candidate_options, client) }

    assert_match(/readback cleanup failure/, error.message)
    journal = JSON.parse(File.read(@journal))
    assert_equal "failed", journal.fetch("phase")
    assert_equal "mutated", journal.fetch("outcome")
    assert journal.fetch("stateEvidence")
    assert journal.dig("destination", "observed")
    assert_equal "RuntimeError", journal.dig("failures", "terminal")
  end

  def test_observation_only_existing_release_never_mutates_or_commits
    source = track("internal", [release(200, status: "completed")])
    destination = track("closed", [*unrelated_releases, release(200, status: "completed")])
    client = FakePlayClient.new("internal" => source, "closed" => destination)
    Supply.config = MobileReleaseKit::PreservingSupplyUploader.configuration(promotion_options)
    uploader = MobileReleaseKit::PlayStoreHarness.new(journal_path: @journal, client: client)

    present = uploader.observe_existing(
      source_track: "internal",
      destination_track: "closed",
      version_code: 200,
      expected_status: "completed",
    )

    assert present
    assert_equal "already-present", uploader.outcome
    assert_equal "observation", uploader.state_evidence.fetch(:mode)
    assert_empty client.updates
    assert_empty client.commits
    assert_equal 1, client.aborts
  end

  def test_observation_returns_false_when_target_is_absent
    client = FakePlayClient.new(
      "internal" => track("internal", [release(200, status: "completed")]),
      "closed" => track("closed", unrelated_releases),
    )
    Supply.config = MobileReleaseKit::PreservingSupplyUploader.configuration(promotion_options)
    uploader = MobileReleaseKit::PlayStoreHarness.new(journal_path: @journal, client: client)
    refute uploader.observe_existing(
      source_track: "internal",
      destination_track: "closed",
      version_code: 200,
      expected_status: "completed",
    )
    assert_empty client.updates
    assert_empty client.commits
    assert_equal 1, client.aborts
  end

  def test_observation_accepts_destination_after_source_was_automatically_deactivated
    source = track("internal", [release(150, status: "completed", name: "unrelated-source")])
    destination = track("closed", [*unrelated_releases, release(200, status: "completed")])
    client = FakePlayClient.new("internal" => source, "closed" => destination)
    Supply.config = MobileReleaseKit::PreservingSupplyUploader.configuration(promotion_options)
    uploader = MobileReleaseKit::PlayStoreHarness.new(journal_path: @journal, client: client)

    assert uploader.observe_existing(
      source_track: "internal",
      destination_track: "closed",
      version_code: 200,
      expected_status: "completed",
    )

    assert_equal "already-present", uploader.outcome
    assert_equal "already-deactivated", uploader.state_evidence.fetch(:sourceTargetTransition)
    assert_equal uploader.state_evidence.fetch(:sourceBeforeSha256),
                 uploader.state_evidence.fetch(:sourceExpectedSha256)
    assert_equal uploader.state_evidence.fetch(:sourceExpectedSha256),
                 uploader.state_evidence.fetch(:sourceCommittedSha256)
    assert_empty client.updates
    assert_empty client.commits
  end

  def test_dependency_fields_and_unsupported_options_fail_closed
    MobileReleaseKit::PreservingSupplyUploader.assert_dependency_contract!
    client = FakePlayClient.new("internal" => track("internal", unrelated_releases))
    error = assert_raises(FastlaneCore::Interface::FastlaneError) do
      run_uploader(candidate_options(rollout: "0.5"), client)
    end
    assert_match(/does not accept rollout/, error.message)
    assert_empty client.updates
    assert_empty client.commits
  end
end
