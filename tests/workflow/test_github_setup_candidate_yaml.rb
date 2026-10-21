# frozen_string_literal: true

# Shipped caller/reusable YAML DATA only. No command, provider or Actions runs.
require "json"
require "minitest/autorun"
require "psych"

class GitHubSetupCandidateYamlTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  REPOSITORY = "Example/mobile-release-kit"
  SHA = "b" * 40

  def setup
    resource = JSON.parse(File.read(File.join(ROOT, "src/mobile_release/api/data/github-setup-v1.json")))
    @template = resource.fetch("workflows").fetch("candidate")
    @caller = Psych.safe_load(@template.gsub("__MOBILE_RELEASE_KIT_REPOSITORY__", REPOSITORY)
      .gsub("__MOBILE_RELEASE_KIT_SHA__", SHA), permitted_classes: [], aliases: false)
    @reusable = Psych.safe_load(File.read(File.join(ROOT, ".github/workflows/reusable-candidate.yml")),
      permitted_classes: [], aliases: false)
  end

  def inputs(workflow, kind)
    workflow.fetch("on") { workflow.fetch(true) }.fetch(kind).fetch("inputs")
  end

  def test_canonical_generator_resource_exposes_only_supported_dispatch_choices
    assert_equal File.binread(File.join(ROOT, "templates/workflows/mobile-candidate.yml")), @template
    assert_operator @template.bytesize, :<=, 16 * 1024
    dispatch = inputs(@caller, "workflow_dispatch")
    assert_equal %w[operation platform confirmation recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref], dispatch.keys
    assert_equal "candidate", dispatch.fetch("operation").fetch("default")
    assert_equal %w[candidate reserve-version recover-play-edit], dispatch.fetch("operation").fetch("options")
    assert_equal %w[android ios both], dispatch.fetch("platform").fetch("options")
    assert_equal "string", dispatch.fetch("confirmation").fetch("type")
    assert dispatch.fetch("confirmation").fetch("required")
    assert_includes dispatch.fetch("confirmation").fetch("description"), "recover-play-edit:<candidateUUID>:<attemptUUID>"
    %w[recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref].each do |name|
      assert_equal "", dispatch.fetch(name).fetch("default")
      refute dispatch.fetch(name).fetch("required")
    end
  end

  def test_both_real_invocations_pin_toolkit_and_source_without_inheriting_secrets
    assert_equal({}, @caller.fetch("permissions"))
    jobs = @caller.fetch("jobs")
    assert_equal %w[candidate reserve_version], jobs.keys
    candidate, reserve = jobs.values_at("candidate", "reserve_version")
    assert_equal "inputs.operation == 'candidate'", candidate.fetch("if")
    assert_equal "inputs.operation == 'reserve-version' || inputs.operation == 'recover-play-edit'", reserve.fetch("if")
    assert_equal "candidate", candidate.fetch("with").fetch("operation")
    assert_equal "${{ inputs.operation }}", reserve.fetch("with").fetch("operation")
    jobs.each_value do |job|
      assert_equal "#{REPOSITORY}/.github/workflows/reusable-candidate.yml@#{SHA}", job.fetch("uses")
      assert_equal SHA, job.fetch("with").fetch("tooling_sha")
      assert_equal "${{ github.sha }}", job.fetch("with").fetch("source_sha")
      assert_equal %w[operation tooling_sha source_sha platform confirmation recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref], job.fetch("with").keys
      %w[platform confirmation recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref].each do |name|
        assert_equal "${{ inputs.#{name} }}", job.fetch("with").fetch(name)
      end
      refute job.key?("steps")
    end
    assert_equal({ "actions" => "read", "artifact-metadata" => "write", "attestations" => "write", "contents" => "read", "id-token" => "write" }, candidate.fetch("permissions"))
    refute candidate.key?("secrets")
    assert_equal({ "actions" => "read", "contents" => "read" }, reserve.fetch("permissions"))
    assert_equal({
      "version_allocation_app_id" => "${{ secrets.MOBILE_RELEASE_VERSION_APP_ID }}",
      "version_allocation_app_private_key" => "${{ secrets.MOBILE_RELEASE_VERSION_APP_PRIVATE_KEY }}"
    }, reserve.fetch("secrets"))
  end

  def test_updated_reusable_still_binds_dispatch_head_and_retains_original_history
    call = inputs(@reusable, "workflow_call")
    @caller.fetch("jobs").each_value { |job| assert_empty(job.fetch("with").keys - call.keys) }
    reserve = @reusable.fetch("jobs").fetch("version_reserve")
    assert_equal "mobile-candidate", reserve.fetch("environment")
    assert_equal({ "actions" => "read", "contents" => "read" }, reserve.fetch("permissions"))
    steps = reserve.fetch("steps")
    validation = steps.find { |step| step.fetch("run", "").include?('[[ "$MOBILE_RELEASE_SOURCE_SHA" == "$MOBILE_RELEASE_CALLER_SHA" ]]') }
    refute_nil validation
    assert_equal "${{ inputs.source_sha }}", validation.fetch("env").fetch("MOBILE_RELEASE_SOURCE_SHA")
    assert_equal "${{ github.sha }}", validation.fetch("env").fetch("MOBILE_RELEASE_CALLER_SHA")
    app = steps.find { |step| step.fetch("with", {})["path"] == "app" }
    assert_equal "${{ inputs.source_sha }}", app.fetch("with").fetch("ref")
    assert_equal 0, app.fetch("with").fetch("fetch-depth")
    assert_equal false, app.fetch("with").fetch("persist-credentials")
    cleanup = steps.find { |step| step["if"] == "inputs.operation == 'recover-play-edit'" }
    assert_equal "python -P -m mobile_release.version_hosted_play_recovery cleanup", cleanup.fetch("run")
    guard = @reusable.fetch("jobs").fetch("validate-platform").fetch("steps").first.fetch("run")
    assert_includes guard, '[[ -z "$MOBILE_RELEASE_RECOVERY_RUN_ID$MOBILE_RELEASE_RECOVERY_CONFIRMATION$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]'
    refute reserve.key?("outputs")
  end
end
