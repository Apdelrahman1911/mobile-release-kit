# frozen_string_literal: true

# Workflow DATA only: no run block, Actions, environment secret or API executes.
require "minitest/autorun"
require "psych"

class HostedVersionWorkflowTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  PROJECTION = ENV.fetch("MRK_VERSION_HOSTED_TEST_ROOT", ROOT)

  def setup
    @caller = Psych.safe_load(File.read(File.join(PROJECTION, "templates/workflows/mobile-candidate.yml")), permitted_classes: [], aliases: false)
    @reusable = Psych.safe_load(File.read(File.join(PROJECTION, ".github/workflows/reusable-candidate.yml")), permitted_classes: [], aliases: false)
  end

  def inputs(workflow, kind)
    workflow.fetch("on") { workflow.fetch(true) }.fetch(kind).fetch("inputs")
  end

  def test_existing_candidate_is_default_and_reserve_has_no_ambient_write_token
    public_input = inputs(@caller, "workflow_dispatch")
    assert_equal "candidate", public_input.fetch("operation").fetch("default")
    assert_equal %w[candidate reserve-version], public_input.fetch("operation").fetch("options")
    assert_equal "candidate", inputs(@reusable, "workflow_call").fetch("operation").fetch("default")
    jobs = @caller.fetch("jobs")
    assert_equal %w[candidate reserve_version], jobs.keys
    candidate, reserve = jobs.values_at("candidate", "reserve_version")
    assert_equal "inputs.operation == 'candidate'", candidate.fetch("if")
    assert_equal "inputs.operation == 'reserve-version'", reserve.fetch("if")
    assert_equal "read", candidate.fetch("permissions").fetch("contents")
    assert_equal({ "actions" => "read", "contents" => "read" }, reserve.fetch("permissions"))
    assert_equal candidate.fetch("uses"), reserve.fetch("uses")
    assert_equal "reserve-version", reserve.fetch("with").fetch("operation")
    %w[recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref].each do |name|
      assert_equal "${{ inputs.#{name} }}", reserve.fetch("with").fetch(name) # validated, not silently dropped
    end
  end

  def test_reserve_cannot_fall_through_resolvers_or_always_store_jobs
    jobs = @reusable.fetch("jobs")
    %w[android ios].each do |platform|
      resolver = jobs.fetch("#{platform}_resolve")
      assert_equal "inputs.operation == 'candidate' && (inputs.platform == '#{platform}' || inputs.platform == 'both')", resolver.fetch("if")
      %w[online build store].each do |kind|
        name = "#{platform}_#{kind}"
        ancestors = []
        frontier = [name]
        until frontier.empty?
          entry = frontier.pop
          next if ancestors.include?(entry)
          ancestors << entry
          frontier.concat(Array(jobs.fetch(entry)["needs"]))
        end
        assert_includes ancestors, "#{platform}_resolve"
        if kind == "store"
          assert_includes jobs.fetch(name).fetch("if"), "needs.#{platform}_resolve.result == 'success'"
        end
      end
    end
    validation = jobs.fetch("validate-platform").fetch("steps").first
    assert_includes validation.fetch("run"), '[[ "$MOBILE_RELEASE_OPERATION" =~ ^(candidate|reserve-version)$ ]]'
    assert_includes validation.fetch("run"), 'if [[ "$MOBILE_RELEASE_PLATFORM" == "ios" ]]; then'
    assert_includes validation.fetch("run"), '[[ "$MOBILE_RELEASE_CONFIRMATION" == "reserve-version:ios" ]]'
    assert_includes validation.fetch("run"), '[[ "$MOBILE_RELEASE_CONFIRMATION" == "reserve-version:$MOBILE_RELEASE_PLATFORM:temporary-play-edit" ]]'
    assert_includes validation.fetch("run"), '[[ -z "$MOBILE_RELEASE_RECOVERY_RUN_ID$MOBILE_RELEASE_RECOVERY_CONFIRMATION$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]'
    %w[OPERATION CONFIRMATION RECOVERY_RUN_ID RECOVERY_CONFIRMATION].each do |suffix|
      assert validation.fetch("env").key?("MOBILE_RELEASE_#{suffix}")
    end
  end

  def test_single_protected_read_and_reserve_job_has_no_build_upload_source_write_or_other_secret
    reserve = @reusable.fetch("jobs").fetch("version_reserve")
    assert_equal "inputs.operation == 'reserve-version' && (inputs.platform == 'android' || inputs.platform == 'ios' || inputs.platform == 'both')", reserve.fetch("if")
    assert_equal "validate-platform", reserve.fetch("needs")
    assert_equal "mobile-candidate", reserve.fetch("environment")
    assert_equal({ "actions" => "read", "contents" => "read" }, reserve.fetch("permissions"))
    steps = reserve.fetch("steps")
    action_steps = steps.select { |step| step.key?("uses") }
    assert_equal ["actions/checkout", "actions/checkout", "actions/setup-python", "ruby/setup-ruby", "actions/create-github-app-token"], action_steps.map { |step| step.fetch("uses").split("@").first }
    action_steps.each { |step| assert_match(/@[0-9a-f]{40}\z/, step.fetch("uses")) }
    checkouts = action_steps.take(2)
    assert_equal %w[app tooling], checkouts.map { |s| s.fetch("with").fetch("path") }
    assert checkouts.all? { |s| s.fetch("with").fetch("persist-credentials") == false }
    assert_equal "${{ inputs.source_sha }}", checkouts.first.fetch("with").fetch("ref")
    assert_equal "${{ job.workflow_sha }}", checkouts.last.fetch("with").fetch("ref")
    assert_equal 2, steps.count { |step| step.key?("run") } # original pin validation, one closed entry
    invoke = steps.last
    assert_equal "python -P -m mobile_release.version_hosted reserve", invoke.fetch("run")
    assert_equal %w[MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64 MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64], invoke.fetch("env").select { |_, v| v.include?("secrets.") }.keys
    refute invoke.fetch("env").key?("GH_TOKEN")
    assert_equal "${{ steps.version-token.outputs.token }}", invoke.fetch("env").fetch("MOBILE_RELEASE_VERSION_GITHUB_TOKEN")
    %w[AUTHORITY POLICY].each do |name|
      assert_equal "${{ vars.MOBILE_RELEASE_VERSION_#{name} }}", invoke.fetch("env").fetch("MOBILE_RELEASE_VERSION_#{name}")
    end
    refute reserve.key?("outputs") # no release evidence/Store delivery/publication claim
  end

  def test_app_key_stays_in_protected_reserve_mint_and_token_never_bridges_jobs
    caller = @caller.fetch("jobs")
    caller.each_value { |job| refute(job.key?("uses") && job.key?("steps")) }
    refute caller.fetch("candidate").key?("secrets")
    assert_equal({
      "version_allocation_app_id" => "${{ secrets.MOBILE_RELEASE_VERSION_APP_ID }}",
      "version_allocation_app_private_key" => "${{ secrets.MOBILE_RELEASE_VERSION_APP_PRIVATE_KEY }}"
    }, caller.fetch("reserve_version").fetch("secrets"))
    call = @reusable.fetch("on") { @reusable.fetch(true) }.fetch("workflow_call")
    assert_equal %w[version_allocation_app_id version_allocation_app_private_key], call.fetch("secrets").keys
    assert call.fetch("secrets").values.all? { |input| input.fetch("required") == false }
    jobs = @reusable.fetch("jobs")
    steps = jobs.fetch("version_reserve").fetch("steps")
    mint = steps[-2]
    assert_equal "version-token", mint.fetch("id")
    assert_equal({
      "app-id" => "${{ secrets.version_allocation_app_id }}",
      "private-key" => "${{ secrets.version_allocation_app_private_key }}",
      "owner" => "${{ github.repository_owner }}",
      "repositories" => "${{ github.event.repository.name }}",
      "permission-administration" => "read", "permission-contents" => "write", "permission-actions" => "read",
      "github-api-url" => "https://api.github.com"
    }, mint.fetch("with")) # No all-repos default, skip-revoke or permission fallback.
    ordinary = Psych.dump(jobs.reject { |name, _| name == "version_reserve" })
    %w[version_allocation_app MOBILE_RELEASE_VERSION_GITHUB_TOKEN create-github-app-token MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64].each do |private_input|
      refute_includes ordinary, private_input
    end
    steps[0...-2].each { |step| refute_includes Psych.dump(step), "version_allocation_app" }
    refute_includes Psych.dump(steps.last), "version_allocation_app"
    refute_includes Psych.dump(jobs.fetch("version_reserve")), "GITHUB_OUTPUT"
  end

  def test_store_secrets_project_only_selected_platforms_without_wif_fallback
    jobs = @reusable.fetch("jobs")
    reserve = jobs.fetch("version_reserve")
    refute jobs.key?("ios_version_reserve")
    environment = reserve.fetch("steps").last.fetch("env")
    %w[KEY_ID ISSUER_ID PRIVATE_KEY_P8_BASE64].each do |suffix|
      name = "MOBILE_RELEASE_ASC_#{suffix}"
      source = suffix == "PRIVATE_KEY_P8_BASE64" ? "secrets" : "vars"
      assert_equal "${{ (inputs.platform == 'ios' || inputs.platform == 'both') && #{source}.#{name} || '' }}", environment.fetch(name)
    end
    name = "MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64"
    assert_equal "${{ (inputs.platform == 'android' || inputs.platform == 'both') && secrets.#{name} || '' }}", environment.fetch(name)
    refute environment.key?("GOOGLE_APPLICATION_CREDENTIALS")
    refute environment.key?("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    refute_includes Psych.dump(reserve), "google-github-actions/auth"
    # The unrelated candidate route retains its actual WIF entry, not the new key.
    assert_includes Psych.dump(jobs.fetch("android_online")), "google-github-actions/auth@"
    assert_includes inputs(@caller, "workflow_dispatch").fetch("confirmation").fetch("description"), "may invalidate another Play edit"
  end
end
