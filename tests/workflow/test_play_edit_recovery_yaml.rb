# frozen_string_literal: true
# Closed workflow DATA only. Never evaluates a run block, secret or API call.
require_relative 'test_version_hosted_yaml'

class PlayEditRecoveryWorkflowTest < Minitest::Test
  def setup
    root = ENV.fetch('MRK_VERSION_HOSTED_TEST_ROOT', File.expand_path('../..', __dir__))
    @workflow = Psych.safe_load(File.read(File.join(root, '.github/workflows/reusable-candidate.yml')), permitted_classes: [], aliases: false)
    @caller = Psych.safe_load(File.read(File.join(root, 'templates/workflows/mobile-candidate.yml')), permitted_classes: [], aliases: false)
    @job = @workflow.fetch('jobs').fetch('version_reserve')
  end

  def test_same_protected_job_fixed_mutually_exclusive_entries_no_build_or_extra_permission
    steps = @job.fetch('steps')
    reserve = steps.find { |step| step["run"] == "python -P -m mobile_release.version_hosted reserve" }
    cleanup = steps.find { |step| step["run"] == "python -P -m mobile_release.version_hosted_play_recovery cleanup" }
    assert_equal "inputs.operation == 'reserve-version' || inputs.operation == 'reserve-future-tag'", reserve.fetch('if')
    assert_equal "inputs.operation == 'recover-play-edit'", cleanup.fetch('if')
    assert_equal 'python -P -m mobile_release.version_hosted reserve', reserve.fetch('run')
    assert_equal 'python -P -m mobile_release.version_hosted_play_recovery cleanup', cleanup.fetch('run')
    assert_equal 'mobile-candidate', @job.fetch('environment')
    assert_equal 15, @job.fetch('timeout-minutes')
    assert_equal false, @workflow.fetch('concurrency').fetch('cancel-in-progress')
    assert_equal({ 'actions' => 'read', 'contents' => 'read' }, @job.fetch('permissions'))
    assert_equal 1, steps.count { |step| step['id'] == 'version-token' }
    assert_equal 'candidate', @caller.fetch('on') { @caller.fetch(true) }.fetch('workflow_dispatch').fetch('inputs').fetch('operation').fetch('default')
    refute @job.key?('outputs')
    refute_includes Psych.dump(@job), 'upload-artifact'
    refute_includes Psych.dump(@job), 'GITHUB_OUTPUT'
  end

  def test_new_key_is_opt_in_android_only_and_cleanup_receives_neither_p8_nor_counter_policy
    reserve = @job.fetch("steps").find { |step| step["run"] == "python -P -m mobile_release.version_hosted reserve" }
    cleanup = @job.fetch("steps").find { |step| step["run"] == "python -P -m mobile_release.version_hosted_play_recovery cleanup" }
    key = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_BASE64'
    version = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_VERSION'
    assert_equal "${{ (inputs.platform == 'android' || inputs.platform == 'both') && secrets.#{key} || '' }}", reserve.fetch('env').fetch(key)
    assert_equal "${{ (inputs.platform == 'android' || inputs.platform == 'both') && vars.#{version} || '' }}", reserve.fetch('env').fetch(version)
    env = cleanup.fetch('env')
    assert_equal "${{ secrets.#{key} }}", env.fetch(key)
    assert_equal "${{ vars.#{version} }}", env.fetch(version)
    assert_equal %w[MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64 MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_BASE64],
      env.select { |_, value| value.include?('secrets.') }.keys
    refute env.key?('MOBILE_RELEASE_VERSION_POLICY')
    refute env.keys.any? { |name| name.start_with?('MOBILE_RELEASE_ASC_') }
    refute env.key?('GOOGLE_APPLICATION_CREDENTIALS')
    refute env.key?('GH_TOKEN')
    refute env.key?('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    other = Psych.dump(@workflow.fetch('jobs').reject { |name, _| name == 'version_reserve' })
    refute_includes other, key
    refute_includes other, version
    refute_includes other, 'mobile_release.version_hosted_play_recovery'
  end

  def test_only_public_uuid_confirmation_and_saved_authority_are_forwarded_no_id_url_or_path
    caller_inputs = @caller.fetch('on') { @caller.fetch(true) }.fetch('workflow_dispatch').fetch('inputs')
    assert_equal %w[candidate reserve-version reserve-future-tag bind-version-tag recover-play-edit], caller_inputs.fetch('operation').fetch('options')
    assert_equal %w[operation platform confirmation recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref], caller_inputs.keys
    validation = @workflow.fetch('jobs').fetch('validate-platform').fetch('steps').first.fetch('run')
    assert_includes validation, 'elif [[ "$MOBILE_RELEASE_OPERATION" == "recover-play-edit" ]]; then'
    assert_includes validation, '[[ "$MOBILE_RELEASE_PLATFORM" =~ ^(android|both)$ ]]'
    assert_includes validation, '[[ "$MOBILE_RELEASE_CONFIRMATION" =~ ^recover-play-edit:$uuid:$uuid$ ]]'
    assert_includes validation, '[[ -z "$MOBILE_RELEASE_RECOVERY_RUN_ID$MOBILE_RELEASE_RECOVERY_CONFIRMATION$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]'
    env = @job.fetch('steps').last.fetch('env')
    assert_equal '${{ inputs.confirmation }}', env.fetch('MOBILE_RELEASE_CONFIRMATION')
    assert_equal '${{ vars.MOBILE_RELEASE_VERSION_AUTHORITY }}', env.fetch('MOBILE_RELEASE_VERSION_AUTHORITY')
    %w[MOBILE_RELEASE_RECOVERY_RUN_ID MOBILE_RELEASE_RECOVERY_CONFIRMATION MOBILE_RELEASE_DESKTOP_REQUEST MOBILE_RELEASE_DESKTOP_SOURCE_SHA MOBILE_RELEASE_DESKTOP_EXPECTED_REF].each do |name|
      assert env.key?(name) # Validated as empty; never silently ignored.
    end
    assert_equal '${{ inputs.operation }}', @caller.fetch('jobs').fetch('reserve_version').fetch('with').fetch('operation')
  end
end
