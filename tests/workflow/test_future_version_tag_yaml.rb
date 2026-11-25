# frozen_string_literal: true
# Workflow DATA only. No run block, action, token, Git or provider is executed.
require_relative 'test_play_edit_recovery_yaml'
require_relative 'test_version_ci_yaml'

class FutureVersionTagWorkflowTest < Minitest::Test
  def setup
    @root = ENV.fetch('MRK_VERSION_HOSTED_TEST_ROOT', File.expand_path('../..', __dir__))
    @workflow = Psych.safe_load(File.read(File.join(@root, '.github/workflows/reusable-candidate.yml')), permitted_classes: [], aliases: false)
    @caller_bytes = File.read(File.join(@root, 'templates/workflows/mobile-candidate.yml'))
    @caller = Psych.safe_load(@caller_bytes, permitted_classes: [], aliases: false)
    @job = @workflow.fetch('jobs').fetch('version_reserve')
  end

  def test_binding_uses_the_same_protected_job_token_and_source_without_store_material
    steps = @job.fetch('steps')
    entries = steps.select { |step| step.key?('run') }
    assert_equal 4, entries.size # Authority check, reserve, bind, cleanup.
    bind = entries.find { |step| step['run'] == 'python -P -m mobile_release.version_hosted bind-version-tag' }
    refute_nil bind
    assert_equal "inputs.operation == 'bind-version-tag'", bind.fetch('if')
    assert_equal 'mobile-candidate', @job.fetch('environment')
    assert_equal 15, @job.fetch('timeout-minutes')
    assert_equal({ 'actions' => 'read', 'contents' => 'read' }, @job.fetch('permissions'))
    assert_equal 1, steps.count { |step| step['id'] == 'version-token' }
    ruby = steps.find { |step| step.fetch('uses', '').start_with?('ruby/setup-ruby@') }
    assert_equal "inputs.operation != 'bind-version-tag'", ruby.fetch('if')
    env = bind.fetch('env')
    assert_equal %w[MOBILE_RELEASE_VERSION_GITHUB_TOKEN MOBILE_RELEASE_OPERATION MOBILE_RELEASE_CONFIRMATION
      MOBILE_RELEASE_SELECTED_PLATFORM MOBILE_RELEASE_RECOVERY_RUN_ID MOBILE_RELEASE_RECOVERY_CONFIRMATION
      MOBILE_RELEASE_DESKTOP_REQUEST MOBILE_RELEASE_DESKTOP_SOURCE_SHA MOBILE_RELEASE_DESKTOP_EXPECTED_REF
      MOBILE_RELEASE_DISPATCH_SHA MOBILE_RELEASE_DISPATCH_REF MOBILE_RELEASE_APP_ROOT MOBILE_RELEASE_TOOLING_ROOT
      MOBILE_RELEASE_VERSION_AUTHORITY], env.keys
    assert_equal '${{ steps.version-token.outputs.token }}', env.fetch('MOBILE_RELEASE_VERSION_GITHUB_TOKEN')
    assert_equal '${{ github.sha }}', env.fetch('MOBILE_RELEASE_DISPATCH_SHA')
    assert_equal '${{ github.ref }}', env.fetch('MOBILE_RELEASE_DISPATCH_REF')
    refute env.values.any? { |value| value.include?('secrets.') }
    refute env.keys.any? { |name| name.include?('PLAY') || name.include?('ASC') || name == 'GH_TOKEN' }
    refute @job.key?('outputs')
    refute_includes Psych.dump(@job), 'upload-artifact'
  end

  def test_exact_future_tag_confirmations_keep_real_branch_and_empty_legacy_markers
    validation = @workflow.fetch('jobs').fetch('validate-platform').fetch('steps').first
    text = validation.fetch('run')
    assert_includes text, 'prefix="reserve-future-tag:$MOBILE_RELEASE_PLATFORM:"'
    assert_includes text, 'if [[ "$MOBILE_RELEASE_PLATFORM" != "ios" ]]; then prefix+="temporary-play-edit:"; fi'
    assert_includes text, '[[ "$tag" =~ ^refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$ ]]'
    assert_includes text, '[[ "$MOBILE_RELEASE_CONFIRMATION" =~ ^bind-version-tag:$MOBILE_RELEASE_PLATFORM:$uuid:[0-9a-f]{64}:$MOBILE_RELEASE_CALLER_SHA$ ]]'
    assert_includes text, '[[ "$MOBILE_RELEASE_CALLER_REF" == refs/heads/* ]]'
    empty = '[[ -z "$MOBILE_RELEASE_RECOVERY_RUN_ID$MOBILE_RELEASE_RECOVERY_CONFIRMATION$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]'
    assert_equal 4, text.scan(empty).size # Old reserve/recovery and both new operations.
    assert_equal '${{ github.sha }}', validation.fetch('env').fetch('MOBILE_RELEASE_CALLER_SHA')
    assert_equal '${{ github.ref }}', validation.fetch('env').fetch('MOBILE_RELEASE_CALLER_REF')
    inputs = @caller.fetch('on') { @caller.fetch(true) }.fetch('workflow_dispatch').fetch('inputs')
    assert_equal %w[operation platform confirmation recovery_run_id recovery_confirmation desktop_request desktop_source_sha desktop_expected_ref], inputs.keys
    assert_equal 'candidate', inputs.fetch('operation').fetch('default')
    assert_equal %w[candidate reserve-version reserve-future-tag bind-version-tag recover-play-edit], inputs.fetch('operation').fetch('options')
    assert_includes inputs.fetch('confirmation').fetch('description'), 'may invalidate another Play edit'
    assert_includes inputs.fetch('confirmation').fetch('description'), 'bind-version-tag:<platform>:<candidateUUID>:<rowSHA256>:<finalSHA>'
  end

end
