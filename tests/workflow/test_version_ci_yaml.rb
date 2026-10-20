# frozen_string_literal: true

# Fixed workflow DATA only. Does not execute run blocks, Actions or cloud APIs.
require "minitest/autorun"
require "psych"

class VersionCiWorkflowTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  PATH = ENV.fetch("MRK_VERSION_CI_TEST_WORKFLOW", File.join(ROOT, ".github/workflows/reusable-candidate.yml"))
  GATE = "Verify the existing version reservation before new work"

  def setup
    @workflow = Psych.safe_load(File.read(PATH), permitted_classes: [], aliases: false)
  end

  def test_fresh_gate_is_reachable_before_application_code_and_store_auth_for_every_platform
    %w[android ios].each do |platform|
      %w[online build store].each do |kind|
        job = @workflow.fetch("jobs").fetch("#{platform}_#{kind}")
        steps = job.fetch("steps")
        gates = steps.each_index.select { |i| steps[i]["name"] == GATE }
        assert_equal 1, gates.size
        index = gates.first
        gate = steps[index]
        assert_equal "read", job.fetch("permissions").fetch("contents")
        assert_equal "mobile-candidate", job["environment"]
        assert_equal "${{ github.token }}", gate.fetch("env").fetch("GH_TOKEN")
        assert_equal "${{ vars.MOBILE_RELEASE_VERSION_AUTHORITY }}", gate["env"]["MOBILE_RELEASE_VERSION_AUTHORITY"]
        assert_equal "${{ inputs.platform }}", gate["env"]["MOBILE_RELEASE_SELECTED_PLATFORM"]
        assert_equal 3, gate["env"].size
        assert_equal "python -P -m mobile_release.workflow verify-version-reservation --stage candidate --platform #{platform} --app-root app", gate["run"]
        assert_operator index, :>, steps.index { |s| s["name"] == "Set up Python" }
        assert steps.take(index).any? { |s| s.fetch("with", {})["path"] == "app" }
        effect = steps.index { |s| s["name"] == (kind == "build" ? "Diagnose #{platform == 'android' ? 'Android' : 'iOS'} configuration" :
          kind == "store" ? "Prepare immutable Store operation without mutation" :
          platform == "android" ? "Authenticate to Google Play for non-publishing online gate" : "Check iOS Store state without running application commands") }
        refute_nil effect
        assert_operator index, :<, effect
        if kind == "store"
          assert_equal "success() && (steps.resolve.outputs.mode == 'prepare')", gate["if"]
          seal = steps.find { |s| s["name"] == "Bind durable intent to its actual workflow attempt and job" }
          assert_equal "success() && (steps.resolve.outputs.mode == 'prepare')", seal["if"]
          assert_equal gate["env"], seal["env"]
        else
          refute gate.key?("if") # Normal success semantics; failure skips later work.
        end
      end
    end
  end

  def test_initial_resolution_and_authenticated_recovery_do_not_acquire_fresh_allocation_requirements
    %w[android ios].each do |platform|
      resolver = @workflow.fetch("jobs").fetch("#{platform}_resolve")
      refute resolver.fetch("steps").any? { |s| s["name"] == GATE }
      store = @workflow.fetch("jobs").fetch("#{platform}_store")
      gate = store["steps"].find { |s| s["name"] == GATE }
      refute_includes gate["if"], "resume"
      refute_includes gate["if"], "complete"
    end
    # Opt-in is a protected setting, not another public dispatch authority.
    # Psych's YAML 1.1 resolver treats the unquoted Actions `on` key as true.
    trigger = @workflow.fetch("on") { @workflow.fetch(true) }
    refute trigger.fetch("workflow_call").fetch("inputs").key?("version_authority")
  end
end
