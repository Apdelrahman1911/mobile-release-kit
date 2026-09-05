# frozen_string_literal: true

require "minitest/autorun"
require "bundler/setup"
require "fastlane"
require "spaceship"
require_relative "../../fastlane/apple_store"

class AppleOperationTransportTest < Minitest::Test
  Token = Struct.new(:in_house, :text) do
    def expired? = false
  end

  def setup
    @mode = ENV["MOBILE_RELEASE_STORE_MODE"]
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    @requests = []
    @client = Spaceship::ConnectAPI::APIClient.new(token: Token.new(false, "synthetic-test-token"))
    @client.extend(MobileReleaseKit::AppleOperationTransport)
    @client.define_singleton_method(:sleep) { |_seconds| }
  end

  def teardown
    ENV["MOBILE_RELEASE_STORE_MODE"] = @mode
  end

  def transport(status:, raise_error: nil)
    requests = @requests
    connection = Faraday.new("https://api.appstoreconnect.apple.com/") do |builder|
      builder.response(:json)
      builder.adapter(:test) do |stub|
        %i[get post patch delete].each do |method|
          stub.public_send(method, %r{.*}) do |env|
            requests << [env.method, env.url.path, env.body]
            raise raise_error if raise_error

            [status, { "content-type" => "application/json" },
             JSON.generate("data" => { "type" => "reviewSubmissions", "id" => "test-id", "attributes" => { "state" => "READY_FOR_REVIEW" } })]
          end
        end
      end
    end
    @client.instance_variable_set(:@client, connection)
  end

  def test_non_idempotent_writes_are_never_retried_by_either_sdk_layer
    [401, 429, 500, 502, 503, 504].each do |status|
      transport(status: status)
      before = @requests.length
      assert_raises(StandardError, "status #{status}") do
        @client.post("v1/reviewSubmissions", { data: { attributes: {} } })
      end
      assert_equal 1, @requests.length - before, "SDK retried POST for HTTP #{status}"
    end
    transport(status: 200, raise_error: Faraday::TimeoutError.new("synthetic lost reply"))
    before = @requests.length
    assert_raises(Faraday::TimeoutError) do
      @client.patch("v1/reviewSubmissions/test-id", { data: { attributes: { submitted: true } } })
    end
    assert_equal 1, @requests.length - before
  end

  def test_read_retries_are_bounded_and_do_not_multiply_across_layers
    transport(status: 500)
    assert_raises(MobileReleaseKit::ContractError) { @client.get("v1/apps/test-id") }
    assert_equal 3, @requests.length
  end

  def test_prepare_and_public_or_destructive_operations_do_not_reach_transport
    transport(status: 200)
    ENV["MOBILE_RELEASE_STORE_MODE"] = "prepare"
    assert_raises(MobileReleaseKit::ContractError) do
      @client.post("v1/reviewSubmissions", { data: { attributes: {} } })
    end
    ENV["MOBILE_RELEASE_STORE_MODE"] = "execute"
    assert_raises(MobileReleaseKit::ContractError) { @client.delete("v1/appScreenshots/test-id") }
    assert_raises(MobileReleaseKit::ContractError) do
      @client.post("v1/appStoreVersionReleaseRequests", { data: {} })
    end
    [{ releaseType: "AFTER_APPROVAL" }, { earliestReleaseDate: nil }, { canceled: true }, { expired: true }].each do |attributes|
      assert_raises(MobileReleaseKit::ContractError) do
        @client.patch("v1/appStoreVersions/test-id", { data: { attributes: attributes } })
      end
    end
    assert_empty @requests
  end

  def test_actual_sdk_request_builder_submits_only_the_named_review_resource
    transport(status: 200)
    facade = Spaceship::ConnectAPI::Client.new(token: Token.new(false, "synthetic-test-token"))
    facade.tunes_request_client = @client
    submission = Spaceship::ConnectAPI::ReviewSubmission.new("exact-submission", { "state" => "READY_FOR_REVIEW" })
    submission.submit_for_review(client: facade)
    assert_equal 1, @requests.length
    method, path, body = @requests.first
    assert_equal :patch, method
    assert_equal "/v1/reviewSubmissions/exact-submission", path
    assert_equal({ "submitted" => true }, JSON.parse(body).fetch("data").fetch("attributes"))
  end
end

class AppleStoreContractTest < Minitest::Test
  def test_unchanged_private_target_is_final_and_changed_inputs_fail_before_write
    environment = {
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64" => Base64.strict_encode64("k" * 32),
      "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION" => "test-v1",
    }
    value = { "notes" => "Fictional review", "demoAccountRequired" => false }
    digest = MobileReleaseKit.hmac_commitment("app-review", value, environment)
    commitments = { "keyVersion" => "test-v1", "domains" => { "app-review" => { "before" => digest, "target" => digest } } }
    assert_equal :target, MobileReleaseKit::AppleStore.private_phase!(
      commitments, "app-review", current: value, target: value, environ: environment,
    )
    assert_raises(MobileReleaseKit::ContractError) do
      MobileReleaseKit::AppleStore.private_phase!(
        commitments, "app-review", current: value, target: value.merge("notes" => "changed"), environ: environment,
      )
    end
  end

  def test_external_graph_accepts_actual_sdk_states_and_rejects_regressions
    before = { "externalState" => "READY_FOR_BETA_SUBMISSION", "betaReviewState" => "NOT_SUBMITTED" }
    %w[READY_FOR_BETA_SUBMISSION WAITING_FOR_BETA_REVIEW IN_BETA_REVIEW BETA_APPROVED READY_FOR_BETA_TESTING IN_BETA_TESTING].each do |state|
      result = MobileReleaseKit::AppleStore.external_transition!(before, before.merge("externalState" => state))
      assert result.fetch(:external)
    end
    %w[BETA_REJECTED EXPIRED PROCESSING_EXCEPTION READY_TO_SUBMIT UNKNOWN].each do |state|
      assert_raises(MobileReleaseKit::ContractError) do
        MobileReleaseKit::AppleStore.external_transition!(before, before.merge("externalState" => state))
      end
    end
    assert_raises(MobileReleaseKit::ContractError) do
      MobileReleaseKit::AppleStore.external_transition!(before.merge("externalState" => "IN_BETA_TESTING"), before)
    end
  end

  def test_locales_can_independently_resume_without_authorizing_third_values_or_deletion
    before = [{ "locale" => "en-US", "description" => "old-en" }, { "locale" => "fr-FR", "description" => "old-fr" }]
    target = [{ "locale" => "en-US", "description" => "new-en" }, { "locale" => "fr-FR", "description" => "new-fr" }]
    refute MobileReleaseKit::AppleStore.localizations_phase!(before, target, [target[0], before[1]], fields: ["description"])
    assert MobileReleaseKit::AppleStore.localizations_phase!(before, target, target, fields: ["description"])
    [[target[0]], [target[0], before[1].merge("description" => "unrelated edit")]].each do |current|
      assert_raises(MobileReleaseKit::ContractError) do
        MobileReleaseKit::AppleStore.localizations_phase!(before, target, current, fields: ["description"])
      end
    end
  end
end
