# frozen_string_literal: true

# The complete CURRENT ReadOwner is loaded by these existing inert SDK
# fixtures. No real gems, network, crypto, account or native helper is run.
require_relative "test_apple_provisioning_signing"

class AppleProfileCurrentReadOwnerTest < Minitest::Test
  Signing = MobileReleaseKit::AppleSigningProvisioning
  Read = MobileReleaseKit::AppleBundleRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK

  def setup = FAKE.reset

  def test_actual_current_parent_admits_only_exact_signing_input_and_step
    Signing::STEPS.each do |step|
      FAKE.reset
      env = AppleSigningProvisioningTest.new("fixture_only").environment(step)
      input = Signing::Input.new(env)
      assert Read.supported_input?(input)
      frame = JSON.parse(Signing::Operation.new(input).execute)
      assert_nil frame.fetch("response").fetch("failure")
      assert_equal 1, FAKE.wire.length
      assert_equal step == "create_profile" ? :post : :get, FAKE.wire[0][:method]
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
  end

  def test_parent_acceptance_does_not_grant_write_or_allow_subclass_lookalikes
    env = AppleSigningProvisioningTest.new("fixture_only").environment("create_profile")
    input = Signing::Input.new(env)
    subclass = Class.new(Signing::Input).new(env)
    refute Read.supported_input?(subclass)
    refute Read.supported_input?(Object.new)
    token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Read::ReadOwner.new(input, token, client)
    adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: input.context)
    assert_raises(Provisioning::Error) { adapter.exchange(input.request, approval: input.approval) }
    refute input.ack_consumed?
    assert_empty FAKE.wire
    assert_raises(Read::Error) { Read::ReadOwner.new(subclass, token, client) }
  end
end
