# frozen_string_literal: true

# Shared inert SDK doubles only. Filter /AppleSigningProvisioningTest/; loading
# these fixtures never loads the real gems, runs Ruby crypto or opens a socket.
require_relative "test_apple_provisioning_bundle_registration"
require_relative "../../fastlane/apple_provisioning_signing"

class AppleSigningProvisioningTest < Minitest::Test
  Signing = MobileReleaseKit::AppleSigningProvisioning
  Read = MobileReleaseKit::AppleBundleRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK
  PREFIX = Signing::PREFIX

  def setup = FAKE.reset

  def environment(step = "list_profiles")
    value = AppleBundleReadTest.new("fixture_only").environment.merge(
      PREFIX + "STEP" => step, PREFIX + "OPERATION_ID" => "synthetic-profile-operation")
    if step == "create_profile"
      value.merge!(PREFIX + "BUNDLE_RESOURCE_ID" => "bundle-fixture", PREFIX + "CERTIFICATE_RESOURCE_ID" => "cert-fixture",
        PREFIX + "PLAN_SHA256" => "b" * 64, PREFIX + "ACK_SHA256" => "c" * 64)
    elsif step == "download_profile"
      value[PREFIX + "PROFILE_RESOURCE_ID"] = "profile-fixture"
    end
    value
  end

  def execute(env = environment)
    JSON.parse(Signing::Operation.new(Signing::Input.new(env)).execute)
  end

  def failure(frame, status: nil)
    assert_equal({ "status" => status, "bodyBase64" => nil, "failure" => Read::PRIVATE_FAILURE }, frame.fetch("response"))
    refute_match(/PRIVATE_PROVIDER_DETAIL|SYNTHETIC_NOT_A_JWT|INERT_PRIVATE/, JSON.generate(frame))
    refute frame.key?("settled")
  end

  def test_all_fixed_read_shapes_use_one_raw_call_without_approval
    Signing::LISTS.each do |step|
      FAKE.reset
      input = Signing::Input.new(environment(step))
      frame = JSON.parse(Signing::Operation.new(input).execute)
      assert_equal 1, FAKE.wire.length
      wire = FAKE.wire.fetch(0)
      assert_equal :get, wire[:method]
      assert_equal input.request.fetch("path"), wire[:url].path
      assert_equal input.request.fetch("query"), URI.decode_www_form(wire[:url].query).to_h
      assert_nil input.approval
      refute input.ack_consumed?
      assert_equal FAKE.body, Base64.strict_decode64(frame.fetch("response").fetch("bodyBase64"))
      assert_equal Signing::SCOPE, frame.fetch("scope")
      assert_equal input.request_sha256, frame.fetch("requestSha256")
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
  end

  def test_only_list_cursor_and_exact_single_profile_download_are_admitted
    Signing::LISTS.each do |step|
      FAKE.reset
      env = environment(step).merge(PREFIX + "CURSOR" => "synthetic+/cursor=2")
      frame = execute(env)
      assert_nil frame.fetch("response").fetch("failure")
      assert_equal "synthetic+/cursor=2", URI.decode_www_form(FAKE.wire[0][:url].query).to_h.fetch("cursor")
      assert_equal 1, FAKE.wire.length
    end
    FAKE.reset
    input = Signing::Input.new(environment("download_profile"))
    execute(environment("download_profile"))
    assert_equal "/v1/profiles/profile-fixture", FAKE.wire[0][:url].path
    assert_includes input.request.fetch("query").fetch("fields[profiles]"), "profileContent"
    assert_raises(Signing::Error) { Signing::Input.new(environment("download_profile").merge(PREFIX + "CURSOR" => "bad")) }
  end

  def test_exact_one_post_with_consumed_ack_retains_sparse_201_raw_not_success
    FAKE.status = 201
    FAKE.body = '{"data":{"type":"profiles","id":"created-fixture"}}'
    input = Signing::Input.new(environment("create_profile"))
    operation = Signing::Operation.new(input)
    frame = JSON.parse(operation.execute)
    assert input.ack_consumed?
    assert_equal 1, FAKE.wire.length
    wire = FAKE.wire.fetch(0)
    assert_equal :post, wire[:method]
    assert_equal "/v1/profiles", wire[:url].path
    assert_equal input.request.fetch("body").to_json, wire[:body]
    data = JSON.parse(wire[:body]).fetch("data")
    assert_equal "IOS_APP_STORE", data.fetch("attributes").fetch("profileType")
    assert_equal "MRK-" + Digest::SHA256.hexdigest(input.operation_id)[0, 24], data.fetch("attributes").fetch("name")
    assert_equal %w[bundleId certificates], data.fetch("relationships").keys.sort
    assert_equal 1, data.fetch("relationships").fetch("certificates").fetch("data").size
    assert_equal "c" * 64, frame.fetch("ackSha256")
    assert_equal FAKE.body, Base64.strict_decode64(frame.fetch("response").fetch("bodyBase64"))
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
    assert_equal 1, FAKE.refreshes
    assert_empty FAKE.last_client.logs
    assert_empty FAKE.last_client.retry_entries
  end

  def test_wrong_ack_burns_same_attempt_and_old_read_owner_cannot_write
    input = Signing::Input.new(environment("create_profile"))
    assert_raises(Signing::Error) do
      input.consume_ack!(input.context, "different-operation", input.plan_sha256, input.request_sha256)
    end
    assert_raises(Signing::Error) do
      input.consume_ack!(input.context, input.operation_id, input.plan_sha256, input.request_sha256)
    end
    failure(JSON.parse(Signing::Operation.new(input).execute))
    assert_empty FAKE.wire
    FAKE.reset
    input = Signing::Input.new(environment("create_profile"))
    token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Read::ReadOwner.new(input, token, client)
    adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: input.context)
    assert_raises(Provisioning::Error) { adapter.exchange(input.request, approval: input.approval) }
    assert_empty FAKE.wire
  end

  def test_other_mutations_missing_ack_and_ambient_roles_are_zero_sdk
    invalid = [environment("create_certificate"), environment("revoke"), environment.merge(PREFIX + "URL" => "https://foreign.invalid"),
      environment.merge("MOBILE_RELEASE_ASC_PROVISIONING_STEP" => "register"), environment.merge("MOBILE_RELEASE_ASC_SIGNING_KEY" => "PRIVATE"),
      environment("create_profile").reject { |key, _| key == PREFIX + "ACK_SHA256" },
      environment("create_profile").merge(PREFIX + "BUNDLE_RESOURCE_ID" => "../other"),
      environment("create_profile").merge(PREFIX + "ACK_SHA256" => "not-an-ack"),
      environment.merge(PREFIX + "CURSOR" => "bad\nvalue"), environment.merge(PREFIX + "CURSOR" => "x" * 1025)]
    %w[SPACESHIP_KEY FASTLANE_USER HTTPS_PROXY DEBUG].each { |key| invalid << environment.merge(key => "PRIVATE") }
    invalid.each { |env| assert_raises(Signing::Error) { Signing::Input.new(env) } }
    assert_equal 0, FAKE.loads
    assert_empty FAKE.wire
  end

  def test_wire_path_method_query_and_exact_post_bytes_cannot_change
    changes = [->(e) { e[:url].host = "foreign.invalid" }, ->(e) { e[:url].path = "/v1/certificates" },
      ->(e) { e[:method] = :delete }, ->(e) { e[:url].query += "&cursor=other" }]
    changes.each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute)
      assert_empty FAKE.wire
    end
    [->(e) { e[:body] = e[:body].sub("cert-fixture", "cert-other") },
      ->(e) { e[:body] = JSON.parse(e[:body]) }, ->(e) { e[:url].query = "extra=1" }].each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute(environment("create_profile")))
      assert_empty FAKE.wire
    end
  end

  def test_raw_duplicate_members_survive_sdk_decode_and_callback_bounds_are_exact
    FAKE.body = '{"data":{"lost":"PRIVATE"},"data":[]}'
    frame = execute
    assert_equal [], FAKE.normalized["data"]
    assert_equal FAKE.body, Base64.strict_decode64(frame.fetch("response").fetch("bodyBase64"))
    [0, 2].each do |count|
      FAKE.reset; FAKE.callback_count = count
      failure(execute)
      assert_equal 1, FAKE.wire.length
    end
    FAKE.reset; FAKE.response_status = 201
    failure(execute)
    assert_equal 1, FAKE.wire.length
  end

  def test_page_download_and_private_frame_caps_remain_distinct
    FAKE.body = '{"data":[]}' + " " * Signing::PAGE_LIMIT
    failure(execute)
    FAKE.reset; FAKE.body = '{"data":{}}' + " " * Signing::PAGE_LIMIT
    frame = execute(environment("download_profile"))
    assert_equal FAKE.body, Base64.strict_decode64(frame.fetch("response").fetch("bodyBase64"))
    FAKE.reset; FAKE.body = '{"data":{}}' + " " * Signing::DOWNLOAD_LIMIT
    failure(execute(environment("download_profile")))
    # A raw value near the limit may not fit its base64+header handoff. That is
    # unconfirmed, never permission to omit bytes or retry the original call.
    FAKE.reset; FAKE.body = '{"data":{}}' + " " * (Signing::DOWNLOAD_LIMIT - 12)
    failure(execute(environment("download_profile")))
    assert_equal 1, FAKE.wire.length
  end

  def test_denied_and_transport_failed_requests_never_retry_refresh_or_log
    [401, 403, 409, 429, 500].each do |status|
      FAKE.reset; FAKE.status = status
      operation = Signing::Operation.new(Signing::Input.new(environment("create_profile")))
      failure(JSON.parse(operation.execute), status: status)
      failure(JSON.parse(operation.execute))
      assert_equal 1, FAKE.wire.length
      assert_equal 1, FAKE.refreshes
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
    FAKE.reset; FAKE.transport_error = IOError.new("PRIVATE_PROVIDER_DETAIL")
    failure(execute)
    assert_equal 1, FAKE.wire.length
    FAKE.reset; FAKE.before_wire = ->(_) { FAKE.expired = true }
    failure(execute)
    assert_empty FAKE.wire
    assert_equal 1, FAKE.refreshes
  end

  def test_main_only_fixed_no_arguments_and_no_private_error_output
    output = StringIO.new
    assert_equal 70, Signing.main(["--post"], environment("create_profile"), output)
    assert_empty output.string
    assert_equal 0, Signing.main([], environment, output)
    assert_operator output.string.bytesize, :<=, Signing::FRAME_LIMIT
    refute_match(/INERT_PRIVATE|SYNTHETIC_NOT_A_JWT/, output.string)
  end
end
