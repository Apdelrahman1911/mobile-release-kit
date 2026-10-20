# frozen_string_literal: true

# Existing inert SDK/adapter/callback doubles only. Select this test class;
# no real SDK, HTTP, key/CSR generation or native admission is executed.
require_relative "test_apple_provisioning_bundle_registration"
require_relative "../../fastlane/apple_provisioning_certificate_issuance"

class AppleCertificateIssuanceTest < Minitest::Test
  Issuance = MobileReleaseKit::AppleCertificateIssuance
  Read = MobileReleaseKit::AppleBundleRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK
  PREFIX = Issuance::PREFIX
  CSR = "-----BEGIN CERTIFICATE REQUEST-----\nbm90LWEtcmVhbC1DU1I=\n-----END CERTIFICATE REQUEST-----\n".freeze

  def setup = FAKE.reset

  def environment(step = "create_certificate")
    value = AppleBundleReadTest.new("fixture_only").environment.merge(
      PREFIX + "STEP" => step, PREFIX + "OPERATION_ID" => "synthetic-certificate-operation")
    if step == "create_certificate"
      value.merge!(PREFIX + "PLAN_SHA256" => "b" * 64, PREFIX + "KEY_SAVED_ACK_SHA256" => "d" * 64,
        PREFIX + "ACK_SHA256" => "c" * 64, PREFIX + "CSR_BASE64" => Base64.strict_encode64(CSR))
    end
    value
  end

  def execute(env = environment)
    JSON.parse(Issuance::Operation.new(Issuance::Input.new(env)).execute)
  end

  def failure(frame, status: nil)
    assert_equal({ "status" => status, "bodyBase64" => nil, "failure" => Read::PRIVATE_FAILURE }, frame.fetch("response"))
    refute_match(/PRIVATE_PROVIDER_DETAIL|SYNTHETIC_NOT_A_JWT|INERT_PRIVATE/, JSON.generate(frame))
    refute frame.key?("settled")
  end

  def test_fixed_post_has_only_public_csr_and_distribution_no_profile_or_revoke
    FAKE.status = 201
    FAKE.body = '{"data":{"type":"certificates","id":"created-fixture"}}'
    input = Issuance::Input.new(environment)
    operation = Issuance::Operation.new(input)
    frame = JSON.parse(operation.execute)
    assert input.ack_consumed?
    assert_equal 1, FAKE.wire.length
    wire = FAKE.wire.fetch(0)
    assert_equal :post, wire[:method]
    assert_equal "/v1/certificates", wire[:url].path
    assert_equal input.request.fetch("body").to_json, wire[:body]
    data = JSON.parse(wire[:body]).fetch("data")
    assert_equal %w[attributes type], data.keys.sort
    assert_equal({ "certificateType" => "DISTRIBUTION", "csrContent" => CSR }, data.fetch("attributes"))
    assert_equal Issuance::SCOPE, frame.fetch("scope")
    assert_equal "d" * 64, frame.fetch("keySavedAckSha256")
    assert_equal "c" * 64, frame.fetch("ackSha256")
    assert_equal input.request_sha256, frame.fetch("requestSha256")
    assert_equal FAKE.body, Base64.strict_decode64(frame.fetch("response").fetch("bodyBase64"))
    refute frame.key?("settled")
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
    assert_equal 1, FAKE.loads
    assert_empty FAKE.last_client.logs
    assert_empty FAKE.last_client.retry_entries
  end

  def test_three_fixed_inventory_gets_preserve_cursor_and_never_consume_write_ack
    Issuance::LISTS.each do |step|
      FAKE.reset
      input = Issuance::Input.new(environment(step).merge(PREFIX + "CURSOR" => "synthetic+/cursor=2"))
      frame = JSON.parse(Issuance::Operation.new(input).execute)
      assert_equal 1, FAKE.wire.length
      wire = FAKE.wire.fetch(0)
      assert_equal :get, wire[:method]
      assert_equal input.request.fetch("path"), wire[:url].path
      assert_equal input.request.fetch("query"), URI.decode_www_form(wire[:url].query).to_h
      assert_nil frame["ackSha256"]
      assert_nil frame["keySavedAckSha256"]
      refute input.ack_consumed?
      assert_equal FAKE.body, Base64.strict_decode64(frame["response"]["bodyBase64"])
    end
  end

  def test_missing_either_ack_wrong_csr_or_other_role_refuses_before_sdk_loading
    changes = [->(e) { e.delete(PREFIX + "KEY_SAVED_ACK_SHA256") }, ->(e) { e.delete(PREFIX + "ACK_SHA256") },
      ->(e) { e[PREFIX + "KEY_SAVED_ACK_SHA256"] = "not-an-ack" }, ->(e) { e[PREFIX + "PLAN_SHA256"] = "A" * 64 },
      ->(e) { e[PREFIX + "STEP"] = "revoke" }, ->(e) { e[PREFIX + "STEP"] = "create_profile" },
      ->(e) { e[PREFIX + "URL"] = "https://foreign.invalid/" }, ->(e) { e[PREFIX + "CURSOR"] = "extra" },
      ->(e) { e[PREFIX + "CSR_BASE64"] = "!!!!" },
      ->(e) { e[PREFIX + "CSR_BASE64"] = Base64.strict_encode64("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n") },
      ->(e) { e[PREFIX + "CSR_BASE64"] = Base64.strict_encode64("x" * (Issuance::CSR_LIMIT + 1)) },
      ->(e) { e["MOBILE_RELEASE_ASC_SIGNING_STEP"] = "create_profile" },
      ->(e) { e["MOBILE_RELEASE_ASC_PROVISIONING_STEP"] = "register" }]
    changes.each do |change|
      env = environment; change.call(env)
      assert_raises(Issuance::Error) { Issuance::Input.new(env) }
    end
    env = environment("list_certificates"); env[PREFIX + "KEY_SAVED_ACK_SHA256"] = "d" * 64
    assert_raises(Issuance::Error) { Issuance::Input.new(env) }
    assert_empty FAKE.wire
    assert_equal 0, FAKE.loads
  end

  def test_failed_foreign_ack_burns_one_claim_and_real_base_read_owner_cannot_write
    input = Issuance::Input.new(environment)
    assert_raises(Issuance::Error) { input.consume_ack!(input.context, "foreign", input.plan_sha256, input.request_sha256) }
    assert_raises(Issuance::Error) { input.consume_ack!(input.context, input.operation_id, input.plan_sha256, input.request_sha256) }
    refute input.ack_consumed?
    failure(JSON.parse(Issuance::Operation.new(input).execute))
    assert_empty FAKE.wire
    FAKE.reset
    input = Issuance::Input.new(environment)
    token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Read::ReadOwner.new(input, token, client)
    adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: input.context)
    assert_raises(Provisioning::Error) { adapter.exchange(input.request, approval: input.approval) }
    refute input.ack_consumed?
    assert_empty FAKE.wire
  end

  def test_ambient_proxy_account_debug_and_later_refresh_refuse_without_wire
    %w[SPACESHIP_KEY FASTLANE_USER HTTPS_PROXY http_proxy DEBUG].each do |name|
      assert_raises(Issuance::Error) { Issuance::Input.new(environment.merge(name => "PRIVATE")) }
    end
    FAKE.before_wire = ->(_) { FAKE.expired = true }
    failure(execute)
    assert_empty FAKE.wire
    assert_equal 1, FAKE.refreshes # Initial fake Token.create only, no refresh retry.
  end

  def test_same_token_owner_origin_tls_headers_and_thread_are_checked
    changes = [->(c) { c.hostname = "https://foreign.invalid/" }, ->(c) { c.token.in_house = true },
      ->(c) { c.additional_headers["X-Private"] = "PRIVATE" }, ->(c) { c.csrf_tokens["cookie"] = "PRIVATE" },
      ->(c) { c.client.proxy = "http://foreign.invalid" }, ->(c) { c.client.ssl[:verify] = false }]
    changes.each do |change|
      FAKE.reset; FAKE.construct = change
      failure(execute)
      assert_empty FAKE.wire
    end
    FAKE.reset
    input = Issuance::Input.new(environment)
    token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Issuance::Owner.new(input, token, client)
    owner.admit_client!(client, input.context)
    # A joined inert Ruby thread only checks the owner; it makes no HTTP call.
    result = Thread.new { begin owner.check!(input.context); false; rescue Read::Error; true; end }.value
    assert result
    assert_empty FAKE.wire
  end

  def test_exact_post_method_origin_query_and_public_csr_bytes_cannot_change
    changes = [->(e) { e[:url].host = "foreign.invalid" }, ->(e) { e[:url].path = "/v1/profiles" },
      ->(e) { e[:method] = :delete }, ->(e) { e[:url].query = "extra=1" },
      ->(e) { e[:body] = e[:body].sub("DISTRIBUTION", "IOS_DEVELOPMENT") },
      ->(e) { e[:body] = e[:body].sub("bm90", "c2Ft") }, ->(e) { e[:body] = JSON.parse(e[:body]) }]
    changes.each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute)
      assert_empty FAKE.wire
    end
  end

  def test_raw_duplicate_members_survive_and_missing_or_multiple_callback_is_unconfirmed
    FAKE.body = '{"data":{"lost":"PRIVATE"},"data":[]}'
    frame = execute(environment("list_certificates"))
    assert_equal [], FAKE.normalized["data"]
    assert_equal FAKE.body, Base64.strict_decode64(frame["response"]["bodyBase64"])
    [0, 2].each do |count|
      FAKE.reset; FAKE.callback_count = count
      failure(execute)
      assert_equal 1, FAKE.wire.length
    end
    FAKE.reset; FAKE.status = 201; FAKE.response_status = 200
    failure(execute)
    assert_equal 1, FAKE.wire.length
    FAKE.reset; FAKE.body = " " * (Issuance::RAW_LIMIT + 1)
    failure(execute)
    assert_equal 1, FAKE.wire.length
  end

  def test_rejections_rate_limit_timeout_and_second_call_never_retry_or_log
    [400, 401, 403, 409, 422, 429, 500].each do |status|
      FAKE.reset; FAKE.status = status
      operation = Issuance::Operation.new(Issuance::Input.new(environment))
      failure(JSON.parse(operation.execute), status: status)
      failure(JSON.parse(operation.execute))
      assert_equal 1, FAKE.wire.length
      assert_equal 1, FAKE.loads
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
    FAKE.reset; FAKE.transport_error = IOError.new("PRIVATE_PROVIDER_DETAIL")
    operation = Issuance::Operation.new(Issuance::Input.new(environment))
    failure(JSON.parse(operation.execute))
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
  end

  def test_fixed_main_redacts_errors_and_fatal_interruption_never_repeats
    output = StringIO.new
    assert_equal 70, Issuance.main(["--csr", "PRIVATE"], environment, output)
    assert_empty output.string
    assert_equal 0, Issuance.main([], environment, output)
    assert_operator output.string.bytesize, :<=, Issuance::FRAME_LIMIT
    refute_match(/INERT_PRIVATE|SYNTHETIC_NOT_A_JWT/, output.string)
    FAKE.reset; FAKE.transport_error = Interrupt.new("PRIVATE_PROVIDER_DETAIL")
    operation = Issuance::Operation.new(Issuance::Input.new(environment))
    assert_raises(Interrupt) { operation.execute }
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
  end
end
