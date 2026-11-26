# frozen_string_literal: true

# Reuse the existing tiny fake SDK/callback order, not gems/HTTP/native owners.
# Run this file with --name /AppleBundleRegistrationTest/ to select only the
# new tests; requiring the read fixture does not execute any provider command.
require_relative "test_apple_provisioning_bundle_read"
require_relative "../../fastlane/apple_provisioning_bundle_registration"

# This fake's POST models APIClient's same response/error dispatch as GET.
# Neither method opens a socket or loads/evaluates the real SDK.
class Spaceship::ConnectAPI::APIClient
  def post(path, body, tries: 5)
    response = with_asc_retry(tries) { request(:post) { |req| req.path, req.body = path, body.to_json } }
    raise "PRIVATE_PROVIDER_DETAIL" unless response.status.between?(200, 299)
    Response.new(BundleReadFakeSDK.response_status || response.status, response.body)
  end
end

class AppleBundleRegistrationTest < Minitest::Test
  Registration = MobileReleaseKit::AppleBundleRegistration
  Read = MobileReleaseKit::AppleBundleRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK
  PREFIX = Registration::PREFIX

  def setup = FAKE.reset

  def environment(step = "register")
    value = AppleBundleReadTest.new("fixture_only").environment.merge(
      PREFIX + "STEP" => step, PREFIX + "OPERATION_ID" => "synthetic-operation")
    if step == "register"
      value.merge!(PREFIX + "PLAN_SHA256" => "b" * 64, PREFIX + "ACK_SHA256" => "c" * 64,
                   PREFIX + "DISPLAY_NAME_BASE64" => Base64.strict_encode64("Synthetic App"))
    end
    value
  end

  def execute(env = environment)
    JSON.parse(Registration::Operation.new(Registration::Input.new(env)).execute)
  end

  def failure(value, status: nil)
    assert_equal({ "status" => status, "bodyBase64" => nil, "failure" => Registration::PRIVATE_FAILURE }, value.fetch("response"))
    refute_match(/PRIVATE_PROVIDER_DETAIL|SYNTHETIC_NOT_A_JWT|INERT_PRIVATE/, JSON.generate(value))
    refute value.key?("settled")
  end

  def test_exact_one_post_ack_binding_and_current_explicit_token_without_retry
    FAKE.status = 201
    env = environment
    env[PREFIX + "DISPLAY_NAME_BASE64"] = Base64.strict_encode64("Synthetic \u{1F34E} App")
    input = Registration::Input.new(env)
    value = JSON.parse(Registration::Operation.new(input).execute)
    assert input.ack_consumed?
    assert_equal 1, FAKE.wire.length
    sent = FAKE.wire.fetch(0)
    assert_equal :post, sent[:method]
    assert_equal "/v1/bundleIds", sent[:url].path
    assert_equal input.request.fetch("body"), JSON.parse(sent[:body])
    assert_equal "IOS", JSON.parse(sent[:body]).fetch("data").fetch("attributes").fetch("platform")
    assert_equal input.request_sha256, value.fetch("requestSha256")
    assert_equal "c" * 64, value.fetch("ackSha256")
    assert_equal "synthetic-operation", value.fetch("operationId")
    assert_equal FAKE.body, Base64.strict_decode64(value.fetch("response").fetch("bodyBase64"))
    assert_equal 1, FAKE.loads
    assert_equal 1, FAKE.refreshes
    assert_equal 1, FAKE.creates.length
    assert_equal false, FAKE.creates[0][:in_house]
    assert_empty FAKE.last_client.logs
    assert_empty FAKE.last_client.retry_entries
    refute value.key?("settled")
  end

  def test_inspection_uses_exact_one_get_and_no_write_ack
    input = Registration::Input.new(environment("inspect"))
    value = JSON.parse(Registration::Operation.new(input).execute)
    assert_equal 1, FAKE.wire.length
    assert_equal :get, FAKE.wire[0][:method]
    assert_nil value["ackSha256"]
    refute input.ack_consumed?
    assert_raises(Registration::Error) { input.consume_ack!(input.context, input.operation_id, "b" * 64, input.request_sha256) }
    # Old read operation remains a GET even if a new-worker env is handed to it.
    FAKE.reset
    JSON.parse(Read::Operation.new(Read::Input.new(environment)).execute)
    assert_equal [:get], FAKE.wire.map { |wire| wire[:method] }
  end

  def test_closed_request_inputs_refuse_before_sdk_loading
    changes = [->(e) { e.delete(PREFIX + "ACK_SHA256") }, ->(e) { e[PREFIX + "ACK_SHA256"] = "not-an-ack" },
      ->(e) { e[PREFIX + "PLAN_SHA256"] = "A" * 64 }, ->(e) { e[PREFIX + "STEP"] = "revoke" },
      ->(e) { e[PREFIX + "URL"] = "https://foreign.invalid/" }, ->(e) { e[PREFIX + "DISPLAY_NAME_BASE64"] = "!!!!" },
      ->(e) { e[PREFIX + "DISPLAY_NAME_BASE64"] = Base64.strict_encode64("x\nprivate") },
      ->(e) { e[PREFIX + "DISPLAY_NAME_BASE64"] = Base64.strict_encode64("x" * 129) },
      ->(e) { e[PREFIX + "DISPLAY_NAME_BASE64"] = Base64.strict_encode64("\xff".b) },
      ->(e) { e["MOBILE_RELEASE_ASC_BUNDLE_ID"] = "*" }]
    changes.each do |change|
      env = environment; change.call(env)
      assert_raises(Registration::Error) { Registration::Input.new(env) }
    end
    env = environment("inspect"); env[PREFIX + "ACK_SHA256"] = "c" * 64
    assert_raises(Registration::Error) { Registration::Input.new(env) }
    assert_equal 0, FAKE.loads
    assert_empty FAKE.wire
  end

  def test_ambient_account_proxy_debug_and_later_token_refresh_refuse
    %w[SPACESHIP_KEY FASTLANE_USER HTTPS_PROXY DEBUG].each do |key|
      env = environment; env[key] = "PRIVATE"
      assert_raises(Registration::Error) { Registration::Input.new(env) }
    end
    FAKE.before_wire = ->(_) { FAKE.expired = true }
    failure(execute)
    assert_equal 1, FAKE.refreshes
    assert_empty FAKE.wire
  end

  def test_exact_post_bytes_origin_and_method_are_checked_at_actual_wire_seam
    changes = [->(e) { e[:method] = :patch }, ->(e) { e[:url].path = "/v1/certificates" },
      ->(e) { e[:url].host = "foreign.invalid" }, ->(e) { e[:url].query = "extra=1" },
      ->(e) { e[:body] = e[:body].sub('"IOS"', '"MAC_OS"') },
      ->(e) { e[:body] = e[:body].sub('"Synthetic App"', '"Other App"') },
      ->(e) { e[:body] = JSON.parse(e[:body]) }]
    changes.each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute)
      assert_empty FAKE.wire
    end
  end

  def test_instance_origin_headers_token_or_tls_change_is_zero_wire
    changes = [->(c) { c.hostname = "https://foreign.invalid/" }, ->(c) { c.token.in_house = true },
      ->(c) { c.additional_headers["X-Private"] = "PRIVATE" }, ->(c) { c.csrf_tokens["cookie"] = "PRIVATE" },
      ->(c) { c.client.proxy = "http://foreign.invalid" }, ->(c) { c.client.ssl[:verify] = false }]
    changes.each do |change|
      FAKE.reset; FAKE.construct = change
      failure(execute)
      assert_empty FAKE.wire
    end
  end

  def test_raw_response_precedes_duplicate_collapse_no_normalized_substitute
    FAKE.status = 201
    FAKE.body = '{"data":{"hidden":"PRIVATE"},"data":{}}'
    value = execute
    assert_equal({}, FAKE.normalized["data"])
    assert_equal FAKE.body, Base64.strict_decode64(value["response"]["bodyBase64"])
    assert_equal 2, Base64.strict_decode64(value["response"]["bodyBase64"]).scan('"data"').length
  end

  def test_missing_duplicate_oversized_or_mismatched_capture_never_claims_result
    [0, 2].each do |count|
      FAKE.reset; FAKE.callback_count = count
      failure(execute)
      assert_equal 1, FAKE.wire.length
    end
    FAKE.reset; FAKE.body = " " * (Registration::RAW_LIMIT + 1)
    failure(execute)
    FAKE.reset; FAKE.status = 201; FAKE.response_status = 200
    failure(execute)
    assert_equal 1, FAKE.wire.length
  end

  def test_provider_denial_transport_error_and_repeat_never_retry_or_log
    [401, 403, 409, 429, 500].each do |status|
      FAKE.reset; FAKE.status = status
      operation = Registration::Operation.new(Registration::Input.new(environment))
      failure(JSON.parse(operation.execute), status: status)
      failure(JSON.parse(operation.execute))
      assert_equal 1, FAKE.wire.length
      assert_equal 1, FAKE.loads
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
    FAKE.reset; FAKE.transport_error = IOError.new("PRIVATE_PROVIDER_DETAIL")
    operation = Registration::Operation.new(Registration::Input.new(environment))
    failure(JSON.parse(operation.execute))
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
  end

  def test_wrong_ack_binding_consumes_the_single_claim_without_wire_permission
    input = Registration::Input.new(environment)
    assert_raises(Registration::Error) do
      input.consume_ack!(input.context, "other-operation", input.plan_sha256, input.request_sha256)
    end
    assert_raises(Registration::Error) do
      input.consume_ack!(input.context, input.operation_id, input.plan_sha256, input.request_sha256)
    end
    refute input.ack_consumed?
    failure(JSON.parse(Registration::Operation.new(input).execute))
    assert_empty FAKE.wire
  end

  def test_main_fixed_output_and_input_errors_do_not_emit_private_exceptions
    output = StringIO.new
    assert_equal 70, Registration.main(["--post"], environment, output)
    assert_empty output.string
    assert_equal 0, Registration.main([], environment, output)
    assert_operator output.string.bytesize, :<=, Registration::FRAME_LIMIT
    refute_match(/INERT_PRIVATE|SYNTHETIC_NOT_A_JWT/, output.string)
  end

  def test_fatal_interruption_propagates_without_second_worker_attempt
    FAKE.transport_error = Interrupt.new("PRIVATE_PROVIDER_DETAIL")
    operation = Registration::Operation.new(Registration::Input.new(environment))
    assert_raises(Interrupt) { operation.execute }
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
  end
end
