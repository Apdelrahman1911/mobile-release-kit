# frozen_string_literal: true

# Reuse the actual existing fake SDK/callback model AND rerun its old assertions
# because this slice narrowly extends the shared owner. No real gems/crypto,
# HTTP, keys, account or native processes are loaded by either test suite.
require_relative "test_apple_provisioning_bundle_read"
require_relative "../../fastlane/apple_provisioning_profile_read"

class AppleProfileReadTest < Minitest::Test
  Read = MobileReleaseKit::AppleBundleRead
  Profile = MobileReleaseKit::AppleProfileRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK

  def setup = FAKE.reset
  def environment
    { "SPACESHIP_TIMEOUT" => "30", "MOBILE_RELEASE_ASC_BUNDLE_ID" => "com.example.reader",
      "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT" => "a" * 64, "MOBILE_RELEASE_ASC_KEY_ID" => "ABCDEFGHIJ",
      "MOBILE_RELEASE_ASC_ISSUER_ID" => "12345678-1234-1234-1234-123456789abc",
      "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64" => Base64.strict_encode64(AppleBundleReadTest::KEY) }
      .merge(Read::SAFE_FASTLANE.to_h { |key| [key, "true"] })
  end

  def execute = JSON.parse(Read::Operation.new(Profile::Input.new(environment)).execute)
  def failure(value)
    assert_equal Read::PRIVATE_FAILURE, value.fetch("response").fetch("failure")
    assert_nil value["response"]["bodyBase64"]
    refute_match(/PRIVATE_PROVIDER_DETAIL|SYNTHETIC_NOT_A_JWT|INERT_PRIVATE/, JSON.generate(value))
  end

  def test_exact_one_supported_profile_get_no_content_downloads_or_bundle_filter
    FAKE.body = '{"data":[],"included":[],"links":{},"meta":{"paging":{"total":0}}}'
    value = execute
    assert_equal 1, FAKE.wire.length
    assert_equal :get, FAKE.wire[0][:method]
    assert_equal "/v1/profiles", FAKE.wire[0][:url].path
    assert_nil FAKE.wire[0][:body]
    query = URI.decode_www_form(FAKE.wire[0][:url].query).to_h
    assert_equal Profile::Input.new(environment).request["query"], query
    refute query.key?("filter[bundleId]")
    refute_match(/Content|cursor/, JSON.generate(query))
    assert_equal "IOS_APP_STORE", query["filter[profileType]"]
    assert_equal "bundleId,certificates", query["include"]
    assert_equal FAKE.body, Base64.strict_decode64(value["response"]["bodyBase64"])
    assert_equal "a" * 64, value["contextSha256"]
    assert_equal "com.example.reader", value["bundleId"]
    assert_equal 1, FAKE.loads
    assert_equal 1, FAKE.creates.length
    assert_equal 1, FAKE.refreshes
    assert_empty FAKE.last_client.retry_entries
    assert_empty FAKE.last_client.logs
    refute value.key?("settled")
  end

  def test_raw_profile_member_duplicates_survive_sdk_collapse_for_python_validation
    FAKE.body = '{"data":[{"mustNotDisappear":1}],"data":[],"included":[],"links":{},"meta":{"paging":{"total":0}}}'
    value = execute
    assert_equal [], FAKE.normalized["data"]
    assert_equal FAKE.body, Base64.strict_decode64(value["response"]["bodyBase64"])
    assert_equal 1, FAKE.wire.length
  end

  def test_wrong_path_fields_pagination_and_writes_refuse_before_any_wire_effect
    [->(env) { env[:url].path = "/v1/profiles/not-authorized" },
     ->(env) { env[:url].path = "/v1/certificates" },
     ->(env) { env[:url].query += "&cursor=next" },
     ->(env) { env[:url].query += "&fields%5Bprofiles%5D=profileContent" },
     ->(env) { env[:url].query += "&filter%5BbundleId%5D=invented" },
     ->(env) { env[:method] = :post }, ->(env) { env[:body] = "PRIVATE" }].each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute); assert_empty FAKE.wire
    end
  end

  def test_only_two_exact_input_classes_are_allowed_not_subclasses_or_generic_factories
    [Class.new(Read::Input), Class.new(Profile::Input)].each do |klass|
      assert_raises(Read::Error) { Read::Operation.new(klass.new(environment)) }
    end
    output = StringIO.new
    assert_equal 70, Read.main([], environment, output, query: :download_profile)
    assert_empty output.string
    assert_equal 0, FAKE.loads
    assert_empty FAKE.creates
    assert_empty FAKE.wire
  end

  def test_expiry_or_mutated_token_vetoes_profile_data_without_refresh
    [->(_env) { FAKE.expired = true }, ->(_env) { FAKE.last_client.token = Object.new }].each do |change|
      FAKE.reset; FAKE.after_wire = change
      failure(execute)
      assert_equal 1, FAKE.wire.length
      assert_equal 1, FAKE.refreshes
    end
  end

  def test_denied_and_unknown_profile_reads_do_not_retry_or_log
    [401, 403, 429, 503].each do |status|
      FAKE.reset; FAKE.status = status; FAKE.body = '{"errors":[{"detail":"PRIVATE_PROVIDER_DETAIL"}]}'
      result = execute; failure(result)
      assert_equal status, result["response"]["status"]
      assert_equal 1, FAKE.wire.length
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
    end
    FAKE.reset; FAKE.transport_error = RuntimeError.new("PRIVATE_PROVIDER_DETAIL")
    operation = Read::Operation.new(Profile::Input.new(environment))
    failure(JSON.parse(operation.execute)); failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.wire.length
    assert_equal 1, FAKE.loads
  end

  def test_same_profile_read_owner_has_no_mutation_permission
    input = Profile::Input.new(environment); token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Read::ReadOwner.new(input, token, client)
    adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: input.context)
    write = { "kind" => "register_bundle_id", "method" => "POST", "path" => "/v1/bundleIds", "query" => {},
      "body" => { "data" => { "type" => "bundleIds", "attributes" => { "identifier" => input.bundle_id,
        "name" => "Synthetic", "platform" => "IOS" } } } }
    assert_raises(Provisioning::Error) { adapter.exchange(write, approval: { "operationId" => "synthetic", "planSha256" => "b" * 64 }) }
    assert_empty FAKE.wire
  end

  def test_fixed_profile_entry_refuses_arguments_ambient_state_and_unbounded_capture
    output = StringIO.new
    assert_equal 70, Profile.main(["--profile-id", "private"], environment, output)
    assert_equal 70, Profile.main([], environment.merge("SPACESHIP_SESSION" => "PRIVATE"), output)
    assert_empty output.string
    assert_equal 0, FAKE.loads
    FAKE.body = " " * (Read::RAW_LIMIT + 1)
    failure(execute)
    assert_equal 1, FAKE.wire.length
    FAKE.reset; output = StringIO.new
    assert_equal 0, Profile.main([], environment, output)
    assert_operator output.string.bytesize, :<=, Read::FRAME_LIMIT
    refute_match(/INERT_PRIVATE|SYNTHETIC_NOT_A_JWT/, output.string)
  end
end
