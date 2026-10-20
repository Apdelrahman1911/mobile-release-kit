# frozen_string_literal: true

# Reuse the original inert Faraday/Spaceship ABI fixture. No gems, sockets,
# credentials, cryptography, real processes or provider calls are loaded.
require_relative "test_apple_provisioning_bundle_read"
require_relative "../../fastlane/apple_store_versions"

class AppleStoreVersionsTest < Minitest::Test
  Read = MobileReleaseKit::AppleStoreVersions
  Original = MobileReleaseKit::AppleBundleRead
  FAKE = BundleReadFakeSDK
  APP = "1234567890"

  def setup
    FAKE.reset
    @pages = {}
    @app = { "data" => { "type" => "apps", "id" => APP, "attributes" => { "bundleId" => "com.example.reader" } } }
    FAKE.before_wire = lambda do |env|
      key = [env[:url].path, URI.decode_www_form(env[:url].query).to_h["cursor"]]
      body = @pages.fetch(key) { env[:url].path == "/v1/apps/#{APP}" ? @app : collection }
      FAKE.body = body.instance_of?(String) ? body : JSON.generate(body)
    end
  end

  def environment
    AppleBundleReadTest.new(:unused).environment.merge("MOBILE_RELEASE_ASC_APP_ID" => APP)
  end

  def collection(total = 0, data: [], following: nil)
    { "data" => data, "links" => { "next" => following }, "meta" => { "paging" => { "total" => total, "limit" => 200 } } }
  end

  def operation = Read::Operation.new(Read::Input.new(environment))
  def execute = JSON.parse(operation.execute)

  def test_original_raw_owner_fixed_five_gets_one_token_no_retries_or_mutations
    value = execute
    assert_equal %w[app-before builds buildUploads appStoreVersions app-after], value["pages"].map { |p| p["step"] }
    assert_equal 5, FAKE.wire.size
    assert_equal 1, FAKE.loads
    assert_equal 1, FAKE.creates.size
    assert_equal 1, FAKE.refreshes
    assert FAKE.wire.all? { |env| env[:method] == :get && env[:body].nil? }
    assert_empty FAKE.last_client.logs
    assert_empty FAKE.last_client.retry_entries
    assert_equal Read::SCOPE, value["scope"]
    assert_equal APP, value["appStoreAppId"]
    assert_equal true, value["queryFinished"]
    value["pages"].each { |p| assert_equal 200, p["response"]["status"]; assert_nil p["response"]["failure"] }
    refute_match(/SYNTHETIC_NOT_A_JWT|INERT_PRIVATE_P8/, JSON.generate(value))
  end

  def test_two_pages_per_collection_at_most_eight_attempts_exact_cursor
    input = Read::Input.new(environment)
    Read::COLLECTIONS.each do |step|
      req = input.request_for(step, cursor: "second")
      link = "https://api.appstoreconnect.apple.com#{req['path']}?#{URI.encode_www_form(req['query'])}"
      @pages[[req["path"], nil]] = collection(2, data: [{ "id" => "one" }], following: link)
      @pages[[req["path"], "second"]] = collection(2, data: [{ "id" => "two" }])
    end
    value = execute
    assert_equal 8, FAKE.wire.size
    assert_equal 8, value["pages"].size
    assert_equal "app-after", value["pages"].last["step"]
    assert_equal 3, FAKE.wire.count { |env| URI.decode_www_form(env[:url].query).to_h["cursor"] == "second" }
  end

  def test_third_page_wrong_origin_or_changed_query_never_gets_an_extra_request
    input = Read::Input.new(environment)
    ["https://other.invalid/v1/builds?cursor=x", "https://api.appstoreconnect.apple.com/v1/builds?cursor=x",
     "https://api.appstoreconnect.apple.com/v1/builds?cursor=x&cursor=y"].each do |link|
      setup
      @pages[["/v1/builds", nil]] = collection(2, data: [{ "id" => "one" }], following: link)
      value = execute
      assert_equal 2, FAKE.wire.size
      assert_equal 2, value["pages"].size
    end
    setup
    %w[second third].each_with_index do |cursor, index|
      req = input.request_for("builds", cursor: cursor)
      link = "https://api.appstoreconnect.apple.com/v1/builds?#{URI.encode_www_form(req['query'])}"
      @pages[["/v1/builds", index.zero? ? nil : "second"]] = collection(3, data: [{ "id" => index.to_s }], following: link)
    end
    assert_equal 3, execute["pages"].size
    assert_equal 3, FAKE.wire.size
  end

  def test_duplicate_raw_members_wrong_app_and_raw_limit_fail_before_further_get
    @pages[["/v1/apps/#{APP}", nil]] = '{"data":{},"data":{}}'
    assert_equal 1, execute["pages"].size
    assert_equal 1, FAKE.wire.size
    setup
    @app["data"]["attributes"]["bundleId"] = "com.example.other"
    assert_equal 1, execute["pages"].size
    assert_equal 1, FAKE.wire.size
    setup
    @pages[["/v1/builds", nil]] = " " * (Read::RAW_LIMIT + 1)
    value = execute
    assert_equal 2, FAKE.wire.size
    assert_equal "inventory_limit", value["pages"].last["response"]["failure"]
    assert_nil value["pages"].last["response"]["bodyBase64"]
  end

  def test_failed_or_reentered_attempt_cannot_repeat_and_no_token_refresh
    original = operation
    original.execute
    assert_raises(Original::Error) { original.execute }
    assert_equal 5, FAKE.wire.size
    setup
    FAKE.transport_error = RuntimeError.new("INERT_NETWORK_ERROR")
    value = execute
    assert_equal 1, FAKE.wire.size
    assert_equal Original::PRIVATE_FAILURE, value["pages"].last["response"]["failure"]
    setup
    FAKE.after_wire = ->(_env) { FAKE.expired = true }
    value = execute
    assert_operator value["pages"].size, :<=, 1
    assert_equal 1, FAKE.wire.size
    assert_equal 1, FAKE.refreshes
  end

  def test_final_original_check_failure_cannot_promote_complete_looking_pages
    original = Read::ReadOwner.instance_method(:complete!)
    Read::ReadOwner.send(:define_method, :complete!) { raise Original::Error }
    begin
      value = execute
      assert_equal 5, FAKE.wire.size
      assert_equal "app-after", value["pages"].last["step"]
      assert_equal false, value["queryFinished"]
    ensure
      Read::ReadOwner.send(:define_method, :complete!, original)
    end
  end

  def test_no_public_input_can_select_endpoint_or_ambient_identity
    [environment.merge("MOBILE_RELEASE_ASC_APP_ID" => "../apps"),
     environment.merge("HTTPS_PROXY" => "https://other.invalid"),
     environment.merge("SPACESHIP_CONNECT_API_TOKEN" => "INERT")].each do |env|
      assert_raises(Original::Error) { Read::Input.new(env) }
    end
    assert_empty FAKE.creates
    assert_equal 0, FAKE.loads
    input = Read::Input.new(environment)
    assert_raises(Original::Error) { input.request_for("create-build") }
    assert_raises(Original::Error) { input.request_for("app-before", cursor: "x") }
    wire = input.request_for("builds")
    wire["query"]["filter[expired]"] = "false"
    assert_raises(MobileReleaseKit::AppleProvisioning::Error) { MobileReleaseKit::AppleProvisioning::Request.new(wire) }
  end
end
