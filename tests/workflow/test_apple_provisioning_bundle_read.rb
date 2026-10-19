# frozen_string_literal: true

# Synthetic SDK/HTTP DATA only. No gem load, token cryptography, sockets,
# credentials, installed runtime or native finality is exercised here.
# Builder/response callback order mirrors locked public Faraday1.10.6.
require "minitest/autorun"
require "json"
require "uri"
require "base64"
require "stringio"
raise "Run this fake-SDK test alone" if defined?(Spaceship) || defined?(Faraday)

module BundleReadFakeSDK
  class << self
    attr_accessor :body, :status, :wire, :loads, :creates, :refreshes, :last_client,
                  :before_wire, :after_wire, :construct, :transport_error,
                  :callback_count, :response_status, :normalized, :expired
    def reset
      self.body = '{"data":[],"links":{},"meta":{"paging":{"total":0}}}'
      self.status = 200
      self.wire, self.creates = [], []
      self.loads = self.refreshes = 0
      self.before_wire = self.after_wire = self.construct = self.transport_error = self.response_status = self.normalized = nil
      self.callback_count, self.expired = 1, false
    end
  end
end

module Faraday
  class Response
    attr_reader :env
    def initialize(env) = @env = env
    def on_complete
      BundleReadFakeSDK.callback_count.times { yield @env }
      self
    end
    def status = @env[:status]
    def body = @env[:body]
  end

  module Adapter
    class NetHttp
      def initialize(*) = nil
      def call(env)
        BundleReadFakeSDK.wire << env.dup
        raise BundleReadFakeSDK.transport_error if BundleReadFakeSDK.transport_error
        env[:body], env[:status] = BundleReadFakeSDK.body.dup, BundleReadFakeSDK.status
        BundleReadFakeSDK.after_wire&.call(env)
        Response.new(env)
      end
    end
  end

  class RackBuilder
    Handler = Struct.new(:klass, :args) do
      def build(app = nil) = klass.new(app, *args)
    end
    attr_reader :handlers, :adapter
    def initialize
      @handlers, @adapter = [], Handler.new(Adapter::NetHttp, [])
    end
    def locked? = @handlers.frozen?
    def use(klass, *args)
      raise "locked builder" if locked?
      @handlers << Handler.new(klass, args)
    end
    def app
      @app ||= begin
        @handlers.freeze
        @handlers.reverse.inject(@adapter.build) { |app, handler| handler.build(app) }
      end
    end
  end

  class Connection
    attr_reader :builder, :ssl
    attr_accessor :proxy
    def initialize(token)
      @builder, @ssl, @proxy = RackBuilder.new, { verify: true }, nil
      @builder.use(ParseJson)
      @builder.use(RefreshToken, token)
    end
  end

  class ParseJson
    def initialize(app) = @app = app
    def call(env)
      @app.call(env).on_complete do |response|
        response[:body] = JSON.parse(response[:body])
        BundleReadFakeSDK.normalized = response[:body]
      end
    end
  end

  class RefreshToken
    def initialize(app, token) = (@app, @token = app, token)
    def call(env)
      @token.refresh! if @token.expired?
      env[:request_headers]["Authorization"] = "Bearer #{@token.text}"
      @app.call(env)
    end
  end
end

module Spaceship
  class ConnectAPI
    class Token
      attr_reader :key_id, :issuer_id, :key_raw, :text
      attr_accessor :in_house
      def self.create(**options)
        BundleReadFakeSDK.creates << options
        new(**options)
      end
      def initialize(key_id:, issuer_id:, key:, duration:, in_house:)
        raise "not explicit" unless duration == 1200
        @key_id, @issuer_id, @key_raw, @in_house = key_id, issuer_id, key, in_house
        refresh!
      end
      def refresh!
        BundleReadFakeSDK.refreshes += 1
        @text = "SYNTHETIC_NOT_A_JWT"
      end
      def expired? = BundleReadFakeSDK.expired
    end

    class APIClient
      Request = Struct.new(:path, :params, :body)
      Response = Struct.new(:status, :body)
      attr_accessor :token, :hostname, :csrf_tokens, :additional_headers
      attr_reader :client, :logs, :retry_entries
      def initialize(token:)
        @token, @hostname = token, "https://api.appstoreconnect.apple.com/"
        @csrf_tokens, @additional_headers = {}, {}
        @logs, @retry_entries = [], []
        @client = Faraday::Connection.new(token)
        BundleReadFakeSDK.last_client = self
        BundleReadFakeSDK.construct&.call(self)
      end
      def web_session? = @token.nil?
      def get(path, params = nil)
        response = with_asc_retry { request(:get) { |req| req.path, req.params = path, params } }
        raise "PRIVATE_PROVIDER_DETAIL" unless response.status.between?(200, 299)
        Response.new(BundleReadFakeSDK.response_status || response.status, response.body)
      end
      def post(path, body, tries: 5)
        with_asc_retry(tries) { request(:post) { |req| req.path, req.body = path, JSON.generate(body) } }
      end
      def request(method, _path = nil, _params = nil, _headers = {}, _auto = false)
        with_retry do
          req = Request.new; yield req
          env = { method: method, url: URI.join(hostname, req.path + "?" + URI.encode_www_form(req.params || {})),
                  body: req.body, request_headers: {} }
          BundleReadFakeSDK.before_wire&.call(env)
          log_request(method, req.path, req.body)
          response = @client.builder.app.call(env)
          log_response(method, req.path, response)
          response
        end
      end
      def with_retry(*)
        @retry_entries << :transport
        yield
      end
      def with_asc_retry(*)
        @retry_entries << :asc
        yield
      end
      def log_request(*) = @logs << "PRIVATE_REQUEST"
      def log_response(*) = @logs << "PRIVATE_RESPONSE"
    end
  end
end

require_relative "../../fastlane/apple_provisioning_bundle_read"
module MobileReleaseKit::AppleBundleRead
  # The test replaces only loading with fake classes above, never evaluates SDK.
  def self.load_sdk! = BundleReadFakeSDK.loads += 1
end

class AppleBundleReadTest < Minitest::Test
  Read = MobileReleaseKit::AppleBundleRead
  Provisioning = MobileReleaseKit::AppleProvisioning
  FAKE = BundleReadFakeSDK
  KEY = "INERT_PRIVATE_P8_NOT_CRYPTOGRAPHIC".freeze
  def setup = FAKE.reset
  def environment
    { "SPACESHIP_TIMEOUT" => "30", "MOBILE_RELEASE_ASC_BUNDLE_ID" => "com.example.reader",
      "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT" => "a" * 64, "MOBILE_RELEASE_ASC_KEY_ID" => "ABCDEFGHIJ",
      "MOBILE_RELEASE_ASC_ISSUER_ID" => "12345678-1234-1234-1234-123456789abc",
      "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64" => Base64.strict_encode64(KEY) }.merge(Read::SAFE_FASTLANE.to_h { |key| [key, "true"] })
  end
  def execute = JSON.parse(Read::Operation.new(Read::Input.new(environment)).execute)
  def failure(value)
    assert_equal({ "status" => nil, "bodyBase64" => nil, "failure" => Read::PRIVATE_FAILURE }, value.fetch("response"))
    refute_match(/PRIVATE_PROVIDER_DETAIL|SYNTHETIC_NOT_A_JWT|INERT_PRIVATE/, JSON.generate(value))
  end

  def test_exact_supported_construction_one_get_and_original_raw_response
    value = execute
    assert_equal 1, FAKE.loads
    assert_equal 1, FAKE.refreshes
    assert_equal 1, FAKE.creates.length
    assert_equal %i[duration in_house issuer_id key key_id], FAKE.creates[0].keys.sort
    assert_equal false, FAKE.creates[0][:in_house]
    assert_equal KEY, FAKE.creates[0][:key]
    assert_equal 1, FAKE.wire.length
    assert_equal :get, FAKE.wire[0][:method]
    assert_equal "/v1/bundleIds", FAKE.wire[0][:url].path
    assert_equal FAKE.body, Base64.strict_decode64(value["response"]["bodyBase64"])
    assert_nil value["response"]["failure"]
    assert_empty FAKE.last_client.logs
    assert_empty FAKE.last_client.retry_entries
    assert_equal "a" * 64, value["contextSha256"]
    assert_equal "com.example.reader", value["bundleId"]
    refute value.key?("settled")
  end

  def test_raw_callback_precedes_sdk_duplicate_key_collapse
    FAKE.body = '{"data":[{"doNotLose":"earlier"}],"data":[],"links":{},"meta":{"paging":{"total":0}}}'
    value = execute
    assert_equal [], FAKE.normalized["data"] # SDK normalization really occurred.
    assert_equal FAKE.body, Base64.strict_decode64(value["response"]["bodyBase64"])
    assert_equal 2, Base64.strict_decode64(value["response"]["bodyBase64"]).scan('"data"').length
  end

  def test_missing_repeated_oversized_and_non_json_capture_is_not_a_response
    [0, 2].each do |count|
      FAKE.reset; FAKE.callback_count = count
      failure(execute)
      assert_equal 1, FAKE.wire.length
    end
    ["x" * (Read::RAW_LIMIT + 1), "not JSON", ""].each do |body|
      FAKE.reset; FAKE.body = body
      failure(execute)
      assert_equal 1, FAKE.wire.length
    end
  end

  def test_adapter_response_must_be_same_captured_status
    FAKE.response_status = 201
    failure(execute)
    assert_equal 1, FAKE.wire.length
  end

  def test_denied_rate_limited_server_and_transport_errors_never_retry_or_log
    [401, 403, 429, 500, 503].each do |status|
      FAKE.reset; FAKE.status = status; FAKE.body = '{"errors":[{"detail":"PRIVATE_PROVIDER_DETAIL"}]}'
      value = execute
      assert_equal status, value["response"]["status"]
      assert_nil value["response"]["bodyBase64"]
      assert_equal Read::PRIVATE_FAILURE, value["response"]["failure"]
      assert_equal 1, FAKE.wire.length
      assert_empty FAKE.last_client.logs
      assert_empty FAKE.last_client.retry_entries
      assert_equal 1, FAKE.refreshes
    end
    FAKE.reset; FAKE.transport_error = RuntimeError.new("PRIVATE_PROVIDER_DETAIL")
    failure(execute)
    assert_equal 1, FAKE.wire.length
  end

  def test_ambient_sdk_credentials_proxy_or_debug_are_refused_before_sdk_load
    %w[SPACESHIP_CONNECT_API_KEY SPACESHIP_CONNECT_API_IN_HOUSE SPACESHIP_SESSION SPACESHIP_PROXY FASTLANE_SESSION FASTLANE_USER DEBUG VERBOSE HTTPS_PROXY https_proxy ALL_PROXY].each do |name|
      assert_raises(Read::Error) { Read::Input.new(environment.merge(name => "PRIVATE")) }
    end
    assert_equal 0, FAKE.loads
    assert_empty FAKE.creates
    assert_empty FAKE.wire
    assert_equal 70, Read.main(["--arbitrary"], environment, StringIO.new)
  end

  def test_selected_private_input_is_bounded_explicit_and_redacted
    ["MOBILE_RELEASE_ASC_BUNDLE_ID", "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT", "MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"].each do |name|
      [nil, "", "\0", "é"].each do |value|
        error = assert_raises(Read::Error) { Read::Input.new(environment.merge(name => value)) }
        refute_match(/PRIVATE|é/, error.message)
        assert_nil error.cause
      end
    end
    assert_raises(Read::Error) { Read::Input.new(environment.merge("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64" => Base64.strict_encode64("x" * (16 * 1024 + 1)))) }
    input = Read::Input.new(environment)
    refute_includes input.inspect, KEY
    refute_includes Read::Operation.new(input).inspect, KEY
  end

  def test_same_operation_cannot_reenter_even_after_known_failure
    FAKE.transport_error = RuntimeError.new("PRIVATE_PROVIDER_DETAIL")
    operation = Read::Operation.new(Read::Input.new(environment))
    failure(JSON.parse(operation.execute))
    failure(JSON.parse(operation.execute))
    assert_equal 1, FAKE.loads
    assert_equal 1, FAKE.creates.length
    assert_equal 1, FAKE.wire.length
  end

  def test_new_token_cannot_refresh_or_silently_choose_enterprise
    input = Read::Input.new(environment)
    token = input.token
    assert_raises(Read::Error) { token.refresh! }
    assert_equal 1, FAKE.refreshes
    FAKE.reset; FAKE.expired = true
    failure(execute)
    assert_empty FAKE.wire
    FAKE.reset; FAKE.construct = ->(client) { client.token.in_house = true }
    failure(execute)
    assert_empty FAKE.wire
  end

  def test_origin_tls_path_method_and_query_are_checked_before_wire
    mutations = [->(c) { c.hostname = "https://other.invalid/" }, ->(c) { c.client.proxy = "https://other.invalid" },
                 ->(c) { c.client.ssl[:verify] = false }, ->(c) { c.client.ssl[:verify_mode] = 0 },
                 ->(c) { c.csrf_tokens["cookie"] = "PRIVATE" }, ->(c) { c.additional_headers["Other"] = "PRIVATE" }]
    mutations.each do |change|
      FAKE.reset; FAKE.construct = change
      failure(execute); assert_empty FAKE.wire
    end
    [->(env) { env[:url] = URI("http://api.appstoreconnect.apple.com/v1/bundleIds") },
     ->(env) { env[:url].path = "/v1/certificates" }, ->(env) { env[:method] = :post },
     ->(env) { env[:url].query += "&cursor=next" }, ->(env) { env[:body] = "PRIVATE" }].each do |change|
      FAKE.reset; FAKE.before_wire = change
      failure(execute); assert_empty FAKE.wire
    end
  end

  def test_token_change_or_expiry_after_send_vetoes_result
    [->(_env) { FAKE.expired = true }, ->(_env) { FAKE.last_client.token = Object.new }].each do |change|
      FAKE.reset; FAKE.after_wire = change
      failure(execute)
      assert_equal 1, FAKE.wire.length
      assert_equal 1, FAKE.refreshes
    end
  end

  def test_same_read_owner_refuses_every_write_even_with_shaped_approval
    input = Read::Input.new(environment); token = input.token
    client = Spaceship::ConnectAPI::APIClient.new(token: token)
    owner = Read::ReadOwner.new(input, token, client)
    adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: input.context)
    request = { "kind" => "register_bundle_id", "method" => "POST", "path" => "/v1/bundleIds", "query" => {},
                "body" => { "data" => { "type" => "bundleIds", "attributes" => { "identifier" => input.bundle_id, "name" => "Synthetic", "platform" => "IOS" } } } }
    assert_raises(Provisioning::Error) { adapter.exchange(request, approval: { "operationId" => "synthetic", "planSha256" => "b" * 64 }) }
    assert_empty FAKE.wire
    refute_includes owner.inspect, KEY
  end

  def test_main_only_bounded_private_frame_and_no_exception_details
    output = StringIO.new
    assert_equal 0, Read.main([], environment, output)
    assert_operator output.string.bytesize, :<=, Read::FRAME_LIMIT
    assert_equal %w[bundleId contextSha256 response schemaVersion], JSON.parse(output.string).keys.sort
    refute_match(/INERT_PRIVATE|SYNTHETIC_NOT_A_JWT/, output.string)
    output = StringIO.new
    assert_equal 70, Read.main([], environment.merge("DEBUG" => "1"), output)
    assert_empty output.string
  end
end
