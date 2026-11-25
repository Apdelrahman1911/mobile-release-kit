# frozen_string_literal: true

# Synthetic SDK behavior only. No Fastlane load/authentication, HTTP, accounts,
# cryptographic assets or native finality. Signatures follow the pinned public
# Fastlane 2.235.0 APIClient/Client source; this is NOT locked-runtime acceptance.
require "minitest/autorun"
require "json"
raise "Run the provisioning fake-SDK test in its own process" if defined?(Spaceship::ConnectAPI::APIClient)

module Spaceship
  module ConnectAPI
    class APIClient
      Response = Struct.new(:status, :body)
      Request = Struct.new(:url, :params, :body)
      attr_accessor :hostname, :status, :response_body, :transport_error, :on_request
      attr_reader :calls, :logs, :retry_entries, :post_tries

      def initialize
        @hostname = "https://api.appstoreconnect.apple.com/"
        @status, @response_body = 201, { "data" => { "id" => "synthetic-resource" } }
        @calls, @logs, @retry_entries, @post_tries = [], [], [], []
      end

      def get(path, params = nil)
        with_asc_retry do
          response = request(:get) { |req| req.url, req.params = path, params }
          handle_response(response)
        end
      end

      def post(path, body, tries: 5)
        @post_tries << tries
        with_asc_retry(tries) do
          response = request(:post) { |req| req.url, req.body = path, JSON.generate(body) }
          handle_response(response)
        end
      end

      def request(method, _path = nil, _params = nil, _headers = {}, _auto_paginate = false)
        with_retry do
          req = Request.new
          yield req
          @on_request&.call
          @calls << [method, req.url, req.params, req.body]
          log_request(method, req.url, req.body)
          raise @transport_error if @transport_error
          response = Response.new(@status, @response_body)
          log_response(method, req.url, response)
          response
        end
      end

      # Both would retry and log private bodies without ScopedTransport.
      def with_retry(*)
        @retry_entries << :transport
        attempts = 0
        begin
          attempts += 1
          yield
        rescue StandardError
          retry if attempts < 3
          raise
        end
      end

      def with_asc_retry(*)
        @retry_entries << :asc
        attempts = 0
        begin
          attempts += 1
          yield
        rescue StandardError
          retry if attempts < 3
          raise
        end
      end

      def log_request(*) = @logs << "PRIVATE_SYNTHETIC_REQUEST"
      def log_response(*) = @logs << "PRIVATE_SYNTHETIC_RESPONSE"

      def handle_response(response)
        raise "PRIVATE_SYNTHETIC_PROVIDER_DETAIL HTTP #{@status}" unless @status.between?(200, 299)
        response
      end
    end
  end
end

require_relative "../../fastlane/apple_provisioning"

class AppleProvisioningAdapterTest < Minitest::Test
  Provisioning = MobileReleaseKit::AppleProvisioning
  CONTEXT = "a" * 64
  PLAN = "b" * 64
  BUNDLE = "invalid.example.provisioning"
  CSR = "-----BEGIN CERTIFICATE REQUEST-----\nbm90LWEtcmVhbC1DU1I=\n-----END CERTIFICATE REQUEST-----\n"

  class Owner
    attr_accessor :admitted, :current, :durable, :check_error, :write_error
    attr_reader :intents, :checks
    def initialize
      @admitted = @current = @durable = true
      @intents, @checks = [], []
    end
    def admit_client!(_client, _context) = @admitted
    def check!(context)
      raise @check_error if @check_error
      @checks << context
      @current
    end
    def before_write!(context, operation, plan, request)
      @intents << [context, operation, plan, request]
      raise @write_error if @write_error
      @durable
    end
  end

  def setup
    @owner, @client = Owner.new, Spaceship::ConnectAPI::APIClient.new
    @adapter = Provisioning::Adapter.new(client: @client, owner: @owner, context_sha256: CONTEXT)
  end

  def wire(kind, method, path, query = {}, body = nil)
    { "kind" => kind, "method" => method, "path" => path, "query" => query, "body" => body }
  end

  def certificate_write
    wire("create_certificate", "POST", "/v1/certificates", {},
         { "data" => { "type" => "certificates", "attributes" => { "certificateType" => "DISTRIBUTION", "csrContent" => CSR } } })
  end

  def bundle_write(name = "Synthetic")
    wire("register_bundle_id", "POST", "/v1/bundleIds", {},
         { "data" => { "type" => "bundleIds", "attributes" => { "identifier" => BUNDLE, "name" => name, "platform" => "IOS" } } })
  end

  def profile_write
    wire("create_profile", "POST", "/v1/profiles", {}, {
      "data" => { "type" => "profiles", "attributes" => { "name" => "Synthetic", "profileType" => "IOS_APP_STORE" },
        "relationships" => { "bundleId" => { "data" => { "type" => "bundleIds", "id" => "bundle-one" } },
          "certificates" => { "data" => [{ "type" => "certificates", "id" => "certificate-one" }] } } }
    })
  end

  def bundle_query
    wire("list_bundle_ids", "GET", "/v1/bundleIds", {
      "filter[identifier]" => BUNDLE, "fields[bundleIds]" => "identifier,platform,seedId", "limit" => "200"
    })
  end

  def certificate_query
    wire("list_certificates", "GET", "/v1/certificates", {
      "filter[certificateType]" => "DISTRIBUTION,IOS_DISTRIBUTION",
      "fields[certificates]" => "certificateType,platform,expirationDate,certificateContent", "limit" => "200"
    })
  end

  def profile_query(download: false)
    query = Provisioning::PROFILE_RELATIONS.merge("fields[profiles]" => Provisioning::PROFILE_FIELDS + (download ? ",profileContent" : ""))
    query.merge!("filter[profileType]" => "IOS_APP_STORE", "limit" => "200") unless download
    wire(download ? "download_profile" : "list_profiles", "GET", download ? "/v1/profiles/profile-one" : "/v1/profiles", query)
  end

  def approval(operation = "synthetic-operation", plan = PLAN)
    { "operationId" => operation, "planSha256" => plan }
  end

  def test_all_seven_closed_operations_use_actual_adapter_calls
    [bundle_query, certificate_query, profile_query, profile_query(download: true)].each do |query|
      result = @adapter.exchange(query)
      assert_equal 201, result.status
      assert_nil result.failure
    end
    [bundle_write, certificate_write, profile_write].each do |request|
      result = @adapter.exchange(request, approval: approval)
      assert_nil result.failure
    end
    assert_equal 7, @client.calls.length
    assert_equal 3, @owner.intents.length
    assert_equal [1, 1, 1], @client.post_tries
    assert_empty @client.logs
    assert_empty @client.retry_entries
    assert_equal [:get, "v1/bundleIds", bundle_query["query"], nil], @client.calls.first
  end

  def test_fixed_cursor_read_is_allowed_without_route_expansion
    query = certificate_query
    query["query"]["cursor"] = "synthetic-next-page"
    @adapter.exchange(query)
    assert_equal "synthetic-next-page", @client.calls.first[2]["cursor"]
    ["", "with space", "a" * 1025].each do |cursor|
      query["query"]["cursor"] = cursor
      assert_raises(Provisioning::Error) { @adapter.exchange(query) }
    end
    assert_equal 1, @client.calls.length
  end

  def test_closed_role_rejects_foreign_paths_methods_devices_or_certificate_types
    bad = []
    bad << bundle_query.merge("path" => "https://other.invalid/v1/bundleIds")
    bad << bundle_query.merge("path" => "/v1/apps")
    bad << certificate_write.merge("method" => "DELETE")
    bad << certificate_write.merge("path" => "/v1/certificates/existing")
    bad << certificate_query.merge("query" => certificate_query["query"].merge("filter[other]" => "any"))
    request = certificate_write
    request["body"]["data"]["attributes"]["certificateType"] = "IOS_DEVELOPMENT"
    bad << request
    request = certificate_write
    request["body"]["data"]["attributes"]["csrContent"] = "-----BEGIN PRIVATE KEY-----\naaaa\n-----END PRIVATE KEY-----\n"
    bad << request
    request = profile_write
    request["body"]["data"]["relationships"]["devices"] = { "data" => [] }
    bad << request
    bad.each { |request| assert_raises(Provisioning::Error) { @adapter.exchange(request, approval: approval) } }
    assert_empty @client.calls
    assert_empty @owner.intents
  end

  def test_writes_require_original_owner_durable_admission_before_sdk
    @owner.durable = false
    assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval) }
    assert_empty @client.calls
    assert_equal [[CONTEXT, "synthetic-operation", PLAN, Provisioning::Request.new(certificate_write).sha256]], @owner.intents
    @owner.durable = true
    # Even ambiguous durable acknowledgement cannot automatically re-arm.
    assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval) }
    assert_empty @client.calls
    assert_equal 1, @owner.intents.length
  end

  def test_missing_or_changed_approval_cannot_bypass_admission_or_latch
    assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write) }
    assert_empty @owner.intents
    @client.on_request = -> { assert_equal 1, @owner.intents.length }
    @adapter.exchange(certificate_write, approval: approval)
    assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval("synthetic-operation", "c" * 64)) }
    assert_equal 1, @client.calls.length
    assert_raises(Provisioning::Error) { @adapter.exchange(bundle_query, approval: approval) }
  end

  def test_both_sdk_retry_layers_and_token_refresh_retries_are_suppressed
    [400, 401, 403, 409, 422, 429, 500, 502, 503, 504].each_with_index do |status, index|
      @client.status = status
      before = @client.calls.length
      result = @adapter.exchange(certificate_write, approval: approval("operation-#{index}"))
      assert_equal "provider_request_unconfirmed", result.failure
      assert_equal status, result.status
      assert_nil result.body
      assert_equal 1, @client.calls.length - before
      assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval("operation-#{index}")) }
    end
    assert_empty @client.retry_entries
    assert_empty @client.logs
  end

  def test_network_lost_reply_stays_private_and_never_retries
    @client.transport_error = IOError.new("PRIVATE_SYNTHETIC_TRANSPORT_DETAIL")
    result = @adapter.exchange(certificate_write, approval: approval)
    assert_equal "provider_request_unconfirmed", result.failure
    assert_nil result.status
    assert_nil result.body
    assert_equal 1, @client.calls.length
    assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval) }
    refute_match(/PRIVATE_SYNTHETIC|CERTIFICATE REQUEST/, [result.inspect, @adapter.inspect, Provisioning::Request.new(certificate_write).inspect].join)
    assert_empty @client.logs
  end

  def test_authorization_change_after_response_is_not_success
    @client.on_request = -> { @owner.current = false }
    result = @adapter.exchange(certificate_write, approval: approval)
    assert_equal "provider_request_unconfirmed", result.failure
    assert_nil result.body
    assert_equal 1, @client.calls.length
  end

  def test_unadmitted_client_enterprise_and_existing_release_role_refused
    owner = Owner.new
    owner.admitted = false
    assert_raises(Provisioning::Error) { Provisioning::Adapter.new(client: Spaceship::ConnectAPI::APIClient.new, owner: owner, context_sha256: CONTEXT) }
    owner.admitted = true
    client = Spaceship::ConnectAPI::APIClient.new
    client.hostname = "https://api.enterprise.developer.apple.com/"
    assert_raises(Provisioning::Error) { Provisioning::Adapter.new(client: client, owner: owner, context_sha256: CONTEXT) }
    MobileReleaseKit.const_set(:AppleOperationTransport, Module.new) unless defined?(MobileReleaseKit::AppleOperationTransport)
    client = Spaceship::ConnectAPI::APIClient.new
    client.extend(MobileReleaseKit::AppleOperationTransport)
    assert_raises(Provisioning::Error) { Provisioning::Adapter.new(client: client, owner: owner, context_sha256: CONTEXT) }
    assert_raises(Provisioning::Error) { Provisioning::Adapter.new(client: @client, owner: owner, context_sha256: CONTEXT) }
  end

  def test_direct_lower_level_and_reentrant_sdk_bypasses_refused
    assert_raises(Provisioning::Error) { @client.post("v1/certificates", certificate_write["body"]) }
    assert_raises(Provisioning::Error) { @client.request(:get, "v1/apps") {} }
    @client.on_request = lambda do
      assert_raises(Provisioning::Error) { @client.post("v1/certificates", certificate_write["body"]) }
      assert_raises(Provisioning::Error) { @client.request(:post) {} }
      assert_raises(Provisioning::Error) { @adapter.exchange(certificate_write, approval: approval("nested-operation")) }
    end
    assert_nil @adapter.exchange(certificate_write, approval: approval).failure
    assert_equal 1, @client.calls.length
    assert_raises(Provisioning::Error) { @client.get("v1/bundleIds", bundle_query["query"]) }
  end

  def test_handoff_bound_and_original_finality_not_result_json
    result = @adapter.exchange(bundle_query)
    assert_equal %w[body failure status], result.private_wire.keys.sort
    refute_respond_to result, :settled
    @client.response_body = { "private" => "x" * Provisioning::MAX_RESPONSE_BYTES }
    result = @adapter.exchange(certificate_query)
    assert_equal "provider_request_unconfirmed", result.failure
    assert_nil result.body
    assert_empty @client.logs
  end

  def test_native_owner_errors_are_fixed_without_private_exception_causes
    @owner.check_error = RuntimeError.new("PRIVATE_SYNTHETIC_OWNER_DETAIL")
    error = assert_raises(Provisioning::Error) { @adapter.exchange(bundle_query) }
    refute_match(/PRIVATE_SYNTHETIC/, error.message)
    assert_nil error.cause
    assert_empty @client.calls
  end

  def test_request_copies_public_csr_and_binds_hash_before_owner_admission
    input = certificate_write
    request = Provisioning::Request.new(input)
    original = request.sha256
    input["body"]["data"]["attributes"]["csrContent"] = "changed"
    assert_equal CSR, request.body["data"]["attributes"]["csrContent"]
    assert_equal original, request.sha256
    assert request.body.frozen?
    assert request.body["data"]["attributes"]["csrContent"].frozen?
  end

  def test_request_digest_matches_python_private_owner_gate_fixture
    assert_equal "f2bf3d53ff01255fbc588099c17830348b748a6e2eab6bc439d6e385848bc356",
      Provisioning::Request.new(bundle_write("Synthetic café 🍎")).sha256
  end
end
