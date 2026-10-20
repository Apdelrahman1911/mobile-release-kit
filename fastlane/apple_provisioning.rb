# frozen_string_literal: true

# Internal adapter for the original native provisioning owner. It reuses an
# already authenticated, pinned Spaceship APIClient; it creates no token/client,
# loads no environment credentials, and grants no release-operation permission.
# Load only in a separate provisioning worker, never prepend globally.
require "json"
require "digest"

module MobileReleaseKit
  module AppleProvisioning
    MAX_RESPONSE_BYTES = 6 * 1024 * 1024
    ID = /\A[A-Za-z0-9_-]{1,128}\z/
    SHA256 = /\A[0-9a-f]{64}\z/
    BUNDLE = /\A[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\z/
    PROFILE_FIELDS = "name,platform,profileType,profileState,uuid,createdDate,expirationDate,bundleId,certificates"
    PROFILE_RELATIONS = {
      "include" => "bundleId,certificates",
      "fields[bundleIds]" => "identifier,platform,seedId",
      "fields[certificates]" => "certificateType,platform,expirationDate"
    }.freeze

    class Error < StandardError
      def initialize = super("Apple provisioning request is unavailable; preserve its original operation for review.")
    end

    def self.require!(condition)
      raise Error unless condition
    end

    def self.text?(value, limit)
      value.instance_of?(String) && value.valid_encoding? && value.bytesize.between?(1, limit)
    end

    def self.keys?(value, keys)
      value.instance_of?(Hash) && value.keys.all? { |key| key.instance_of?(String) } && value.keys.sort == keys.sort
    end

    def self.deep_freeze(value)
      case value
      when Hash then value.transform_values { |item| deep_freeze(item) }.freeze
      when Array then value.map { |item| deep_freeze(item) }.freeze
      when String then value.dup.freeze
      else value
      end
    end

    def self.canonical(value)
      sorted = lambda do |item|
        case item
        when Hash then item.keys.sort.to_h { |key| [key, sorted.call(item.fetch(key))] }
        when Array then item.map { |child| sorted.call(child) }
        else item
        end
      end
      JSON.generate(sorted.call(value), ascii_only: true)
    end

    class Request
      attr_reader :kind, :method, :path, :query, :body, :sha256

      def initialize(wire)
        AppleProvisioning.require!(AppleProvisioning.keys?(wire, %w[kind method path query body]))
        AppleProvisioning.require!(%w[kind method path].all? { |key| AppleProvisioning.text?(wire[key], 256) })
        @kind, @method, @path, @query, @body = wire.values_at("kind", "method", "path", "query", "body")
        AppleProvisioning.require!(@query.instance_of?(Hash) && @query.size <= 10 && @query.all? do |key, value|
          AppleProvisioning.text?(key, 64) && AppleProvisioning.text?(value, 2048)
        end)
        @method == "GET" ? validate_read! : validate_write!
        frozen = AppleProvisioning.deep_freeze(wire)
        @kind, @method, @path, @query, @body = frozen.values_at("kind", "method", "path", "query", "body")
        @sha256 = Digest::SHA256.hexdigest(AppleProvisioning.canonical(frozen)).freeze
        freeze
      end

      def inspect = "#<AppleProvisioning::Request private>"

      private

      def validate_read!
        AppleProvisioning.require!(@body.nil?)
        expected = case @kind
                   when "list_bundle_ids"
                     id = @query["filter[identifier]"]
                     AppleProvisioning.require!(AppleProvisioning.text?(id, 255) && id.match?(BUNDLE))
                     AppleProvisioning.require!(@path == "/v1/bundleIds")
                     { "filter[identifier]" => id, "fields[bundleIds]" => "identifier,platform,seedId", "limit" => "200" }
                   when "list_certificates"
                     AppleProvisioning.require!(@path == "/v1/certificates")
                     { "filter[certificateType]" => "DISTRIBUTION,IOS_DISTRIBUTION",
                       "fields[certificates]" => "certificateType,platform,expirationDate,certificateContent", "limit" => "200" }
                   when "list_profiles"
                     AppleProvisioning.require!(@path == "/v1/profiles")
                     PROFILE_RELATIONS.merge("filter[profileType]" => "IOS_APP_STORE", "fields[profiles]" => PROFILE_FIELDS, "limit" => "200")
                   when "download_profile"
                     AppleProvisioning.require!(@path.match?(%r{\A/v1/profiles/[A-Za-z0-9_-]{1,128}\z}))
                     PROFILE_RELATIONS.merge("fields[profiles]" => PROFILE_FIELDS + ",profileContent")
                   when "current_app_before", "current_app_after"
                     AppleProvisioning.require!(@path.match?(%r{\A/v1/apps/[1-9][0-9]{0,19}\z}))
                     { "fields[apps]" => "bundleId" }
                   when "current_builds"
                     app = @query["filter[app]"]
                     AppleProvisioning.require!(@path == "/v1/builds" && app.instance_of?(String) && app.match?(/\A[1-9][0-9]{0,19}\z/))
                     { "filter[app]" => app, "include" => "app,preReleaseVersion",
                       "fields[builds]" => "version,app,preReleaseVersion", "fields[apps]" => "bundleId",
                       "fields[preReleaseVersions]" => "version,platform,app", "limit" => "200" }
                   when "current_buildUploads"
                     AppleProvisioning.require!(@path.match?(%r{\A/v1/apps/[1-9][0-9]{0,19}/buildUploads\z}))
                     { "fields[buildUploads]" => "cfBundleVersion,cfBundleShortVersionString,platform,build", "limit" => "200" }
                   when "current_appStoreVersions"
                     AppleProvisioning.require!(@path.match?(%r{\A/v1/apps/[1-9][0-9]{0,19}/appStoreVersions\z}))
                     { "fields[appStoreVersions]" => "versionString,platform", "limit" => "200" }
                   else raise Error
                   end
        if @query.key?("cursor")
          cursor = @query["cursor"]
          AppleProvisioning.require!(!%w[download_profile current_app_before current_app_after].include?(@kind) && cursor.bytesize <= 1024 && cursor.match?(/\A[!-~]+\z/))
          expected = expected.merge("cursor" => cursor)
        end
        AppleProvisioning.require!(@query == expected)
      end

      def name!(name)
        AppleProvisioning.require!(AppleProvisioning.text?(name, 512) && name.length <= 128 && !name.match?(/[\x00-\x1f\x7f]/))
      end

      def relationship!(relation, type, many: false)
        AppleProvisioning.require!(AppleProvisioning.keys?(relation, %w[data]))
        data = relation["data"]
        if many
          AppleProvisioning.require!(data.instance_of?(Array) && data.size == 1)
          data = data.first
        end
        AppleProvisioning.require!(AppleProvisioning.keys?(data, %w[type id]) && data["type"] == type &&
          AppleProvisioning.text?(data["id"], 128) && data["id"].match?(ID))
      end

      def validate_write!
        AppleProvisioning.require!(@method == "POST" && @query.empty? && AppleProvisioning.keys?(@body, %w[data]))
        data = @body["data"]
        AppleProvisioning.require!(AppleProvisioning.keys?(data, @kind == "create_profile" ? %w[type attributes relationships] : %w[type attributes]))
        attributes = data["attributes"]
        case @kind
        when "register_bundle_id"
          AppleProvisioning.require!(@path == "/v1/bundleIds" && data["type"] == "bundleIds" &&
            AppleProvisioning.keys?(attributes, %w[identifier name platform]) && attributes["platform"] == "IOS")
          bundle = attributes["identifier"]
          AppleProvisioning.require!(AppleProvisioning.text?(bundle, 255) && bundle.match?(BUNDLE))
          name!(attributes["name"])
        when "create_certificate"
          AppleProvisioning.require!(@path == "/v1/certificates" && data["type"] == "certificates" &&
            AppleProvisioning.keys?(attributes, %w[certificateType csrContent]) && attributes["certificateType"] == "DISTRIBUTION")
          csr = attributes["csrContent"]
          AppleProvisioning.require!(AppleProvisioning.text?(csr, 32 * 1024) && csr.match?(
            /\A-----BEGIN CERTIFICATE REQUEST-----\n(?:[A-Za-z0-9+\/=]{1,64}\n)+-----END CERTIFICATE REQUEST-----\n?\z/))
        when "create_profile"
          AppleProvisioning.require!(@path == "/v1/profiles" && data["type"] == "profiles" &&
            AppleProvisioning.keys?(attributes, %w[name profileType]) && attributes["profileType"] == "IOS_APP_STORE")
          name!(attributes["name"])
          relationships = data["relationships"]
          AppleProvisioning.require!(AppleProvisioning.keys?(relationships, %w[bundleId certificates]))
          relationship!(relationships["bundleId"], "bundleIds")
          relationship!(relationships["certificates"], "certificates", many: true)
        else raise Error
        end
      end
    end

    # Per-instance only. This preserves suppression of BOTH SDK retry layers,
    # token-refresh retry, request/response logs, and direct write bypasses.
    # It is intentionally NOT derived from the release-only AppleOperationTransport.
    module ScopedTransport
      def get(path, params = nil)
        provisioning_guard!(:get, path, params || {}, nil)
        super
      end

      def post(path, body, **options)
        provisioning_guard!(:post, path, {}, body)
        AppleProvisioning.require!(options.empty?)
        super(path, body, tries: 1)
      end

      def patch(*) = raise(Error)
      def delete(*) = raise(Error)
      def put(*) = raise(Error)

      # APIClient#get/post call request(method) with their own fixed builder
      # block. Disallow direct lower-level endpoint/header/pagination injection.
      def request(method, path = nil, params = nil, headers = {}, auto_paginate = false, &block)
        active = @mrk_provisioning_request
        AppleProvisioning.require!(active.instance_of?(Request) && method == active.method.downcase.to_sym &&
          @mrk_provisioning_thread == Thread.current && @mrk_provisioning_call_started == true &&
          @mrk_provisioning_request_started != true && path.nil? && params.nil? &&
          headers.instance_of?(Hash) && headers.empty? && auto_paginate == false && block)
        @mrk_provisioning_request_started = true
        super
      end

      protected

      def provisioning_guard!(method, path, query, body)
        active = @mrk_provisioning_request
        AppleProvisioning.require!(active.instance_of?(Request) && active.method.downcase.to_sym == method &&
          @mrk_provisioning_thread == Thread.current && @mrk_provisioning_call_started != true &&
          path == active.path.delete_prefix("/") && query == active.query && body == active.body)
        @mrk_provisioning_call_started = true
      end

      def with_retry(*) = yield
      def with_asc_retry(*) = yield
      def log_request(*) = nil
      def log_response(_method, _url, response, *)
        # Only the numeric HTTP status survives exception paths. Never retain
        # the response/body/native exception for public error diagnostics.
        @mrk_provisioning_http_status = response.status if response.status.instance_of?(Integer)
      end
    end

    class Result
      attr_reader :status, :body, :failure
      def initialize(status:, body:, failure: nil)
        @status, @body, @failure = status, body, failure
        freeze
      end
      def inspect = "#<AppleProvisioning::Result private>"
      def private_wire = { "status" => @status, "body" => @body, "failure" => @failure }
      # No `settled` flag: only the enclosing native process/transport owner can
      # supply real lifecycle finality to Python after all original joins.
    end

    class Adapter
      # The existing selected P8 owner must provide these methods. These calls
      # are in-process capabilities, not commands exposed to a renderer/CLI:
      # admit_client!(client, context_sha256), check!(context_sha256),
      # before_write!(context_sha256, operation_id, plan_sha256, request_sha256).
      # before_write! checks actual current consent/lease/key loan, records the
      # durable intent, and returns true only AFTER durable acknowledgement.
      def initialize(client:, owner:, context_sha256:)
        AppleProvisioning.require!(defined?(Spaceship::ConnectAPI::APIClient) &&
          client.instance_of?(Spaceship::ConnectAPI::APIClient) &&
          AppleProvisioning.text?(context_sha256, 64) && context_sha256.match?(SHA256))
        AppleProvisioning.require!(!defined?(MobileReleaseKit::AppleOperationTransport) ||
          !client.is_a?(MobileReleaseKit::AppleOperationTransport))
        AppleProvisioning.require!(!client.is_a?(ScopedTransport))
        AppleProvisioning.require!(owner.admit_client!(client, context_sha256) == true)
        # Origin/TLS/proxy/token/runtime admission belongs to the original owner.
        # It must supply a token-based, non-enterprise ASC client, never cookies.
        AppleProvisioning.require!(client.hostname == "https://api.appstoreconnect.apple.com/")
        @client, @owner, @context = client, owner, context_sha256.dup.freeze
        @attempted, @active, @lock = {}, false, Mutex.new
        @client.extend(ScopedTransport)
      rescue StandardError
        raise Error.new, cause: nil
      end

      def inspect = "#<AppleProvisioning::Adapter private>"

      def exchange(wire, approval: nil)
        AppleProvisioning.require!(@lock.try_lock)
        begin
          exchange_owned(wire, approval: approval)
        rescue StandardError
          raise Error.new, cause: nil
        ensure
          @lock.unlock
        end
      end

      private

      def exchange_owned(wire, approval:)
        AppleProvisioning.require!(!@active)
        request = Request.new(wire)
        AppleProvisioning.require!(@owner.check!(@context) == true)
        if request.method == "POST"
          AppleProvisioning.require!(AppleProvisioning.keys?(approval, %w[operationId planSha256]) &&
            AppleProvisioning.text?(approval["operationId"], 128) && approval["operationId"].match?(ID) &&
            AppleProvisioning.text?(approval["planSha256"], 64) && approval["planSha256"].match?(SHA256))
          operation = approval["operationId"]
          # One logical provisioning operation can have separately approved
          # bundle/certificate/profile steps, but never repeat the same step.
          attempt = [operation.dup.freeze, request.kind].freeze
          AppleProvisioning.require!(!@attempted.key?(attempt))
          # Latch BEFORE durable admission; even ambiguous admission failure
          # cannot turn this original adapter into an automatic retry route.
          @attempted[attempt] = true
          AppleProvisioning.require!(@owner.before_write!(@context, operation, approval["planSha256"], request.sha256) == true)
          AppleProvisioning.require!(@owner.check!(@context) == true)
        else
          AppleProvisioning.require!(approval.nil?)
        end
        @active = true
        @client.instance_variable_set(:@mrk_provisioning_request, request)
        @client.instance_variable_set(:@mrk_provisioning_http_status, nil)
        @client.instance_variable_set(:@mrk_provisioning_thread, Thread.current)
        @client.instance_variable_set(:@mrk_provisioning_call_started, false)
        @client.instance_variable_set(:@mrk_provisioning_request_started, false)
        begin
          response = request.method == "GET" ? @client.get(request.path.delete_prefix("/"), request.query) :
            @client.post(request.path.delete_prefix("/"), request.body)
          AppleProvisioning.require!(@owner.check!(@context) == true)
          AppleProvisioning.require!(response && response.status.instance_of?(Integer) && response.body.instance_of?(Hash))
          # This bounds the private handoff, not the SDK's already-buffered HTTP
          # allocation. Ingress/process memory admission stays with native owner.
          body = JSON.generate(response.body, ascii_only: true)
          AppleProvisioning.require!(body.bytesize <= MAX_RESPONSE_BYTES)
          Result.new(status: response.status, body: body.freeze)
        rescue StandardError
          status = @client.instance_variable_get(:@mrk_provisioning_http_status)
          # Never pass through SDK errors (many embed complete private bodies).
          Result.new(status: status, body: nil, failure: "provider_request_unconfirmed")
        ensure
          @client.instance_variable_set(:@mrk_provisioning_request, nil)
          @client.instance_variable_set(:@mrk_provisioning_http_status, nil)
          @client.instance_variable_set(:@mrk_provisioning_thread, nil)
          @client.instance_variable_set(:@mrk_provisioning_call_started, nil)
          @client.instance_variable_set(:@mrk_provisioning_request_started, nil)
          @active = false
        end
      end
    end
  end
end
