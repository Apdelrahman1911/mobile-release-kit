# frozen_string_literal: true

# Fixed profile-only command of the existing Apple SavedCommand operation.
# It uses the selected Token/APIClient/ScopedTransport/raw middleware already
# owned by that operation, not Fastfile, a release permission or a new client
# stack. One invocation makes ONE request; the original Python owner bounds
# the finite page/download schedule and retains all C/A/W and journal facts.
require_relative "apple_provisioning_bundle_read"

module MobileReleaseKit
  module AppleSigningProvisioning
    Read = AppleBundleRead
    Provisioning = AppleProvisioning
    SCOPE = "existing-p12-app-store-profile"
    PAGE_LIMIT = 128 * 1024
    DOWNLOAD_LIMIT = 1536 * 1024
    FRAME_LIMIT = 2 * 1024 * 1024
    PREFIX = "MOBILE_RELEASE_ASC_SIGNING_"
    BASE = %w[BUNDLE_ID BUNDLE_READ_CONTEXT KEY_ID ISSUER_ID PRIVATE_KEY_P8_BASE64].map { |name| "MOBILE_RELEASE_ASC_" + name }.freeze
    LISTS = %w[list_bundle_ids list_certificates list_profiles].freeze
    STEPS = (LISTS + %w[download_profile create_profile]).freeze
    COMMON = %w[STEP OPERATION_ID].freeze
    WRITE = %w[BUNDLE_RESOURCE_ID CERTIFICATE_RESOURCE_ID PLAN_SHA256 ACK_SHA256].freeze

    class Error < StandardError
      def initialize = super("The selected App Store profile operation is unconfirmed.")
    end

    def self.require!(condition)
      raise Error unless condition
    end

    class Input
      attr_reader :step, :operation_id, :plan_sha256, :ack_sha256, :request_sha256

      def initialize(environment)
        @key = Read::Input.new(environment)
        @step = text(environment, "STEP", 32)
        AppleSigningProvisioning.require!(STEPS.include?(@step))
        extra = @step == "create_profile" ? WRITE : (@step == "download_profile" ? ["PROFILE_RESOURCE_ID"] : [])
        extra += ["CURSOR"] if LISTS.include?(@step) && environment.key?(PREFIX + "CURSOR")
        expected = (COMMON + extra).map { |name| PREFIX + name }
        AppleSigningProvisioning.require!(environment.keys.select { |name| name.start_with?("MOBILE_RELEASE_ASC_") }.sort ==
          (BASE + expected).sort)
        @operation_id = text(environment, "OPERATION_ID", 128)
        AppleSigningProvisioning.require!(@operation_id.match?(Provisioning::ID))
        @plan_sha256 = @ack_sha256 = nil
        wire = case @step
               when "list_bundle_ids" then @key.request
               when "list_certificates"
                 read("/v1/certificates", { "filter[certificateType]" => "DISTRIBUTION,IOS_DISTRIBUTION",
                   "fields[certificates]" => "certificateType,platform,expirationDate,certificateContent", "limit" => "200" })
               when "list_profiles"
                 read("/v1/profiles", { "filter[profileType]" => "IOS_APP_STORE", "fields[profiles]" => Provisioning::PROFILE_FIELDS,
                   **Provisioning::PROFILE_RELATIONS, "limit" => "200" })
               when "download_profile"
                 identity = text(environment, "PROFILE_RESOURCE_ID", 128)
                 AppleSigningProvisioning.require!(identity.match?(Provisioning::ID))
                 read("/v1/profiles/" + identity, { "fields[profiles]" => Provisioning::PROFILE_FIELDS + ",profileContent",
                   **Provisioning::PROFILE_RELATIONS })
               when "create_profile"
                 bundle, certificate = %w[BUNDLE_RESOURCE_ID CERTIFICATE_RESOURCE_ID].map { |name| text(environment, name, 128) }
                 @plan_sha256, @ack_sha256 = %w[PLAN_SHA256 ACK_SHA256].map { |name| text(environment, name, 64) }
                 AppleSigningProvisioning.require!([bundle, certificate].all? { |value| value.match?(Provisioning::ID) } &&
                   [@plan_sha256, @ack_sha256].all? { |value| value.match?(Provisioning::SHA256) })
                 { "kind" => "create_profile", "method" => "POST", "path" => "/v1/profiles", "query" => {},
                   "body" => { "data" => { "type" => "profiles", "attributes" => {
                     "name" => "MRK-" + Digest::SHA256.hexdigest(@operation_id)[0, 24], "profileType" => "IOS_APP_STORE" },
                     "relationships" => { "bundleId" => { "data" => { "type" => "bundleIds", "id" => bundle } },
                       "certificates" => { "data" => [{ "type" => "certificates", "id" => certificate }] } } } } }
               end
        if extra.include?("CURSOR")
          cursor = text(environment, "CURSOR", 1024)
          AppleSigningProvisioning.require!(cursor.bytes.all? { |byte| byte > 32 && byte < 127 })
          wire.fetch("query")["cursor"] = cursor
        end
        request = Provisioning::Request.new(wire) # Exact existing public API shapes.
        @wire, @request_sha256 = Provisioning.deep_freeze(wire), request.sha256
        @ack_attempted = @ack_consumed = false
      rescue StandardError
        raise Error.new, cause: nil
      end

      def inspect = "#<AppleSigningProvisioning::Input private>"
      def context = @key.context
      def bundle_id = @key.bundle_id
      def key_id = @key.key_id
      def issuer_id = @key.issuer_id
      def token = @key.token
      def request = @wire
      def raw_limit = LISTS.include?(@step) ? PAGE_LIMIT : DOWNLOAD_LIMIT
      def ack_consumed? = @ack_consumed

      def approval
        @step == "create_profile" ? { "operationId" => @operation_id, "planSha256" => @plan_sha256 } : nil
      end

      def consume_ack!(context, operation, plan, request)
        AppleSigningProvisioning.require!(@step == "create_profile" && !@ack_attempted)
        @ack_attempted = true # Even failed/foreign admission burns this handoff.
        AppleSigningProvisioning.require!(context == self.context && operation == @operation_id &&
          plan == @plan_sha256 && request == @request_sha256)
        @ack_consumed = true
        true
      end

      def frame(response)
        JSON.generate({ "schemaVersion" => 1, "scope" => SCOPE, "contextSha256" => context, "bundleId" => bundle_id,
                        "operationId" => @operation_id, "requestSha256" => @request_sha256,
                        "ackSha256" => @ack_sha256, "response" => response }, ascii_only: true) + "\n"
      end

      private

      def read(path, query)
        { "kind" => @step, "method" => "GET", "path" => path, "query" => query, "body" => nil }
      end

      def text(environment, name, maximum)
        value = environment[PREFIX + name]
        AppleSigningProvisioning.require!(value.instance_of?(String) && value.ascii_only? &&
          value.bytesize.between?(1, maximum) && !value.include?("\0"))
        value.dup.freeze
      end
    end

    # Reuse the original per-instance current-token/TLS/adapter/raw-callback
    # checks. The old ReadOwner retains its unconditional write refusal.
    class Owner < Read::ReadOwner
      def initialize(input, token, client)
        AppleSigningProvisioning.require!(input.instance_of?(Input))
        super
      end

      def inspect = "#<AppleSigningProvisioning::Owner private>"

      def before_write!(context, operation, plan, request)
        check!(context)
        @input.consume_ack!(context, operation, plan, request)
      end

      def before_wire!(environment)
        check!(@input.context)
        AppleSigningProvisioning.require!(!@sent)
        @sent = true # No replay after wire entry, even if validation then fails.
        url, request = environment[:url], @input.request
        AppleSigningProvisioning.require!(url.is_a?(URI::HTTPS) && url.scheme == "https" &&
          url.host == "api.appstoreconnect.apple.com" && url.port == 443 && url.userinfo.nil? &&
          url.fragment.nil? && url.path == request.fetch("path") && url.to_s.bytesize <= 4096 &&
          environment[:request_headers]["Authorization"] == "Bearer #{@token.text}")
        if @input.step == "create_profile"
          # Locked APIClient#post serializes this same Hash with #to_json.
          AppleSigningProvisioning.require!(@input.ack_consumed? && environment[:method] == :post &&
            (url.query.nil? || url.query.empty?) && environment[:body].instance_of?(String) &&
            environment[:body] == request.fetch("body").to_json)
        else
          pairs = URI.decode_www_form(url.query || "")
          AppleSigningProvisioning.require!(environment[:method] == :get && environment[:body].nil? &&
            pairs.size == request.fetch("query").size && pairs.to_h == request.fetch("query") && !@input.ack_consumed?)
        end
        true
      end

      def capture!(environment)
        check!(@input.context)
        AppleSigningProvisioning.require!(@sent && !@captured)
        @captured = true
        body, status = environment[:body], environment[:status]
        AppleSigningProvisioning.require!(body.instance_of?(String) && body.bytesize.between?(1, @input.raw_limit) &&
          status.instance_of?(Integer) && status.between?(100, 599))
        @status, @raw = status, body.dup.force_encoding(Encoding::BINARY).freeze
        true
      end
    end

    class Operation
      def initialize(input)
        AppleSigningProvisioning.require!(input.instance_of?(Input))
        @input, @used = input, false
      end

      def inspect = "#<AppleSigningProvisioning::Operation private>"

      def execute
        AppleSigningProvisioning.require!(!@used)
        @used = true
        Read.load_sdk!
        token = @input.token
        client = Spaceship::ConnectAPI::APIClient.new(token: token)
        owner = Owner.new(@input, token, client)
        adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: @input.context)
        result = adapter.exchange(@input.request, approval: @input.approval)
        frame = @input.frame(owner.finish(result))
        AppleSigningProvisioning.require!(frame.bytesize <= FRAME_LIMIT)
        frame
      rescue StandardError
        @input.frame("status" => nil, "bodyBase64" => nil, "failure" => Read::PRIVATE_FAILURE)
      end
    end

    def self.main(arguments, environment, output)
      require!(arguments.empty?)
      frame = Operation.new(Input.new(environment)).execute
      require!(frame.bytesize <= FRAME_LIMIT && output.write(frame) == frame.bytesize)
      output.flush
      0
    rescue StandardError
      70
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::AppleSigningProvisioning.main(ARGV, ENV, STDOUT)
  rescue Exception
    Process.exit!(70) # Never print a private exception/backtrace on interruption.
  end
  exit(code)
end
