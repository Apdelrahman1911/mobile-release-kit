# frozen_string_literal: true

# Fixed certificate-only command of the SAME Apple SavedSession/Store runtime.
# No private signing key enters this helper: only selected API P8 and public CSR.
# The native parent must already own a durable keySaved ACK and (for POST) the
# durable possible-send ACK. Their digests compare the handoff, not authority.
# Never run Fastfile, read a key path, generate a key, revoke or retry a request.
require_relative "apple_provisioning_bundle_read"

module MobileReleaseKit
  module AppleCertificateIssuance
    Read = AppleBundleRead
    Provisioning = AppleProvisioning
    SCOPE = "saved-apple-distribution-key-certificate"
    CSR_LIMIT = 4096
    RAW_LIMIT = 128 * 1024
    FRAME_LIMIT = 192 * 1024
    PREFIX = "MOBILE_RELEASE_ASC_CERTIFICATE_"
    BASE = %w[BUNDLE_ID BUNDLE_READ_CONTEXT KEY_ID ISSUER_ID PRIVATE_KEY_P8_BASE64].map { |name| "MOBILE_RELEASE_ASC_" + name }.freeze
    LISTS = %w[list_bundle_ids list_certificates list_profiles].freeze
    COMMON = %w[STEP OPERATION_ID].freeze
    WRITE = %w[PLAN_SHA256 KEY_SAVED_ACK_SHA256 ACK_SHA256 CSR_BASE64].freeze

    class Error < StandardError
      def initialize = super("The selected Apple certificate request is unconfirmed.")
    end

    def self.require!(condition)
      raise Error unless condition
    end

    class Input
      attr_reader :step, :operation_id, :plan_sha256, :key_saved_ack_sha256, :ack_sha256, :request_sha256

      def initialize(environment)
        @key = Read::Input.new(environment) # Selected P8 only; no ambient auth/refresh.
        @step = text(environment, "STEP", 32)
        AppleCertificateIssuance.require!((LISTS + ["create_certificate"]).include?(@step))
        extra = @step == "create_certificate" ? WRITE : []
        extra += ["CURSOR"] if LISTS.include?(@step) && environment.key?(PREFIX + "CURSOR")
        AppleCertificateIssuance.require!(environment.keys.select { |name| name.start_with?("MOBILE_RELEASE_ASC_") }.sort ==
          (BASE + (COMMON + extra).map { |name| PREFIX + name }).sort)
        @operation_id = text(environment, "OPERATION_ID", 128)
        AppleCertificateIssuance.require!(@operation_id.match?(Provisioning::ID))
        @plan_sha256 = @key_saved_ack_sha256 = @ack_sha256 = nil
        wire = case @step
               when "list_bundle_ids" then @key.request
               when "list_certificates"
                 read("/v1/certificates", { "filter[certificateType]" => "DISTRIBUTION,IOS_DISTRIBUTION",
                   "fields[certificates]" => "certificateType,platform,expirationDate,certificateContent", "limit" => "200" })
               when "list_profiles"
                 read("/v1/profiles", { "filter[profileType]" => "IOS_APP_STORE", "fields[profiles]" => Provisioning::PROFILE_FIELDS,
                   **Provisioning::PROFILE_RELATIONS, "limit" => "200" })
               when "create_certificate"
                 @plan_sha256, @key_saved_ack_sha256, @ack_sha256 = %w[PLAN_SHA256 KEY_SAVED_ACK_SHA256 ACK_SHA256].map do |name|
                   text(environment, name, 64)
                 end
                 AppleCertificateIssuance.require!([@plan_sha256, @key_saved_ack_sha256, @ack_sha256].all? do |value|
                   value.match?(Provisioning::SHA256)
                 end)
                 encoded = text(environment, "CSR_BASE64", 4 * ((CSR_LIMIT + 2) / 3))
                 csr = Base64.strict_decode64(encoded)
                 AppleCertificateIssuance.require!(csr.ascii_only? && csr.bytesize.between?(1, CSR_LIMIT) &&
                   Base64.strict_encode64(csr) == encoded)
                 { "kind" => "create_certificate", "method" => "POST", "path" => "/v1/certificates", "query" => {},
                   "body" => { "data" => { "type" => "certificates", "attributes" => {
                     "certificateType" => "DISTRIBUTION", "csrContent" => csr } } } }
               end
        if extra.include?("CURSOR")
          cursor = text(environment, "CURSOR", 1024)
          AppleCertificateIssuance.require!(cursor.bytes.all? { |byte| byte > 32 && byte < 127 })
          wire.fetch("query")["cursor"] = cursor
        end
        request = Provisioning::Request.new(wire) # Closed maintained API shape/CSR envelope.
        @wire, @request_sha256 = Provisioning.deep_freeze(wire), request.sha256
        @ack_attempted = @ack_consumed = false
      rescue StandardError
        raise Error.new, cause: nil
      end

      def inspect = "#<AppleCertificateIssuance::Input private>"
      def context = @key.context
      def bundle_id = @key.bundle_id
      def key_id = @key.key_id
      def issuer_id = @key.issuer_id
      def token = @key.token
      def request = @wire
      def ack_consumed? = @ack_consumed
      def approval
        @step == "create_certificate" ? { "operationId" => @operation_id, "planSha256" => @plan_sha256 } : nil
      end

      def consume_ack!(context, operation, plan, request)
        AppleCertificateIssuance.require!(@step == "create_certificate" && !@ack_attempted)
        @ack_attempted = true # Failed/foreign admission cannot renew this handoff.
        AppleCertificateIssuance.require!(context == self.context && operation == @operation_id &&
          plan == @plan_sha256 && request == @request_sha256 && @key_saved_ack_sha256.match?(Provisioning::SHA256))
        @ack_consumed = true
        true
      end

      def frame(response)
        JSON.generate({ "schemaVersion" => 1, "scope" => SCOPE, "contextSha256" => context, "bundleId" => bundle_id,
                        "operationId" => @operation_id, "requestSha256" => @request_sha256,
                        "keySavedAckSha256" => @key_saved_ack_sha256, "ackSha256" => @ack_sha256,
                        "response" => response }, ascii_only: true) + "\n"
      end

      private

      def read(path, query)
        { "kind" => @step, "method" => "GET", "path" => path, "query" => query, "body" => nil }
      end

      def text(environment, name, maximum)
        value = environment[PREFIX + name]
        AppleCertificateIssuance.require!(value.instance_of?(String) && value.ascii_only? &&
          value.bytesize.between?(1, maximum) && !value.include?("\0"))
        value.dup.freeze
      end
    end

    # Reuse the exact selected-token/origin/TLS/thread/raw-response owner.
    # Only this fixed companion can consume certificate write approval;
    # the ordinary ReadOwner's before_write! remains unconditionally false.
    class Owner < Read::ReadOwner
      def initialize(input, token, client)
        AppleCertificateIssuance.require!(input.instance_of?(Input))
        super
      end

      def inspect = "#<AppleCertificateIssuance::Owner private>"

      def before_write!(context, operation, plan, request)
        check!(context)
        @input.consume_ack!(context, operation, plan, request)
      end

      def before_wire!(environment)
        check!(@input.context)
        AppleCertificateIssuance.require!(!@sent)
        @sent = true # Including refused/uncertain entry; no logical retry.
        url, request = environment[:url], @input.request
        AppleCertificateIssuance.require!(url.is_a?(URI::HTTPS) && url.scheme == "https" &&
          url.host == "api.appstoreconnect.apple.com" && url.port == 443 && url.userinfo.nil? &&
          url.fragment.nil? && url.path == request.fetch("path") && url.to_s.bytesize <= 4096 &&
          environment[:request_headers]["Authorization"] == "Bearer #{@token.text}")
        if @input.step == "create_certificate"
          AppleCertificateIssuance.require!(@input.ack_consumed? && environment[:method] == :post &&
            (url.query.nil? || url.query.empty?) && environment[:body].instance_of?(String) &&
            environment[:body] == request.fetch("body").to_json)
        else
          pairs = URI.decode_www_form(url.query || "")
          AppleCertificateIssuance.require!(environment[:method] == :get && environment[:body].nil? &&
            pairs.size == request.fetch("query").size && pairs.to_h == request.fetch("query") && !@input.ack_consumed?)
        end
        true
      end

      def capture!(environment)
        check!(@input.context)
        AppleCertificateIssuance.require!(@sent && !@captured)
        @captured = true
        body, status = environment[:body], environment[:status]
        AppleCertificateIssuance.require!(body.instance_of?(String) && body.bytesize.between?(1, RAW_LIMIT) &&
          status.instance_of?(Integer) && status.between?(100, 599))
        @status, @raw = status, body.dup.force_encoding(Encoding::BINARY).freeze
        true
      end

    end

    class Operation
      def initialize(input)
        AppleCertificateIssuance.require!(input.instance_of?(Input))
        @input, @used = input, false
      end

      def inspect = "#<AppleCertificateIssuance::Operation private>"

      def execute
        AppleCertificateIssuance.require!(!@used)
        @used = true
        Read.load_sdk!
        token = @input.token
        client = Spaceship::ConnectAPI::APIClient.new(token: token)
        owner = Owner.new(@input, token, client)
        adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: @input.context)
        result = adapter.exchange(@input.request, approval: @input.approval)
        frame = @input.frame(owner.finish(result))
        AppleCertificateIssuance.require!(frame.bytesize <= FRAME_LIMIT)
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
    code = MobileReleaseKit::AppleCertificateIssuance.main(ARGV, ENV, STDOUT)
  rescue Exception
    code = 70 # Fatal interruption never renders a private exception/backtrace.
  end
  exit(code)
end
