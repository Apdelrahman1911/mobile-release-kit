# frozen_string_literal: true

# Fixed private command for the separate native provisioning owner. This is
# NOT another read-query flag or a public CLI: only that owner's original
# selected-P8/runtime loan may launch it. For register, the parent must first
# obtain and consume its durable Pending ACK under the original W/STOP clock.
# The ACK digest below binds that handoff; a string is not native authority.
require_relative "apple_provisioning_bundle_read"

module MobileReleaseKit
  module AppleBundleRegistration
    Read = AppleBundleRead
    Provisioning = AppleProvisioning
    RAW_LIMIT = Read::RAW_LIMIT
    FRAME_LIMIT = Read::FRAME_LIMIT
    PRIVATE_FAILURE = Read::PRIVATE_FAILURE
    PREFIX = "MOBILE_RELEASE_ASC_PROVISIONING_"
    COMMON = %w[STEP OPERATION_ID].freeze
    WRITE = %w[PLAN_SHA256 ACK_SHA256 DISPLAY_NAME_BASE64].freeze

    class Error < StandardError
      def initialize = super("The selected Bundle-ID operation is unconfirmed.")
    end

    def self.require!(condition)
      raise Error unless condition
    end

    class Input
      attr_reader :step, :operation_id, :plan_sha256, :ack_sha256, :request_sha256

      def initialize(environment)
        # Reuse explicit selected Token.create, no-refresh and clean ambient
        # environment checks. Never change ReadOwner's unconditional write veto.
        @key = Read::Input.new(environment)
        @step = text(environment, "STEP", 8)
        AppleBundleRegistration.require!(%w[inspect register].include?(@step))
        expected = COMMON + (@step == "register" ? WRITE : [])
        AppleBundleRegistration.require!(environment.keys.select { |name| name.start_with?(PREFIX) }.sort ==
          expected.map { |name| PREFIX + name }.sort)
        @operation_id = text(environment, "OPERATION_ID", 128)
        AppleBundleRegistration.require!(@operation_id.match?(Provisioning::ID))
        @plan_sha256 = @ack_sha256 = nil
        if @step == "register"
          @plan_sha256, @ack_sha256 = %w[PLAN_SHA256 ACK_SHA256].map { |name| text(environment, name, 64) }
          AppleBundleRegistration.require!([@plan_sha256, @ack_sha256].all? { |value| value.match?(Provisioning::SHA256) })
          encoded = text(environment, "DISPLAY_NAME_BASE64", 4 * ((512 + 2) / 3))
          name = Base64.strict_decode64(encoded).force_encoding(Encoding::UTF_8)
          AppleBundleRegistration.require!(Base64.strict_encode64(name) == encoded && name.valid_encoding?)
          wire = { "kind" => "register_bundle_id", "method" => "POST", "path" => "/v1/bundleIds", "query" => {},
                   "body" => { "data" => { "type" => "bundleIds", "attributes" => {
                     "identifier" => bundle_id, "name" => name, "platform" => "IOS" } } } }
        else
          wire = @key.request
        end
        @request = Provisioning::Request.new(wire)
        @wire = Provisioning.deep_freeze(wire)
        @request_sha256 = @request.sha256
        @ack_attempted = @ack_consumed = false
      rescue StandardError
        raise Error.new, cause: nil
      end

      def inspect = "#<AppleBundleRegistration::Input private>"
      def context = @key.context
      def bundle_id = @key.bundle_id
      def key_id = @key.key_id
      def issuer_id = @key.issuer_id
      def token = @key.token
      def request = @wire

      def approval
        @step == "register" ? { "operationId" => @operation_id, "planSha256" => @plan_sha256 } : nil
      end

      def consume_ack!(context, operation, plan, request)
        AppleBundleRegistration.require!(@step == "register" && !@ack_attempted)
        @ack_attempted = true # Foreign or failed admission never renews the ACK.
        AppleBundleRegistration.require!(
          context == self.context && operation == @operation_id && plan == @plan_sha256 && request == @request_sha256)
        @ack_consumed = true
        true
      end

      def ack_consumed? = @ack_consumed

      def frame(response)
        JSON.generate({ "schemaVersion" => 1, "contextSha256" => context, "bundleId" => bundle_id,
                        "operationId" => @operation_id, "requestSha256" => @request_sha256,
                        "ackSha256" => @ack_sha256, "response" => response }, ascii_only: true) + "\n"
      end

      private

      def text(environment, name, maximum)
        value = environment[PREFIX + name]
        AppleBundleRegistration.require!(value.instance_of?(String) && value.ascii_only? &&
          value.bytesize.between?(1, maximum) && !value.include?("\0"))
        value.dup.freeze
      end
    end

    # A new closed owner, not a permission added to ReadOwner/release transport.
    # It reuses the SAME maintained client/ScopedTransport/raw callback order.
    class Owner
      def initialize(input, token, client)
        AppleBundleRegistration.require!(input.instance_of?(Input))
        @input, @token, @client, @thread = input, token, client, Thread.current
        @connection, @builder = client.client, client.client.builder
        @admitted = @sent = @captured = @finished = false
        @raw = @status = nil
        AppleBundleRegistration.require!(@connection.instance_of?(Faraday::Connection) &&
          @builder.instance_of?(Faraday::RackBuilder) && !@builder.locked?)
        @builder.use(Read::RawResponse, self)
        @handler_count = @builder.handlers.size
        current!(input.context)
      end

      def inspect = "#<AppleBundleRegistration::Owner private>"

      def admit_client!(client, context)
        AppleBundleRegistration.require!(!@admitted && client.equal?(@client))
        current!(context)
        @admitted = true
      end

      def check!(context)
        AppleBundleRegistration.require!(@admitted)
        current!(context)
      end

      def before_write!(context, operation, plan, request)
        check!(context)
        @input.consume_ack!(context, operation, plan, request)
      end

      def before_wire!(environment)
        check!(@input.context)
        AppleBundleRegistration.require!(!@sent)
        @sent = true # No second attempt even after a refused/lost wire entry.
        url, request = environment[:url], @input.request
        AppleBundleRegistration.require!(url.is_a?(URI::HTTPS) && url.scheme == "https" &&
          url.host == "api.appstoreconnect.apple.com" && url.port == 443 && url.userinfo.nil? &&
          url.fragment.nil? && url.path == "/v1/bundleIds" && url.to_s.bytesize <= 2048 &&
          environment[:request_headers]["Authorization"] == "Bearer #{@token.text}")
        if @input.step == "inspect"
          pairs = URI.decode_www_form(url.query || "")
          AppleBundleRegistration.require!(environment[:method] == :get && environment[:body].nil? &&
            pairs.size == 3 && pairs.to_h == request.fetch("query") && !@input.ack_consumed?)
        else
          # Locked APIClient#post serializes this same Hash with #to_json.
          # Compare exact original bytes, not a lossy JSON round trip.
          AppleBundleRegistration.require!(@input.ack_consumed? && environment[:method] == :post &&
            (url.query.nil? || url.query.empty?) && environment[:body].instance_of?(String) &&
            environment[:body] == request.fetch("body").to_json)
        end
        true
      end

      def capture!(environment)
        check!(@input.context)
        AppleBundleRegistration.require!(@sent && !@captured)
        @captured = true
        body, status = environment[:body], environment[:status]
        AppleBundleRegistration.require!(body.instance_of?(String) && body.bytesize.between?(1, RAW_LIMIT) &&
          status.instance_of?(Integer) && status.between?(100, 599))
        @status, @raw = status, body.dup.force_encoding(Encoding::BINARY).freeze
        true
      end

      def finish(result)
        check!(@input.context)
        @finished = true
        same = result.instance_of?(Provisioning::Result) && @sent && @captured && @raw && result.status == @status
        if same && result.failure.nil?
          { "status" => @status, "bodyBase64" => Base64.strict_encode64(@raw), "failure" => nil }
        else
          { "status" => same ? @status : nil, "bodyBase64" => nil, "failure" => PRIVATE_FAILURE }
        end
      end

      private

      def current!(context)
        AppleBundleRegistration.require!(!@finished && Thread.current.equal?(@thread) && context == @input.context &&
          @client.token.equal?(@token) && @client.hostname == Read::ORIGIN && !@client.web_session? &&
          @token.in_house == false && @token.key_id == @input.key_id && @token.issuer_id == @input.issuer_id && !@token.expired? &&
          @client.csrf_tokens.empty? && @client.additional_headers.empty? && @client.client.equal?(@connection) &&
          @connection.builder.equal?(@builder) && @connection.proxy.nil? && @connection.ssl[:verify] != false &&
          @connection.ssl[:verify_mode] != 0 && @builder.handlers.size == @handler_count &&
          @builder.handlers.last.klass == Read::RawResponse && @builder.adapter.klass.name == "Faraday::Adapter::NetHttp")
        true
      end
    end

    class Operation
      def initialize(input)
        AppleBundleRegistration.require!(input.instance_of?(Input))
        @input, @used = input, false
      end

      def inspect = "#<AppleBundleRegistration::Operation private>"

      def execute
        AppleBundleRegistration.require!(!@used)
        @used = true
        Read.load_sdk!
        token = @input.token
        client = Spaceship::ConnectAPI::APIClient.new(token: token)
        owner = Owner.new(@input, token, client)
        adapter = Provisioning::Adapter.new(client: client, owner: owner, context_sha256: @input.context)
        result = adapter.exchange(@input.request, approval: @input.approval)
        frame = @input.frame(owner.finish(result))
        AppleBundleRegistration.require!(frame.bytesize <= FRAME_LIMIT)
        frame
      rescue StandardError
        @input.frame("status" => nil, "bodyBase64" => nil, "failure" => PRIVATE_FAILURE)
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
    code = MobileReleaseKit::AppleBundleRegistration.main(ARGV, ENV, STDOUT)
  rescue Exception
    code = 70 # No private Ruby exception/backtrace after fatal interruption.
  end
  exit(code)
end
