# frozen_string_literal: true

# Fixed private worker entry, not a new public CLI/HTTP client. Only the existing
# native StorePreflightRun supplies its selected P8 and held installed runtime.
# Never load Fastfile: its release transport/consent is a different contract.
require "base64"
require "json"
require "uri"
require_relative "apple_provisioning"

module MobileReleaseKit
  module AppleBundleRead
    RAW_LIMIT = 32 * 1024
    FRAME_LIMIT = 64 * 1024
    ORIGIN = "https://api.appstoreconnect.apple.com/"
    PRIVATE_FAILURE = "provider_request_unconfirmed"
    SAFE_FASTLANE = %w[FASTLANE_HIDE_CHANGELOG FASTLANE_OPT_OUT_USAGE FASTLANE_SKIP_DOCS FASTLANE_SKIP_UPDATE_CHECK].freeze

    class Error < StandardError
      def initialize = super("The selected Bundle-ID read is unavailable.")
    end

    def self.require!(value)
      raise Error unless value
    end

    def self.supported_input?(input)
      input.instance_of?(Input) ||
        (defined?(AppleProfileRead::Input) && input.instance_of?(AppleProfileRead::Input)) ||
        (defined?(AppleCertificateIssuance::Input) && input.instance_of?(AppleCertificateIssuance::Input)) ||
        (defined?(AppleStoreVersions::Input) && input.instance_of?(AppleStoreVersions::Input)) ||
        (defined?(AppleSigningProvisioning::Input) && input.instance_of?(AppleSigningProvisioning::Input))
    end

    class Input
      attr_reader :bundle_id, :context, :key_id, :issuer_id

      def initialize(environment)
        names = environment.keys
        AppleBundleRead.require!(names.size <= 256 && names.all? { |name| name.instance_of?(String) && name.bytesize <= 256 })
        # No SDK ambient account, proxy/debug TLS switch, cookies or interactive
        # login. Bundler's own fixed Ruby setup environment is left untouched.
        AppleBundleRead.require!(names.none? do |name|
          (name.start_with?("SPACESHIP_") && name != "SPACESHIP_TIMEOUT") ||
            (name.start_with?("FASTLANE_") && !SAFE_FASTLANE.include?(name)) ||
            %w[DEBUG VERBOSE HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy].include?(name)
        end)
        AppleBundleRead.require!(environment["SPACESHIP_TIMEOUT"] == "30" &&
          SAFE_FASTLANE.all? { |name| environment[name] == "true" })
        @bundle_id = text(environment, "MOBILE_RELEASE_ASC_BUNDLE_ID", 255)
        @context = text(environment, "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT", 64)
        @key_id = text(environment, "MOBILE_RELEASE_ASC_KEY_ID", 10)
        @issuer_id = text(environment, "MOBILE_RELEASE_ASC_ISSUER_ID", 36)
        AppleBundleRead.require!(@bundle_id.match?(AppleProvisioning::BUNDLE) && @context.match?(AppleProvisioning::SHA256) &&
          @key_id.match?(/\A[A-Z0-9]{10}\z/) && @issuer_id.match?(/\A[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\z/))
        encoded = text(environment, "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", 4 * ((16 * 1024 + 2) / 3))
        @key = Base64.strict_decode64(encoded).freeze
        AppleBundleRead.require!(@key.bytesize.between?(1, 16 * 1024) && Base64.strict_encode64(@key) == encoded)
      rescue StandardError
        raise Error.new, cause: nil
      end

      def inspect = "#<AppleBundleRead::Input private>"

      def token
        # Same maintained API-key construction used by Fastlane, without its
        # global token setter, cookie selection, keyfile fallback or Fastfile.
        token = Spaceship::ConnectAPI::Token.create(key_id: @key_id, issuer_id: @issuer_id, key: @key,
          duration: 1200, in_house: false)
        token.extend(NoRefresh)
        AppleBundleRead.require!(token.key_id == @key_id && token.issuer_id == @issuer_id &&
          token.in_house == false && token.key_raw.equal?(@key) && !token.expired?)
        token
      end

      def request
        { "kind" => "list_bundle_ids", "method" => "GET", "path" => "/v1/bundleIds", "body" => nil,
          "query" => { "filter[identifier]" => @bundle_id, "fields[bundleIds]" => "identifier,platform,seedId", "limit" => "200" } }
      end

      def frame(response)
        JSON.generate({ "schemaVersion" => 1, "contextSha256" => @context,
                        "bundleId" => @bundle_id, "response" => response }, ascii_only: true) + "\n"
      end

      private

      def text(environment, name, maximum)
        value = environment[name]
        AppleBundleRead.require!(value.instance_of?(String) && value.ascii_only? && value.bytesize.between?(1, maximum) && !value.include?("\0"))
        value.dup.freeze
      end
    end

    # The initial supported Token.create above creates the JWT. Only that exact
    # token is extended; later middleware/SDK refresh attempts refuse, not retry.
    module NoRefresh
      def refresh! = raise(Error)
    end

    # Faraday1.10.6 RackBuilder#use appends nearest the existing adapter; response
    # callbacks run from that inner app outward. This callback therefore sees
    # the original String BEFORE response(:json)/(:plist) normalize anything.
    # The byte cap is AFTER the HTTP adapter has buffered, not a socket/RSS cap.
    class RawResponse
      def initialize(app, owner)
        @app, @owner = app, owner
      end

      def call(environment)
        @owner.before_wire!(environment)
        @app.call(environment).on_complete { |response| @owner.capture!(response) }
      end

      def inspect = "#<AppleBundleRead::RawResponse private>"
    end

    class ReadOwner
      def initialize(input, token, client)
        AppleBundleRead.require!(AppleBundleRead.supported_input?(input))
        @input, @token, @client, @thread = input, token, client, Thread.current
        @request = AppleProvisioning::Request.new(input.request)
        kind = if input.instance_of?(Input) then "list_bundle_ids"
               elsif defined?(AppleProfileRead::Input) && input.instance_of?(AppleProfileRead::Input) then "list_profiles"
               elsif defined?(AppleCertificateIssuance::Input) && input.instance_of?(AppleCertificateIssuance::Input) then input.step
               elsif defined?(AppleSigningProvisioning::Input) && input.instance_of?(AppleSigningProvisioning::Input) then input.step
               else "current_app_before"
               end
        AppleBundleRead.require!(@request.kind == kind)
        @connection, @builder = client.client, client.client.builder
        @admitted = @sent = @captured = @finished = false
        @raw = @status = nil
        AppleBundleRead.require!(@connection.instance_of?(Faraday::Connection) && @builder.instance_of?(Faraday::RackBuilder) && !@builder.locked?)
        @builder.use(RawResponse, self)
        @handler_count = @builder.handlers.size
        current!(input.context)
      end

      def inspect = "#<AppleBundleRead::ReadOwner private>"

      def admit_client!(client, context)
        AppleBundleRead.require!(!@admitted && client.equal?(@client))
        current!(context)
        @admitted = true
      end

      def check!(context)
        AppleBundleRead.require!(@admitted)
        current!(context)
      end

      # This particular worker has NO write permission, including when supplied
      # an otherwise well-shaped provisioning approval/operation ID.
      def before_write!(*) = false

      def before_wire!(environment)
        check!(@input.context)
        AppleBundleRead.require!(!@sent)
        @sent = true # A failed or lost wire entry consumes this one read.
        url = environment[:url]
        AppleBundleRead.require!(environment[:method] == :get && environment[:body].nil? && url.is_a?(URI::HTTPS) &&
          url.scheme == "https" && url.host == "api.appstoreconnect.apple.com" && url.port == 443 &&
          url.userinfo.nil? && url.fragment.nil? && url.path == @request.path && url.to_s.bytesize <= 2048)
        pairs = URI.decode_www_form(url.query || "")
        AppleBundleRead.require!(pairs.size == @request.query.size && pairs.to_h == @request.query &&
          environment[:request_headers]["Authorization"] == "Bearer #{@token.text}")
        true
      end

      def capture!(environment)
        check!(@input.context)
        AppleBundleRead.require!(@sent && !@captured)
        @captured = true # Invalid/duplicate callbacks never get a second chance.
        body, status = environment[:body], environment[:status]
        AppleBundleRead.require!(body.instance_of?(String) && body.bytesize.between?(1, RAW_LIMIT) &&
          status.instance_of?(Integer) && status.between?(100, 599))
        @status, @raw = status, body.dup.force_encoding(Encoding::BINARY).freeze
        true
      end

      def finish(result)
        check!(@input.context)
        @finished = true
        same_response = result.instance_of?(AppleProvisioning::Result) && @sent && @captured && @raw && result.status == @status
        if same_response && result.failure.nil?
          { "status" => @status, "bodyBase64" => Base64.strict_encode64(@raw), "failure" => nil }
        else
          { "status" => same_response ? @status : nil, "bodyBase64" => nil, "failure" => PRIVATE_FAILURE }
        end
      end

      private

      def current!(context)
        AppleBundleRead.require!(!@finished && Thread.current.equal?(@thread) && context == @input.context &&
          @client.token.equal?(@token) && @client.hostname == ORIGIN && !@client.web_session? &&
          @token.in_house == false && @token.key_id == @input.key_id && @token.issuer_id == @input.issuer_id && !@token.expired? &&
          @client.csrf_tokens.empty? && @client.additional_headers.empty? && @client.client.equal?(@connection) &&
          @connection.builder.equal?(@builder) && @connection.proxy.nil? && @connection.ssl[:verify] != false &&
          @connection.ssl[:verify_mode] != 0 && @builder.handlers.size == @handler_count &&
          @builder.handlers.last.klass == RawResponse && @builder.adapter.klass.name == "Faraday::Adapter::NetHttp")
        true
      end
    end

    class Operation
      def initialize(input)
        AppleBundleRead.require!(AppleBundleRead.supported_input?(input))
        @input, @used = input, false
      end

      def inspect = "#<AppleBundleRead::Operation private>"

      def execute
        AppleBundleRead.require!(!@used)
        @used = true # Even failed SDK loading/construction cannot replay.
        AppleBundleRead.load_sdk!
        token = @input.token
        client = Spaceship::ConnectAPI::APIClient.new(token: token)
        owner = ReadOwner.new(@input, token, client)
        adapter = AppleProvisioning::Adapter.new(client: client, owner: owner, context_sha256: @input.context)
        result = adapter.exchange(@input.request)
        frame = @input.frame(owner.finish(result))
        AppleBundleRead.require!(frame.bytesize <= FRAME_LIMIT)
        frame
      rescue StandardError
        # No exception text, normalized provider body, P8, JWT or account IDs.
        # Interrupted/fatal Exception subclasses are NOT turned into observations.
        @input.frame("status" => nil, "bodyBase64" => nil, "failure" => PRIVATE_FAILURE)
      end
    end

    def self.load_sdk!
      require "spaceship"
      require!(Gem.loaded_specs.fetch("fastlane").version.to_s == "2.235.0" &&
        Gem.loaded_specs.fetch("faraday").version.to_s == "1.10.6" &&
        Gem.loaded_specs.fetch("faraday_middleware").version.to_s == "1.2.1")
    end

    def self.main(arguments, environment, output, query: :bundle)
      require!(arguments.empty?)
      # The fixed entry script selects one of two exact classes; no endpoint,
      # factory, credential, arbitrary operation or caller-selected URL input.
      input = case query
              when :bundle then Input.new(environment)
              when :profiles
                require!(defined?(AppleProfileRead::Input))
                AppleProfileRead::Input.new(environment)
              else raise Error
              end # Refuse ambient SDK state before loading it.
      frame = Operation.new(input).execute
      require!(frame.bytesize <= FRAME_LIMIT && output.write(frame) == frame.bytesize)
      output.flush
      0
    rescue StandardError
      70 # Fixed failure; no private exception/backtrace output.
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::AppleBundleRead.main(ARGV, ENV, STDOUT)
  rescue Exception
    # Do not let Ruby format private state after interruption/fatal failure.
    # This is a failed worker, never a provider observation or cleanup proof.
    Process.exit!(70)
  end
  exit(code)
end
