# frozen_string_literal: true

# One explicit, non-publishing Play temporary edit on the existing pinned
# Google SDK / HTTPClient. It can invalidate another editor's in-progress edit.
# All output is private raw DATA for Python; this is not a native receipt.
require 'json'
require 'base64'
require 'digest'
require 'stringio'
require 'uri'
require 'logger'

module MobileReleaseKit
  module AndroidStoreVersions
    SCOPE = 'play-android-current-inventory/1'
    TOKEN = 'https://oauth2.googleapis.com/token'
    ORIGIN = 'https://androidpublisher.googleapis.com'
    PLAY_SCOPE = 'https://www.googleapis.com/auth/androidpublisher'
    STEPS = %w[insert tracks bundles apks delete].freeze
    RAW_LIMIT = 128 * 1024
    SMALL_LIMIT = 16 * 1024
    TOTAL_LIMIT = 1024 * 1024
    FRAME_LIMIT = 2 * 1024 * 1024
    PRIVATE_FAILURE = 'provider_request_unconfirmed'
    SECOND = 1_000_000_000

    class Error < StandardError
      def initialize = super('Current Play inventory was refused')
    end
    class Limit < Error; end
    def self.need(value) = (raise Error unless value)

    class StrictObject < Hash
      def []=(key, value)
        raise Error if key?(key)
        super
      end
    end

    def self.object(raw, limit = RAW_LIMIT)
      need(raw.instance_of?(String) && raw.bytesize.between?(1, limit))
      value = JSON.parse(raw, object_class: StrictObject, max_nesting: 16, allow_nan: false)
      need(value.is_a?(Hash))
      value
    end

    class Input
      attr_reader :package, :context, :read_end, :hard_end
      def initialize(environment)
        # A fresh native-selected environment only; never gcloud/ADC discovery,
        # custom OAuth hosts, proxy credentials, Ruby injection or debug logs.
        forbidden = %w[GOOGLE_AUTH_SUPPRESS_CREDENTIALS_WARNINGS GOOGLE_CLOUD_PROJECT GOOGLE_CLOUD_QUOTA_PROJECT
          GOOGLE_CLOUD_UNIVERSE_DOMAIN GOOGLE_AUTH_TOKEN_URL GCE_METADATA_HOST RUBYOPT RUBYLIB
          http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY]
        AndroidStoreVersions.need(forbidden.none? { |key| environment.key?(key) })
        @package = text(environment, 'MOBILE_RELEASE_PLAY_PACKAGE', 255)
        @context = text(environment, 'MOBILE_RELEASE_PLAY_CONTEXT', 64)
        AndroidStoreVersions.need(@package.match?(/\A[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\z/) &&
          @context.match?(/\A[0-9a-f]{64}\z/))
        @read_end = endpoint(environment, 'MOBILE_RELEASE_PLAY_READ_END_NS')
        @hard_end = endpoint(environment, 'MOBILE_RELEASE_PLAY_HARD_END_NS')
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        AndroidStoreVersions.need(now < @read_end && @read_end <= @hard_end && @hard_end - now <= 60 * SECOND)
        path = text(environment, 'GOOGLE_APPLICATION_CREDENTIALS', 4096)
        AndroidStoreVersions.need(path.start_with?('/') && File.const_defined?(:NOFOLLOW))
        # The original SelectedStoreMaterial owns the snapshot through native
        # postchecks. This bounded one read closes before any external effect.
        File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
          original = file.stat
          AndroidStoreVersions.need(original.file? && original.size.between?(1, SMALL_LIMIT) &&
            original.uid == Process.uid && (original.mode & 0o077).zero?)
          @json = file.read(SMALL_LIMIT + 1)
          AndroidStoreVersions.need(@json.bytesize == original.size && file.read(1).nil? && file_facts(file.stat) == file_facts(original))
        end
        key = AndroidStoreVersions.object(@json, SMALL_LIMIT)
        required = %w[type project_id private_key_id private_key client_email client_id token_uri]
        optional = %w[auth_uri auth_provider_x509_cert_url client_x509_cert_url universe_domain]
        AndroidStoreVersions.need((required - key.keys).empty? && (key.keys - required - optional).empty? &&
          key.values.all? { |value| value.instance_of?(String) && !value.empty? && !value.include?("\0") } &&
          key['type'] == 'service_account' && key['token_uri'] == TOKEN && key['project_id'].match?(/\A[a-z][a-z0-9-]{4,61}[a-z0-9]\z/) &&
          key['client_email'].match?(/\A[a-zA-Z0-9._-]{1,64}@#{Regexp.escape(key['project_id'])}\.iam\.gserviceaccount\.com\z/) &&
          key['private_key_id'].match?(/\A[a-fA-F0-9]{40}\z/) && key['client_id'].match?(/\A[0-9]{1,32}\z/) &&
          key['private_key'].start_with?("-----BEGIN PRIVATE KEY-----\n") && key['private_key'].rstrip.end_with?('-----END PRIVATE KEY-----'))
        { 'auth_uri' => 'https://accounts.google.com/o/oauth2/auth',
          'auth_provider_x509_cert_url' => 'https://www.googleapis.com/oauth2/v1/certs', 'universe_domain' => 'googleapis.com' }.each do |name, expected|
          AndroidStoreVersions.need(!key.key?(name) || key[name] == expected)
        end
        if key.key?('client_x509_cert_url')
          base = 'https://www.googleapis.com/robot/v1/metadata/x509/'
          AndroidStoreVersions.need([base + key['client_email'], base + key['client_email'].sub('@', '%40')].include?(key['client_x509_cert_url']))
        end
      end
      def inspect = '#<AndroidStoreVersions::Input private>'
      def credentials
        Google::Auth::ServiceAccountCredentials.make_creds(json_key_io: StringIO.new(@json), scope: PLAY_SCOPE,
          token_credential_uri: TOKEN, audience: TOKEN, enable_self_signed_jwt: false)
      end
      def request(step, edit)
        AndroidStoreVersions.need(STEPS.include?(step) && (step == 'insert' ? edit.nil? : edit.instance_of?(String) && edit.match?(/\A[A-Za-z0-9_-]{1,128}\z/)))
        path = "/androidpublisher/v3/applications/#{@package}/edits"
        path += "/#{edit}" unless step == 'insert'
        path += "/#{step}" unless %w[insert delete].include?(step)
        { 'kind' => "current_#{step}", 'method' => step == 'insert' ? 'POST' : step == 'delete' ? 'DELETE' : 'GET',
          'path' => path, 'query' => {}, 'body' => step == 'insert' ? {} : nil }
      end
      private
      def file_facts(stat)
        [stat.dev, stat.ino, stat.mode, stat.uid, stat.gid, stat.nlink, stat.size, stat.mtime, stat.ctime]
      end
      def text(environment, name, limit)
        value = environment[name]
        AndroidStoreVersions.need(value.instance_of?(String) && value.bytesize.between?(1, limit) && !value.include?("\0"))
        value.dup.freeze
      end
      def endpoint(environment, name)
        value = text(environment, name, 20)
        AndroidStoreVersions.need(value.match?(/\A[1-9][0-9]{0,19}\z/))
        Integer(value, 10)
      end
    end

    # Attached to ONE actual HTTPClient instance. HTTPClient 2.9 calls this
    # before Session#query on EVERY do_get_block, including internal retries.
    class SendFilter
      def initialize(owner) = (@owner = owner)
      def filter_request(request) = @owner.before_wire(request)
      def filter_response(_request, _response) = nil
      def inspect = '#<AndroidStoreVersions::SendFilter private>'
    end

    # Closed per-command override, not a replacement transport. The SDK still
    # builds/serializes the exact fixed ApiCommand. Its usual follow_redirect,
    # buffered error decoder and refresh path are NOT used in this query.
    module RawCommand
      def logger = @mrk_inventory.logger
      def execute_once(client)
        @mrk_inventory.require_client(client)
        request_header = header.dup
        apply_request_options(request_header)
        response = client.request(method.to_s.upcase, url.to_s, query: nil, body: body,
          header: request_header, follow_redirect: false) { |res, part| @mrk_inventory.append(res, part) }
        @mrk_inventory.complete(response) # Raw body retained before any parsing/late clock check.
      end
    end

    # Signet's supported non-Faraday connector. The real signer generates the
    # assertion; this never implements JWT, discovers credentials or retries.
    class TokenConnection
      Response = Struct.new(:status_code, :body, :header) do
        def status = status_code
        def inspect = '#<AndroidStoreVersions::TokenResponse private>'
      end
      def initialize(owner) = (@owner = owner)
      def post(url, parameters)
        AndroidStoreVersions.need(url == TOKEN && parameters.instance_of?(Hash) &&
          parameters.keys.sort == %w[assertion grant_type] && parameters['grant_type'] == 'urn:ietf:params:oauth:grant-type:jwt-bearer' &&
          parameters['assertion'].instance_of?(String) && parameters['assertion'].bytesize.between?(1, SMALL_LIMIT))
        body = URI.encode_www_form(parameters)
        client = @owner.token_slot(body)
        response = client.request('POST', TOKEN, query: nil, body: body,
          header: { 'Content-Type' => 'application/x-www-form-urlencoded' }, follow_redirect: false) { |res, part| @owner.append(res, part) }
        raw = @owner.complete(response)
        # Full bounded object before Signet's ordinary JSON parser. Errors stay
        # private even when Signet constructs an exception including its body.
        AndroidStoreVersions.object(raw, SMALL_LIMIT)
        Response.new(response.status, raw, { content_type: 'application/json' })
      end
      def inspect = '#<AndroidStoreVersions::TokenConnection private>'
    end

    class Operation
      attr_reader :logger
      def initialize(input)
        AndroidStoreVersions.need(input.instance_of?(Input))
        @input, @used, @pages = input, false, []
        @insert_entered = @delete_entered = @delete_confirmed = @finished = false
        @edit = @token = @slot = @client = @service = nil
        @total, @sequence, @clock_bad = 0, -1, false
        @last_clock = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        @cleanup_end, @first_failure = input.hard_end, nil
        @logger = Logger.new(nil)
      end
      def inspect = '#<AndroidStoreVersions::Operation private>'

      def execute
        AndroidStoreVersions.need(!@used)
        @used = true
        begin
          AndroidStoreVersions.load_sdk!
          check
          @service = Google::Apis::AndroidpublisherV3::AndroidPublisherService.new
          @service.root_url = ORIGIN + '/'
          @service.universe_domain = 'googleapis.com'
          @service.client_options.log_http_requests = false
          @service.client_options.transparent_gzip_decompression = false
          @service.client_options.proxy_url = nil
          @service.define_singleton_method(:logger) { @mrk_inventory.logger }
          @service.instance_variable_set(:@mrk_inventory, self)
          @client = @service.client
          AndroidStoreVersions.need(@client.instance_of?(HTTPClient))
          @client.proxy = nil
          @client.debug_dev = nil
          @client.transparent_gzip_decompression = false
          @client.follow_redirect_count = 0
          @filter = SendFilter.new(self)
          @client.instance_variable_set(:@request_filter, [@filter])
          @service.define_singleton_method(:execute_or_queue_command) do |command, &callback|
            AndroidStoreVersions.need(callback.nil? && current_batch.nil? && command.instance_of?(Google::Apis::Core::ApiCommand))
            @mrk_inventory.bind_command(command)
            command.execute(client)
          end
          # Deliberately NON-bang: googleauth's bang wrapper retries failures.
          credentials = @input.credentials
          token = credentials.fetch_access_token(connection: TokenConnection.new(self))
          AndroidStoreVersions.need(token.instance_of?(Hash) && token['access_token'].instance_of?(String) &&
            token['access_token'].bytesize.between?(1, SMALL_LIMIT) && token['access_token'].match?(/\A[!-~]+\z/) &&
            token['token_type'] == 'Bearer' && token['expires_in'].instance_of?(Integer) && token['expires_in'] >= 60)
          @token = token['access_token'].dup.freeze
          @service.authorization = @token # String: no apply!, refresh or ambient credentials.
          api('insert')
          AndroidStoreVersions.need(!@edit.nil?)
          %w[tracks bundles apks].each { |step| api(step) }
          @finished = true
        rescue StandardError
          failed
        ensure
          failed unless @finished
          if @edit && !@delete_entered
            begin
              api('delete')
            rescue StandardError
              failed
            end
          end
        end
        frame
      end

      def require_client(client)
        AndroidStoreVersions.need(client.equal?(@client) && @service.client.equal?(@client) &&
          @client.instance_variable_get(:@request_filter) == [@filter] && @client.proxy.nil? &&
          @client.debug_dev.nil? && !@client.transparent_gzip_decompression && @slot && !@slot[:complete])
        check(cleanup: @slot[:step] == 'delete')
      end

      def token_slot(body)
        AndroidStoreVersions.need(@sequence == -1 && @slot.nil? && @token.nil?)
        @sequence = 0
        slot('token', 'POST', TOKEN, body, SMALL_LIMIT)
        @client
      end

      def bind_command(command)
        require_client(@client)
        AndroidStoreVersions.need(@slot[:step] != 'token')
        command.options.retries = 0
        command.options.authorization = @token
        command.options.skip_deserialization = true
        command.instance_variable_set(:@mrk_inventory, self)
        command.extend(RawCommand)
      end

      def before_wire(request)
        require_client(@client)
        s = @slot
        AndroidStoreVersions.need(!s[:sent] && request.header.request_method.to_s.upcase == s[:method] &&
          request.header.request_uri.to_s == s[:url] && request.header.request_query.nil? &&
          request.http_body.content == s[:body] && !request.header.request_absolute_uri)
        auth = request.header['Authorization']
        AndroidStoreVersions.need(s[:step] == 'token' ? auth.empty? : auth == ['Bearer ' + @token])
        s[:sent] = true # Before the underlying Session#query, also on failed sends.
        @insert_entered = true if s[:step] == 'insert'
        @delete_entered = true if s[:step] == 'delete'
        true
      end

      def append(response, part)
        s = @slot
        AndroidStoreVersions.need(s && s[:sent] && !s[:complete] && part.instance_of?(String))
        status = response.status
        AndroidStoreVersions.need(status.instance_of?(Integer) && status.between?(100, 599) && (!s[:status] || s[:status] == status))
        s[:status] = status
        if s[:raw].bytesize + part.bytesize > s[:limit] || @total + part.bytesize > TOTAL_LIMIT
          s[:failure] = 'inventory_limit'
          raise Limit
        end
        s[:raw] << part.b # BEFORE SDK response/error parsing; streaming has no other body append.
        @total += part.bytesize
        check(cleanup: s[:step] == 'delete')
      end

      def complete(response)
        s = @slot
        AndroidStoreVersions.need(s && s[:sent] && !s[:complete] && s[:failure].nil? &&
          response.status.instance_of?(Integer) && response.status.between?(100, 599) &&
          (!s[:status] || s[:status] == response.status))
        s[:status], s[:complete] = response.status, true
        if s[:step] == 'insert' && s[:status] == 200
          created = AndroidStoreVersions.object(s[:raw], SMALL_LIMIT)
          AndroidStoreVersions.need(created.keys.sort == %w[expiryTimeSeconds id] &&
            created['id'].instance_of?(String) && created['id'].match?(/\A[A-Za-z0-9_-]{1,128}\z/) &&
            created['expiryTimeSeconds'].instance_of?(String) && created['expiryTimeSeconds'].match?(/\A[1-9][0-9]{0,18}\z/))
          @edit = created['id'].dup.freeze # Retain before a late STOP/work-clock refusal.
        elsif s[:step] == 'delete'
          @delete_confirmed = s[:status] == 204 && s[:raw].empty?
        end
        check(cleanup: s[:step] == 'delete')
        s[:raw]
      end

      private
      def check(cleanup: false)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        @clock_bad = true unless now.instance_of?(Integer) && now >= @last_clock
        AndroidStoreVersions.need(!@clock_bad)
        @last_clock = now
        AndroidStoreVersions.need(now < (cleanup ? @cleanup_end : @input.read_end))
        remaining = ((cleanup ? @cleanup_end : @input.read_end) - now).fdiv(SECOND)
        if @client
          @client.connect_timeout = @client.send_timeout = @client.receive_timeout = [remaining, 10].min
        end
        true
      end
      def failed
        @finished = false # A late/failed DELETE never publishes a usable floor.
        return if @first_failure
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        @clock_bad = true unless now.instance_of?(Integer) && now >= @last_clock
        @first_failure = @clock_bad ? @last_clock : now
        @cleanup_end = [@cleanup_end, @first_failure + 10 * SECOND].min
      end
      def slot(step, method, url, body, limit)
        check(cleanup: step == 'delete')
        @slot = { step: step, method: method, url: url, body: body, limit: limit,
                  sent: false, complete: false, status: nil, raw: +''.b, failure: nil }
      end
      def api(step)
        index = STEPS.index(step)
        AndroidStoreVersions.need(index && @token && !@delete_entered &&
          (step == 'delete' ? @edit && @sequence.between?(1, 4) : @sequence == index))
        @sequence = index + 1 # Never reset a failed command into another insert/list.
        wire = @input.request(step, step == 'insert' ? nil : @edit)
        slot(step, wire['method'], ORIGIN + wire['path'], step == 'insert' ? '{}' : '',
             %w[insert delete].include?(step) ? SMALL_LIMIT : RAW_LIMIT)
        begin
          case step
          when 'insert' then @service.insert_edit(@input.package, Google::Apis::AndroidpublisherV3::AppEdit.new)
          when 'tracks' then @service.list_edit_tracks(@input.package, @edit)
          when 'bundles' then @service.list_edit_bundles(@input.package, @edit)
          when 'apks' then @service.list_edit_apks(@input.package, @edit)
          when 'delete' then @service.delete_edit(@input.package, @edit)
          end
          AndroidStoreVersions.need(@slot[:complete] && @slot[:status] == (step == 'delete' ? 204 : 200))
          if step == 'delete'
            AndroidStoreVersions.need(@delete_confirmed)
          elsif step != 'insert'
            object = AndroidStoreVersions.object(@slot[:raw])
            AndroidStoreVersions.need((object.keys - ['kind', step]).empty? && (!object.key?('kind') || object['kind'] == "androidpublisher##{step}ListResponse"))
            rows = object.fetch(step, [])
            raise Limit unless rows.instance_of?(Array) && rows.length <= 400
          end
        rescue StandardError => error
          @slot[:failure] ||= error.is_a?(Limit) ? 'inventory_limit' : PRIVATE_FAILURE unless @slot[:complete]
          raise
        ensure
          if @slot[:sent]
            @pages << { 'step' => step, 'request' => wire, 'response' => { 'status' => @slot[:status],
              'bodyBase64' => @slot[:complete] ? Base64.strict_encode64(@slot[:raw]) : nil,
              'failure' => @slot[:failure] || (@slot[:complete] ? nil : PRIVATE_FAILURE) } }
          end
        end
      end
      def frame
        value = { 'schemaVersion' => 1, 'scope' => SCOPE, 'contextSha256' => @input.context,
          'packageName' => @input.package, 'pages' => @pages, 'queryFinished' => @finished,
          'temporaryEdit' => { 'insertAttempted' => @insert_entered, 'editId' => @edit,
            'deleteAttempted' => @delete_entered, 'deleteConfirmed' => @delete_confirmed } }
        raw = JSON.generate(value, ascii_only: true) + "\n"
        AndroidStoreVersions.need(raw.bytesize <= FRAME_LIMIT)
        raw
      end
    end

    def self.load_sdk!
      require 'google/apis/androidpublisher_v3'
      require 'googleauth'
      { 'google-apis-androidpublisher_v3' => '0.106.0', 'google-apis-core' => '0.18.0',
        'googleauth' => '1.17.3', 'signet' => '0.22.0', 'httpclient' => '2.9.0' }.each do |name, version|
        need(Gem.loaded_specs.fetch(name).version.to_s == version)
      end
    end
    def self.main(arguments, environment, output)
      need(arguments.empty?)
      raw = Operation.new(Input.new(environment)).execute
      need(output.write(raw) == raw.bytesize)
      output.flush
      0
    rescue StandardError
      70 # No private exception, HTTP body, credential or edit ID diagnostic.
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::AndroidStoreVersions.main(ARGV, ENV, STDOUT)
  rescue Exception
    Process.exit!(70) # No observation/finality from an interrupted/fatal worker.
  end
  exit(code)
end
