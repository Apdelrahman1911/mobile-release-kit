# frozen_string_literal: true

# One closed current-inventory query on the existing selected-P8 RawResponse +
# ScopedTransport. No Fastfile, account discovery, SDK automatic pagination,
# retry, upload, edit or mutation. A frame is DATA, never native finality.
require_relative "apple_provisioning_bundle_read"

module MobileReleaseKit
  module AppleStoreVersions
    RAW_LIMIT = 128 * 1024
    RAW_TOTAL_LIMIT = 1024 * 1024
    FRAME_LIMIT = 2 * 1024 * 1024
    MAX_REQUESTS = 8
    QUERY_SECONDS = 60
    COLLECTIONS = %w[builds buildUploads appStoreVersions].freeze
    SCOPE = "asc-ios-current-inventory/1"

    # Reuse the same original selected P8 and nonrefreshing instance token.
    class Input < AppleBundleRead::Input
      attr_reader :app_id

      def initialize(environment)
        super
        @app_id = text(environment, "MOBILE_RELEASE_ASC_APP_ID", 20)
        AppleBundleRead.require!(@app_id.match?(/\A[1-9][0-9]{0,19}\z/))
      end

      def inspect = "#<AppleStoreVersions::Input private>"
      def request = request_for("app-before")

      def request_for(step, cursor: nil)
        path, query = case step
                      when "app-before", "app-after"
                        ["/v1/apps/#{@app_id}", { "fields[apps]" => "bundleId" }]
                      when "builds"
                        ["/v1/builds", { "filter[app]" => @app_id, "include" => "app,preReleaseVersion",
                          "fields[builds]" => "version,app,preReleaseVersion", "fields[apps]" => "bundleId",
                          "fields[preReleaseVersions]" => "version,platform,app", "limit" => "200" }]
                      when "buildUploads"
                        ["/v1/apps/#{@app_id}/buildUploads", {
                          "fields[buildUploads]" => "cfBundleVersion,cfBundleShortVersionString,platform,build", "limit" => "200" }]
                      when "appStoreVersions"
                        ["/v1/apps/#{@app_id}/appStoreVersions", { "fields[appStoreVersions]" => "versionString,platform", "limit" => "200" }]
                      else raise AppleBundleRead::Error
                      end
        if cursor
          AppleBundleRead.require!(COLLECTIONS.include?(step) && cursor.instance_of?(String) && cursor.bytesize.between?(1, 1024) && cursor.match?(/\A[!-~]+\z/))
          query = query.merge("cursor" => cursor)
        end
        { "kind" => "current_#{step.tr('-', '_')}", "method" => "GET", "path" => path, "query" => query, "body" => nil }
      end

      def frame(pages, query_finished: false)
        JSON.generate({ "schemaVersion" => 1, "scope" => SCOPE, "contextSha256" => context,
          "appStoreAppId" => @app_id, "bundleId" => bundle_id, "pages" => pages,
          "queryFinished" => query_finished }, ascii_only: true) + "\n"
      end
    end

    class StrictObject < Hash
      def []=(key, value)
        raise AppleBundleRead::Error if key?(key)
        super
      end
    end

    # Same original raw callback and current token/client/connection checks.
    # Only this closed subclass has multiple finite GET slots and larger caps;
    # Bundle/Profile single-read semantics and their 32/64KiB limits do not change.
    class ReadOwner < AppleBundleRead::ReadOwner
      attr_reader :pages

      def initialize(input, token, client)
        AppleBundleRead.require!(input.instance_of?(Input))
        @last_clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        AppleBundleRead.require!(@last_clock.finite?)
        @deadline = @last_clock + QUERY_SECONDS
        @pages, @total_bytes, @seen = [], 0, {}
        @step, @wire, @page_finished, @limit_hit = "app-before", AppleProvisioning.deep_freeze(input.request), false, false
        super
      end

      def inspect = "#<AppleStoreVersions::ReadOwner private>"

      def check!(context)
        super
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        AppleBundleRead.require!(now.finite? && now >= @last_clock && now < @deadline)
        @last_clock = now
        true
      end

      def next_read!(step, wire)
        check!(@input.context)
        AppleBundleRead.require!(@page_finished && @pages.size < MAX_REQUESTS && wire == @input.request_for(step, cursor: wire["query"]["cursor"]))
        # A lost/failed read consumes the original schedule; it cannot reset.
        AppleBundleRead.require!(@pages.last["response"]["status"] == 200 && @pages.last["response"]["failure"].nil?)
        cursor = wire["query"]["cursor"]
        allowed = case @step
                  when "app-before" then step == "builds" && cursor.nil?
                  when "builds" then step == "builds" && !cursor.nil? || step == "buildUploads" && cursor.nil?
                  when "buildUploads" then step == "buildUploads" && !cursor.nil? || step == "appStoreVersions" && cursor.nil?
                  when "appStoreVersions" then step == "appStoreVersions" && !cursor.nil? || step == "app-after" && cursor.nil?
                  else false
                  end
        AppleBundleRead.require!(allowed && @pages.count { |p| p["step"] == step } < 2)
        digest = Digest::SHA256.hexdigest(AppleProvisioning.canonical(wire))
        AppleBundleRead.require!(!@seen.key?(digest))
        @request = AppleProvisioning::Request.new(wire)
        @wire, @step = AppleProvisioning.deep_freeze(wire), step
        @sent = @captured = @page_finished = @limit_hit = false
        @raw = @status = nil
        true
      end

      def before_wire!(environment)
        digest = Digest::SHA256.hexdigest(AppleProvisioning.canonical(@wire))
        AppleBundleRead.require!(!@seen.key?(digest) && @pages.size < MAX_REQUESTS)
        @seen[digest] = true # Even failed/lost network entry is one attempt.
        super
      end

      def capture!(environment)
        check!(@input.context)
        AppleBundleRead.require!(@sent && !@captured)
        @captured = true
        body, status = environment[:body], environment[:status]
        AppleBundleRead.require!(status.instance_of?(Integer) && status.between?(100, 599))
        @status = status
        @limit_hit = body.instance_of?(String) && (body.bytesize > RAW_LIMIT || body.bytesize + @total_bytes > RAW_TOTAL_LIMIT)
        AppleBundleRead.require!(!@limit_hit && body.instance_of?(String) && body.bytesize.between?(1, RAW_LIMIT))
        @total_bytes += body.bytesize
        @raw = body.dup.force_encoding(Encoding::BINARY).freeze
        true
      end

      def finish(result)
        check!(@input.context)
        AppleBundleRead.require!(!@page_finished && @pages.size < MAX_REQUESTS)
        @page_finished = true
        matched = result.instance_of?(AppleProvisioning::Result) && @sent && @captured && @raw && result.status == @status && result.failure.nil?
        response = { "status" => @status, "bodyBase64" => matched ? Base64.strict_encode64(@raw) : nil,
          "failure" => matched ? nil : @limit_hit ? "inventory_limit" : AppleBundleRead::PRIVATE_FAILURE }
        @pages << { "step" => @step, "request" => @wire, "response" => response }
        AppleBundleRead.require!(matched && @status == 200)
        parsed = JSON.parse(@raw, object_class: StrictObject, max_nesting: 16, create_additions: false)
        AppleBundleRead.require!(parsed.is_a?(Hash) && !parsed.key?("errors") && !parsed.key?("error"))
        parsed
      end

      def complete!
        check!(@input.context)
        AppleBundleRead.require!(@step == "app-after" && @page_finished)
        @finished = true
      end
    end

    def self.next_request(input, step, page)
      rows, links, meta = page.values_at("data", "links", "meta")
      AppleBundleRead.require!(rows.instance_of?(Array) && rows.size <= 200 && links.is_a?(Hash) && meta.is_a?(Hash) && meta["paging"].is_a?(Hash))
      total = meta["paging"]["total"]
      AppleBundleRead.require!(total.instance_of?(Integer) && total.between?(0, 400))
      link = links["next"]
      return nil if link.nil?
      AppleBundleRead.require!(!rows.empty? && link.instance_of?(String) && link.ascii_only? && link.bytesize.between?(1, 4096))
      uri = URI.parse(link)
      AppleBundleRead.require!(uri.is_a?(URI::HTTPS) && uri.host == "api.appstoreconnect.apple.com" && uri.port == 443 && uri.userinfo.nil? && uri.fragment.nil?)
      pairs = URI.decode_www_form(uri.query || "")
      AppleBundleRead.require!(pairs.size <= 10 && pairs.size == pairs.to_h.size && pairs.to_h.key?("cursor"))
      wire = input.request_for(step, cursor: pairs.to_h["cursor"])
      AppleBundleRead.require!(uri.path == wire["path"] && pairs.to_h == wire["query"])
      wire
    end

    def self.same_app!(input, page)
      data = page["data"]
      AppleBundleRead.require!(data.is_a?(Hash) && data["type"] == "apps" && data["id"] == input.app_id &&
        data["attributes"].is_a?(Hash) && data["attributes"] == { "bundleId" => input.bundle_id })
    end

    class Operation
      def initialize(input)
        AppleBundleRead.require!(input.instance_of?(Input))
        @input, @used, @owner = input, false, nil
      end

      def inspect = "#<AppleStoreVersions::Operation private>"

      def execute
        AppleBundleRead.require!(!@used)
        @used = true
        perform
      end

      private

      def perform
        AppleBundleRead.load_sdk!
        token = @input.token
        client = Spaceship::ConnectAPI::APIClient.new(token: token)
        @owner = ReadOwner.new(@input, token, client)
        adapter = AppleProvisioning::Adapter.new(client: client, owner: @owner, context_sha256: @input.context)
        AppleStoreVersions.same_app!(@input, @owner.finish(adapter.exchange(@input.request)))
        COLLECTIONS.each do |step|
          wire = @input.request_for(step)
          2.times do
            @owner.next_read!(step, wire)
            page = @owner.finish(adapter.exchange(wire))
            wire = AppleStoreVersions.next_request(@input, step, page)
            break if wire.nil?
          end
          AppleBundleRead.require!(wire.nil?)
        end
        wire = @input.request_for("app-after")
        @owner.next_read!("app-after", wire)
        AppleStoreVersions.same_app!(@input, @owner.finish(adapter.exchange(wire)))
        @owner.complete!
        @input.frame(@owner.pages, query_finished: true)
      rescue StandardError
        # Partial/raw original pages remain a refused comparison, never empty
        # inventory. Even all eight pages do not erase a failed final current
        # token/deadline check. This flag is query DATA, not process finality.
        # Fatal/interrupt Exception still fails the outer worker.
        @input.frame(@owner ? @owner.pages : [])
      end
    end

    def self.main(arguments, environment, output)
      AppleBundleRead.require!(arguments.empty?)
      input = Input.new(environment) # No SDK load before selected-input checks.
      frame = Operation.new(input).execute
      AppleBundleRead.require!(frame.bytesize <= FRAME_LIMIT && output.write(frame) == frame.bytesize)
      output.flush
      0
    rescue StandardError
      70
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::AppleStoreVersions.main(ARGV, ENV, STDOUT)
  rescue Exception
    Process.exit!(70)
  end
  exit(code)
end
