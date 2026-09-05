# frozen_string_literal: true

# A credential-free Publisher service at the generated SDK command boundary.
# Supply's real listing/changelog/image/mapping adapters and the pinned Google's
# request serializers/response parsers remain in use. No request can use a socket.
require "bundler/setup"
require "fastlane"
require "supply"
require "json"
require "digest"
require "net/http"

class PlayFixture
  attr_reader :service, :supply_client, :requests, :edits, :image_bytes
  attr_accessor :state, :before_request, :after_request, :persist_bundles_outside_edit

  def initialize(code: 200)
    @code = code
    @sequence = 0
    @image_sequence = 0
    @requests = []
    @edits = {}
    @image_bytes = {}
    @state = { "tracks" => {}, "bundles" => [], "listings" => {}, "images" => {}, "mappings" => {} }
    @service = Google::Apis::AndroidpublisherV3::AndroidPublisherService.new
    owner = self
    @service.define_singleton_method(:execute_or_queue_command) { |command, &_block| owner.execute(command) }
    @supply_client = Supply::Client.allocate
    @supply_client.client = @service
  end

  def clone(value) = Marshal.load(Marshal.dump(value))

  def add_track(name, releases)
    state.fetch("tracks")[name] = { "track" => name, "releases" => clone(releases) }
  end

  def add_bundle(bytes, code: @code)
    bundle = { "versionCode" => code, "sha256" => Digest::SHA256.hexdigest(bytes) }
    state.fetch("bundles") << bundle
    bundle
  end

  def add_image(language, type, bytes, store: state)
    @image_sequence += 1
    id = "image-#{@image_sequence}"
    @image_bytes[id] = bytes.b
    image = { "id" => id, "sha256" => Digest::SHA256.hexdigest(bytes), "url" => "https://play-fixture.googleusercontent.com/#{id}" }
    (store.fetch("images")[[language, type]] ||= []) << image
    image
  end

  def mutations
    requests.select { |entry| entry.fetch(:mutation) }
  end

  def commits
    requests.select { |entry| entry.fetch(:path).end_with?(":commit") }
  end

  def execute(command)
    url = command.url.respond_to?(:expand) ? command.url.expand(command.params) : command.url
    path = url.path
    body = command.request_object && JSON.parse(command.request_representation.new(command.request_object).to_json(user_options: { skip_undefined: true }))
    upload = command.respond_to?(:upload_source) && command.upload_source
    entry = {
      method: command.method, path: path, body: body, params: clone(command.params),
      command_class: command.class.name,
      query: clone(command.query), retries: command.options.retries,
      upload_sha256: upload && Digest::SHA256.file(upload).hexdigest,
      mutation: command.method != :get && (path.include?("/tracks/") || path.include?("/bundles") || path.include?("/deobfuscationFiles/") || path.include?("/listings/") || path.end_with?(":commit")),
    }
    @requests << entry
    before_request&.call(entry)
    raise "Wrong synthetic package" unless command.params.fetch("packageName") == "test.example.release"
    prefix = "/androidpublisher/v3/applications/test.example.release/edits"
    path = path.delete_prefix("/upload")
    raise "Unexpected Publisher path #{path}" unless path.start_with?(prefix)
    resource = path.delete_prefix(prefix)
    method = command.method
    data = if resource.empty? && method == :post
             @sequence += 1
             id = "edit-#{@sequence}"
             @edits[id] = clone(state)
             { "id" => id }
           else
             respond_edit(method, resource, body, upload)
           end
    after_request&.call(entry)
    command.response_class&.from_json(JSON.generate(data || {}))
  end

  def respond_edit(method, resource, body, upload)
    id, suffix = resource.delete_prefix("/").split("/", 2)
    if id.end_with?(":commit")
      edit_id = id.delete_suffix(":commit")
      @state = clone(@edits.fetch(edit_id))
      @edits.delete(edit_id)
      return { "id" => edit_id }
    end
    if id.end_with?(":validate")
      edit_id = id.delete_suffix(":validate")
      @edits.fetch(edit_id)
      return { "id" => edit_id }
    end
    if method == :delete && suffix.nil?
      @edits.delete(id)
      return {}
    end
    pending = @edits.fetch(id)
    segments = suffix.to_s.split("/")
    if segments == ["bundles"]
      return { "bundles" => clone(pending.fetch("bundles")) } if method == :get
      raise "Unexpected bundle method" unless method == :post
      raise Google::Apis::ClientError, "duplicate version" if pending.fetch("bundles").any? { |item| item["versionCode"] == @code }
      bundle = { "versionCode" => @code, "sha256" => Digest::SHA256.file(upload).hexdigest }
      pending.fetch("bundles") << bundle
      state.fetch("bundles") << clone(bundle) if persist_bundles_outside_edit
      return bundle
    end
    if segments[0] == "apks" && segments[2] == "deobfuscationFiles"
      raise "Unexpected mapping method" unless method == :post
      pending.fetch("mappings")[[segments[1], segments[3]]] = File.binread(upload)
      return {}
    end
    if segments[0] == "tracks"
      return { "tracks" => pending.fetch("tracks").values } if segments.length == 1 && method == :get
      name = segments.fetch(1)
      return pending.fetch("tracks")[name] || raise(Google::Apis::ClientError.new("missing track", status_code: 404)) if method == :get
      raise "Unexpected track method" unless method == :put
      # Publisher omits unset fields and serializes int64 version codes as text.
      body.fetch("releases", []).each do |release|
        release.reject! { |_key, value| value.nil? }
        release["versionCodes"] = release.fetch("versionCodes").map(&:to_s)
      end
      pending.fetch("tracks")[name] = clone(body)
      return body
    end
    if segments[0] == "testers" && method == :get
      return { "googleGroups" => ["fictional-testers@example.test"] }
    end
    if segments[0] == "listings"
      return { "listings" => pending.fetch("listings").values } if segments.length == 1 && method == :get
      language = segments.fetch(1)
      if segments.length == 2
        return pending.fetch("listings")[language] || raise(Google::Apis::ClientError.new("missing listing", status_code: 404)) if method == :get
        raise "Unexpected listing method" unless method == :put
        pending.fetch("listings")[language] = clone(body)
        return body
      end
      type = segments.fetch(2)
      rows = pending.fetch("images")[[language, type]] ||= []
      return { "images" => rows } if method == :get
      if method == :delete
        segments.length == 4 ? rows.reject! { |row| row["id"] == segments[3] } : rows.clear
        return {}
      end
      raise "Unexpected image method" unless method == :post
      rows.clear if Supply::IMAGES_TYPES.include?(type)
      return { "image" => add_image(language, type, File.binread(upload), store: pending) }
    end
    raise "Unexpected Publisher fixture operation #{method} #{resource}"
  end

  def image_connection(host, port, proxy)
    raise "Unexpected image transport origin" unless host == "play-fixture.googleusercontent.com" && port == 443 && proxy.nil?
    ImageConnection.new(@image_bytes)
  end

  class ImageConnection
    attr_accessor :use_ssl, :open_timeout, :read_timeout, :write_timeout, :max_retries
    attr_reader :requests

    def initialize(image_bytes, responses: nil)
      @image_bytes = image_bytes
      @responses = responses
      @requests = []
    end

    def start
      yield self
    end

    def request(request)
      @requests << request
      if @responses
        response = @responses.shift || raise("Unexpected image request")
      else
        id = request.path.delete_prefix("/").delete_suffix("=s0")
        bytes = @image_bytes.fetch(id)
        response = self.class.response(bytes)
      end
      yield response
    end

    def self.response(bytes = "", code: 200, headers: {}, chunks: nil)
      klass = Net::HTTPResponse::CODE_TO_OBJ.fetch(code.to_s)
      response = klass.new("1.1", code.to_s, "Synthetic")
      headers.each { |name, value| response[name] = value }
      response.define_singleton_method(:body) { raise "Whole image body must never be buffered" }
      response.define_singleton_method(:read_body) do |&block|
        (chunks || [bytes.b]).each { |chunk| block.call(chunk) }
      end
      response
    end
  end
end
