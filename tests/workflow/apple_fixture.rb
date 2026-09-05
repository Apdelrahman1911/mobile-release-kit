# frozen_string_literal: true

# A credential-free JSON:API service at the HTTP boundary. Production SDK
# request builders and model parsing stay in the execution path; only transport
# and time are synthetic. Unknown endpoints fail instead of reaching a network.
require "bundler/setup"
require "fastlane"
require "spaceship"
require "json"
require "uri"
require_relative "../../fastlane/apple_store"

class AppleFixture
  class InvalidRequest < Exception; end # unexpected requests must not look like retryable Store errors

  Token = Struct.new(:in_house, :text) do
    def expired? = false
  end

  attr_reader :requests, :resources, :client
  attr_accessor :after_write, :before_read, :assigned, :visible, :before_write,
                :hidden_resources, :hide_assignment, :mask_review_state

  def initialize
    @resources = Hash.new { |hash, key| hash[key] = {} }
    @requests = []
    @assigned = false
    @visible = true
    @hidden_resources = []
    @hide_assignment = false
    @mask_review_state = false
    add("apps", "12345", "bundleId" => "test.example.release", "name" => "Fictional App")
    add("preReleaseVersions", "train-1", "version" => "1.2.3", "platform" => "IOS")
    add("buildBetaDetails", "detail-1", "autoNotifyEnabled" => true,
        "externalBuildState" => "READY_FOR_BETA_SUBMISSION", "internalBuildState" => "READY_FOR_BETA_TESTING")
    build = add("builds", "build-1", "version" => "123", "processingState" => "VALID",
                "uploadedDate" => Time.now.utc.iso8601, "expirationDate" => (Time.now.utc + 86_400 * 90).iso8601,
                "expired" => false, "usesNonExemptEncryption" => nil)
    link(build, "app", "apps", "12345")
    link(build, "preReleaseVersion", "preReleaseVersions", "train-1")
    link(build, "buildBetaDetail", "buildBetaDetails", "detail-1")
    add("betaGroups", "group-1", "name" => "External QA", "isInternalGroup" => false)
    add("betaAppReviewDetails", "private-detail-1", "contactFirstName" => "Old", "contactLastName" => "Reviewer",
        "contactEmail" => "old@example.test", "contactPhone" => "+12025550123", "demoAccountRequired" => false,
        "demoAccountName" => "", "demoAccountPassword" => "", "notes" => "Old review notes")
    add("betaBuildLocalizations", "locale-en", "locale" => "en-US", "whatsNew" => "Old English")
    add("betaBuildLocalizations", "locale-fr", "locale" => "fr-FR", "whatsNew" => "Old French")
    add("betaBuildLocalizations", "locale-unconfigured", "locale" => "ja", "whatsNew" => "  Unconfigured 日本語 <keep> 🧪\n\n")
    token = Token.new(false, "synthetic-no-credential")
    transport = Spaceship::ConnectAPI::APIClient.new(token: token)
    transport.extend(MobileReleaseKit::AppleOperationTransport)
    transport.define_singleton_method(:sleep) { |_seconds| }
    service = self
    connection = Faraday.new("https://api.appstoreconnect.apple.com/") do |builder|
      builder.response(:json)
      builder.adapter(:test) do |stub|
        %i[get post patch delete].each do |method|
          stub.public_send(method, %r{.*}) { |env| service.respond(env) }
        end
      end
    end
    transport.instance_variable_set(:@client, connection)
    @client = Spaceship::ConnectAPI::Client.new(token: token)
    @client.test_flight_request_client = transport
    @client.tunes_request_client = transport
  end

  def add(type, id, attributes = {})
    @resources[type][id] = { "type" => type, "id" => id, "attributes" => attributes, "relationships" => {} }
  end

  def link(resource, relation, type, id)
    resource["relationships"][relation] = { "data" => { "type" => type, "id" => id } }
  end

  def attributes(type, id)
    @resources.fetch(type).fetch(id).fetch("attributes")
  end

  def writes = @requests.reject { |method, _path, _body| method == :get }

  def respond(env)
    path = env.url.path
    body = env.body ? JSON.parse(env.body) : nil
    @requests << [env.method, path, body]
    if env.method == :get
      before_read&.call(path)
      data = read(path, URI.decode_www_form(env.url.query || "").to_h)
    else
      before_write&.call(env.method, path, body)
      data = write(env.method, path, body)
      after_write&.call(env.method, path, body)
    end
    payload = Marshal.load(Marshal.dump("data" => data, "included" => @resources.values.flat_map(&:values)))
    if env.method == :get
      hidden = ->(record) { record && hidden_resources.include?([record["type"], record["id"]]) }
      payload["data"] = payload["data"].is_a?(Array) ? payload["data"].reject { |record| hidden.call(record) } : (hidden.call(payload["data"]) ? nil : payload["data"])
      payload["included"].reject! { |record| hidden.call(record) }
      if mask_review_state
        (Array(payload["included"]) + (payload["data"].is_a?(Array) ? payload["data"] : [payload["data"]])).compact.each do |record|
          record.fetch("attributes")["externalBuildState"] = "READY_FOR_BETA_SUBMISSION" if record["type"] == "buildBetaDetails"
        end
      end
    end
    [200, { "content-type" => "application/json", "date" => Time.now.httpdate }, JSON.generate(payload)]
  end

  def read(path, _query)
    return @assigned && !hide_assignment ? @resources["builds"].values : [] if path == "/v1/betaGroups/group-1/builds"
    return [] if path == "/v1/builds" && !@visible
    segments = path.split("/").reject(&:empty?)
    raise InvalidRequest, "Unexpected Apple fixture GET #{path}" unless segments[0] == "v1" && segments.length.between?(2, 3)
    type, id = segments[1, 2]
    raise InvalidRequest, "Unexpected Apple fixture resource #{path}" unless @resources.key?(type)
    id ? @resources.fetch(type).fetch(id) : @resources.fetch(type).values
  end

  def write(method, path, body)
    if method == :post && path == "/v1/builds/build-1/relationships/betaGroups"
      raise "Wrong build/group relationship" unless body.fetch("data") == [{ "type" => "betaGroups", "id" => "group-1" }]
      @assigned = true
      return []
    end
    type, id = path.split("/").reject(&:empty?)[1, 2]
    data = body.fetch("data")
    raise "Wrong SDK JSON:API type" unless data.fetch("type") == type
    case [method, type]
    when [:patch, "builds"], [:patch, "buildBetaDetails"], [:patch, "betaAppReviewDetails"], [:patch, "betaBuildLocalizations"]
      raise "Wrong SDK JSON:API ID" unless data.fetch("id") == id
      @resources.fetch(type).fetch(id).fetch("attributes").merge!(data.fetch("attributes"))
    when [:post, "betaBuildLocalizations"]
      id = "locale-#{@resources[type].length + 1}"
      raise "Wrong beta localization parent" unless data.dig("relationships", "build", "data", "id") == "build-1"
      add(type, id, data.fetch("attributes"))
    when [:post, "betaAppReviewSubmissions"]
      raise "Duplicate Beta Review submission" unless @resources[type].empty?
      raise "Wrong beta review build" unless data.dig("relationships", "build", "data", "id") == "build-1"
      id = "review-1"
      add(type, id, "betaReviewState" => "WAITING_FOR_REVIEW")
      link(@resources["builds"]["build-1"], "betaAppReviewSubmission", type, id)
      attributes("buildBetaDetails", "detail-1")["externalBuildState"] = "WAITING_FOR_BETA_REVIEW"
    else
      raise InvalidRequest, "Unexpected Apple fixture mutation #{method} #{path}"
    end
    @resources.fetch(type).fetch(id)
  end
end
