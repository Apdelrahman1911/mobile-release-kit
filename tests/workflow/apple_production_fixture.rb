# frozen_string_literal: true

require_relative "apple_fixture"
require "digest"

# A synthetic JSON:API Store, not a stub of the production adapter. Requests use
# the pinned Spaceship builders and transport wrapper. Unexpected endpoints or
# writes fail immediately and can never fall through to a live HTTP connection.
class AppleProductionFixture < AppleFixture
  class InvalidRequest < Exception; end # do not let production ambiguity handling hide fixture mistakes

  APP_ID = "12345"
  VERSION_ID = "version-target"
  INFO_ID = "info-editable"
  PRIVATE = {
    "contactFirstName" => "Previous", "contactLastName" => "Reviewer",
    "contactEmail" => "previous@example.test", "contactPhone" => "+12025550123",
    "demoAccountRequired" => true, "demoAccountName" => "fictional-demo",
    "demoAccountPassword" => "fictional-password", "notes" => "Previous review instructions",
  }.freeze
  VERSION_TEXT = {
    "description" => "Previous description", "keywords" => "fictional,previous",
    "marketingUrl" => "https://example.test/old", "promotionalText" => "Keep promotional text",
    "supportUrl" => "https://example.test/support", "whatsNew" => "Previous release notes",
  }.freeze
  INFO_TEXT = {
    "name" => "Fictional App", "subtitle" => "Previous subtitle",
    "privacyPolicyUrl" => "https://example.test/privacy", "privacyPolicyText" => "Keep privacy text",
    "privacyChoicesUrl" => "https://example.test/choices",
  }.freeze
  CATEGORIES = %w[primaryCategory primarySubcategoryOne primarySubcategoryTwo secondaryCategory secondarySubcategoryOne secondarySubcategoryTwo].freeze

  attr_accessor :inherit_version, :inherit_private, :page_size, :transform_read,
                :after_upload, :screenshot_complete_on_commit, :before_upload,
                :transform_write_response
  attr_reader :uploads, :queries, :deleted_screenshots

  def initialize
    super
    @inherit_version = true
    @inherit_private = true
    @screenshot_complete_on_commit = true
    @uploads = []
    @queries = []
    @deleted_screenshots = []
    @sequence = Hash.new(0)
    %w[appStoreVersions appInfos appStoreVersionLocalizations appInfoLocalizations appStoreReviewDetails appStoreVersionPhasedReleases appScreenshotSets appScreenshots reviewSubmissions reviewSubmissionItems appCategories].each { |type| @resources[type] }
    attributes("builds", "build-1")["usesNonExemptEncryption"] = false
    attributes("buildBetaDetails", "detail-1")["autoNotifyEnabled"] = false
    %w[UTILITIES PRODUCTIVITY GAMES GAMES_ACTION].each do |id|
      record = add("appCategories", id, "platforms" => ["IOS", "MAC_OS"])
      relate(record, "parent", "appCategories", id == "GAMES_ACTION" ? "GAMES" : nil)
    end
    add_version("version-live", version: "1.2.2", state: "READY_FOR_DISTRIBUTION", build_id: "previous-build")
    add_version("version-old", version: "1.2.1", state: "REPLACED_WITH_NEW_VERSION", build_id: "historical-build")
    add_version("version-mac", version: "1.2.3", state: "PREPARE_FOR_SUBMISSION", platform: "MAC_OS")
    add_version("version-other-app", version: "1.2.3", state: "IN_REVIEW", app_id: "other-app")
    add_info("info-live", state: "READY_FOR_DISTRIBUTION")
    add_info(INFO_ID)
    %w[en-US fr-FR].each do |locale|
      add_version_locale("version-live", locale)
      add_info_locale("info-live", locale)
      add_info_locale(INFO_ID, locale)
    end
    add_private("version-live", PRIVATE)
    add_submission("review-historical", state: "COMPLETE", version_id: "version-old", item_state: "APPROVED")
    add_submission("review-mac", platform: "MAC_OS")
    add_submission("review-other-app", app_id: "other-app")
  end

  def copy(value) = Marshal.load(Marshal.dump(value))
  def all(type) = @resources.fetch(type).values
  def id(type) = "#{type}-#{@sequence[type] += 1}"

  def relate(resource, relation, type, id)
    resource.fetch("relationships")[relation] = { "data" => id ? { "type" => type, "id" => id } : nil }
  end

  def parent_id(resource, relation) = resource.dig("relationships", relation, "data", "id")

  def children(type, relation, parent)
    all(type).select { |record| parent_id(record, relation) == parent }
  end

  def add_version(id, version: "1.2.3", state: "PREPARE_FOR_SUBMISSION", build_id: nil, platform: "IOS", app_id: APP_ID, copyright: "Previous copyright")
    record = add("appStoreVersions", id, "platform" => platform, "versionString" => version,
                 "appVersionState" => state, "releaseType" => "MANUAL", "copyright" => copyright,
                 "earliestReleaseDate" => nil)
    relate(record, "app", "apps", app_id)
    relate(record, "build", "builds", build_id)
    record
  end

  def add_info(id, state: "PREPARE_FOR_SUBMISSION", primary: "UTILITIES")
    record = add("appInfos", id, "state" => state)
    relate(record, "app", "apps", APP_ID)
    CATEGORIES.each { |field| relate(record, field, "appCategories", field == "primaryCategory" ? primary : nil) }
    record
  end

  def add_version_locale(version_id, locale, values = VERSION_TEXT)
    record = add("appStoreVersionLocalizations", id("locale"), copy(values).merge("locale" => locale))
    relate(record, "appStoreVersion", "appStoreVersions", version_id)
    record
  end

  def add_info_locale(info_id, locale, values = INFO_TEXT)
    record = add("appInfoLocalizations", id("info-locale"), copy(values).merge("locale" => locale))
    relate(record, "appInfo", "appInfos", info_id)
    record
  end

  def add_private(version_id, values)
    record = add("appStoreReviewDetails", id("private"), copy(values))
    relate(record, "appStoreVersion", "appStoreVersions", version_id)
    record
  end

  def add_submission(id, state: "READY_FOR_REVIEW", version_id: nil, item_state: "READY_FOR_REVIEW", platform: "IOS", app_id: APP_ID, item_type: "appStoreVersions")
    record = add("reviewSubmissions", id, "state" => state, "platform" => platform)
    relate(record, "app", "apps", app_id)
    if version_id
      item = add("reviewSubmissionItems", self.id("item"), "state" => item_state)
      relate(item, "reviewSubmission", "reviewSubmissions", id)
      name = { "appStoreVersions" => "appStoreVersion", "appEvents" => "appEvent", "appCustomProductPageVersions" => "appCustomProductPageVersion" }.fetch(item_type)
      relate(item, name, item_type, version_id)
    end
    record
  end

  def add_set(locale_id, display = "APP_IPHONE_47")
    record = add("appScreenshotSets", id("set"), "screenshotDisplayType" => display)
    relate(record, "appStoreVersionLocalization", "appStoreVersionLocalizations", locale_id)
    record.fetch("relationships")["appScreenshots"] = { "data" => [] }
    record
  end

  def add_shot(set_id, name:, bytes:, state: "COMPLETE", checksum: nil, expires: Time.now.to_i + 3600)
    record = add("appScreenshots", id("shot"), "fileName" => name, "fileSize" => bytes.bytesize,
                 "sourceFileChecksum" => checksum || (state == "COMPLETE" ? Digest::MD5.hexdigest(bytes) : nil),
                 "assetDeliveryState" => { "state" => state })
    relate(record, "appScreenshotSet", "appScreenshotSets", set_id)
    @resources.fetch("appScreenshotSets").fetch(set_id).fetch("relationships").fetch("appScreenshots").fetch("data") << record.slice("type", "id")
    set_upload_operations(record, expires: expires)
    record
  end

  def set_upload_operations(record, expires: Time.now.to_i + 3600)
    size = record.dig("attributes", "fileSize")
    # Two parts exercise interruption and exact ordered byte reconstruction.
    length = [size / 2, 1].max
    ranges = [[0, length]]
    ranges << [length, size - length] if size > length
    record.fetch("attributes")["uploadOperations"] = ranges.map do |offset, count|
      { "method" => "PUT", "url" => "https://upload.blobstore.apple.com/#{record.fetch('id')}/#{offset}?Expires=#{expires}",
        "offset" => offset, "length" => count,
        "requestHeaders" => [{ "name" => "Content-Type", "value" => "image/png" }, { "name" => "Content-Length", "value" => count.to_s }] }
    end
  end

  def clone_version
    record = add_version(VERSION_ID, copyright: @inherit_version ? "Previous copyright" : "")
    if @inherit_version
      children("appStoreVersionLocalizations", "appStoreVersion", "version-live").each do |source|
        locale = add_version_locale(VERSION_ID, source.dig("attributes", "locale"), source.fetch("attributes"))
        children("appScreenshotSets", "appStoreVersionLocalization", source.fetch("id")).each do |source_set|
          set = add_set(locale.fetch("id"), source_set.dig("attributes", "screenshotDisplayType"))
          source_set.dig("relationships", "appScreenshots", "data").each do |link|
            source_shot = @resources.fetch("appScreenshots").fetch(link.fetch("id"))
            shot = copy(source_shot)
            shot["id"] = id("shot")
            relate(shot, "appScreenshotSet", "appScreenshotSets", set.fetch("id"))
            @resources.fetch("appScreenshots")[shot.fetch("id")] = shot
            set.dig("relationships", "appScreenshots", "data") << shot.slice("type", "id")
          end
        end
      end
    end
    add_private(VERSION_ID, children("appStoreReviewDetails", "appStoreVersion", "version-live").first.fetch("attributes")) if @inherit_private
    unless @resources.fetch("appInfos").key?(INFO_ID)
      add_info(INFO_ID)
      children("appInfoLocalizations", "appInfo", "info-live").each do |source|
        add_info_locale(INFO_ID, source.dig("attributes", "locale"), source.fetch("attributes")) if @inherit_version
      end
    end
    record
  end

  def respond(env)
    path = env.url.path
    body = env.body && JSON.parse(env.body)
    query = URI.decode_www_form(env.url.query.to_s).to_h
    @requests << [env.method, path, copy(body)]
    links = {}
    if env.method == :get
      @queries << [path, query]
      before_read&.call(path)
      data = copy(read(path, query))
      data = transform_read.call(path, data) if transform_read
      if page_size && data.is_a?(Array) && data.length > page_size
        cursor = Integer(query.fetch("cursor", 0))
        total = data.length
        data = data.slice(cursor, page_size) || []
        if cursor + page_size < total
          links["next"] = "https://api.appstoreconnect.apple.com#{path}?#{URI.encode_www_form(query.merge('cursor' => cursor + page_size))}"
        end
      end
    else
      before_write&.call(env.method, path, body)
      data = write(env.method, path, body)
      after_write&.call(env.method, path, body)
      data = transform_write_response.call(env.method, path, copy(data)) if transform_write_response
    end
    payload = { "data" => data, "links" => links }
    # The outer Fastfile discovers its candidate through hydrated SDK Build
    # models. Production resources deliberately stay unhydrated so the adapter
    # must still honor their raw relationship IDs rather than SDK conveniences.
    if path == "/v1/builds"
      payload["included"] = %w[apps preReleaseVersions buildBetaDetails betaAppReviewSubmissions].flat_map { |kind| @resources[kind].values }
    end
    [200, { "content-type" => "application/json", "date" => Time.now.httpdate }, JSON.generate(payload)]
  end

  def read(path, query)
    segments = path.split("/").reject(&:empty?)
    _, type, parent, relationship = segments
    if path == "/v1/apps"
      raise InvalidRequest, "App discovery omitted the exact Bundle ID" unless query["filter[bundleId]"] == "test.example.release"
      return all("apps").select { |record| record.dig("attributes", "bundleId") == query.fetch("filter[bundleId]") }
    end
    if path == "/v1/builds"
      unless query["filter[app]"] == APP_ID && query["filter[preReleaseVersion.version]"] == "1.2.3" && query["filter[version]"] == "123"
        raise InvalidRequest, "Build discovery omitted an exact candidate identity filter"
      end
      return visible ? all("builds") : []
    end
    if type == "apps" && relationship
      case relationship
      when "appStoreVersions"
        raise InvalidRequest, "iOS list omitted explicit platform filter" unless query["filter[platform]"] == "IOS"
        return children(relationship, "app", parent).select { |record| record.dig("attributes", "platform") == "IOS" }
      when "reviewSubmissions"
        values = children(relationship, "app", parent)
        return query["filter[platform]"] ? values.select { |record| record.dig("attributes", "platform") == query.fetch("filter[platform]") } : values
      when "appInfos"
        return children("appInfos", "app", parent)
      end
    end
    if type == "reviewSubmissions" && !parent
      raise InvalidRequest, "Global App Review inventory omitted app scope" unless query["filter[app]"] == APP_ID
      values = children("reviewSubmissions", "app", APP_ID)
      return query["filter[platform]"] ? values.select { |record| record.dig("attributes", "platform") == query.fetch("filter[platform]") } : values
    end
    case [type, relationship]
    when ["appStoreVersions", "appStoreVersionLocalizations"]
      return children("appStoreVersionLocalizations", "appStoreVersion", parent)
    when ["appStoreVersions", "appStoreReviewDetail"]
      return children("appStoreReviewDetails", "appStoreVersion", parent).first
    when ["appStoreVersions", "appStoreVersionPhasedRelease"]
      return children("appStoreVersionPhasedReleases", "appStoreVersion", parent).first
    when ["appInfos", "appInfoLocalizations"]
      return children("appInfoLocalizations", "appInfo", parent)
    when ["appStoreVersionLocalizations", "appScreenshotSets"]
      return children("appScreenshotSets", "appStoreVersionLocalization", parent)
    when ["appScreenshotSets", "appScreenshots"]
      # Resource listing order is intentionally different from relationship order.
      return children("appScreenshots", "appScreenshotSet", parent).reverse
    when ["appScreenshotSets", "relationships"]
      raise InvalidRequest, "Unexpected relationship request" unless segments.last == "appScreenshots"
      return @resources.fetch("appScreenshotSets").fetch(parent).dig("relationships", "appScreenshots", "data")
    when ["reviewSubmissions", "items"]
      return children("reviewSubmissionItems", "reviewSubmission", parent)
    end
    if segments.length == 3 && @resources.key?(type)
      return @resources.fetch(type).fetch(parent) { raise InvalidRequest, "Unknown fixture ID #{path}" }
    end
    raise InvalidRequest, "Unexpected production fixture GET #{path}"
  end

  def expected_parent(data, name, type)
    relation = data.dig("relationships", name, "data")
    unless relation.is_a?(Hash) && relation.fetch("type") == type && @resources.fetch(type).key?(relation.fetch("id"))
      raise InvalidRequest, "Wrong JSON:API parent #{name}"
    end
    relation.fetch("id")
  end

  def write(method, path, body)
    _, type, resource_id = path.split("/").reject(&:empty?)
    if method == :delete
      raise InvalidRequest, "Only exact incomplete screenshot deletion is supported" unless type == "appScreenshots" && resource_id
      shot = @resources.fetch(type).fetch(resource_id)
      unless %w[AWAITING_UPLOAD FAILED].include?(shot.dig("attributes", "assetDeliveryState", "state"))
        raise InvalidRequest, "Attempted deletion of committed screenshot"
      end
      @deleted_screenshots << copy(shot)
      set = @resources.fetch("appScreenshotSets").fetch(parent_id(shot, "appScreenshotSet"))
      set.dig("relationships", "appScreenshots", "data").reject! { |item| item.fetch("id") == resource_id }
      @resources.fetch(type).delete(resource_id)
      return nil
    end
    data = body.fetch("data")
    raise InvalidRequest, "Wrong SDK JSON:API resource type" unless data.fetch("type") == type
    attrs = data.fetch("attributes", {})
    case [method, type]
    when [:post, "appStoreVersions"]
      unless expected_parent(data, "app", "apps") == APP_ID && attrs == { "platform" => "IOS", "versionString" => "1.2.3", "releaseType" => "MANUAL" }
        raise InvalidRequest, "Unscoped or automatic new Store version"
      end
      raise InvalidRequest, "Duplicate App Store version creation" if @resources.fetch(type).key?(VERSION_ID)
      return clone_version
    when [:post, "appStoreVersionLocalizations"]
      parent = expected_parent(data, "appStoreVersion", "appStoreVersions")
      raise InvalidRequest, "Wrote unrelated version locale" unless parent == VERSION_ID
      return add_version_locale(parent, attrs.fetch("locale"), attrs)
    when [:post, "appInfoLocalizations"]
      parent = expected_parent(data, "appInfo", "appInfos")
      raise InvalidRequest, "AppInfo locale missing name or incorrect parent" unless parent == INFO_ID && attrs.fetch("name").is_a?(String) && !attrs.fetch("name").empty?
      return add_info_locale(parent, attrs.fetch("locale"), attrs)
    when [:post, "appStoreReviewDetails"]
      parent = expected_parent(data, "appStoreVersion", "appStoreVersions")
      raise InvalidRequest, "Duplicate/other-version review details" unless parent == VERSION_ID && children(type, "appStoreVersion", parent).empty?
      return add_private(parent, attrs)
    when [:post, "appScreenshotSets"]
      parent = expected_parent(data, "appStoreVersionLocalization", "appStoreVersionLocalizations")
      raise InvalidRequest, "Screenshot set belongs to unrelated version" unless parent_id(@resources.fetch("appStoreVersionLocalizations").fetch(parent), "appStoreVersion") == VERSION_ID
      raise InvalidRequest, "Duplicate screenshot set" if children(type, "appStoreVersionLocalization", parent).any? { |set| set.dig("attributes", "screenshotDisplayType") == attrs.fetch("screenshotDisplayType") }
      return add_set(parent, attrs.fetch("screenshotDisplayType"))
    when [:post, "appScreenshots"]
      parent = expected_parent(data, "appScreenshotSet", "appScreenshotSets")
      return add_shot(parent, name: attrs.fetch("fileName"), bytes: "\0" * attrs.fetch("fileSize"), state: "AWAITING_UPLOAD")
    when [:post, "reviewSubmissions"]
      raise InvalidRequest, "Wrong App Review app/platform" unless expected_parent(data, "app", "apps") == APP_ID && attrs.fetch("platform") == "IOS"
      return add_submission(id("review"))
    when [:post, "reviewSubmissionItems"]
      submission_id = expected_parent(data, "reviewSubmission", "reviewSubmissions")
      version_id = expected_parent(data, "appStoreVersion", "appStoreVersions")
      raise InvalidRequest, "Unrelated or duplicate review item" unless version_id == VERSION_ID && children(type, "reviewSubmission", submission_id).empty?
      item = add(type, id("item"), "state" => "READY_FOR_REVIEW")
      relate(item, "reviewSubmission", "reviewSubmissions", submission_id)
      relate(item, "appStoreVersion", "appStoreVersions", version_id)
      return item
    when [:patch, "appStoreVersions"], [:patch, "appStoreVersionLocalizations"], [:patch, "appInfoLocalizations"], [:patch, "appInfos"], [:patch, "appStoreReviewDetails"]
      raise InvalidRequest, "PATCH changed resource ID" unless data.fetch("id") == resource_id
      record = @resources.fetch(type).fetch(resource_id)
      raise InvalidRequest, "Automatic or dated release" if attrs.key?("earliestReleaseDate") || (attrs.key?("releaseType") && attrs["releaseType"] != "MANUAL")
      record.fetch("attributes").merge!(copy(attrs))
      record.fetch("relationships").merge!(copy(data.fetch("relationships", {})))
      return record
    when [:patch, "appScreenshots"]
      shot = @resources.fetch(type).fetch(resource_id)
      raise InvalidRequest, "Wrong screenshot commit" unless attrs.keys.sort == %w[sourceFileChecksum uploaded] && attrs.fetch("uploaded") == true && shot.dig("attributes", "assetDeliveryState", "state") == "AWAITING_UPLOAD"
      complete = assembled_upload(resource_id)
      unless complete.bytesize == shot.dig("attributes", "fileSize") && Digest::MD5.hexdigest(complete) == attrs.fetch("sourceFileChecksum")
        raise InvalidRequest, "Screenshot commit does not match uploaded bytes"
      end
      shot.fetch("attributes")["sourceFileChecksum"] = attrs.fetch("sourceFileChecksum")
      shot.fetch("attributes")["assetDeliveryState"] = { "state" => screenshot_complete_on_commit ? "COMPLETE" : "UPLOAD_COMPLETE" }
      return shot
    when [:patch, "reviewSubmissions"]
      raise InvalidRequest, "Only manual review submission is authorized" unless data.fetch("id") == resource_id && attrs == { "submitted" => true }
      record = @resources.fetch(type).fetch(resource_id)
      items = children("reviewSubmissionItems", "reviewSubmission", resource_id)
      raise InvalidRequest, "Review submission is not ready/exact" unless record.dig("attributes", "state") == "READY_FOR_REVIEW" && items.length == 1 && parent_id(items.first, "appStoreVersion") == VERSION_ID
      version = @resources.fetch("appStoreVersions").fetch(VERSION_ID)
      raise InvalidRequest, "Review selected wrong build/release mode" unless parent_id(version, "build") == "build-1" && version.dig("attributes", "releaseType") == "MANUAL"
      record.fetch("attributes")["state"] = "WAITING_FOR_REVIEW"
      version.fetch("attributes")["appVersionState"] = "WAITING_FOR_REVIEW"
      attributes("appInfos", INFO_ID)["state"] = "WAITING_FOR_REVIEW"
      return record
    end
    raise InvalidRequest, "Unexpected production fixture mutation #{method} #{path}"
  end

  def upload(range, bytes)
    shot_id, offset = range.fetch(:uri).path.split("/").reject(&:empty?)
    shot = @resources.fetch("appScreenshots").fetch(shot_id)
    raise InvalidRequest, "Part upload attempted after commit" unless shot.dig("attributes", "assetDeliveryState", "state") == "AWAITING_UPLOAD"
    raise InvalidRequest, "Part upload uses wrong source range" unless Integer(offset) == range.fetch(:offset) && bytes.bytesize == range.fetch(:length)
    before_upload&.call(range, bytes)
    @uploads << [shot_id, range.fetch(:offset), bytes.dup]
    after_upload&.call(range, bytes)
  end

  def assembled_upload(shot_id)
    @uploads.select { |id, _offset, _bytes| id == shot_id }.to_h { |_id, offset, bytes| [offset, bytes] }.sort.map(&:last).join
  end

  def baseline_records
    # Includes all resources existing before execution, except the AppInfo and
    # its locales intentionally covered by the operation's metadata target.
    records = all("appInfoLocalizations").select { |item| parent_id(item, "appInfo") == INFO_ID }.map { |item| item.fetch("id") }
    @resources.transform_values do |values|
      values.reject { |key, _value| key == INFO_ID || records.include?(key) }
    end.then { |value| copy(value) }
  end

  def existing_records_like(baseline)
    baseline.to_h do |type, values|
      [type, values.keys.to_h { |key| [key, copy(@resources.fetch(type)[key])] }]
    end
  end
end
