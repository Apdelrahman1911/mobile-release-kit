# frozen_string_literal: true

require "securerandom"
require "time"
require "deliver/app_screenshot"
require_relative "apple_store"
require_relative "apple_asset_upload"
require_relative "apple_create_retry"

module MobileReleaseKit
  # This is intentionally not Deliver's aggregate upload/submit action. Each
  # write is one scoped API request bracketed by complete public/private state
  # validation. A new process resumes the authenticated intent, not a macro.
  class AppleProduction
    VERSION_FIELDS = {
      "description.txt" => "description", "keywords.txt" => "keywords",
      "marketing_url.txt" => "marketingUrl", "promotional_text.txt" => "promotionalText",
      "support_url.txt" => "supportUrl", "release_notes.txt" => "whatsNew",
    }.freeze
    INFO_FIELDS = {
      "name.txt" => "name", "subtitle.txt" => "subtitle", "privacy_url.txt" => "privacyPolicyUrl",
      "apple_tv_privacy_policy.txt" => "privacyPolicyText",
    }.freeze
    INFO_OBSERVED_FIELDS = (INFO_FIELDS.values + ["privacyChoicesUrl"]).freeze
    CATEGORY_FIELDS = {
      "primary_category.txt" => "primaryCategory", "primary_first_sub_category.txt" => "primarySubcategoryOne",
      "primary_second_sub_category.txt" => "primarySubcategoryTwo", "secondary_category.txt" => "secondaryCategory",
      "secondary_first_sub_category.txt" => "secondarySubcategoryOne", "secondary_second_sub_category.txt" => "secondarySubcategoryTwo",
    }.freeze
    PRIVATE_FIELDS = %w[contactFirstName contactLastName contactEmail contactPhone demoAccountRequired demoAccountName demoAccountPassword notes].freeze
    VERSION_TRANSITIONS = {
      "PREPARE_FOR_SUBMISSION" => %w[PREPARE_FOR_SUBMISSION READY_FOR_REVIEW WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_DEVELOPER_RELEASE],
      "READY_FOR_REVIEW" => %w[READY_FOR_REVIEW WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_DEVELOPER_RELEASE],
      "WAITING_FOR_REVIEW" => %w[WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_DEVELOPER_RELEASE],
      "IN_REVIEW" => %w[IN_REVIEW ACCEPTED PENDING_DEVELOPER_RELEASE],
      "ACCEPTED" => %w[ACCEPTED PENDING_DEVELOPER_RELEASE],
      "PENDING_DEVELOPER_RELEASE" => %w[PENDING_DEVELOPER_RELEASE],
    }.freeze
    SUBMISSION_TRANSITIONS = {
      "READY_FOR_REVIEW" => %w[READY_FOR_REVIEW WAITING_FOR_REVIEW IN_REVIEW COMPLETING COMPLETE],
      "WAITING_FOR_REVIEW" => %w[WAITING_FOR_REVIEW IN_REVIEW COMPLETING COMPLETE],
      "IN_REVIEW" => %w[IN_REVIEW COMPLETING COMPLETE],
      "COMPLETING" => %w[COMPLETING COMPLETE], "COMPLETE" => %w[COMPLETE],
    }.freeze
    INFO_TRANSITIONS = {
      "PREPARE_FOR_SUBMISSION" => %w[PREPARE_FOR_SUBMISSION READY_FOR_REVIEW WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_RELEASE],
      "READY_FOR_REVIEW" => %w[READY_FOR_REVIEW WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_RELEASE],
      "WAITING_FOR_REVIEW" => %w[WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_RELEASE],
      "IN_REVIEW" => %w[IN_REVIEW ACCEPTED PENDING_RELEASE],
      "ACCEPTED" => %w[ACCEPTED PENDING_RELEASE], "PENDING_RELEASE" => %w[PENDING_RELEASE],
    }.freeze
    LIVE_STATES = %w[READY_FOR_SALE READY_FOR_DISTRIBUTION].freeze
    HISTORICAL_STATES = %w[REPLACED_WITH_NEW_VERSION REPLACED_WITH_NEW_INFO REMOVED_FROM_SALE DEVELOPER_REMOVED_FROM_SALE].freeze
    PUBLIC_FIELDS = %w[production appInfo liveReference appInfoReference unrelatedVersions reviewSubmissions].freeze

    def initialize(client:, app_id:, bundle_id:, version:, build:, metadata_root:, locales:, private_target:, environment:, read_build:, journal:, upload_part: AppleAssetUpload.method(:put), create_guard: nil)
      @client, @app_id, @bundle_id, @version, @build = client, app_id, bundle_id, version, build
      @root = File.realpath(metadata_root)
      @locales, @private_target, @environment = locales, private_target, environment
      @read_build, @journal = read_build, journal
      @upload_part = upload_part
      @create_guard = create_guard
      @replacements = {}
    end

    def records(response, type, maximum = 10_000) = AppleStore.records(response, type: type, maximum: maximum)

    def text(record, field)
      value = record.fetch("attributes", {})[field]
      return "" if value.nil?
      raise ContractError, "Apple public text value is invalid" unless value.is_a?(String) && value.bytesize <= 64 * 1024
      value
    end

    def one(response, type)
      records(response, type, 1).first
    end

    def fields(record, names)
      names.to_h { |field| [field, text(record, field)] }
    end

    def state(record)
      names = record["type"] == "appInfos" ? %w[state appStoreState] : %w[appVersionState appStoreState state]
      value = names.map { |field| text(record, field) }.find { |item| !item.empty? }
      raise ContractError, "Apple resource is missing its state" unless value
      value
    end

    def version_summary(record)
      scoped_to_app!(record)
      raise ContractError, "App Store version is not scoped to iOS" unless text(record, "platform") == "IOS"
      {
        "id" => record.fetch("id"), "appId" => @app_id, "platform" => "IOS",
        "versionString" => text(record, "versionString"), "state" => state(record),
        "buildId" => AppleStore.relationship_id(record, "build", type: "builds"),
        "releaseType" => text(record, "releaseType"), "earliestReleaseDate" => text(record, "earliestReleaseDate"),
        "copyright" => text(record, "copyright"),
      }
    end

    def private_record(version_id)
      record = version_id && one(@client.get_app_store_review_detail(app_store_version_id: version_id), "appStoreReviewDetails")
      attributes = record ? record.fetch("attributes", {}) : {}
      unless attributes.is_a?(Hash) && PRIVATE_FIELDS.all? { |field|
        value = attributes[field]
        field == "demoAccountRequired" ? [nil, true, false].include?(value) : value.nil? || value.is_a?(String)
      }
        raise ContractError, "Apple private review record has invalid field types"
      end
      value = PRIVATE_FIELDS.to_h do |field|
        [field, field == "demoAccountRequired" ? attributes[field] == true : attributes[field].to_s]
      end
      if value.values.any? { |item| item.is_a?(String) && (item.include?("•") || item.match?(/\A\*+\z/)) } ||
         (value["demoAccountRequired"] && %w[demoAccountName demoAccountPassword].any? { |field| !attributes.key?(field) || value[field].empty? })
        raise ContractError, "Apple private review values are masked/unavailable; equality cannot be proven"
      end
      [record && record.fetch("id"), value]
    end

    def localizations(parent_id, info: false)
      return [] unless parent_id
      response = info ? @client.get_app_info_localizations(app_info_id: parent_id, limit: 200) :
                        @client.get_app_store_version_localizations(app_store_version_id: parent_id, limit: 200)
      type = info ? "appInfoLocalizations" : "appStoreVersionLocalizations"
      values = records(response, type, 100).map do |record|
        value = { "id" => record.fetch("id"), "locale" => text(record, "locale") }.merge(fields(record, info ? INFO_OBSERVED_FIELDS : VERSION_FIELDS.values))
        value["screenshotSets"] = screenshot_sets(record.fetch("id")) unless info
        value
      end
      unique!(values, "locale")
      values.sort_by { |item| item.fetch("locale") }
    end

    def screenshot_sets(localization_id)
      values = records(@client.get_app_screenshot_sets(app_store_version_localization_id: localization_id, limit: 200), "appScreenshotSets", 100).map do |record|
        ordered = records(@client.tunes_request_client.get("v1/appScreenshotSets/#{record.fetch('id')}/relationships/appScreenshots", { limit: 200 }), "appScreenshots", 10)
        related = records(@client.tunes_request_client.get("v1/appScreenshotSets/#{record.fetch('id')}/appScreenshots", { limit: 200 }), "appScreenshots", 10)
        by_id = related.to_h { |shot| [shot.fetch("id"), shot] }
        raise ContractError, "Screenshot relationship membership is incomplete" unless ordered.map { |shot| shot.fetch("id") }.sort == by_id.keys.sort
        shots = ordered.map { |shot| by_id.fetch(shot.fetch("id")) }
        {
          "id" => record.fetch("id"), "displayType" => text(record, "screenshotDisplayType"),
          "screenshots" => shots.each_with_index.map do |shot, order|
            attrs = shot.fetch("attributes", {})
            size = attrs["fileSize"]
            raise ContractError, "Apple screenshot size is invalid" unless size.is_a?(Integer) && size.between?(1, 10 * 1024 * 1024)
            {
              "id" => shot.fetch("id"), "order" => order, "fileName" => text(shot, "fileName"),
              "fileSize" => size, "sourceFileChecksum" => text(shot, "sourceFileChecksum").downcase,
              "deliveryState" => attrs.fetch("assetDeliveryState", {}).fetch("state", ""),
            }
          end,
        }
      end
      unique!(values, "displayType")
      values.sort_by { |item| item.fetch("displayType") }
    end

    def detailed_version(summary)
      return nil unless summary
      phased = one(@client.get_app_store_version_phased_release(app_store_version_id: summary.fetch("id")), "appStoreVersionPhasedReleases")
      private_id, private_value = private_record(summary.fetch("id"))
      [summary.merge(
        "localizations" => localizations(summary.fetch("id")), "privateDetailId" => private_id,
        "phasedRelease" => phased && { "id" => phased.fetch("id"), "state" => text(phased, "phasedReleaseState") },
      ), private_value]
    end

    def app_info(record)
      return nil unless record
      scoped_to_app!(record)
      {
        "id" => record.fetch("id"), "appId" => @app_id, "state" => state(record),
        "categories" => CATEGORY_FIELDS.values.to_h { |name| [name, AppleStore.relationship_id(record, name, type: "appCategories")] },
        "localizations" => localizations(record.fetch("id"), info: true),
      }
    end

    def review_submissions
      # An empty ReviewSubmission may have no platform. Filtering for IOS would
      # hide it and permit an unsafe duplicate create after a lost response.
      records(@client.get_review_submissions(app_id: @app_id, limit: 200), "reviewSubmissions").map do |record|
        scoped_to_app!(record)
        platform = text(record, "platform")
        unless %w[IOS MAC_OS TV_OS VISION_OS].include?(platform) || platform.empty?
          raise ContractError, "Review submission has an unknown platform"
        end
        if platform.empty? && text(record, "state") != "COMPLETE"
          raise ContractError, "An unscoped open App Review submission is ambiguous"
        end
        items = records(@client.get_review_submission_items(review_submission_id: record.fetch("id"), includes: "appStoreVersion,appStoreVersionExperiment,appCustomProductPageVersion,appEvent", limit: 200), "reviewSubmissionItems").map do |item|
          types = { "appStoreVersion" => "appStoreVersions", "appStoreVersionExperiment" => "appStoreVersionExperiments", "appCustomProductPageVersion" => "appCustomProductPageVersions", "appEvent" => "appEvents" }
          relations = types.filter_map do |name, type|
            id = AppleStore.relationship_id(item, name, type: type, required: false)
            { "type" => type, "id" => id } if id
          end
          unknown = item.fetch("relationships", {}).reject { |name, _| (types.keys + ["reviewSubmission"]).include?(name) }
          if unknown.values.any? { |relation| relation.is_a?(Hash) && relation["data"] }
            raise ContractError, "App Review item contains unsupported resource relationships"
          end
          raise ContractError, "Review item membership is missing or ambiguous" unless relations.length == 1
          { "id" => item.fetch("id"), "state" => text(item, "state"), "resource" => relations.first }
        end
        { "id" => record.fetch("id"), "state" => text(record, "state"), "platform" => platform, "items" => items.sort_by { |item| item.fetch("id") } }
      end.sort_by { |item| item.fetch("id") }
    end

    def read
      versions = records(@client.get_app_store_versions(app_id: @app_id, filter: { platform: "IOS" }, includes: "build", limit: 200), "appStoreVersions").map { |item| version_summary(item) }
      matching = versions.select { |item| item.fetch("versionString") == @version }
      raise ContractError, "Multiple App Store records have the intended version" if matching.length > 1
      target = matching.first
      unrelated = versions.reject { |item| item == target }
      unless unrelated.all? { |item| (LIVE_STATES + HISTORICAL_STATES).include?(item.fetch("state")) }
        raise ContractError, "Another iOS version is active; it will not be repurposed"
      end
      live = unrelated.select { |item| LIVE_STATES.include?(item.fetch("state")) }
      raise ContractError, "Live iOS reference is ambiguous" if live.length > 1
      info_records = records(@client.get_app_infos(app_id: @app_id, includes: CATEGORY_FIELDS.values.join(","), limit: 200), "appInfos", 100)
      editable = info_records.reject { |item| (LIVE_STATES + HISTORICAL_STATES).include?(state(item)) }
      raise ContractError, "Editable AppInfo is ambiguous" if editable.length > 1
      info_reference = info_records.select { |item| LIVE_STATES.include?(state(item)) }
      raise ContractError, "Live AppInfo reference is ambiguous" if info_reference.length > 1
      production, current_private = target ? detailed_version(target) : [nil, private_record(nil).last]
      reference, reference_private = live.first ? detailed_version(live.first) : [nil, nil]
      {
        "production" => production, "appInfo" => app_info(editable.first),
        "liveReference" => reference, "appInfoReference" => app_info(info_reference.first),
        "unrelatedVersions" => unrelated.sort_by { |item| item.fetch("id") },
        "reviewSubmissions" => review_submissions,
        "_private" => current_private, "_referencePrivate" => reference_private,
      }
    end

    def unique!(values, key)
      raise ContractError, "Apple #{key} inventory is ambiguous" unless values.map { |item| item.fetch(key) }.uniq.length == values.length
    end

    def scoped_to_app!(record)
      app_id = AppleStore.relationship_id(record, "app", type: "apps", required: false)
      raise ContractError, "Apple resource belongs to another application" if app_id && app_id != @app_id
    end

    def public_state(current) = current.slice(*PUBLIC_FIELDS)

    def text_file(path)
      safe = MobileReleaseKit.safe_path(@root, path)
      raise ContractError, "Store metadata must be a bounded regular file" if File.symlink?(safe) || !File.file?(safe) || File.size(safe) > 64 * 1024
      File.read(safe, encoding: "UTF-8").strip
    end

    def target_localizations(before, mapping, info: false)
      observed = info ? INFO_OBSERVED_FIELDS : mapping.values
      values = Array(before).to_h do |item|
        [item.fetch("locale"), item.slice("locale", *observed)]
      end
      @locales.each do |locale|
        prior = values[locale] || { "locale" => locale }.merge(observed.to_h { |name| [name, ""] })
        mapping.each do |file, field|
          path = "#{locale}/#{file}"
          prior[field] = text_file(path) if File.file?(File.join(@root, path))
        end
        if info && prior.fetch("name").empty?
          raise ContractError, "A new AppInfo locale requires an approved name.txt (or an existing captured name)"
        end
        values[locale] = prior
      end
      values.values.sort_by { |item| item.fetch("locale") }
    end

    def metadata_target(current, nonce:)
      base = current["production"] || current["liveReference"] || {}
      info = current["appInfo"] || current["appInfoReference"] || {}
      # Do not silently ignore files that Deliver would interpret differently.
      Dir.glob(File.join(@root, "**", "*"), File::FNM_DOTMATCH).each do |path|
        next if File.directory?(path) && !File.symlink?(path)
        relative = path.delete_prefix(@root + "/")
        next if relative == ".gitkeep" || relative.end_with?("/.gitkeep")
        parts = relative.split("/")
        allowed = (parts.length == 1 && (CATEGORY_FIELDS.keys + ["copyright.txt"]).include?(parts.first)) ||
                  (parts.length == 2 && @locales.include?(parts.first) && (VERSION_FIELDS.keys + INFO_FIELDS.keys).include?(parts.last)) ||
                  (parts.first == "screenshots" && %w[.png .jpg .jpeg].include?(File.extname(path).downcase))
        raise ContractError, "Unsupported iOS Store metadata input: #{relative}" unless allowed && !File.symlink?(path)
      end
      categories = info.fetch("categories", CATEGORY_FIELDS.values.to_h { |field| [field, nil] }).dup
      CATEGORY_FIELDS.each do |file, field|
        next unless File.file?(File.join(@root, file))
        value = text_file(file)
        categories[field] = if field.include?("Subcategory")
                              Spaceship::ConnectAPI::AppCategory.map_subcategory_from_itc(value)
                            else
                              Spaceship::ConnectAPI::AppCategory.map_category_from_itc(value)
                            end
      end
      {
        "version" => {
          "copyright" => File.file?(File.join(@root, "copyright.txt")) ? text_file("copyright.txt") : base.fetch("copyright", ""),
          "localizations" => target_localizations(base["localizations"], VERSION_FIELDS),
        },
        "appInfo" => { "categories" => categories, "localizations" => target_localizations(info["localizations"], INFO_FIELDS, info: true) },
        "screenshots" => local_screenshots(nonce),
      }
    end

    def prepare(server_time:)
      current = read
      nonce = SecureRandom.hex(16)
      commitments = {
        "algorithm" => "hmac-sha256", "keyVersion" => @environment.fetch("MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION"),
        "domains" => { "app-review" => {
          "before" => MobileReleaseKit.hmac_commitment("app-review", current.fetch("_private"), @environment),
          "target" => MobileReleaseKit.hmac_commitment("app-review", @private_target, @environment),
        } },
      }
      if current["production"].nil? && current["liveReference"]
        commitments.fetch("domains").fetch("app-review")["inherited"] = MobileReleaseKit.hmac_commitment("app-review", current.fetch("_referencePrivate"), @environment)
      end
      snapshot = {
        "canonicalization" => "mrk-apple-operation-v1", "appStoreAppId" => @app_id,
        "serverObservedAt" => server_time, "build" => @build, "operationNonce" => nonce,
        "metadataTarget" => metadata_target(current, nonce: nonce), "privateStateCommitments" => commitments,
      }.merge(public_state(current))
      validate_categories!(snapshot.fetch("metadataTarget").dig("appInfo", "categories"))
      classification = classify(snapshot, current)
      if current["production"] && !classification.fetch(:final)
        raise ContractError, "An existing partial App Store version needs its original operation intent, not a new authorization"
      end
      snapshot
    end

    def local_screenshots(nonce)
      raise ContractError, "Screenshot operation nonce is invalid" unless nonce.match?(/\A[a-f0-9]{32}\z/)
      paths = Dir.glob(File.join(@root, "screenshots", "**", "*" )).select { |path| File.file?(path) && File.basename(path) != ".gitkeep" }.sort
      values = paths.map do |path|
        relative = path.delete_prefix(@root + "/")
        parts = relative.split("/")
        unless parts.length.between?(3, 4) && @locales.include?(parts[1])
          raise ContractError, "Screenshots require screenshots/<locale>/[<displayType>/]<file>"
        end
        safe = MobileReleaseKit.safe_path(@root, relative)
        size = File.size(safe)
        raise ContractError, "Screenshot is empty, oversized or a symlink" if File.symlink?(safe) || !size.between?(1, 10 * 1024 * 1024)
        dimensions = FastImage.size(safe)
        types = Deliver::AppScreenshot::DEVICE_RESOLUTIONS.select { |name, sizes| name.start_with?("APP_IPHONE_", "APP_IPAD_", "APP_WATCH_") && sizes.include?(dimensions) }.keys
        display = parts.length == 4 ? parts[2] : (types.length == 1 ? types.first : nil)
        raise ContractError, "Screenshot dimensions/display type are unsupported or ambiguous; use an explicit displayType directory" unless types.include?(display)
        digest = Digest::SHA256.file(safe).hexdigest
        {
          "localPath" => relative, "locale" => parts[1], "displayType" => display,
          "fileName" => "mrk-#{nonce}-#{digest}#{File.extname(safe).downcase}",
          "fileSize" => size, "sha256" => digest, "sourceFileChecksum" => Digest::MD5.file(safe).hexdigest,
        }
      end
      values.group_by { |item| [item.fetch("locale"), item.fetch("displayType")] }.each_value do |items|
        unique!(items, "sha256")
        raise ContractError, "Screenshot target exceeds Apple's ten-image set limit" if items.length > 10
      end
      values
    end

    def transition!(before, current, graph, label)
      unless graph.key?(current) && graph.fetch(before, []).include?(current)
        raise ContractError, "#{label} state is unsupported, terminal or regressed"
      end
    end

    def localization_phase!(before, inherited, target, current, fields:, fixed:)
      actual = current.to_h { |item| [item.fetch("locale"), item] }
      wanted = target.to_h { |item| [item.fetch("locale"), item] }
      baseline = Array(fixed ? before : inherited).to_h { |item| [item.fetch("locale"), item] }
      raise ContractError, "Apple localization inventory grew outside the authorized target" unless (actual.keys - wanted.keys).empty?
      if fixed && !(baseline.keys - actual.keys).empty?
        raise ContractError, "A pre-existing Apple localization disappeared"
      end
      actual.each do |locale, value|
        old = baseline[locale]
        if fixed && old && value.fetch("id") != old.fetch("id")
          raise ContractError, "A pre-existing Apple localization identity changed"
        end
        fields.each do |field|
          allowed = [wanted.fetch(locale).fetch(field)]
          allowed << old.fetch(field) if old
          allowed << "" unless fixed && old
          raise ContractError, "Apple localization content drifted" unless allowed.include?(value.fetch(field))
        end
      end
      wanted.all? { |locale, value| actual[locale] && fields.all? { |field| actual.fetch(locale).fetch(field) == value.fetch(field) } }
    end

    def shot_content(shot) = shot.slice("fileName", "fileSize", "sourceFileChecksum")

    def sets_by_key(version)
      Array(version && version["localizations"]).each_with_object({}) do |locale, result|
        locale.fetch("screenshotSets").each { |set| result[[locale.fetch("locale"), set.fetch("displayType")]] = set }
      end
    end

    def screenshot_plan(snapshot, current)
      fixed = !snapshot["production"].nil?
      before = sets_by_key(snapshot["production"] || snapshot["liveReference"])
      actual = sets_by_key(current["production"])
      targets = snapshot.fetch("metadataTarget").fetch("screenshots").group_by { |item| [item.fetch("locale"), item.fetch("displayType")] }
      raise ContractError, "An unrelated screenshot set appeared" unless (actual.keys - before.keys - targets.keys).empty?
      raise ContractError, "A pre-existing screenshot set disappeared" if fixed && !(before.keys - actual.keys).empty?
      plans = (before.keys | targets.keys).sort.map do |key|
        base = before[key]
        now = actual[key]
        if fixed && base && now.fetch("id") != base.fetch("id")
          raise ContractError, "A pre-existing screenshot set identity changed"
        end
        old_shots = base ? base.fetch("screenshots") : []
        shots = now ? now.fetch("screenshots") : []
        # A newly created version may be empty or contain cloned live assets
        # with new IDs. Neither case authorizes a change to the live reference.
        inherited = !fixed && old_shots.any? && shots.first && !shots.first.fetch("fileName").start_with?("mrk-#{snapshot.fetch('operationNonce')}-")
        kept = (fixed || inherited) ? old_shots : []
        kept.each_with_index do |old, index|
          value = shots[index]
          unless value && shot_content(value) == shot_content(old) && value.fetch("deliveryState") == "COMPLETE" &&
                 (!fixed || value.fetch("id") == old.fetch("id"))
            raise ContractError, "An existing/inherited screenshot was deleted, reordered or changed"
          end
        end
        additions = Array(targets[key]).reject do |target|
          matches = kept.select { |shot| shot.fetch("fileSize") == target.fetch("fileSize") && shot.fetch("sourceFileChecksum") == target.fetch("sourceFileChecksum") }
          raise ContractError, "Existing screenshot content is ambiguous" if matches.length > 1
          !matches.empty?
        end
        # Reserve only operation-owned names, never one that was in the prepared
        # before/reference inventory. This is the deletion authority on expiry.
        additions.each do |target|
          raise ContractError, "Operation-owned screenshot name collides with before/reference state" if old_shots.any? { |shot| shot.fetch("fileName") == target.fetch("fileName") }
        end
        # Before an absent version is created, it may inherit all live assets.
        # Prove that maximum footprint fits before any Store mutation occurs.
        potential_additions = Array(targets[key]).reject do |target|
          old_shots.any? { |shot| shot.fetch("fileSize") == target.fetch("fileSize") && shot.fetch("sourceFileChecksum") == target.fetch("sourceFileChecksum") }
        end
        if !fixed && old_shots.length + potential_additions.length > 10
          raise ContractError, "Inherited screenshots plus additions would exceed ten images"
        end
        raise ContractError, "Preserving existing screenshots plus additions would exceed ten images" if kept.length + additions.length > 10
        suffix = shots.drop(kept.length)
        raise ContractError, "Unexpected or duplicated screenshot reservation" if suffix.length > additions.length
        suffix.each_with_index do |shot, index|
          target = additions.fetch(index)
          unless shot.fetch("fileName") == target.fetch("fileName") && shot.fetch("fileSize") == target.fetch("fileSize") &&
                 ["", target.fetch("sourceFileChecksum")].include?(shot.fetch("sourceFileChecksum")) &&
                 %w[AWAITING_UPLOAD UPLOAD_COMPLETE COMPLETE FAILED].include?(shot.fetch("deliveryState"))
            raise ContractError, "Screenshot reservation differs from the authorized target/order"
          end
          if %w[UPLOAD_COMPLETE COMPLETE].include?(shot.fetch("deliveryState")) && shot.fetch("sourceFileChecksum") != target.fetch("sourceFileChecksum")
            raise ContractError, "Committed screenshot checksum differs from target"
          end
        end
        { key: key, set: now, kept: kept, additions: additions, suffix: suffix,
          final: suffix.length == additions.length && suffix.all? { |shot| shot.fetch("deliveryState") == "COMPLETE" } }
      end
      plans
    end

    def selected_submission(submissions, version_id)
      matching = submissions.select do |submission|
        submission.fetch("platform") == "IOS" &&
          (submission.fetch("state") != "COMPLETE" || submission.fetch("items").any? { |item| item.fetch("resource") == { "type" => "appStoreVersions", "id" => version_id } })
      end
      raise ContractError, "Multiple open/intended App Review submissions are ambiguous" if matching.length > 1
      submission = matching.first
      return nil unless submission
      raise ContractError, "App Review submission is unsafe or unsupported" unless SUBMISSION_TRANSITIONS.key?(submission.fetch("state"))
      items = submission.fetch("items")
      unless items.empty? && submission.fetch("state") == "READY_FOR_REVIEW"
        unless version_id && items.length == 1 && items.first.fetch("resource") == { "type" => "appStoreVersions", "id" => version_id } &&
               %w[READY_FOR_REVIEW ACCEPTED APPROVED].include?(items.first.fetch("state"))
          raise ContractError, "App Review submission contains an unrelated, rejected or removed item"
        end
      end
      submission
    end

    def submission_phase!(snapshot, current)
      version_id = current.dig("production", "id")
      before_id = snapshot.dig("production", "id")
      old = selected_submission(snapshot.fetch("reviewSubmissions"), before_id)
      actual = selected_submission(current.fetch("reviewSubmissions"), version_id)
      old_other = snapshot.fetch("reviewSubmissions").reject { |item| old && item.fetch("id") == old.fetch("id") }
      other = current.fetch("reviewSubmissions").reject { |item| actual && item.fetch("id") == actual.fetch("id") }
      raise ContractError, "Unrelated App Review submissions changed" unless old_other == other
      if old
        raise ContractError, "Prepared App Review submission disappeared or changed identity" unless actual && old.fetch("id") == actual.fetch("id")
        transition!(old.fetch("state"), actual.fetch("state"), SUBMISSION_TRANSITIONS, "App Review")
        if old.fetch("items").any?
          unless actual.fetch("items").map { |item| item.slice("id", "resource") } == old.fetch("items").map { |item| item.slice("id", "resource") }
            raise ContractError, "Prepared App Review membership changed"
          end
        end
      end
      actual
    end

    def classify(snapshot, current)
      %w[liveReference appInfoReference unrelatedVersions].each do |field|
        raise ContractError, "Apple read-only reference/unrelated state drifted" unless current[field] == snapshot[field]
      end
      pair = snapshot.fetch("privateStateCommitments").fetch("domains").fetch("app-review")
      inherited_allowed = snapshot["production"].nil? && snapshot["liveReference"] && snapshot["liveReference"]["appId"] == @app_id && snapshot["liveReference"]["platform"] == "IOS"
      if pair.key?("inherited")
        raise ContractError, "Inherited private state lacks an exact live iOS reference" unless inherited_allowed && current["_referencePrivate"]
        digest = MobileReleaseKit.hmac_commitment("app-review", current.fetch("_referencePrivate"), @environment)
        raise ContractError, "Live reference private state drifted" unless MobileReleaseKit.secure_equal(pair.fetch("inherited"), digest)
      end
      private_phase = AppleStore.private_phase!(snapshot.fetch("privateStateCommitments"), "app-review", current: current.fetch("_private"), target: @private_target, environ: @environment, allow_inherited: !!inherited_allowed)
      wanted = snapshot.fetch("metadataTarget")
      version = current["production"]
      old = snapshot["production"]
      if old && (!version || version.fetch("id") != old.fetch("id"))
        raise ContractError, "Prepared App Store version disappeared or changed identity"
      end
      metadata_final = false
      if version
        raise ContractError, "App Store version identity changed" unless version.fetch("appId") == @app_id && version.fetch("versionString") == @version && version.fetch("platform") == "IOS"
        transition!(old ? old.fetch("state") : "PREPARE_FOR_SUBMISSION", version.fetch("state"), VERSION_TRANSITIONS, "App Store version")
        raise ContractError, "App Store version must remain MANUAL without a date" unless version.fetch("releaseType") == "MANUAL" && version.fetch("earliestReleaseDate").empty?
        raise ContractError, "App Store version selects another build" unless [nil, @build.fetch("id")].include?(version.fetch("buildId"))
        if old && old.fetch("buildId") && old.fetch("buildId") != version.fetch("buildId")
          raise ContractError, "App Store build selection regressed"
        end
        raise ContractError, "Phased-release state changed outside the authorized operation" unless version["phasedRelease"] == (old && old["phasedRelease"])
        if old && old["privateDetailId"] && old["privateDetailId"] != version["privateDetailId"]
          raise ContractError, "Prepared App Review detail identity changed"
        end
        inherited = snapshot["liveReference"] || {}
        allowed_copyright = [wanted.dig("version", "copyright"), old ? old.fetch("copyright") : inherited.fetch("copyright", "")]
        allowed_copyright << "" unless old
        raise ContractError, "App Store copyright drifted" unless allowed_copyright.include?(version.fetch("copyright"))
        metadata_final = localization_phase!(old && old["localizations"], inherited["localizations"], wanted.dig("version", "localizations"), version.fetch("localizations"), fields: VERSION_FIELDS.values, fixed: !old.nil?) && version.fetch("copyright") == wanted.dig("version", "copyright")
      end
      info = current["appInfo"]
      old_info = snapshot["appInfo"]
      if old_info && (!info || info.fetch("id") != old_info.fetch("id"))
        raise ContractError, "Prepared AppInfo disappeared or changed identity"
      end
      info_final = false
      if info
        transition!(old_info ? old_info.fetch("state") : "PREPARE_FOR_SUBMISSION", info.fetch("state"), INFO_TRANSITIONS, "AppInfo")
        inherited = snapshot["appInfoReference"] || {}
        baseline = old_info || inherited
        info.fetch("categories").each do |field, value|
          allowed = [wanted.dig("appInfo", "categories", field), baseline.dig("categories", field)]
          allowed << nil unless old_info
          raise ContractError, "AppInfo category drifted" unless allowed.include?(value)
        end
        info_final = localization_phase!(old_info && old_info["localizations"], inherited["localizations"], wanted.dig("appInfo", "localizations"), info.fetch("localizations"), fields: INFO_OBSERVED_FIELDS, fixed: !old_info.nil?) && info.fetch("categories") == wanted.dig("appInfo", "categories")
      end
      plans = screenshot_plan(snapshot, current)
      submission = submission_phase!(snapshot, current)
      submitted = submission && %w[WAITING_FOR_REVIEW IN_REVIEW COMPLETING COMPLETE].include?(submission.fetch("state")) && submission.fetch("items").length == 1
      version_submitted = version && %w[WAITING_FOR_REVIEW IN_REVIEW ACCEPTED PENDING_DEVELOPER_RELEASE].include?(version.fetch("state"))
      if submission && submission.fetch("state") == "COMPLETE" && submission.fetch("items").first.fetch("state") != "APPROVED"
        raise ContractError, "Completed App Review submission does not prove approval"
      end
      final = metadata_final && info_final && plans.all? { |plan| plan.fetch(:final) } && private_phase == :target &&
              version && version.fetch("buildId") == @build.fetch("id") && submitted && version_submitted
      { final: !!final, metadata_final: metadata_final, info_final: info_final, screenshots: plans,
        private_phase: private_phase, submission: submission, submitted: !!submitted }
    end

    def validate_categories!(categories)
      raise ContractError, "AppInfo needs a reviewed primary category before submission" unless categories["primaryCategory"]
      %w[primary secondary].each do |prefix|
        parent = categories["#{prefix}Category"]
        subcategories = %w[One Two].map { |suffix| categories["#{prefix}Subcategory#{suffix}"] }.compact
        raise ContractError, "AppInfo subcategory selection is invalid" if subcategories.uniq.length != subcategories.length || (!parent && subcategories.any?)
        ([parent].compact + subcategories).each do |id|
          raise ContractError, "AppInfo category ID is invalid" unless id.is_a?(String) && id.match?(/\A[A-Z0-9_]{1,100}\z/)
          record = one(@client.tunes_request_client.get("v1/appCategories/#{id}", { include: "parent" }), "appCategories")
          unless record && record.fetch("id") == id && Array(record.fetch("attributes", {})["platforms"]).include?("IOS")
            raise ContractError, "AppInfo category is unavailable for iOS"
          end
          actual_parent = AppleStore.relationship_id(record, "parent", type: "appCategories")
          expected_parent = id == parent ? nil : parent
          raise ContractError, "AppInfo subcategory does not belong to the selected category" unless actual_parent == expected_parent
        end
      end
      if categories["secondaryCategory"] == categories["primaryCategory"]
        raise ContractError, "AppInfo primary and secondary categories must be distinct"
      end
    end

    def progress!(snapshot, before, current)
      %w[production appInfo].each do |field|
        old, value = before[field], current[field]
        next unless old
        raise ContractError, "Apple resource disappeared/replaced during operation" unless value && value.fetch("id") == old.fetch("id")
        transition!(old.fetch("state"), value.fetch("state"), field == "production" ? VERSION_TRANSITIONS : INFO_TRANSITIONS, field)
        wanted = snapshot.fetch("metadataTarget").fetch(field == "production" ? "version" : "appInfo")
        localization_phase!(old.fetch("localizations"), nil, wanted.fetch("localizations"), value.fetch("localizations"), fields: field == "production" ? VERSION_FIELDS.values : INFO_OBSERVED_FIELDS, fixed: true)
        if field == "production"
          if old["privateDetailId"] && old["privateDetailId"] != value["privateDetailId"]
            raise ContractError, "App Review detail identity changed during operation"
          end
          raise ContractError, "App Store selected build regressed" if old["buildId"] && old["buildId"] != value["buildId"]
          raise ContractError, "App Store copyright regressed" if old["copyright"] == wanted["copyright"] && value["copyright"] != wanted["copyright"]
        else
          old.fetch("categories").each do |name, prior|
            raise ContractError, "AppInfo category regressed" if prior == wanted.dig("categories", name) && value.dig("categories", name) != prior
          end
        end
      end
      old_sets, new_sets = sets_by_key(before["production"]), sets_by_key(current["production"])
      old_sets.each do |key, set|
        actual = new_sets[key]
        raise ContractError, "Screenshot set disappeared or changed ID" unless actual && actual.fetch("id") == set.fetch("id")
        kept = set.fetch("screenshots").reject { |shot| shot.fetch("id") == @removing_id }
        prefix = actual.fetch("screenshots").first(kept.length)
        raise ContractError, "Screenshots disappeared or changed order during operation" unless prefix.map { |shot| shot.fetch("id") } == kept.map { |shot| shot.fetch("id") }
        kept.zip(prefix).each do |old, shot|
          raise ContractError, "Existing screenshot identity changed" unless old.slice("fileName", "fileSize") == shot.slice("fileName", "fileSize")
          if old.fetch("sourceFileChecksum") != "" && old.fetch("sourceFileChecksum") != shot.fetch("sourceFileChecksum")
            raise ContractError, "Screenshot source checksum regressed"
          end
          allowed = {
            "AWAITING_UPLOAD" => %w[AWAITING_UPLOAD UPLOAD_COMPLETE COMPLETE FAILED],
            "UPLOAD_COMPLETE" => %w[UPLOAD_COMPLETE COMPLETE FAILED],
            "COMPLETE" => %w[COMPLETE], "FAILED" => %w[FAILED],
          }
          raise ContractError, "Screenshot delivery state regressed" unless allowed.fetch(old.fetch("deliveryState"), []).include?(shot.fetch("deliveryState"))
        end
      end
      old_submission = selected_submission(before.fetch("reviewSubmissions"), before.dig("production", "id"))
      new_submission = selected_submission(current.fetch("reviewSubmissions"), current.dig("production", "id"))
      if old_submission
        raise ContractError, "App Review submission disappeared during operation" unless new_submission && new_submission.fetch("id") == old_submission.fetch("id")
        transition!(old_submission.fetch("state"), new_submission.fetch("state"), SUBMISSION_TRANSITIONS, "App Review")
        old_submission.fetch("items").each do |item|
          actual = new_submission.fetch("items").find { |value| value.fetch("id") == item.fetch("id") }
          allowed = { "READY_FOR_REVIEW" => %w[READY_FOR_REVIEW ACCEPTED APPROVED], "ACCEPTED" => %w[ACCEPTED APPROVED], "APPROVED" => %w[APPROVED] }
          raise ContractError, "App Review item disappeared or regressed" unless actual && actual.fetch("resource") == item.fetch("resource") && allowed.fetch(item.fetch("state"), []).include?(actual.fetch("state"))
        end
      end
      pair = snapshot.fetch("privateStateCommitments").dig("domains", "app-review")
      prior_digest = MobileReleaseKit.hmac_commitment("app-review", before.fetch("_private"), @environment)
      current_digest = MobileReleaseKit.hmac_commitment("app-review", current.fetch("_private"), @environment)
      if MobileReleaseKit.secure_equal(prior_digest, pair.fetch("target")) && !MobileReleaseKit.secure_equal(current_digest, pair.fetch("target"))
        raise ContractError, "Private review details regressed during operation"
      end
    end

    def validated_read(snapshot)
      build = @read_build.call
      AppleStore.require_build!(snapshot.fetch("build"), build, expected_encryption: snapshot.dig("build", "usesNonExemptEncryption"))
      unless build["autoNotifyEnabled"] == snapshot.dig("build", "autoNotifyEnabled")
        raise ContractError, "Candidate notification state changed during production preparation"
      end
      current = read
      classify(snapshot, current)
      progress!(snapshot, @previous, current) if @previous
      observe_creates(snapshot, current) if @create_guard
      @previous = current
      current
    end

    def shot_locator(snapshot, target)
      siblings = snapshot.fetch("metadataTarget").fetch("screenshots").select do |item|
        item.fetch("locale") == target.fetch("locale") && item.fetch("displayType") == target.fetch("displayType")
      end
      target.slice("locale", "displayType", "fileName", "fileSize", "sha256", "sourceFileChecksum").merge("order" => siblings.index(target))
    end

    def private_locator(snapshot)
      commitments = snapshot.fetch("privateStateCommitments")
      { "domain" => "app-review", "keyVersion" => commitments.fetch("keyVersion"),
        "targetHmacSha256" => commitments.dig("domains", "app-review", "target") }
    end

    def create_nodes(snapshot, current)
      guard = @create_guard
      version, info = current.values_at("production", "appInfo")
      target = snapshot.fetch("metadataTarget")
      nodes = []
      unless version
        nodes << guard.node("appStoreVersions", locator: {}, parent: guard.present("apps", @app_id),
                            target: { "platform" => "IOS", "versionString" => @version, "releaseType" => "MANUAL" })
      end
      version_parent = version ? guard.present("appStoreVersions", version.fetch("id")) : guard.missing("appStoreVersions")
      version_dependencies = version ? [] : [guard.logical_key("appStoreVersions")]
      target.dig("version", "localizations").each do |locale|
        present = Array(version && version["localizations"]).find { |item| item.fetch("locale") == locale.fetch("locale") }
        next if present
        nodes << guard.node("appStoreVersionLocalizations", locator: locale.slice("locale"), parent: version_parent, target: locale)
      end
      info_parent = if info
                      guard.present("appInfos", info.fetch("id"))
                    elsif version.nil?
                      guard.automatic_info(Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(snapshot["appInfoReference"])))
                    else
                      raise ContractError, "AppInfo initialization is still pending; read-only reconciliation is required"
                    end
      target.dig("appInfo", "localizations").each do |locale|
        present = Array(info && info["localizations"]).find { |item| item.fetch("locale") == locale.fetch("locale") }
        next if present
        nodes << guard.node("appInfoLocalizations", locator: locale.slice("locale"), parent: info_parent, target: locale)
      end
      unless version && version["privateDetailId"]
        locator = private_locator(snapshot)
        nodes << guard.node("appStoreReviewDetails", locator: locator, parent: version_parent, target: locator)
      end
      screenshot_plan(snapshot, current).each do |plan|
        next if plan.fetch(:additions).empty?
        locale, display = plan.fetch(:key)
        set = plan.fetch(:set)
        unless set
          localization = Array(version && version["localizations"]).find { |item| item.fetch("locale") == locale }
          parent = localization ? guard.present("appStoreVersionLocalizations", localization.fetch("id")) : guard.missing("appStoreVersionLocalizations", { "locale" => locale })
          nodes << guard.node("appScreenshotSets", locator: { "locale" => locale, "displayType" => display }, parent: parent, target: { "screenshotDisplayType" => display })
        end
        parent = set ? guard.present("appScreenshotSets", set.fetch("id")) : guard.missing("appScreenshotSets", { "locale" => locale, "displayType" => display })
        plan.fetch(:additions).each_with_index do |shot, index|
          next if plan.fetch(:suffix)[index]
          nodes << guard.node("appScreenshots", locator: shot_locator(snapshot, shot), parent: parent, target: shot)
        end
      end
      submission = selected_submission(current.fetch("reviewSubmissions"), version && version["id"])
      unless submission
        nodes << guard.node("reviewSubmissions", locator: {}, parent: guard.present("apps", @app_id),
                            target: { "platform" => "IOS", "appId" => @app_id, "buildId" => @build.fetch("id") }, dependencies: version_dependencies)
      end
      if !submission || submission.fetch("items").empty?
        parent = submission ? guard.present("reviewSubmissions", submission.fetch("id")) : guard.missing("reviewSubmissions")
        nodes << guard.node("reviewSubmissionItems", locator: {}, parent: parent,
                            target: { "versionString" => @version, "buildId" => @build.fetch("id") }, dependencies: version_dependencies)
      end
      nodes
    end

    def observe_creates(snapshot, current)
      guard = @create_guard
      version, info = current.values_at("production", "appInfo")
      if version
        guard.observe!("appStoreVersions", locator: {}, id: version.fetch("id"))
        version.fetch("localizations").each do |locale|
          guard.observe!("appStoreVersionLocalizations", locator: locale.slice("locale"), id: locale.fetch("id"))
        end
        if version["privateDetailId"]
          guard.observe!("appStoreReviewDetails", locator: private_locator(snapshot), id: version.fetch("privateDetailId"))
        end
      end
      if info
        guard.resolve_automatic_info!(info.fetch("id"))
        info.fetch("localizations").each { |locale| guard.observe!("appInfoLocalizations", locator: locale.slice("locale"), id: locale.fetch("id")) }
      end
      screenshot_plan(snapshot, current).each do |plan|
        if plan.fetch(:set)
          guard.observe!("appScreenshotSets", locator: { "locale" => plan.fetch(:key).first, "displayType" => plan.fetch(:key).last }, id: plan.fetch(:set).fetch("id"))
        end
        plan.fetch(:suffix).each_with_index do |shot, index|
          guard.observe!("appScreenshots", locator: shot_locator(snapshot, plan.fetch(:additions).fetch(index)), id: shot.fetch("id"))
        end
      end
      submission = selected_submission(current.fetch("reviewSubmissions"), version && version["id"])
      if submission
        guard.observe!("reviewSubmissions", locator: {}, id: submission.fetch("id"))
        item = submission.fetch("items").first
        guard.observe!("reviewSubmissionItems", locator: {}, id: item.fetch("id")) if item
      end
    end

    def create_once(type, locator:, parent_id:)
      @create_guard.consume!(type, locator: locator, parent_id: parent_id)
      response = yield
      record = one(response, type)
      raise ContractError, "Apple create response has no resource identity" unless record
      @create_guard.resolve!(type, locator, record.fetch("id"))
      response
    end

    def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def mutate(phase, snapshot, current, complete:)
      fresh = validated_read(snapshot)
      return fresh unless fresh == current
      @journal.call("#{phase}-dispatched", {})
      @wrote = true
      begin
        yield
      rescue AppleCreateRetry::Denied
        raise
      rescue Interrupt, SystemExit => error
        @journal.call("cancelled", { "failureClass" => error.class.name }) rescue nil
        raise
      rescue StandardError => error
        @journal.call("#{phase}-response-ambiguous", { "failureClass" => error.class.name })
      end
      deadline = now + 300
      loop do
        actual = validated_read(snapshot)
        if complete.call(actual)
          @journal.call("#{phase}-read-back", {})
          return actual
        end
        raise ContractError, "Apple operation is not proven complete; recover the original intent" if now >= deadline
        sleep(5)
      end
    end

    def differing(target, current)
      target.reject { |field, value| field == "locale" || current && current[field] == value }
    end

    def localization_action(snapshot, current, info:)
      resource = current[info ? "appInfo" : "production"]
      return nil unless resource
      target = snapshot.fetch("metadataTarget").dig(info ? "appInfo" : "version", "localizations")
      target.each do |locale|
        old = resource.fetch("localizations").find { |item| item.fetch("locale") == locale.fetch("locale") }
        changes = differing(locale, old)
        next if old && changes.empty?
        complete = lambda do |actual|
          value = actual.fetch(info ? "appInfo" : "production").fetch("localizations").find { |item| item.fetch("locale") == locale.fetch("locale") }
          value && locale.all? { |name, content| value[name] == content }
        end
        write = lambda do
          if old
            if info
              @client.patch_app_info_localization(app_info_localization_id: old.fetch("id"), attributes: changes)
            else
              @client.patch_app_store_version_localization(app_store_version_localization_id: old.fetch("id"), attributes: changes)
            end
          elsif info
            # Fastlane 2.235.0's helper uses the wrong parent relationship.
            create_once("appInfoLocalizations", locator: locale.slice("locale"), parent_id: resource.fetch("id")) do
              @client.tunes_request_client.post("v1/appInfoLocalizations", {
                data: { type: "appInfoLocalizations", attributes: locale.reject { |_name, value| value == "" },
                        relationships: { appInfo: { data: { type: "appInfos", id: resource.fetch("id") } } } },
              })
            end
          else
            create_once("appStoreVersionLocalizations", locator: locale.slice("locale"), parent_id: resource.fetch("id")) do
              @client.post_app_store_version_localization(app_store_version_id: resource.fetch("id"), attributes: locale.reject { |_name, value| value == "" })
            end
          end
        end
        return [info ? "production-app-info-locale" : "production-version-locale", complete, write]
      end
      nil
    end

    def screenshot_action(snapshot, current, plan)
      key, set = plan.values_at(:key, :set)
      unless set
        locale = current.fetch("production").fetch("localizations").find { |value| value.fetch("locale") == key.first }
        raise ContractError, "Screenshot target locale has not been created" unless locale
        return ["production-screenshot-set", ->(value) { sets_by_key(value["production"]).key?(key) }, lambda {
          create_once("appScreenshotSets", locator: { "locale" => key.first, "displayType" => key.last }, parent_id: locale.fetch("id")) do
            @client.post_app_screenshot_set(app_store_version_localization_id: locale.fetch("id"), attributes: { screenshotDisplayType: key.last })
          end
        }]
      end
      additions, suffix = plan.values_at(:additions, :suffix)
      additions.each_with_index do |target, index|
        shot = suffix[index]
        unless shot
          return ["production-screenshot-reservation", ->(value) { sets_by_key(value["production"]).fetch(key).fetch("screenshots").any? { |item| item.fetch("fileName") == target.fetch("fileName") } },
                  lambda {
                    create_once("appScreenshots", locator: shot_locator(snapshot, target), parent_id: set.fetch("id")) do
                      @client.post_app_screenshot(app_screenshot_set_id: set.fetch("id"), attributes: target.slice("fileName", "fileSize"))
                    end
                  }]
        end
        next if shot.fetch("deliveryState") == "COMPLETE"
        return nil if shot.fetch("deliveryState") == "UPLOAD_COMPLETE"
        raw = one(@client.get_app_screenshot(app_screenshot_id: shot.fetch("id")), "appScreenshots")
        unless raw && raw.fetch("id") == shot.fetch("id") && text(raw, "fileName") == target.fetch("fileName") && raw.dig("attributes", "fileSize") == target.fetch("fileSize")
          raise ContractError, "Screenshot reservation readback has changed"
        end
        return nil unless raw.dig("attributes", "assetDeliveryState", "state") == shot.fetch("deliveryState")
        ranges = shot.fetch("deliveryState") == "FAILED" ? [] : AppleAssetUpload.plan(raw.dig("attributes", "uploadOperations"), target.fetch("fileSize"))
        expired = ranges.any? { |range| Time.now.to_i >= range.fetch(:expires) }
        if shot.fetch("deliveryState") == "FAILED" || expired
          raise ContractError, "Only the final incomplete owned screenshot reservation can be replaced" unless index == suffix.length - 1
          raise ContractError, "Screenshot replacement already failed in this execution; retain the intent" if @replacements[target.fetch("localPath")]
          @create_guard.permit_replacement!(
            @create_guard.node("appScreenshots", locator: shot_locator(snapshot, target), parent: @create_guard.present("appScreenshotSets", set.fetch("id")), target: target),
            shot.fetch("id"),
          )
          @replacements[target.fetch("localPath")] = true
          @removing_id = shot.fetch("id")
          return ["production-expired-screenshot-removal", ->(value) { sets_by_key(value["production"]).fetch(key).fetch("screenshots").none? { |item| item.fetch("id") == shot.fetch("id") } },
                  -> { @client.tunes_request_client.mrk_delete_owned_screenshot(shot.fetch("id")) }]
        end
        return [:upload, target, shot, ranges]
      end
      nil
    end

    def upload_screenshot(snapshot, current, target, shot, ranges)
      path = MobileReleaseKit.safe_path(@root, target.fetch("localPath"))
      unless File.size(path) == target.fetch("fileSize") && Digest::SHA256.file(path).hexdigest == target.fetch("sha256") && Digest::MD5.file(path).hexdigest == target.fetch("sourceFileChecksum")
        raise ContractError, "Screenshot bytes changed after authorization"
      end
      deadline = now + 600
      ranges.each_with_index do |range, index|
        current = validated_read(snapshot)
        value = sets_by_key(current["production"]).fetch([target.fetch("locale"), target.fetch("displayType")]).fetch("screenshots").find { |item| item.fetch("id") == shot.fetch("id") }
        raise ContractError, "Screenshot upload reservation is no longer awaiting these bytes" unless value && value.fetch("deliveryState") == "AWAITING_UPLOAD"
        raise ContractError, "Screenshot part upload time bound exceeded" if now >= deadline
        @journal.call("production-screenshot-part-dispatched", { "screenshotId" => shot.fetch("id"), "part" => index })
        @wrote = true
        bytes = File.binread(path, range.fetch(:length), range.fetch(:offset))
        @upload_part.call(range, bytes)
      end
      mutate("production-screenshot-commit", snapshot, current, complete: lambda { |value|
        actual = sets_by_key(value["production"]).fetch([target.fetch("locale"), target.fetch("displayType")]).fetch("screenshots").find { |item| item.fetch("id") == shot.fetch("id") }
        actual && %w[UPLOAD_COMPLETE COMPLETE].include?(actual.fetch("deliveryState")) && actual.fetch("sourceFileChecksum") == target.fetch("sourceFileChecksum")
      }) do
        @client.patch_app_screenshot(app_screenshot_id: shot.fetch("id"), attributes: { uploaded: true, sourceFileChecksum: target.fetch("sourceFileChecksum") })
      end
    end

    def next_action(snapshot, current, status)
      version, info = current.values_at("production", "appInfo")
      target = snapshot.fetch("metadataTarget")
      unless version
        return ["production-create-version", ->(value) { !value["production"].nil? },
                lambda {
                  create_once("appStoreVersions", locator: {}, parent_id: @app_id) do
                    @client.post_app_store_version(app_id: @app_id, attributes: { platform: "IOS", versionString: @version, releaseType: "MANUAL" })
                  end
                }]
      end
      # An asynchronous submitted state is observation-only. Never attempt to
      # repair metadata/builds or re-submit while Apple is processing review.
      return nil if status.fetch(:submitted) || !%w[PREPARE_FOR_SUBMISSION READY_FOR_REVIEW].include?(version.fetch("state"))
      if version.fetch("copyright") != target.dig("version", "copyright")
        return ["production-copyright", ->(value) { value.dig("production", "copyright") == target.dig("version", "copyright") },
                -> { @client.patch_app_store_version(app_store_version_id: version.fetch("id"), attributes: { copyright: target.dig("version", "copyright") }) }]
      end
      action = localization_action(snapshot, current, info: false)
      return action if action
      return nil unless info
      if info.fetch("categories") != target.dig("appInfo", "categories")
        names = {
          "primaryCategory" => :primary_category_id, "primarySubcategoryOne" => :primary_subcategory_one_id, "primarySubcategoryTwo" => :primary_subcategory_two_id,
          "secondaryCategory" => :secondary_category_id, "secondarySubcategoryOne" => :secondary_subcategory_one_id, "secondarySubcategoryTwo" => :secondary_subcategory_two_id,
        }
        changes = target.dig("appInfo", "categories").reject { |name, value| info.fetch("categories")[name] == value }.to_h { |name, value| [names.fetch(name), value] }
        return ["production-categories", ->(value) { value.dig("appInfo", "categories") == target.dig("appInfo", "categories") },
                -> { @client.patch_app_info_categories(app_info_id: info.fetch("id"), category_id_map: changes) }]
      end
      action = localization_action(snapshot, current, info: true)
      return action if action
      if status.fetch(:private_phase) != :target
        return ["production-review-details", ->(value) { classify(snapshot, value).fetch(:private_phase) == :target }, lambda {
          id = version.fetch("privateDetailId")
          if id
            @client.patch_app_store_review_detail(app_store_review_detail_id: id, attributes: @private_target)
          else
            create_once("appStoreReviewDetails", locator: private_locator(snapshot), parent_id: version.fetch("id")) do
              @client.post_app_store_review_detail(app_store_version_id: version.fetch("id"), attributes: @private_target)
            end
          end
        }]
      end
      pending = status.fetch(:screenshots).find { |plan| !plan.fetch(:final) }
      return screenshot_action(snapshot, current, pending) if pending
      if version.fetch("buildId") != @build.fetch("id")
        return ["production-select-build", ->(value) { value.dig("production", "buildId") == @build.fetch("id") },
                -> { @client.patch_app_store_version_with_build(app_store_version_id: version.fetch("id"), build_id: @build.fetch("id")) }]
      end
      submission = status.fetch(:submission)
      unless submission
        return ["production-create-review", ->(value) { !classify(snapshot, value).fetch(:submission).nil? }, lambda {
          create_once("reviewSubmissions", locator: {}, parent_id: @app_id) { @client.post_review_submission(app_id: @app_id, platform: "IOS") }
        }]
      end
      if submission.fetch("items").empty?
        return ["production-add-review-item", ->(value) { classify(snapshot, value).fetch(:submission).fetch("items").length == 1 },
                lambda {
                  create_once("reviewSubmissionItems", locator: {}, parent_id: submission.fetch("id")) do
                    @client.post_review_submission_item(review_submission_id: submission.fetch("id"), app_store_version_id: version.fetch("id"))
                  end
                }]
      end
      ["production-submit-review", ->(value) { classify(snapshot, value).fetch(:submitted) },
       -> { @client.patch_review_submission(review_submission_id: submission.fetch("id"), attributes: { submitted: true }) }]
    end

    def execute(snapshot, resuming:)
      raise ContractError, "Apple production execution requires its immutable create guard" unless @create_guard
      unless metadata_target(snapshot, nonce: snapshot.fetch("operationNonce")) == snapshot.fetch("metadataTarget")
        raise ContractError, "Local Store metadata differs from the authorized target"
      end
      validate_categories!(snapshot.fetch("metadataTarget").dig("appInfo", "categories"))
      current = validated_read(snapshot)
      unless resuming || snapshot["production"]
        unless public_state(current) == snapshot.slice(*public_state(current).keys) &&
               MobileReleaseKit.secure_equal(MobileReleaseKit.hmac_commitment("app-review", current.fetch("_private"), @environment), snapshot.fetch("privateStateCommitments").dig("domains", "app-review", "before"))
          raise ContractError, "Apple production state changed between preparation and first dispatch"
        end
      end
      # A version's AppInfo may be initialized asynchronously. Do not issue an
      # incomplete retry inventory or attach child locales to an arbitrary ID.
      parent_deadline = now + 300
      while current["production"] && current["appInfo"].nil?
        raise ContractError, "AppInfo initialization is not yet proven; recover read-only" if now >= parent_deadline
        sleep(5)
        current = validated_read(snapshot)
      end
      if resuming && !classify(snapshot, current).fetch(:final)
        # Poll before requesting permission: a delayed create may appear and
        # satisfy the operation. A timeout never proves that a POST was rejected.
        absence_deadline = now + 60
        while create_nodes(snapshot, current).any? && now < absence_deadline
          sleep(5)
          current = validated_read(snapshot)
        end
      end
      @create_guard.arm!(public_state: public_state(current).merge("build" => @read_build.call),
                         nodes: create_nodes(snapshot, current), resuming: resuming)
      @wrote = false
      deadline = now + 3_600
      loop do
        status = classify(snapshot, current)
        if status.fetch(:final)
          retry_evidence = @create_guard.retry_evidence
          result = retry_evidence ? "operator_authorized_retry" : (@wrote ? "accepted" : (snapshot["production"] ? "already_present" : "reconciled"))
          state_digest = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(public_state(current)))
          @journal.call("committed-and-read-back", {
            "versionId" => current.dig("production", "id"), "reviewSubmissionId" => status.fetch(:submission).fetch("id"),
            "storeStateSha256" => state_digest, "result" => result,
          })
          return { result: result, submission_state: current.dig("production", "state"), version_id: current.dig("production", "id"), review_submission_id: status.fetch(:submission).fetch("id"), create_retry: retry_evidence, store_state_sha256: state_digest }
        end
        raise ContractError, "Apple processing has not reached verified submission; recover the original intent" if now >= deadline
        action = next_action(snapshot, current, status)
        if action
          if action.first == :upload
            current = upload_screenshot(snapshot, current, *action.drop(1))
          else
            phase, complete, write = action
            current = mutate(phase, snapshot, current, complete: complete, &write)
            @removing_id = nil
          end
        else
          sleep(5)
          current = validated_read(snapshot)
        end
      end
    end
  end
end
