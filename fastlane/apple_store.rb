# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require_relative "release_support"

module MobileReleaseKit
  # Spaceship normally retries both in APIClient and Client. A lost POST response
  # can create a resource twice before a lane gets control back. These overrides
  # are installed only in this toolkit's isolated Fastlane process. Writes get
  # one wire request; the operation state machine, not the HTTP library, decides
  # whether a later request is safe after fresh Store readback.
  module AppleOperationTransport
    def post(url, body, **options)
      mrk_single_write(:post, url, body) { super(url, body, **options) }
    end

    def patch(url, body)
      mrk_single_write(:patch, url, body) { super(url, body) }
    end

    def delete(url, params = nil, body = nil)
      unless @mrk_owned_screenshot_id && url == "v1/appScreenshots/#{@mrk_owned_screenshot_id}"
        raise ContractError, "Apple release operations cannot delete unrelated Store resources"
      end
      mrk_single_write(:delete, url, {}) { super(url, params, body) }
    end

    # Only AppleProduction's full before/target/nonce/expiry guard calls this.
    # The exception never applies to an entire set or a completed/before asset.
    def mrk_delete_owned_screenshot(id)
      raise ContractError, "Screenshot reservation ID is invalid" unless id.match?(/\A[A-Za-z0-9_.-]{1,255}\z/)
      prior = @mrk_owned_screenshot_id
      @mrk_owned_screenshot_id = id
      delete("v1/appScreenshots/#{id}")
    ensure
      @mrk_owned_screenshot_id = prior
    end

    protected

    def mrk_single_write(method, url, body)
      unless ENV["MOBILE_RELEASE_STORE_MODE"] == "execute"
        raise ContractError, "Apple read-only preparation cannot mutate Store state"
      end
      path = URI.parse(url).path.sub(%r{\A/}, "")
      allowed = {
        post: %r{\Av1/(?:appStoreVersions|appStoreVersionLocalizations|appInfoLocalizations|appStoreReviewDetails|appScreenshotSets|appScreenshots|reviewSubmissions|reviewSubmissionItems|betaBuildLocalizations|betaAppReviewSubmissions|builds/[^/]+/relationships/betaGroups)\z},
        patch: %r{\Av1/(?:appStoreVersions/[^/]+(?:/relationships/build)?|appStoreVersionLocalizations/[^/]+|appInfoLocalizations/[^/]+|appInfos/[^/]+|appStoreReviewDetails/[^/]+|appScreenshots/[^/]+|reviewSubmissions/[^/]+|builds/[^/]+|betaAppReviewDetails/[^/]+|betaBuildLocalizations/[^/]+|buildBetaDetails/[^/]+)\z},
        delete: %r{\Av1/appScreenshots/[^/]+\z},
      }
      raise ContractError, "Apple mutation endpoint is outside the release contract" unless allowed.fetch(method).match?(path)
      data = body[:data] || body["data"]
      attributes = data.is_a?(Hash) ? (data[:attributes] || data["attributes"] || {}) : {}
      unless attributes.is_a?(Hash)
        raise ContractError, "Apple mutation attributes must be an object"
      end
      release_type = attributes[:releaseType] || attributes["releaseType"]
      if (release_type && release_type != "MANUAL") ||
         attributes.key?(:earliestReleaseDate) || attributes.key?("earliestReleaseDate") ||
         attributes.key?(:canceled) || attributes.key?("canceled") ||
         attributes.key?(:expired) || attributes.key?("expired")
        raise ContractError, "Apple mutation would cross the manual-release/preservation boundary"
      end
      prior = @mrk_single_write
      @mrk_single_write = true
      yield
    ensure
      @mrk_single_write = prior
    end

    def with_retry(*)
      # Suppress the inner retry layer for reads too: the bounded outer loop
      # below owns read retries, so retries cannot multiply across layers.
      yield
    end

    def with_asc_retry(*)
      if @mrk_single_write
        response = yield
        unless response && response.status.between?(200, 299)
          raise ContractError, "Apple mutation response is not successful; readback is required"
        end
        return response
      end

      attempts = 0
      begin
        attempts += 1
        response = yield
        if response && [429, 500, 502, 503, 504].include?(response.status)
          raise ContractError, "Temporary Apple read failure"
        end
        response
      rescue ContractError, Spaceship::Client::UnexpectedResponse,
             Spaceship::Client::AppleTimeoutError, Spaceship::Client::GatewayTimeoutError,
             Spaceship::Client::BadGatewayError, Faraday::TimeoutError, Faraday::ConnectionFailed
        raise if attempts >= 3

        sleep(attempts)
        retry
      end
    end

    # Request/response bodies include private review inputs. The parent client
    # otherwise persists these to its per-user log even when stdout is hidden.
    def log_request(*); end
    def log_response(*); end
  end

  module AppleStore
    EXTERNAL_STATES = {
      "PROCESSING" => :processing,
      "MISSING_EXPORT_COMPLIANCE" => :compliance,
      "IN_EXPORT_COMPLIANCE_REVIEW" => :compliance_review,
      "READY_FOR_BETA_SUBMISSION" => :ready,
      "WAITING_FOR_BETA_REVIEW" => :waiting,
      "IN_BETA_REVIEW" => :review,
      "BETA_APPROVED" => :approved,
      "READY_FOR_BETA_TESTING" => :approved,
      "IN_BETA_TESTING" => :testing,
    }.freeze
    EXTERNAL_TRANSITIONS = {
      processing: %i[processing compliance compliance_review ready waiting review approved testing],
      compliance: %i[compliance processing compliance_review ready waiting review approved testing],
      compliance_review: %i[compliance_review ready waiting review approved testing],
      ready: %i[ready waiting review approved testing],
      waiting: %i[waiting review approved testing],
      review: %i[review approved testing],
      approved: %i[approved testing],
      testing: %i[testing],
    }.freeze
    REVIEW_STATES = {
      "NOT_SUBMITTED" => :absent,
      "WAITING_FOR_REVIEW" => :waiting,
      "WAITING_FOR_BETA_REVIEW" => :waiting,
      "SUBMITTED" => :waiting,
      "IN_REVIEW" => :review,
      "IN_BETA_REVIEW" => :review,
      "BETA_APPROVED" => :approved,
      "APPROVED" => :approved,
    }.freeze
    REVIEW_TRANSITIONS = {
      absent: %i[absent waiting review approved],
      waiting: %i[waiting review approved],
      review: %i[review approved],
      approved: %i[approved],
    }.freeze
    BUILD_IDENTITY_FIELDS = %w[id appId marketingVersion buildNumber uploadedDate expirationDate].freeze

    def self.models(response, maximum: 10_000)
      result = []
      seen = []
      pages = 0
      while response
        pages += 1
        raise ContractError, "Apple readback exceeded the page bound" if pages > 100
        unless response.respond_to?(:to_models)
          raise ContractError, "Apple readback is not a model response"
        end
        result.concat(response.to_models)
        raise ContractError, "Apple readback exceeded the resource bound" if result.length > maximum
        url = response.next_url
        break unless url

        parsed = URI.parse(url)
        unless parsed.scheme == "https" && parsed.host == "api.appstoreconnect.apple.com" &&
               parsed.userinfo.nil? && parsed.port == 443 && !seen.include?(url)
          raise ContractError, "Apple pagination URL is invalid or repeated"
        end
        seen << url
        response = response.next_page
      end
      result
    end

    # Relationship IDs in the raw JSON:API response are authoritative. The SDK
    # deliberately drops relationships whose included model bodies are absent.
    def self.records(response, type:, maximum: 10_000)
      values = []
      urls = []
      pages = 0
      while response
        pages += 1
        raise ContractError, "Apple response exceeded its page bound" if pages > 100
        unless response.status.to_i.between?(200, 299) && response.body.is_a?(Hash) && response.body.key?("data")
          raise ContractError, "Apple readback is not a successful JSON:API response"
        end
        data = response.body.fetch("data")
        items = data.nil? ? [] : (data.is_a?(Array) ? data : [data])
        items.each do |item|
          unless item.is_a?(Hash) && item["type"] == type && item["id"].is_a?(String) && item["id"].match?(/\A[A-Za-z0-9_.-]{1,255}\z/)
            raise ContractError, "Apple readback contains an invalid resource identity"
          end
          values << item
        end
        raise ContractError, "Apple response exceeded its resource bound" if values.length > maximum
        url = response.next_url
        break unless url

        uri = URI.parse(url)
        unless uri.scheme == "https" && uri.host == "api.appstoreconnect.apple.com" && uri.port == 443 && uri.userinfo.nil? && !urls.include?(url)
          raise ContractError, "Apple pagination URL is invalid or repeated"
        end
        urls << url
        response = response.next_page
      end
      raise ContractError, "Apple response contains duplicate resource IDs" unless values.map { |item| item.fetch("id") }.uniq.length == values.length
      values
    end

    def self.relationship_id(record, name, type:, required: true)
      relation = record.fetch("relationships", {})[name]
      if !relation.is_a?(Hash) || !relation.key?("data")
        raise ContractError, "Apple relationship readback is missing" if required
        return nil
      end
      data = relation.fetch("data")
      return nil if data.nil?
      unless data.is_a?(Hash) && data["type"] == type && data["id"].is_a?(String) && data["id"].match?(/\A[A-Za-z0-9_.-]{1,255}\z/)
        raise ContractError, "Apple relationship readback has the wrong type/identity"
      end
      data.fetch("id")
    end

    def self.require_build!(before, current, expected_encryption:, allow_processing: false)
      unless BUILD_IDENTITY_FIELDS.all? { |field| current.fetch(field) == before.fetch(field) }
        raise ContractError, "TestFlight build identity changed after authorization"
      end
      allowed = allow_processing ? %w[VALID PROCESSING] : %w[VALID]
      if current.fetch("expired") || !allowed.include?(current.fetch("processingState"))
        raise ContractError, "TestFlight build processing/expiry state is unsafe"
      end
      allowed_encryption = [before["usesNonExemptEncryption"], expected_encryption]
      unless allowed_encryption.include?(current["usesNonExemptEncryption"])
        raise ContractError, "TestFlight export-compliance declaration changed"
      end
    end

    def self.external_transition!(before, current)
      external_before = EXTERNAL_STATES[before.fetch("externalState")]
      external_current = EXTERNAL_STATES[current.fetch("externalState")]
      review_before = REVIEW_STATES[before.fetch("betaReviewState")]
      review_current = REVIEW_STATES[current.fetch("betaReviewState")]
      unless external_before && external_current && review_before && review_current
        raise ContractError, "TestFlight external/Beta Review state is terminal or unsupported"
      end
      unless EXTERNAL_TRANSITIONS.fetch(external_before).include?(external_current) &&
             REVIEW_TRANSITIONS.fetch(review_before).include?(review_current)
        raise ContractError, "TestFlight external/Beta Review state regressed"
      end
      { external: external_current, review: review_current }
    end

    # A PATCH of one localization is atomic; different locales can be at
    # different phases. Missing pre-existing locales and third values are drift.
    def self.localizations_phase!(before, target, current, fields:)
      index = lambda do |values|
        raise ContractError, "Apple localization inventory is invalid" unless values.is_a?(Array) && values.length <= 100
        grouped = values.group_by { |item| item.fetch("locale") }
        raise ContractError, "Apple localization inventory is ambiguous" unless grouped.values.all? { |items| items.length == 1 }
        grouped.transform_values(&:first)
      end
      old = index.call(before)
      wanted = index.call(target)
      actual = index.call(current)
      unless (old.keys - actual.keys).empty? && (actual.keys - wanted.keys).empty?
        raise ContractError, "Apple localization set changed outside the authorized operation"
      end
      actual.each do |locale, value|
        expected = wanted.fetch(locale)
        if old[locale] && old.fetch(locale)["id"] && old.fetch(locale)["id"] != value["id"]
          raise ContractError, "Apple localization identity changed after authorization"
        end
        fields.each do |field|
          allowed = [expected.fetch(field), old[locale] ? old.fetch(locale).fetch(field) : ""]
          unless allowed.include?(value.fetch(field))
            raise ContractError, "Apple localization value changed outside the authorized operation"
          end
        end
      end
      wanted.all? do |locale, expected|
        actual[locale] && fields.all? { |field| actual.fetch(locale).fetch(field) == expected.fetch(field) }
      end
    end

    def self.private_phase!(commitments, domain, current:, target:, environ:, allow_inherited: false)
      unless commitments.fetch("keyVersion") == environ["MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION"]
        raise ContractError, "Operation commitment key version changed"
      end
      pair = commitments.fetch("domains").fetch(domain)
      if pair.key?("inherited") && !(allow_inherited && domain == "app-review")
        raise ContractError, "Inherited private state is not authorized for this operation"
      end
      supplied = MobileReleaseKit.hmac_commitment(domain, target, environ)
      unless MobileReleaseKit.secure_equal(supplied, pair.fetch("target"))
        raise ContractError, "Supplied private Apple inputs differ from the authorized target"
      end
      digest = MobileReleaseKit.hmac_commitment(domain, current, environ)
      return :target if MobileReleaseKit.secure_equal(digest, pair.fetch("target"))
      return :before if MobileReleaseKit.secure_equal(digest, pair.fetch("before"))
      return :inherited if pair.key?("inherited") && MobileReleaseKit.secure_equal(digest, pair.fetch("inherited"))

      raise ContractError, "Private Apple state differs from the authorized complete records"
    end
  end
end
