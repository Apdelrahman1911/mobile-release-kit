# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require_relative "../../fastlane/apple_asset_upload"

class AppleAssetUploadTest < Minitest::Test
  class HTTP
    attr_accessor :use_ssl, :open_timeout, :read_timeout, :write_timeout, :max_retries, :status, :error
    attr_reader :requests

    def initialize
      @requests = []
      @status = "200"
    end

    def request(value)
      @requests << value
      raise error if error
      Struct.new(:code).new(status)
    end
  end

  def operation(offset: 0, length: 4)
    { "method" => "PUT", "url" => "https://upload.blobstore.apple.com/fake-part?Expires=#{Time.now.to_i + 3600}&Signature=temporary-fictional-token",
      "offset" => offset, "length" => length,
      "requestHeaders" => [{ "name" => "Content-Type", "value" => "image/png" }, { "name" => "Content-Length", "value" => length.to_s }] }
  end

  def plan(operations = [operation], size = 4) = MobileReleaseKit::AppleAssetUpload.plan(operations, size)
  def copy(value) = Marshal.load(Marshal.dump(value))

  def test_complete_out_of_order_multipart_plan_is_normalized_without_changing_ranges_or_headers
    first = operation(offset: 0, length: 2)
    last = operation(offset: 2, length: 2)
    value = plan([last, first])
    assert_equal [0, 2], value.map { |range| range.fetch(:offset) }
    assert_equal [2, 2], value.map { |range| range.fetch(:length) }
    assert_equal({ "content-type" => "image/png", "content-length" => "2" }, value.first.fetch(:headers))
    assert_equal "upload.blobstore.apple.com", value.first.fetch(:uri).host
  end

  def test_origins_methods_expiry_and_byte_ranges_fail_closed
    variants = {
      non_hash: "not an operation",
      insecure_http: operation.merge("url" => operation.fetch("url").sub("https", "http")),
      wrong_host: operation.merge("url" => operation.fetch("url").sub("upload.blobstore.apple.com", "attacker.example")),
      prefix_attack: operation.merge("url" => operation.fetch("url").sub("upload.blobstore.apple.com", "evilblobstore.apple.com")),
      suffix_attack: operation.merge("url" => operation.fetch("url").sub("upload.blobstore.apple.com", "upload.blobstore.apple.com.attacker.example")),
      nested_host: operation.merge("url" => operation.fetch("url").sub("upload.blobstore.apple.com", "unexpected.upload.blobstore.apple.com")),
      embedded_credentials: operation.merge("url" => operation.fetch("url").sub("https://", "https://fictional:password@")),
      non_tls_port: operation.merge("url" => operation.fetch("url").sub("apple.com/", "apple.com:444/")),
      fragment: operation.merge("url" => operation.fetch("url") + "#fragment"),
      unsafe_method: operation.merge("method" => "POST"),
      missing_expiry: operation.merge("url" => "https://upload.blobstore.apple.com/part"),
      duplicate_expiry: operation.merge("url" => operation.fetch("url") + "&Expires=3000000000"),
      malformed_expiry: operation.merge("url" => "https://upload.blobstore.apple.com/part?Expires=nan"),
      negative_offset: operation.merge("offset" => -1),
      zero_length: operation.merge("length" => 0),
      too_long: operation.merge("length" => 5),
      wrong_offset_type: operation.merge("offset" => "0"),
      wrong_length_type: operation.merge("length" => 4.0),
      no_url: operation.reject { |name, _value| name == "url" },
      null_url: operation.merge("url" => nil),
    }
    variants.each do |name, variant|
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { plan([variant]) }
    end
    [nil, [], [operation] * 129].each do |operations|
      assert_raises(MobileReleaseKit::ContractError) { plan(operations) }
    end
    [[operation(offset: 1, length: 3)], [operation(length: 2)], [operation(length: 3), operation(offset: 2, length: 2)]].each do |operations|
      assert_raises(MobileReleaseKit::ContractError) { plan(operations) }
    end
  end

  def test_header_injection_duplicates_credential_headers_and_malformed_records_are_rejected
    variants = {
      null_list: nil, too_many: Array.new(65) { |i| { "name" => "X-Fake-#{i}", "value" => "x" } },
      null_record: [nil], non_hash_record: ["Host: attacker.example"],
      missing_name: [{ "value" => "x" }], missing_value: [{ "name" => "Content-Type" }],
      duplicate: [{ "name" => "Content-Type", "value" => "a" }, { "name" => "content-type", "value" => "b" }],
      response_split: [{ "name" => "X-Test", "value" => "value\r\nHost: attacker.example" }],
      nul: [{ "name" => "X-Test", "value" => "secret\0suffix" }],
      bad_name: [{ "name" => "X:Test", "value" => "x" }],
      overlong: [{ "name" => "X-Test", "value" => "x" * 8193 }],
      wrong_size: [{ "name" => "Content-Length", "value" => "5" }],
    }
    %w[Authorization Proxy-Authorization Cookie Host Connection Transfer-Encoding].each do |header|
      variants[header] = [{ "name" => header, "value" => "never-forward-this" }]
    end
    variants.each do |name, headers|
      assert_raises(MobileReleaseKit::ContractError, name.to_s) { plan([operation.merge("requestHeaders" => headers)]) }
    end
  end

  def test_actual_net_http_request_disables_proxy_and_retries_and_contains_only_reserved_bytes
    http = HTTP.new
    constructors = []
    range = plan.first
    Net::HTTP.stub(:new, lambda { |*arguments| constructors << arguments; http }) do
      MobileReleaseKit::AppleAssetUpload.put(range, "data")
    end
    assert_equal [["upload.blobstore.apple.com", 443, nil]], constructors
    assert_equal true, http.use_ssl
    assert_equal [10, 60, 60, 0], [http.open_timeout, http.read_timeout, http.write_timeout, http.max_retries]
    assert_equal 1, http.requests.length
    request = http.requests.first
    assert_instance_of Net::HTTP::Put, request
    assert_equal "data", request.body
    assert_equal range.fetch(:uri).request_uri, request.path
    assert_nil request["authorization"]
    assert_nil request["proxy-authorization"]
    assert_nil request["cookie"]
    assert_equal "image/png", request["content-type"]
  end

  def test_expired_or_wrong_length_bytes_never_start_a_network_request
    called = 0
    range = plan.first
    Net::HTTP.stub(:new, ->(*) { called += 1; flunk("unexpected transport") }) do
      assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit::AppleAssetUpload.put(range.merge(expires: Time.now.to_i - 1), "data") }
      assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit::AppleAssetUpload.put(range, "extra bytes") }
    end
    assert_equal 0, called
  end

  def test_non_successful_responses_are_neither_retried_nor_followed_as_redirects
    [301, 302, 307, 308, 401, 429, 500, 503, 504].each do |code|
      http = HTTP.new
      http.status = code.to_s
      Net::HTTP.stub(:new, ->(*) { http }) do
        assert_raises(MobileReleaseKit::ContractError, code.to_s) { MobileReleaseKit::AppleAssetUpload.put(plan.first, "data") }
      end
      assert_equal 1, http.requests.length, "status #{code} caused more than one wire request"
    end
  end

  def test_transport_errors_do_not_expose_temporary_bearer_urls_even_in_exception_cause_chains
    http = HTTP.new
    secret = operation.fetch("url")
    http.error = IOError.new("network rejected #{secret}; header x-secret=synthetic-private-value")
    error = Net::HTTP.stub(:new, ->(*) { http }) do
      assert_raises(MobileReleaseKit::ContractError) { MobileReleaseKit::AppleAssetUpload.put(plan.first, "data") }
    end
    assert_equal 1, http.requests.length
    refute_includes error.message, secret
    refute_includes error.full_message, secret
    refute_includes error.full_message, "synthetic-private-value"
  end

  def test_malformed_url_errors_are_contract_errors_and_do_not_retain_secret_input_in_their_cause
    secret = "https://upload.blobstore.apple.com/a path?Expires=3000000000&Signature=synthetic-secret"
    error = assert_raises(MobileReleaseKit::ContractError) { plan([operation.merge("url" => secret)]) }
    refute_includes error.full_message, "synthetic-secret"
  end
end
