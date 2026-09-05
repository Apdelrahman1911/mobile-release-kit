# frozen_string_literal: true

require "net/http"
require "uri"
require_relative "apple_store"

module MobileReleaseKit
  module AppleAssetUpload
    def self.plan(operations, size)
      unless operations.is_a?(Array) && operations.length.between?(1, 128)
        raise ContractError, "Apple screenshot upload operations are missing or oversized"
      end
      ranges = operations.map do |operation|
        raise ContractError, "Apple upload operation is invalid" unless operation.is_a?(Hash)
        uri = URI.parse(operation.fetch("url"))
        unless operation["method"] == "PUT" && uri.scheme == "https" && uri.port == 443 && uri.userinfo.nil? && uri.fragment.nil? &&
               uri.host&.match?(/\A[a-z0-9-]+\.blobstore\.apple\.com\z/i)
          raise ContractError, "Apple upload operation origin/method is not authorized"
        end
        query = URI.decode_www_form(uri.query.to_s)
        expires = query.select { |key, _value| key == "Expires" }
        unless expires.length == 1 && expires.first.last.match?(/\A[1-9][0-9]{0,11}\z/)
          raise ContractError, "Apple screenshot reservation expiration cannot be verified"
        end
        offset, length = operation.values_at("offset", "length")
        unless offset.is_a?(Integer) && length.is_a?(Integer) && offset >= 0 && length.positive? && offset + length <= size
          raise ContractError, "Apple upload operation byte range is invalid"
        end
        header_list = operation.fetch("requestHeaders")
        unless header_list.is_a?(Array) && header_list.length <= 64
          raise ContractError, "Apple upload headers are invalid"
        end
        headers = {}
        header_list.each do |header|
          raise ContractError, "Apple upload header is invalid" unless header.is_a?(Hash)
          name, value = header.values_at("name", "value")
          unless name.is_a?(String) && name.match?(/\A[A-Za-z0-9-]{1,100}\z/) && value.is_a?(String) && value.bytesize <= 8192 &&
                 !value.match?(/[\r\n\x00]/) && !headers.key?(name.downcase) &&
                 !%w[authorization proxy-authorization cookie host connection transfer-encoding].include?(name.downcase)
            raise ContractError, "Apple upload header is unsafe"
          end
          headers[name.downcase] = value
        end
        if headers["content-length"] && headers["content-length"] != length.to_s
          raise ContractError, "Apple upload Content-Length disagrees with source range"
        end
        { uri: uri, offset: offset, length: length, headers: headers, expires: expires.first.last.to_i }
      end.sort_by { |item| item.fetch(:offset) }
      cursor = 0
      ranges.each do |range|
        raise ContractError, "Apple upload ranges overlap or leave a gap" unless range.fetch(:offset) == cursor
        cursor += range.fetch(:length)
      end
      raise ContractError, "Apple upload ranges do not cover the complete source" unless cursor == size
      ranges
    rescue KeyError, TypeError, URI::InvalidURIError, ArgumentError
      raise ContractError, "Apple screenshot upload operations are malformed", cause: nil
    end

    def self.put(range, bytes)
      uri = range.fetch(:uri)
      raise ContractError, "Apple screenshot reservation has expired" if Time.now.to_i >= range.fetch(:expires)
      raise ContractError, "Screenshot upload bytes do not match the reserved range" unless bytes.bytesize == range.fetch(:length)
      # No environment proxy, redirect handling, Store token, or implicit retry.
      http = Net::HTTP.new(uri.host, 443, nil)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 60
      http.write_timeout = 60
      http.max_retries = 0
      request = Net::HTTP::Put.new(uri.request_uri, range.fetch(:headers))
      request.body = bytes
      response = http.request(request)
      raise ContractError, "Apple screenshot part response is ambiguous; resume the same reservation" unless response.code.to_i.between?(200, 299)
    rescue StandardError
      # URLs/headers are temporary bearer-like credentials. Never propagate a
      # transport exception's message (it may embed either) into Fastlane logs.
      raise ContractError, "Apple screenshot part is not proven accepted; retain and resume the original intent", cause: nil
    end
  end
end
