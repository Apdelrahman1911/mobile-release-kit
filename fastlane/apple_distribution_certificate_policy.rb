# frozen_string_literal: true

# A fixed OFFLINE subset of Apple WWDR CPS 3.0 (2026-03-23), section 4.11.24.
# It is not Apple's SecPolicy, revocation checking, account authorization, a
# signing assignment, or a private-key loan. Only the existing original native
# operation may use this helper's output together with its separately admitted
# leaf/full-SPKI/team, current stored-key loan and fresh ASC association.
#
# No private Security SPI, default paths, Keychain, AIA fetching, caller-selected
# anchors, partial-chain flag, clock override or general verify callback exists.
require 'openssl'
require 'base64'
require 'digest'
require 'json'
require 'time'

module MRKAppleDistributionCertificate
  LEAF_LIMIT = 64 * 1024
  INPUT_MAGIC = "MRK-APPLE-DISTRIBUTION-CERTIFICATE/1\n".b.freeze
  INPUT_PREFIX = INPUT_MAGIC.bytesize + 4 * 64 + 10 + 4
  INPUT_LIMIT = INPUT_PREFIX + LEAF_LIMIT
  OUTPUT_LIMIT = 2048
  ROOT_SHA256 = 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024'
  INTERMEDIATE_SHA256 = 'dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f'
  # Filled from the reviewed existing Apple Root CA and the official G3 URL.
  # These fixed public DER resources are part of the original tooling manifest.
  ROOT_BASE64 = 'MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh'
  INTERMEDIATE_BASE64 = 'MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJHQr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs='
  BC = '2.5.29.19'
  KU = '2.5.29.15'
  EKU = '2.5.29.37'
  IPHONE_SUBMISSION = '1.2.840.113635.100.6.1.4'
  MAC_SUBMISSION = '1.2.840.113635.100.6.1.7'
  CLOUD_MANAGED = '1.2.840.113635.100.6.1.32'
  WWDR = '1.2.840.113635.100.6.2.1'
  # Canonical 05 00 is our deliberately narrow supported marker encoding.
  # CPS specifies the purposes/criticality, not this ASN.1 encoding. Apple's
  # source marker matcher explicitly accepts ASN1 NULL with zero content.
  LEAF_CRITICAL = {
    BC => "\x30\x00".b.freeze,
    KU => "\x03\x02\x07\x80".b.freeze,
    EKU => "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x03".b.freeze,
    IPHONE_SUBMISSION => "\x05\x00".b.freeze,
    MAC_SUBMISSION => "\x05\x00".b.freeze,
  }.freeze
  SIGNATURES = %w[sha256WithRSAEncryption sha384WithRSAEncryption sha512WithRSAEncryption].freeze
  SHA = /\A[0-9a-f]{64}\z/
  TEAM = /\A[A-Z0-9]{10}\z/

  class Refused < StandardError
    def initialize = super('The offline Apple distribution certificate check is unavailable.')
  end

  module_function

  def need(value)
    raise Refused unless value
  end

  def sha(bytes) = Digest::SHA256.hexdigest(bytes)

  def extensions(certificate)
    values = certificate.extensions
    need(values.length <= 32)
    found, total = {}, 0
    values.each do |extension|
      der = extension.to_der
      need(der.bytesize <= 8192)
      sequence = OpenSSL::ASN1.decode(der)
      need(sequence.instance_of?(OpenSSL::ASN1::Sequence) && sequence.to_der == der &&
           [2, 3].include?(sequence.value.length))
      oid, *rest = sequence.value
      need(oid.instance_of?(OpenSSL::ASN1::ObjectId))
      critical = rest.length == 2
      if critical
        flag = rest.shift
        need(flag.instance_of?(OpenSSL::ASN1::Boolean) && flag.value == true)
      end
      value = rest.fetch(0)
      need(value.instance_of?(OpenSSL::ASN1::OctetString) && value.value.bytesize <= 4096 &&
           !found.key?(oid.oid) && extension.critical? == critical)
      total += value.value.bytesize
      need(total <= 16 * 1024)
      found[oid.oid] = [critical, value.value.freeze].freeze
    end
    found.freeze
  end
  private_class_method :extensions

  def leaf_policy(certificate, original, team, spki_sha256)
    need(certificate.version == 2 && certificate.serial.to_i > 0 && certificate.to_der == original &&
         SIGNATURES.include?(certificate.signature_algorithm))
    key = certificate.public_key
    need(key.is_a?(OpenSSL::PKey::RSA) && !key.private? && key.n.num_bits == 2048 && key.e.to_i == 65_537 &&
         sha(key.public_to_der) == spki_sha256)
    # No subject string/CN heuristic, normalization or team inferred from P8.
    units = certificate.subject.to_a.select { |item| item[0] == 'OU' }
    need(units.length == 1 && units[0][1] == team &&
         [OpenSSL::ASN1::UTF8STRING, OpenSSL::ASN1::PRINTABLESTRING].include?(units[0][2]))
    values = extensions(certificate)
    need(!values.key?(CLOUD_MANAGED)) # This operation possesses a local PKCS8 key.
    LEAF_CRITICAL.each { |oid, expected| need(values[oid] == [true, expected]) }
    need(values.all? { |oid, (critical, _)| !critical || LEAF_CRITICAL.key?(oid) })
    true
  end
  private_class_method :leaf_policy

  def resources
    root_der = Base64.strict_decode64(ROOT_BASE64)
    intermediate_der = Base64.strict_decode64(INTERMEDIATE_BASE64)
    need(root_der.bytesize == 1215 && intermediate_der.bytesize == 1109 &&
         sha(root_der) == ROOT_SHA256 && sha(intermediate_der) == INTERMEDIATE_SHA256)
    root, intermediate = [root_der, intermediate_der].map { |der| OpenSSL::X509::Certificate.new(der) }
    need(root.to_der == root_der && intermediate.to_der == intermediate_der &&
         root.subject.to_der == root.issuer.to_der && root.verify(root.public_key) &&
         intermediate.issuer.to_der == root.subject.to_der &&
         extensions(intermediate)[WWDR] == [false, "\x05\x00".b])
    [root, intermediate].freeze
  end
  private_class_method :resources

  def current(certificate, at)
    certificate.not_before <= at && at < certificate.not_after && certificate.not_before < certificate.not_after
  end
  private_class_method :current

  def preflight_resources!
    root, intermediate = resources
    at = Time.now
    need(current(root, at) && current(intermediate, at))
    store = OpenSSL::X509::Store.new # Empty: never set_default_paths/load_file.
    store.add_cert(root)
    need(store.verify(intermediate) && store.error == OpenSSL::X509::V_OK &&
         store.chain.map(&:to_der) == [intermediate.to_der, root.to_der])
    need(current(root, Time.now) && current(intermediate, Time.now))
    true
  rescue StandardError
    raise Refused.new, cause: nil
  end

  def verify_path(certificate, original, root, intermediate)
    at = Time.now
    need([certificate, intermediate, root].all? { |item| current(item, at) } &&
         certificate.issuer.to_der == intermediate.subject.to_der)
    refused = false
    store = OpenSSL::X509::Store.new
    store.add_cert(root)
    # Only these application-defined critical leaf extensions need handling.
    # All were completely admitted by leaf_policy AND the native maintained
    # parser before this call. A previous failure stays sticky even if OpenSSL
    # invokes this callback again. No other error/depth/certificate is waived.
    store.verify_callback = lambda do |valid, context|
      if valid
        !refused
      elsif !refused && context.error == OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION &&
            context.error_depth == 0 && context.current_cert.to_der == original
        true
      else
        refused = true
        false
      end
    end
    need(store.verify(certificate, [intermediate]) && !refused &&
         store.chain.map(&:to_der) == [original, intermediate.to_der, root.to_der] &&
         [certificate, intermediate, root].all? { |item| current(item, Time.now) })
    # Successful application handling can leave this last diagnostic at 34;
    # it is NOT an independent acceptance path. verify+sticky/chain checks above
    # must all succeed; no signature/time/CA/issuer error is accepted here.
    need([OpenSSL::X509::V_OK, OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION].include?(store.error))
    true
  end
  private_class_method :verify_path

  def verify(original, team:, certificate_sha256:, spki_sha256:)
    need(original.instance_of?(String) && original.bytesize.between?(1, LEAF_LIMIT) &&
         team.instance_of?(String) && TEAM.match?(team) &&
         [certificate_sha256, spki_sha256].all? { |value| value.instance_of?(String) && SHA.match?(value) } &&
         sha(original) == certificate_sha256)
    certificate = OpenSSL::X509::Certificate.new(original)
    leaf_policy(certificate, original, team, spki_sha256)
    root, intermediate = resources
    verify_path(certificate, original, root, intermediate)
    observed = Time.now.utc
    { 'checkedAt' => observed.iso8601(observed.usec.zero? ? 0 : 6).sub(/Z\z/, '+00:00'),
      'chainSha256' => [certificate_sha256, sha(intermediate.to_der), sha(root.to_der)] }
  rescue StandardError
    raise Refused.new, cause: nil
  end

  def input(bytes)
    need(bytes.instance_of?(String) && bytes.bytesize.between?(INPUT_PREFIX + 1, INPUT_LIMIT) &&
         bytes.start_with?(INPUT_MAGIC))
    offset = INPUT_MAGIC.bytesize
    binding, ack, certificate_sha256, spki_sha256 = 4.times.map do
      value = bytes.byteslice(offset, 64); offset += 64
      need(SHA.match?(value))
      value
    end
    team = bytes.byteslice(offset, 10); offset += 10
    length = bytes.byteslice(offset, 4).unpack1('N'); offset += 4
    need(TEAM.match?(team) && length.between?(1, LEAF_LIMIT) && offset + length == bytes.bytesize)
    original = bytes.byteslice(offset, length)
    result = verify(original, team: team, certificate_sha256: certificate_sha256, spki_sha256: spki_sha256)
    JSON.generate({ 'schemaVersion' => 1, 'scope' => 'offline-apple-distribution-certificate',
                    'requestBindingSha256' => binding, 'identityAckSha256' => ack,
                    'certificateSha256' => certificate_sha256, 'publicKeySha256' => spki_sha256,
                    'teamId' => team, 'revocationChecked' => false, **result }, ascii_only: true) + "\n"
  end
  private_class_method :input

  def file_state(file)
    value = file.stat
    need(value.file? && value.uid == Process.euid && value.nlink == 1 && (value.mode & 0o7777) == 0o600)
    [value.dev, value.ino, value.mode, value.uid, value.gid, value.nlink,
     value.size, value.mtime.to_r, value.ctime.to_r]
  end
  private_class_method :file_state

  def main(argv)
    need(argv.length == 1 && argv[0].is_a?(String) && argv[0].start_with?('/') &&
         File.basename(argv[0]) == 'apple-distribution-certificate.mrk' && File.const_defined?(:NOFOLLOW))
    result = nil
    File.open(argv[0], File::RDONLY | File::NOFOLLOW) do |file|
      before = file_state(file)
      need(before[6].between?(INPUT_PREFIX + 1, INPUT_LIMIT))
      bytes = file.read(INPUT_LIMIT + 1)
      need(bytes.instance_of?(String) && bytes.bytesize == before[6] && file.read(1).nil? && file_state(file) == before)
      result = input(bytes)
      need(result.bytesize <= OUTPUT_LIMIT && file_state(file) == before)
    end # Actual original read/close must return before emitting any proof DATA.
    STDOUT.binmode
    need(STDOUT.write(result) == result.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    1 # No input/path/provider/certificate/OpenSSL diagnostic is logged.
  end
end
