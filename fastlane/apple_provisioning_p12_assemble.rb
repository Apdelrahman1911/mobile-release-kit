# frozen_string_literal: true

# ONE fixed local packaging command of the existing Apple saved operation.
# Its parent already owns a freshly checked stored key and a freshly verified
# Distribution certificate. This helper cannot nominate a key/certificate,
# generate either, call Apple, or decide that the result is trusted/assigned.
# Inputs are three original FiniteScratch files; passwords never enter argv,
# environment or public output. The result is PRIVATE, bounded binary output.
require_relative 'apple_distribution_key'
require_relative 'apple_provisioning_p12'

module MRKAppleP12Assembly
  MAGIC = "MRK-APPLE-P12/1\n".b.freeze
  CERTIFICATES_MAGIC = "MRK-APPLE-P12-CERTIFICATES/1\n".b.freeze
  P12_LIMIT = 1024 * 1024 # Packaging mode only; ordinary vault P12 limit stays 32 MiB.
  CERTIFICATE_LIMIT = 64 * 1024
  CERTIFICATES_LIMIT = 128 * 1024
  CERTIFICATES_FRAME_LIMIT = CERTIFICATES_MAGIC.bytesize + 12 + CERTIFICATES_LIMIT
  PASSWORD_BYTES = 64 # Native OS CSPRNG 32 bytes, encoded once as lower hex.
  PRIVATE_FRAME_LIMIT = MAGIC.bytesize + 4 + 64 + P12_LIMIT
  ITERATIONS = 100_000
  NAME = 'Mobile Release Kit Apple Distribution'
  DATA_OID = '1.2.840.113549.1.7.1'
  ENCRYPTED_DATA_OID = '1.2.840.113549.1.7.6'
  SHROUDED_KEY_OID = '1.2.840.113549.1.12.10.1.2'

  module_function

  def need(value)
    raise ArgumentError, 'Apple P12 packaging refused' unless value
  end

  def sequence(value, length = nil)
    need(value.is_a?(OpenSSL::ASN1::Sequence) && value.value.is_a?(Array) &&
         (length.nil? || value.value.length == length))
    value.value
  end

  def oid(value, expected)
    need(value.is_a?(OpenSSL::ASN1::ObjectId) && value.oid == expected)
  end

  def integer(value, expected)
    need(value.is_a?(OpenSSL::ASN1::Integer) && value.value.to_i == expected)
  end

  def explicit_zero(value)
    need(value.is_a?(OpenSSL::ASN1::ASN1Data) && value.tag_class == :CONTEXT_SPECIFIC &&
         value.tag == 0 && value.value.is_a?(Array) && value.value.length == 1)
    value.value[0]
  end

  def octets(value, maximum)
    need(value.is_a?(OpenSSL::ASN1::OctetString) && value.value.is_a?(String) &&
         value.value.bytesize.between?(1, maximum))
    value.value
  end

  def decoded(bytes)
    need(bytes.is_a?(String) && bytes.bytesize.between?(1, P12_LIMIT))
    value = OpenSSL::ASN1.decode(bytes)
    need(value.to_der == bytes) # No trailing object/noncanonical alternate encoding.
    value
  rescue OpenSSL::ASN1::ASN1Error
    need(false) # Do not expose parser diagnostics derived from private output.
  end

  # Check the fixed maintained-library output, not an arbitrary encryption
  # policy chosen by a caller. A runtime lacking this modern PKCS12 profile
  # refuses; there is no legacy provider/RC2/3DES/SHA1/default fallback.
  def pbes2(algorithm)
    oid, parameters = sequence(algorithm, 2)
    oid(oid, '1.2.840.113549.1.5.13')
    kdf, cipher = sequence(parameters, 2)
    kdf_oid, kdf_parameters = sequence(kdf, 2)
    oid(kdf_oid, '1.2.840.113549.1.5.12')
    fields = sequence(kdf_parameters)
    need([3, 4].include?(fields.length))
    salt = octets(fields[0], 64)
    need(salt.bytesize >= 8)
    integer(fields[1], ITERATIONS)
    integer(fields[2], 32) if fields.length == 4
    prf = sequence(fields[-1], 2)
    oid(prf[0], '1.2.840.113549.2.9') # HMAC-SHA256, not absent/default SHA1.
    need(prf[1].is_a?(OpenSSL::ASN1::Null))
    cipher_oid, iv = sequence(cipher, 2)
    oid(cipher_oid, '2.16.840.1.101.3.4.1.42') # AES-256-CBC.
    need(octets(iv, 16).bytesize == 16)
  end

  def encryption_profile(der)
    version, auth_safe, mac_data = sequence(decoded(der), 3)
    integer(version, 3)
    kind, body = sequence(auth_safe, 2)
    oid(kind, DATA_OID)
    safes = sequence(decoded(octets(explicit_zero(body), P12_LIMIT)), 2)
    encrypted_kind, encrypted_body = sequence(safes[0], 2)
    oid(encrypted_kind, ENCRYPTED_DATA_OID)
    encrypted_version, encrypted_info = sequence(explicit_zero(encrypted_body), 2)
    integer(encrypted_version, 0)
    encrypted_type, encrypted_algorithm, ciphertext = sequence(encrypted_info, 3)
    oid(encrypted_type, DATA_OID)
    pbes2(encrypted_algorithm)
    need(ciphertext.is_a?(OpenSSL::ASN1::ASN1Data) && ciphertext.tag == 0 &&
         ciphertext.tag_class == :CONTEXT_SPECIFIC && ciphertext.value.is_a?(String) &&
         ciphertext.value.bytesize.between?(1, P12_LIMIT))
    key_kind, key_body = sequence(safes[1], 2)
    oid(key_kind, DATA_OID)
    key_safe = sequence(decoded(octets(explicit_zero(key_body), P12_LIMIT)), 1)
    bag = sequence(key_safe[0])
    need([2, 3].include?(bag.length))
    oid(bag[0], SHROUDED_KEY_OID)
    key_algorithm, encrypted_key = sequence(explicit_zero(bag[1]), 2)
    pbes2(key_algorithm)
    octets(encrypted_key, P12_LIMIT)
    digest_info, salt, count = sequence(mac_data, 3)
    algorithm, digest = sequence(digest_info, 2)
    mac = sequence(algorithm, 2)
    oid(mac[0], '2.16.840.1.101.3.4.2.1') # SHA256 MAC.
    need(mac[1].is_a?(OpenSSL::ASN1::Null) && octets(digest, 32).bytesize == 32 &&
         octets(salt, 64).bytesize >= 8)
    integer(count, ITERATIONS)
    true
  end

  def certificates(frame)
    header = CERTIFICATES_MAGIC.bytesize + 12
    need(frame.is_a?(String) && frame.bytesize.between?(header + 3, CERTIFICATES_FRAME_LIMIT) &&
         frame.start_with?(CERTIFICATES_MAGIC))
    lengths = frame.byteslice(CERTIFICATES_MAGIC.bytesize, 12).unpack('NNN')
    need(lengths.all? { |length| length.between?(1, CERTIFICATE_LIMIT) } &&
         lengths.sum <= CERTIFICATES_LIMIT && header + lengths.sum == frame.bytesize)
    offset = header
    result = lengths.map do |length|
      der = frame.byteslice(offset, length)
      offset += length
      certificate = OpenSSL::X509::Certificate.new(der)
      need(certificate.to_der == der)
      certificate
    end
    need(result.map(&:to_der).uniq.length == 3)
    # Consistency check only: the native policy holder, NOT this shape/signature
    # check or a caller-supplied root, supplies Apple purpose/anchor authority.
    leaf, intermediate, root = result
    need(leaf.issuer.to_der == intermediate.subject.to_der && leaf.verify(intermediate.public_key) &&
         intermediate.issuer.to_der == root.subject.to_der && intermediate.verify(root.public_key) &&
         root.issuer.to_der == root.subject.to_der && root.verify(root.public_key))
    result
  end

  def assemble(stored_key, password, certificate_frame)
    need(password.is_a?(String) && password.bytesize == PASSWORD_BYTES &&
         password.match?(/\A[0-9a-f]{64}\z/))
    # Existing canonical PKCS8/CSR/SPKI and fixed private-key challenge. This
    # neither creates a new key nor exports the private scalar from this helper.
    MRKAppleDistributionKey.public_frame(stored_key)
    lengths = stored_key.byteslice(MRKAppleDistributionKey::MAGIC.bytesize, 12).unpack('NNN')
    offset = MRKAppleDistributionKey::MAGIC.bytesize + 12
    private_der = stored_key.byteslice(offset, lengths[0])
    spki = stored_key.byteslice(offset + lengths[0] + lengths[1], lengths[2])
    key = OpenSSL::PKey.read(private_der)
    leaf, intermediate, root = certificates(certificate_frame)
    need(leaf.check_private_key(key) && leaf.public_key.public_to_der == spki && key.public_to_der == spki)
    archive = OpenSSL::PKCS12.create(password, NAME, key, leaf, [intermediate, root],
                                    'AES-256-CBC', 'AES-256-CBC', ITERATIONS, ITERATIONS)
    der = archive.to_der
    need(der.bytesize.between?(1, P12_LIMIT))
    encryption_profile(der)
    reopened = OpenSSL::PKCS12.new(der, password)
    need(reopened.key.is_a?(OpenSSL::PKey::RSA) && reopened.key.private? &&
         reopened.key.public_to_der == spki && reopened.certificate.to_der == leaf.to_der &&
         reopened.certificate.check_private_key(reopened.key) &&
         (reopened.ca_certs || []).map(&:to_der) == [intermediate.to_der, root.to_der])
    # Exercise the actual decrypted private component as well as its public
    # projection. No equality assertion/exception renders these private bytes.
    roundtrip = reopened.key.private_to_der
    need(roundtrip == private_der)
    MAGIC + [der.bytesize].pack('N') + Digest::SHA256.digest(leaf.to_der) + Digest::SHA256.digest(spki) + der
  ensure
    private_der&.clear if private_der.is_a?(String) && !private_der.frozen?
    roundtrip&.clear if roundtrip.is_a?(String) && !roundtrip.frozen?
    der&.clear if der.is_a?(String) && !der.frozen?
  end

  def main(argv)
    need(argv.length == 3 && argv.all? { |path| path.is_a?(String) && path.start_with?('/') } &&
         argv.map { |path| File.dirname(path) }.uniq.length == 1)
    stored = MRKProvisioningP12.read_original(argv[0], 'pending-apple-key.mrk', MRKAppleDistributionKey::PRIVATE_LIMIT)
    password = MRKProvisioningP12.read_original(argv[1], 'p12-password', PASSWORD_BYTES)
    # Only the same admitted leaf crosses the original material file. The
    # issuer/root are fixed PUBLIC resources in the same held tooling book,
    # never paths/anchors selected by the renderer or by a P12's CA bags.
    # Their presence is not policy/association: the original native holder is
    # still required before the parent can save this command's output.
    require_relative 'apple_distribution_certificate_policy'
    leaf = MRKProvisioningP12.read_original(argv[2], 'distribution-certificate.der', CERTIFICATE_LIMIT)
    root = Base64.strict_decode64(MRKAppleDistributionCertificate::ROOT_BASE64)
    intermediate = Base64.strict_decode64(MRKAppleDistributionCertificate::INTERMEDIATE_BASE64)
    need(root.bytesize == 1215 && intermediate.bytesize == 1109 &&
         Digest::SHA256.hexdigest(root) == MRKAppleDistributionCertificate::ROOT_SHA256 &&
         Digest::SHA256.hexdigest(intermediate) == MRKAppleDistributionCertificate::INTERMEDIATE_SHA256)
    parts = [leaf, intermediate, root]
    chain = CERTIFICATES_MAGIC + parts.map(&:bytesize).pack('NNN') + parts.join
    result = assemble(stored, password, chain)
    STDOUT.binmode
    need(STDOUT.write(result) == result.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    1 # Fixed redacted failure; no OpenSSL/private/path diagnostics.
  ensure
    [stored, password, result].each { |value| value&.clear if value.is_a?(String) && !value.frozen? }
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    status = MRKAppleP12Assembly.main(ARGV)
  rescue Exception
    status = 1 # Do not print fatal exceptions/private input in a backtrace.
  end
  exit status
end
