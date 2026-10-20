# frozen_string_literal: true

# Closed LOCAL key/CSR producer of the existing native Apple operation. Only
# that original owner may run this bundled helper after its durable reservation.
# Output is PRIVATE binary material for its retained private receiver, never a
# public control/JSON frame. This helper cannot publish a CSR or call Apple.
require 'openssl'

module MRKAppleDistributionKey
  MAGIC = "MRK-APPLE-DISTRIBUTION-KEY/1\n".b.freeze
  KEY_LIMIT = 3 * 1024 # Canonical base64 fits one existing 4096-byte vault scalar.
  CSR_LIMIT = 4096
  SPKI_LIMIT = 1024
  SUBJECT = 'Mobile Release Kit Apple Distribution'
  PUBLIC_MAGIC = "MRK-APPLE-DISTRIBUTION-KEY-PUBLIC/1\n".b.freeze
  PRIVATE_LIMIT = MAGIC.bytesize + 12 + KEY_LIMIT + CSR_LIMIT + SPKI_LIMIT
  KEY_CHECK = "MRK Apple Distribution private-key check/1\0".b.freeze

  module_function

  def need(value)
    raise ArgumentError, 'Apple signing key preparation refused' unless value
  end

  def subject
    OpenSSL::X509::Name.new([['CN', SUBJECT, OpenSSL::ASN1::UTF8STRING]])
  end

  def rsa(key, private_key)
    key.is_a?(OpenSSL::PKey::RSA) && key.private? == private_key &&
      key.n.num_bits == 2048 && key.e.to_i == 65_537
  end

  def validate_material(private_key, csr, spki)
    need(private_key.is_a?(String) && private_key.bytesize.between?(1, KEY_LIMIT) &&
         csr.is_a?(String) && csr.ascii_only? && csr.bytesize.between?(1, CSR_LIMIT) &&
         spki.is_a?(String) && spki.bytesize.between?(1, SPKI_LIMIT))
    public_key = OpenSSL::PKey.read(spki)
    need(rsa(public_key, false) && public_key.public_to_der == spki)
    parsed = OpenSSL::PKey.read(private_key)
    need(rsa(parsed, true) && parsed.public_to_der == spki)
    roundtrip = parsed.private_to_der
    need(roundtrip == private_key) # Canonical PKCS#8, not a PKCS#1 input alias.
    request = OpenSSL::X509::Request.new(csr)
    need(request.version == 0 && request.subject.to_der == subject.to_der && request.attributes.empty? &&
         request.signature_algorithm == 'sha256WithRSAEncryption' && request.to_pem == csr &&
         request.public_key.public_to_der == spki && request.verify(public_key))
    # An imported CSR signature alone proves nothing about usability of the
    # private scalar. Exercise only this fixed, local, non-account challenge;
    # the same maintained OpenSSL RSA/SHA256 APIs verify the private match.
    proof = parsed.sign(OpenSSL::Digest::SHA256.new, KEY_CHECK)
    need(proof.is_a?(String) && proof.bytesize == 256 &&
         public_key.verify(OpenSSL::Digest::SHA256.new, proof, KEY_CHECK))
    true
  ensure
    roundtrip&.clear if roundtrip.is_a?(String) && !roundtrip.frozen?
    proof&.clear if proof.is_a?(String) && !proof.frozen?
  end

  def frame
    # Exactly one ordinary maintained-library call; OS/OpenSSL entropy failure
    # is an error, never a fixed seed, fallback key or second generation attempt.
    key = OpenSSL::PKey::RSA.generate(2048, 65_537)
    need(rsa(key, true))
    spki = key.public_to_der
    need(spki.is_a?(String) && spki.bytesize.between?(1, SPKI_LIMIT))
    public_key = OpenSSL::PKey.read(spki)
    need(rsa(public_key, false) && public_key.public_to_der == spki)
    request = OpenSSL::X509::Request.new
    request.version = 0
    request.subject = subject
    request.public_key = public_key
    request.sign(key, OpenSSL::Digest::SHA256.new)
    csr = request.to_pem
    need(csr.is_a?(String) && csr.ascii_only? && csr.bytesize.between?(1, CSR_LIMIT))
    private_key = key.private_to_der # PKCS#8; encrypted only by the native vault.
    validate_material(private_key, csr, spki)
    MAGIC + [private_key.bytesize, csr.bytesize, spki.bytesize].pack('NNN') + private_key + csr + spki
  ensure
    # This retires only owned Ruby strings best-effort. OpenSSL objects/GC and
    # process memory are not promised erased. The original C/A/W owner must
    # contain/join the helper and retain private output through uncertain saves.
    private_key&.clear if private_key.is_a?(String) && !private_key.frozen?
  end

  def public_frame(original)
    need(original.is_a?(String) && original.bytesize.between?(MAGIC.bytesize + 13, PRIVATE_LIMIT) &&
         original.start_with?(MAGIC))
    lengths = original.byteslice(MAGIC.bytesize, 12).unpack('NNN')
    need(lengths.zip([KEY_LIMIT, CSR_LIMIT, SPKI_LIMIT]).all? { |length, limit| length.between?(1, limit) } &&
         MAGIC.bytesize + 12 + lengths.sum == original.bytesize)
    offset = MAGIC.bytesize + 12
    private_key = original.byteslice(offset, lengths[0]); offset += lengths[0]
    csr = original.byteslice(offset, lengths[1]); offset += lengths[1]
    spki = original.byteslice(offset, lengths[2])
    validate_material(private_key, csr, spki)
    PUBLIC_MAGIC + [csr.bytesize, spki.bytesize].pack('NN') + csr + spki
  ensure
    private_key&.clear if private_key.is_a?(String) && !private_key.frozen?
  end

  def file_state(file)
    value = file.stat
    need(value.file? && value.uid == Process.euid && value.nlink == 1 && (value.mode & 0o7777) == 0o600)
    [value.dev, value.ino, value.mode, value.uid, value.gid, value.nlink,
     value.size, value.mtime.to_r, value.ctime.to_r]
  end

  def verify_main(argv)
    # The original FiniteScratch supplies this one fixed input. A path is not
    # authority: parent retains/rechecks the same scratch/reader/runtime before
    # and after this call. No argument selects a private key from user storage.
    need(argv.length == 1 && argv[0].is_a?(String) && argv[0].start_with?('/') &&
         File.basename(argv[0]) == 'pending-apple-key.mrk' && File.const_defined?(:NOFOLLOW))
    original = result = nil
    File.open(argv[0], File::RDONLY | File::NOFOLLOW) do |file|
      before = file_state(file)
      need(before[6].between?(MAGIC.bytesize + 13, PRIVATE_LIMIT))
      original = file.read(PRIVATE_LIMIT + 1)
      need(original.is_a?(String) && original.bytesize == before[6] &&
           original.bytesize <= PRIVATE_LIMIT && file.read(1).nil? && file_state(file) == before)
      result = public_frame(original)
      need(file_state(file) == before)
    end # The actual original close must return before public output.
    STDOUT.binmode
    need(STDOUT.write(result) == result.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    1
  ensure
    original&.clear if original.is_a?(String) && !original.frozen?
    result&.clear if result.is_a?(String) && !result.frozen?
  end

  def main(argv)
    need(argv.empty?) # No key/password, output path or caller algorithm options.
    result = frame
    STDOUT.binmode
    need(STDOUT.write(result) == result.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    # Never render OpenSSL errors, arguments or private output on either stream.
    1
  ensure
    result&.clear if result.is_a?(String) && !result.frozen?
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    status = MRKAppleDistributionKey.main(ARGV)
  rescue Exception
    # The fixed native entry must not print a fatal exception/backtrace with
    # private arguments or OpenSSL diagnostics. It still reports failure.
    status = 1
  end
  exit status
end
