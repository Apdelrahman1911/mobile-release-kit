# frozen_string_literal: true

# Real synthetic OpenSSL objects only: no Apple identity/trust qualification,
# native owner, account, network, Keychain, subprocess command or private input.
require 'minitest/autorun'
require 'minitest/mock'
require 'tmpdir'
require_relative '../../fastlane/apple_provisioning_p12_assemble'

class AppleP12AssemblyTest < Minitest::Test
  def self.fixture
    @fixture ||= begin
      keys = Array.new(3) { OpenSSL::PKey::RSA.generate(2048, 65_537) }
      now = Time.now
      certificates = keys.each_with_index.map do |key, index|
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = index + 1
        certificate.subject = OpenSSL::X509::Name.parse("/CN=Synthetic P12 component #{index}")
        certificate.public_key = key.public_key
        certificate.not_before = now - 60
        certificate.not_after = now + 600
        certificate
      end
      certificates.each_with_index do |certificate, index|
        issuer = index.zero? ? 0 : index - 1
        certificate.issuer = certificates[issuer].subject
        extension = OpenSSL::X509::ExtensionFactory.new
        extension.subject_certificate = certificate
        extension.issuer_certificate = certificates[issuer]
        certificate.add_extension(extension.create_extension('basicConstraints', index == 2 ? 'CA:FALSE' : 'CA:TRUE', true))
        certificate.add_extension(extension.create_extension('keyUsage', index == 2 ? 'digitalSignature' : 'keyCertSign,cRLSign', true))
        certificate.sign(keys[issuer], OpenSSL::Digest::SHA256.new)
      end
      request = OpenSSL::X509::Request.new
      request.version = 0
      request.subject = MRKAppleDistributionKey.subject
      request.public_key = keys[2].public_key
      request.sign(keys[2], OpenSSL::Digest::SHA256.new)
      parts = [keys[2].private_to_der, request.to_pem, keys[2].public_to_der]
      stored = MRKAppleDistributionKey::MAGIC + parts.map(&:bytesize).pack('NNN') + parts.join
      chain_parts = certificates.reverse.map(&:to_der)
      chain = MRKAppleP12Assembly::CERTIFICATES_MAGIC + chain_parts.map(&:bytesize).pack('NNN') + chain_parts.join
      password = 'a' * 64 # Test DATA, never the production native entropy source.
      output = MRKAppleP12Assembly.assemble(stored, password, chain)
      parts[0].clear
      { stored: stored, chain: chain, password: password, output: output,
        leaf: chain_parts[0], spki: keys[2].public_to_der, root: certificates[0] }
    end
  end

  def fixture
    self.class.fixture
  end

  def p12
    frame = fixture[:output]
    header = MRKAppleP12Assembly::MAGIC.bytesize + 4 + 64
    assert frame.start_with?(MRKAppleP12Assembly::MAGIC)
    assert frame.byteslice(MRKAppleP12Assembly::MAGIC.bytesize, 4).unpack1('N') == frame.bytesize - header
    frame.byteslice(header, frame.bytesize - header)
  end

  def test_real_cipher_profile_decrypt_private_key_leaf_and_chain_roundtrip
    raw = p12
    assert MRKAppleP12Assembly.encryption_profile(raw)
    reopened = OpenSSL::PKCS12.new(raw, fixture[:password])
    assert reopened.key.private?
    assert reopened.certificate.check_private_key(reopened.key)
    assert reopened.key.public_to_der == fixture[:spki]
    assert reopened.certificate.to_der == fixture[:leaf]
    assert reopened.ca_certs.length == 2
    # No DER/password mismatch value is rendered by an assertion.
    header = MRKAppleP12Assembly::MAGIC.bytesize + 4
    assert fixture[:output].byteslice(header, 32) == Digest::SHA256.digest(fixture[:leaf])
    assert fixture[:output].byteslice(header + 32, 32) == Digest::SHA256.digest(fixture[:spki])
  end

  def test_wrong_password_does_not_decrypt_and_modified_cipher_is_refused
    assert_raises(OpenSSL::PKCS12::PKCS12Error) { OpenSSL::PKCS12.new(p12, 'b' * 64) }
    modified = p12.dup
    modified.setbyte(modified.bytesize - 1, modified.getbyte(modified.bytesize - 1) ^ 1)
    assert_raises(OpenSSL::PKCS12::PKCS12Error) { OpenSSL::PKCS12.new(modified, fixture[:password]) }
  end

  def test_selected_existing_package_uses_real_private_key_extraction_without_assembly
    expected = Digest::SHA256.hexdigest(fixture[:leaf])
    OpenSSL::PKCS12.stub(:create, ->(*) { raise 'reuse must not assemble a package' }) do
      frame = MRKProvisioningP12.public_frame(p12, fixture[:password], expected)
      magic = MRKProvisioningP12::MAGIC
      assert frame.start_with?(magic)
      leaf_bytes, spki_bytes, count = frame.byteslice(magic.bytesize, 9).unpack('NNC')
      offset = magic.bytesize + 9
      assert frame.byteslice(offset, leaf_bytes) == fixture[:leaf]
      assert frame.byteslice(offset + leaf_bytes, spki_bytes) == fixture[:spki]
      assert count == 2
    end
    # Only real crypto/extraction DATA is tested here. Native BoundLoan,
    # current provider/policy holder and original joins are separate gates.
  end

  def test_selected_existing_package_does_not_relabel_another_leaf_or_password
    raw = p12
    original = OpenSSL::PKCS12.new(raw, fixture[:password])
    another_leaf = OpenSSL::X509::Certificate.new(original.certificate.to_der)
    another_leaf.serial += 1
    another_leaf.sign(original.key, OpenSSL::Digest::SHA256.new)
    # Same key alone is insufficient: the selected current leaf must match
    # byte-for-byte through its exact expected digest, not issuer/name/serial.
    assert_raises(ArgumentError) do
      MRKProvisioningP12.public_frame(raw, fixture[:password], Digest::SHA256.hexdigest(another_leaf.to_der))
    end
    assert_raises(OpenSSL::PKCS12::PKCS12Error) do
      MRKProvisioningP12.public_frame(raw, 'b' * 64, Digest::SHA256.hexdigest(fixture[:leaf]))
    end
  end

  def test_actual_mismatched_leaf_and_reordered_or_duplicate_chain_refused
    lengths = fixture[:chain].byteslice(MRKAppleP12Assembly::CERTIFICATES_MAGIC.bytesize, 12).unpack('NNN')
    offset = MRKAppleP12Assembly::CERTIFICATES_MAGIC.bytesize + 12
    parts = lengths.map { |length| value = fixture[:chain].byteslice(offset, length); offset += length; value }
    # Foreign root as a leaf and order/duplicate substitutions fail before
    # packaging. This does not assert that synthetic certificates are Apple.
    [[parts[2], parts[1], parts[0]], [parts[0], parts[2], parts[1]], [parts[0], parts[1], parts[1]]].each do |changed|
      frame = MRKAppleP12Assembly::CERTIFICATES_MAGIC + changed.map(&:bytesize).pack('NNN') + changed.join
      assert_raises(ArgumentError) { MRKAppleP12Assembly.assemble(fixture[:stored], fixture[:password], frame) }
    end
  end

  def test_corrupt_csr_or_private_key_fails_before_pkcs12_create
    changed = fixture[:stored].dup
    index = MRKAppleDistributionKey::MAGIC.bytesize + 12 + 30
    changed.setbyte(index, changed.getbyte(index) ^ 1)
    assert_raises(StandardError) { MRKAppleP12Assembly.assemble(changed, fixture[:password], fixture[:chain]) }
  end

  def test_empty_oversize_trailing_and_non_fixed_password_refused
    ['', "\0" * 64, 'a' * 63, 'f' * 65, 'A' * 64].each do |password|
      assert_raises(ArgumentError) { MRKAppleP12Assembly.assemble(fixture[:stored], password, fixture[:chain]) }
    end
    ['', fixture[:chain] + 'x', MRKAppleP12Assembly::CERTIFICATES_MAGIC + [0xffffffff, 1, 1].pack('NNN') + 'xxx'].each do |chain|
      assert_raises(ArgumentError) { MRKAppleP12Assembly.certificates(chain) }
    end
    assert_raises(ArgumentError) { MRKAppleP12Assembly.encryption_profile(p12 + 'x') }
  end

  def test_generated_algorithm_parameters_are_not_accepted_with_weaker_iteration_or_legacy_oid
    # Mutate real output ASN.1, not a fake callback. This tests the fixed
    # output-profile admission; decryption tests above exercise the real MAC.
    original = OpenSSL::ASN1.decode(p12)
    original.value[2].value[2] = OpenSSL::ASN1::Integer.new(1)
    assert_raises(ArgumentError) { MRKAppleP12Assembly.encryption_profile(original.to_der) }
    original = OpenSSL::ASN1.decode(p12)
    original.value[2].value[0].value[0].value[0] = OpenSSL::ASN1::ObjectId.new('1.3.14.3.2.26')
    assert_raises(ArgumentError) { MRKAppleP12Assembly.encryption_profile(original.to_der) }
  end

  def test_same_fixed_private_file_reader_accepts_only_owned_original_regular_0600
    directory = Dir.mktmpdir('mrk-p12-synthetic-')
    begin
      File.chmod(0o700, directory)
      path = File.join(directory, 'p12-password')
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(fixture[:password]) }
      assert MRKProvisioningP12.read_original(path, 'p12-password', 64) == fixture[:password]
      File.chmod(0o644, path)
      assert_raises(ArgumentError) { MRKProvisioningP12.read_original(path, 'p12-password', 64) }
      File.unlink(path)
      File.symlink('missing-owned-input', path)
      assert_raises(SystemCallError) { MRKProvisioningP12.read_original(path, 'p12-password', 64) }
      File.unlink(path)
      Dir.rmdir(directory) # Only the successful, now-empty owned fixture.
    rescue StandardError
      # Keep failed task-owned bytes private; no recursive/absence cleanup.
      raise
    end
  end
end
