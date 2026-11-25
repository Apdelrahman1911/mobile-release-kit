# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../../fastlane/apple_distribution_key'

# Real ephemeral RSA/PKCS#8/CSR/SPKI, unlike the separate inert-owner suite.
# No provider, user credential, native admission, process, vault or network is
# touched. Run with the selected bundled Ruby for actual Mac crypto evidence;
# an ordinary local run alone does not qualify that runtime or the app.
class AppleDistributionKeyRealTest < Minitest::Test
  Producer = MRKAppleDistributionKey

  def setup
    @private_buffers = []
  end

  def teardown
    @private_buffers.reverse_each { |buffer| buffer.clear unless buffer.frozen? }
  end

  def retained(value)
    @private_buffers << value
    value
  end

  def generated
    retained(Producer.frame)
  end

  def parts(frame)
    offset = Producer::MAGIC.bytesize + 12
    frame.byteslice(Producer::MAGIC.bytesize, 12).unpack('NNN').map do |length|
      value = retained(frame.byteslice(offset, length))
      offset += length
      value
    end
  end

  def frame(key, csr, spki)
    retained(Producer::MAGIC + [key.bytesize, csr.bytesize, spki.bytesize].pack('NNN') + key + csr + spki)
  end

  def test_actual_generated_key_csr_and_public_frame_match_without_private_publication
    original = generated
    key, csr, spki = parts(original)
    parsed = OpenSSL::PKey.read(key)
    request = OpenSSL::X509::Request.new(csr)
    public_key = OpenSSL::PKey.read(spki)
    assert Producer.rsa(parsed, true)
    assert Producer.rsa(public_key, false)
    assert request.verify(public_key)
    assert request.public_key.public_to_der == spki
    assert parsed.public_to_der == spki
    output = retained(Producer.public_frame(original))
    expected = retained(Producer::PUBLIC_MAGIC + [csr.bytesize, spki.bytesize].pack('NN') + csr + spki)
    # Boolean-only assertions: failing tests must never print private buffers.
    assert output == expected
    refute output.include?(key)
    assert original.bytesize <= Producer::PRIVATE_LIMIT
  end

  def test_actual_mismatched_key_or_public_key_is_refused
    key, csr, spki = parts(generated)
    other_key, _, other_spki = parts(generated)
    assert_raises(ArgumentError) { Producer.public_frame(frame(other_key, csr, spki)) }
    assert_raises(ArgumentError) { Producer.public_frame(frame(key, csr, other_spki)) }
  end

  def test_canonical_csr_with_corrupted_signature_is_refused_by_real_openssl
    key, csr, spki = parts(generated)
    der = retained(OpenSSL::X509::Request.new(csr).to_der)
    der.setbyte(der.bytesize - 1, der.getbyte(der.bytesize - 1) ^ 1)
    corrupted = retained(OpenSSL::X509::Request.new(der).to_pem)
    refute OpenSSL::X509::Request.new(corrupted).verify(OpenSSL::PKey.read(spki))
    assert_raises(ArgumentError) { Producer.public_frame(frame(key, corrupted, spki)) }
  end

  def test_actual_canonical_pkcs1_alias_is_not_an_accepted_private_pkcs8
    key, csr, spki = parts(generated)
    pkcs1 = retained(OpenSSL::PKey.read(key).to_der)
    refute pkcs1 == key
    assert_raises(ArgumentError) { Producer.public_frame(frame(pkcs1, csr, spki)) }
  end

  def test_private_verifier_input_is_read_only_and_requires_the_original_shape
    original = generated
    Dir.mktmpdir('mrk-apple-key-real-') do |root|
      File.chmod(0o700, root)
      path = File.join(root, 'pending-apple-key.mrk')
      File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.binmode
        assert file.write(original) == original.bytesize
      end
      # Call the same strict input/state and crypto routines without redirecting
      # Ruby's process-wide STDOUT or publishing a private frame in a test log.
      File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
        before = Producer.file_state(file)
        content = retained(file.read(Producer::PRIVATE_LIMIT + 1))
        assert content.bytesize == before[6]
        assert_nil file.read(1)
        assert Producer.public_frame(content).start_with?(Producer::PUBLIC_MAGIC)
        assert Producer.file_state(file) == before
      end
      File.chmod(0o644, path)
      File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
        assert_raises(ArgumentError) { Producer.file_state(file) }
      end
    end
  end
end
