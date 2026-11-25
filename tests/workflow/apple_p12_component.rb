# frozen_string_literal: true

# Fixed LOCAL component fixture, never a production Apple certificate source.
# The existing workflow owns the only processes/files/deadline. This bridge
# reads the genuine freshly reopened key and exercises the shared P12 assembler
# with a synthetic three-certificate chain. No production anchor override,
# CertificateBinding, account call, runner or signing permission is introduced.
require_relative '../../fastlane/apple_provisioning_p12_assemble'

module MRKAppleP12Component
  LIMIT = 128 * 1024
  PASSWORD = ('a' * 64).freeze # Explicit TEST data, not native password entropy.

  module_function

  def need(value)
    raise ArgumentError, 'Local P12 component refused' unless value
  end

  def certificate(key, name, serial, now, issuer = nil, issuer_key = nil)
    result = OpenSSL::X509::Certificate.new
    result.version = 2
    result.serial = serial
    result.subject = OpenSSL::X509::Name.new([['CN', name]])
    result.public_key = key.public_key
    result.not_before = now - 60
    result.not_after = now + 600
    result.issuer = (issuer || result).subject
    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = result
    extensions.issuer_certificate = issuer || result
    ca = serial < 3
    result.add_extension(extensions.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true))
    result.add_extension(extensions.create_extension('keyUsage', ca ? 'keyCertSign,cRLSign' : 'digitalSignature', true))
    result.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
    need(result.to_der.bytesize.between?(1, 16 * 1024))
    result
  end

  def chain(parts)
    bytes = parts.map(&:to_der)
    length = MRKAppleP12Assembly::CERTIFICATES_MAGIC.bytesize + 12 + bytes.sum(&:bytesize)
    need(bytes.length == 3 && length <= LIMIT)
    MRKAppleP12Assembly::CERTIFICATES_MAGIC + bytes.map(&:bytesize).pack('NNN') + bytes.join
  end

  def assemble(stored)
    # The input's exact PKCS8/CSR/SPKI/private challenge is checked by the SAME
    # shipped verifier. The leaf uses this original key, never a replacement.
    MRKAppleDistributionKey.public_frame(stored)
    length = stored.byteslice(MRKAppleDistributionKey::MAGIC.bytesize, 4).unpack1('N')
    private_der = stored.byteslice(MRKAppleDistributionKey::MAGIC.bytesize + 12, length)
    key = OpenSSL::PKey.read(private_der)
    now = Time.now
    root_key = OpenSSL::PKey::RSA.generate(2048, 65_537)
    issuer_key = OpenSSL::PKey::RSA.generate(2048, 65_537)
    root = certificate(root_key, 'MRK synthetic component root', 1, now)
    issuer = certificate(issuer_key, 'MRK synthetic component issuer', 2, now, root, root_key)
    leaf = certificate(key, 'MRK synthetic component leaf', 3, now, issuer, issuer_key)
    good = chain([leaf, issuer, root])

    # A genuinely valid signed chain whose leaf belongs to another key MUST
    # fail before packaging. This is an isolated expected negative, not a
    # failed/unknown process that the workflow retries or advances past.
    foreign = certificate(root_key, 'MRK synthetic component foreign leaf', 4, now, issuer, issuer_key)
    wrong = chain([foreign, issuer, root])
    MRKAppleP12Assembly.certificates(wrong)
    need(!foreign.check_private_key(key))
    rejected = false
    begin
      unexpected = MRKAppleP12Assembly.assemble(stored, PASSWORD, wrong)
    rescue ArgumentError
      rejected = true
    ensure
      unexpected&.clear if unexpected.is_a?(String) && !unexpected.frozen?
    end
    need(rejected)

    output = MRKAppleP12Assembly.assemble(stored, PASSWORD, good)
    need(output.bytesize.between?(MRKAppleP12Assembly::MAGIC.bytesize + 69, LIMIT))
    # Real fixed PBES2/AES256/PBKDF2+SHA256/MAC and private key/leaf/chain
    # readback happen inside assemble. This result remains PRIVATE material.
    output
  ensure
    private_der&.clear if private_der.is_a?(String) && !private_der.frozen?
  end

  def read_assemble(path)
    need(path.is_a?(String) && path.start_with?('/') &&
         File.basename(path) == 'pending-apple-key.mrk' && File.const_defined?(:NOFOLLOW))
    stored = result = nil
    File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
      before = MRKAppleDistributionKey.file_state(file)
      need(before[6].between?(MRKAppleDistributionKey::MAGIC.bytesize + 13, MRKAppleDistributionKey::PRIVATE_LIMIT))
      stored = file.read(MRKAppleDistributionKey::PRIVATE_LIMIT + 1)
      need(stored.is_a?(String) && stored.bytesize == before[6] && file.read(1).nil? &&
           MRKAppleDistributionKey.file_state(file) == before)
      result = assemble(stored)
      need(MRKAppleDistributionKey.file_state(file) == before)
    end # Actual original close precedes any private output publication.
    result
  ensure
    stored&.clear if stored.is_a?(String) && !stored.frozen?
  end

  def main(argv)
    need(argv.length == 1)
    result = read_assemble(argv[0])
    STDOUT.binmode
    need(STDOUT.write(result) == result.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    1 # Never emit private input, OpenSSL diagnostics, paths or a backtrace.
  ensure
    result&.clear if result.is_a?(String) && !result.frozen?
  end
end

if $PROGRAM_NAME == __FILE__ && ARGV == ['--self-test']
  # Focused existing-minitest style, not a process/fixture execution framework.
  # The native workflow NEVER selects this branch or forwards user arguments.
  ARGV.clear
  require 'minitest/autorun'
  require 'minitest/mock'
  require 'tmpdir'
  class AppleP12ComponentTest < Minitest::Test
    def self.stored
      @stored ||= MRKAppleDistributionKey.frame
    end

    def test_genuine_original_key_fixed_cipher_and_extractor_reuse
      # Delegate the positive call to REAL OpenSSL; count only to prove the
      # valid-chain/wrong-key negative cannot reach PKCS12.create first.
      original = OpenSSL::PKCS12.method(:create)
      calls = 0
      frame = nil
      OpenSSL::PKCS12.stub(:create, ->(*args) { calls += 1; original.call(*args) }) do
        frame = MRKAppleP12Component.assemble(self.class.stored)
      end
      assert calls == 1
      header = MRKAppleP12Assembly::MAGIC.bytesize + 4 + 64
      raw = frame.byteslice(header, frame.bytesize - header)
      assert frame.bytesize <= MRKAppleP12Component::LIMIT
      assert MRKAppleP12Assembly.encryption_profile(raw)
      leaf_hash = frame.byteslice(header - 64, 32).unpack1('H*')
      expected = MRKAppleDistributionKey.public_frame(self.class.stored)
      offset = MRKAppleDistributionKey::PUBLIC_MAGIC.bytesize
      csr_length, spki_length = expected.byteslice(offset, 8).unpack('NN')
      expected_spki = expected.byteslice(offset + 8 + csr_length, spki_length)
      OpenSSL::PKCS12.stub(:create, ->(*) { raise 'component reuse must not assemble' }) do
        public = MRKProvisioningP12.public_frame(raw, MRKAppleP12Component::PASSWORD, leaf_hash)
        offset = MRKProvisioningP12::MAGIC.bytesize
        leaf_length, public_length, count = public.byteslice(offset, 9).unpack('NNC')
        assert count == 2
        assert public.byteslice(offset + 9 + leaf_length, public_length) == expected_spki
      end
      assert_raises(ArgumentError) do
        MRKProvisioningP12.public_frame(raw, MRKAppleP12Component::PASSWORD, '0' * 64)
      end
      assert_raises(OpenSSL::PKCS12::PKCS12Error) do
        MRKProvisioningP12.public_frame(raw, 'b' * 64, leaf_hash)
      end
    ensure
      frame&.clear
      raw&.clear
    end

    def test_invalid_stored_material_never_reaches_local_ca_generation
      OpenSSL::PKey::RSA.stub(:generate, ->(*) { raise 'unexpected generation' }) do
        ['', 'x' * (MRKAppleDistributionKey::PRIVATE_LIMIT + 1)].each do |invalid|
          assert_raises(ArgumentError) { MRKAppleP12Component.assemble(invalid) }
        end
      end
    end

    def test_actual_private_file_reader_and_close_before_result
      root = Dir.mktmpdir('mrk-p12-component-unit-')
      File.chmod(0o700, root)
      path = File.join(root, 'pending-apple-key.mrk')
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(self.class.stored) }
      frame = MRKAppleP12Component.read_assemble(path)
      assert frame.start_with?(MRKAppleP12Assembly::MAGIC)
      assert frame.bytesize <= MRKAppleP12Component::LIMIT
      File.chmod(0o644, path)
      assert_raises(ArgumentError) { MRKAppleP12Component.read_assemble(path) }
      File.unlink(path)
      File.symlink('missing-original', path)
      assert_raises(SystemCallError) { MRKAppleP12Component.read_assemble(path) }
      File.unlink(path)
      Dir.rmdir(root) # Only this known-successful now-empty unit fixture.
    ensure
      frame&.clear
      # Unexpected failure retains the private fixture, never a recursive wipe.
    end
  end
elsif $PROGRAM_NAME == __FILE__
  begin
    status = MRKAppleP12Component.main(ARGV)
  rescue Exception
    status = 1 # Fatal exceptions cannot print private arguments/backtraces.
  end
  exit status
end
