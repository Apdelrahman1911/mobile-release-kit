# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require 'tmpdir'
require_relative '../../fastlane/apple_distribution_certificate_policy'

# Actual maintained OpenSSL path/signature verification on SYNTHETIC chains.
# Only ephemeral fixture keys are generated in memory; no real account/key,
# Apple leaf, Keychain, network, provider, installed runtime or native owner is
# used. Replacing the fixed resources below is test-only, not a production API.
class AppleDistributionCertificatePolicyTest < Minitest::Test
  Policy = MRKAppleDistributionCertificate
  TEAM = 'ABCDE12345'

  def self.key
    @key ||= OpenSSL::PKey::RSA.generate(2048, 65_537)
  end

  def self.issuer_key
    @issuer_key ||= OpenSSL::PKey::RSA.generate(2048, 65_537)
  end

  def self.root_key
    @root_key ||= OpenSSL::PKey::RSA.generate(2048, 65_537)
  end

  def extension(oid, value, critical = true)
    OpenSSL::X509::Extension.new(oid, value, critical)
  end

  def sign(name, key, issuer: nil, issuer_key: key, ca: false, path: nil, extra: [], before: Time.now - 3600, after: Time.now + 3600)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 10
    certificate.subject = OpenSSL::X509::Name.new([['CN', name, OpenSSL::ASN1::UTF8STRING], ['OU', TEAM, OpenSSL::ASN1::UTF8STRING]])
    certificate.issuer = issuer ? issuer.subject : certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before, certificate.not_after = before, after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate, factory.issuer_certificate = certificate, issuer || certificate
    if ca
      certificate.add_extension(factory.create_extension('basicConstraints', "CA:TRUE#{path.nil? ? '' : ',pathlen:' + path.to_s}", true))
      certificate.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    else
      Policy::LEAF_CRITICAL.each { |oid, value| certificate.add_extension(extension(oid, value)) }
    end
    extra.each { |item| certificate.add_extension(item) }
    certificate.sign(issuer_key, OpenSSL::Digest::SHA256.new)
    certificate
  end

  def root
    @root ||= sign('SYNTHETIC ONLY Root', self.class.root_key, ca: true, path: 1)
  end

  def intermediate(**changes)
    sign('SYNTHETIC ONLY WWDR', self.class.issuer_key, issuer: root, issuer_key: self.class.root_key,
         ca: true, path: 0, **changes)
  end

  def leaf(issuer, **changes)
    sign('SYNTHETIC ONLY Distribution', self.class.key, issuer: issuer, issuer_key: self.class.issuer_key, **changes)
  end

  def accepted(certificate, issuer)
    resources = [root, issuer].freeze
    Policy.stub(:resources, resources) do
      Policy.verify(certificate.to_der, team: TEAM, certificate_sha256: Policy.sha(certificate.to_der),
                    spki_sha256: Policy.sha(self.class.key.public_to_der))
    end
  end

  def plain_store(certificate, issuer)
    store = OpenSSL::X509::Store.new
    store.add_cert(root)
    [store.verify(certificate, [issuer]), store.error]
  end

  def test_reviewed_public_resources_form_exact_current_two_chain
    # Public root/intermediate only. This is not a real Apple signing identity
    # nor an installed/bundled-runtime qualification of the new operation.
    assert Policy.preflight_resources!
    root, issuer = Policy.send(:resources)
    assert_equal [Policy::ROOT_SHA256, Policy::INTERMEDIATE_SHA256], [root, issuer].map { |item| Policy.sha(item.to_der) }
    assert_equal [1215, 1109], [root.to_der.bytesize, issuer.to_der.bytesize]
  end

  def test_real_valid_synthetic_three_chain_requires_exact_leaf_application_handling
    issuer = intermediate
    certificate = leaf(issuer)
    ok, error = plain_store(certificate, issuer)
    refute ok
    assert_equal OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION, error
    result = accepted(certificate, issuer)
    assert_equal [certificate, issuer, root].map { |item| Policy.sha(item.to_der) }, result.fetch('chainSha256')
    assert Time.iso8601(result.fetch('checkedAt')) <= Time.now
  end

  def test_real_wrong_signature_is_not_overridden_after_leaf_marker_error
    issuer = intermediate
    certificate = leaf(issuer)
    certificate.sign(self.class.root_key, OpenSSL::Digest::SHA256.new) # Correct name, wrong private signer.
    refute certificate.verify(issuer.public_key)
    assert_raises(Policy::Refused) { accepted(certificate, issuer) }
  end

  def test_real_expired_and_not_yet_valid_certificates_do_not_pass_callback
    issuer = intermediate
    [leaf(issuer, before: Time.now - 7200, after: Time.now - 60),
     leaf(issuer, before: Time.now + 60, after: Time.now + 7200)].each do |certificate|
      assert_raises(Policy::Refused) { accepted(certificate, issuer) }
    end
  end

  def test_extra_unknown_critical_leaf_extension_does_not_share_whitelist_error
    issuer = intermediate
    certificate = leaf(issuer, extra: [extension('1.2.3.4.999', "\x05\x00".b)])
    ok, error = plain_store(certificate, issuer)
    refute ok
    assert_equal OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION, error
    assert_raises(Policy::Refused) { accepted(certificate, issuer) }
  end

  def test_unhandled_critical_intermediate_is_never_waived_at_nonzero_depth
    issuer = intermediate(extra: [extension('1.2.3.4.998', "\x05\x00".b)])
    certificate = leaf(issuer)
    assert certificate.verify(issuer.public_key)
    assert_raises(Policy::Refused) { accepted(certificate, issuer) }
  end

  def test_wrong_issuer_ca_constraints_and_path_cannot_become_leaf_handling
    issuer = intermediate
    certificate = leaf(issuer)
    other = sign('SYNTHETIC OTHER ISSUER', self.class.issuer_key, issuer: root, issuer_key: self.class.root_key, ca: true)
    assert_raises(Policy::Refused) { accepted(certificate, other) }
    not_ca = sign('SYNTHETIC ONLY WWDR', self.class.issuer_key, issuer: root, issuer_key: self.class.root_key)
    assert_raises(Policy::Refused) { accepted(leaf(not_ca), not_ca) }
    issuer.not_after = Time.now - 60
    issuer.sign(self.class.root_key, OpenSSL::Digest::SHA256.new)
    assert_raises(Policy::Refused) { accepted(certificate, issuer) }
  end

  def test_duplicate_malformed_missing_noncritical_or_cloud_markers_are_refused
    issuer = intermediate
    original = leaf(issuer)
    variants = []
    duplicate = OpenSSL::X509::Certificate.new(original.to_der)
    duplicate.add_extension(extension(Policy::IPHONE_SUBMISSION, "\x05\x00".b))
    variants << duplicate
    [nil, "\x05\x01\x00".b, "\x05\x00\x00".b, "\x30\x00".b].each do |bytes|
      changed = OpenSSL::X509::Certificate.new(original.to_der)
      changed.extensions = changed.extensions.reject { |item| item.oid == Policy::IPHONE_SUBMISSION }
      changed.add_extension(extension(Policy::IPHONE_SUBMISSION, bytes)) if bytes
      variants << changed
    end
    changed = OpenSSL::X509::Certificate.new(original.to_der)
    changed.extensions = changed.extensions.reject { |item| item.oid == Policy::MAC_SUBMISSION }
    changed.add_extension(extension(Policy::MAC_SUBMISSION, "\x05\x00".b, false))
    variants << changed
    variants << leaf(issuer, extra: [extension(Policy::CLOUD_MANAGED, "\x05\x00".b, false)])
    variants.each do |certificate|
      certificate.sign(self.class.issuer_key, OpenSSL::Digest::SHA256.new)
      assert certificate.verify(issuer.public_key)
      assert_raises(Policy::Refused) { accepted(certificate, issuer) }
    end
  end

  def test_team_full_spki_hash_original_der_and_digest_are_exact
    issuer = intermediate
    certificate = leaf(issuer)
    Policy.stub(:resources, [root, issuer]) do
      [[TEAM.downcase, Policy.sha(self.class.key.public_to_der), Policy.sha(certificate.to_der), certificate.to_der],
       [TEAM, Policy.sha(self.class.root_key.public_to_der), Policy.sha(certificate.to_der), certificate.to_der],
       [TEAM, Policy.sha(self.class.key.public_to_der), '0' * 64, certificate.to_der],
       [TEAM, Policy.sha(self.class.key.public_to_der), Policy.sha(certificate.to_der + "\x00"), certificate.to_der + "\x00"]].each do |team, spki, digest, der|
        assert_raises(Policy::Refused) { Policy.verify(der, team: team, certificate_sha256: digest, spki_sha256: spki) }
      end
    end
  end

  def test_fixed_private_handoff_original_eof_close_then_bounded_redacted_output
    issuer = intermediate
    certificate = leaf(issuer)
    body = Policy::INPUT_MAGIC + 'a' * 64 + 'b' * 64 + Policy.sha(certificate.to_der) +
           Policy.sha(self.class.key.public_to_der) + TEAM + [certificate.to_der.bytesize].pack('N') + certificate.to_der
    Dir.mktmpdir('mrk-synthetic-certificate-') do |directory|
      path = File.join(directory, 'apple-distribution-certificate.mrk')
      File.write(path, body, mode: 'wb', perm: 0o600)
      output = []
      Policy.stub(:resources, [root, issuer]) do
        STDOUT.stub(:write, ->(bytes) { output << bytes.dup; bytes.bytesize }) do
          STDERR.stub(:write, ->(*) { flunk 'no diagnostic output' }) do
            assert_equal 0, Policy.main([path])
            assert_equal 1, Policy.main([path, '--ignore-critical'])
            File.write(path, body + 'trailing', mode: 'wb')
            assert_equal 1, Policy.main([path])
            File.chmod(0o644, path)
            assert_equal 1, Policy.main([path])
          end
        end
      end
      assert_equal 1, output.length
      assert_operator output[0].bytesize, :<=, Policy::OUTPUT_LIMIT
      value = JSON.parse(output[0])
      assert_equal 'offline-apple-distribution-certificate', value['scope']
      assert_equal 'a' * 64, value['requestBindingSha256']
      assert_equal 'b' * 64, value['identityAckSha256']
      assert_equal false, value['revocationChecked']
      refute value.key?('certificateContent')
      refute value.key?('privateKey')
    end
  end
end
