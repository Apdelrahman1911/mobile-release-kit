# frozen_string_literal: true

# Fixed local helper for the original Desktop Apple provisioning operation.
# Arguments are TWO original private-input paths and a PUBLIC certificate
# digest. No private key/password, credential discovery, provider call or
# replacement-certificate action is an argument, output or fallback.
require 'openssl'
require 'digest'

module MRKProvisioningP12
  MAGIC = "MRK-P12-PUBLIC/1\n".b.freeze
  P12_LIMIT = 4 * 1024 * 1024 # Automatic profile setup only, not the vault limit.
  PASSWORD_LIMIT = 4096
  CERTIFICATE_LIMIT = 64 * 1024
  SPKI_LIMIT = 16 * 1024
  CHAIN_LIMIT = 8

  module_function

  def require_value(value)
    raise ArgumentError, 'P12 input refused' unless value
  end

  def state(file)
    value = file.stat
    require_value(value.file? && value.uid == Process.euid && value.nlink == 1 &&
                  (value.mode & 0o7777) == 0o600)
    [value.dev, value.ino, value.mode, value.uid, value.gid, value.nlink,
     value.size, value.mtime.to_r, value.ctime.to_r]
  end

  def read_original(path, basename, maximum)
    require_value(path.is_a?(String) && path.start_with?('/') &&
                  File.basename(path) == basename && File.const_defined?(:NOFOLLOW))
    File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
      before = state(file)
      require_value(before[6].positive? && before[6] <= maximum)
      bytes = file.read(maximum + 1)
      require_value(bytes.is_a?(String) && bytes.bytesize == before[6] &&
                    bytes.bytesize <= maximum && file.read(1).nil? && state(file) == before)
      bytes.b
    end
  end

  def public_frame(p12_bytes, password, expected)
    require_value(p12_bytes.is_a?(String) && p12_bytes.bytesize.between?(1, P12_LIMIT) &&
                  password.is_a?(String) && password.bytesize.between?(1, PASSWORD_LIMIT) &&
                  !password.include?("\0") && expected.is_a?(String) &&
                  expected.match?(/\A[0-9a-f]{64}\z/))
    password = password.dup.force_encoding(Encoding::UTF_8)
    require_value(password.valid_encoding?)
    archive = OpenSSL::PKCS12.new(p12_bytes, password)
    key = archive.key
    certificate = archive.certificate
    # PKCS12#key/#certificate do not attest the number of original key bags.
    # Only the exact returned private key and expected leaf are used here.
    require_value((key.is_a?(OpenSSL::PKey::RSA) || key.is_a?(OpenSSL::PKey::EC)) &&
                  key.private? && certificate.is_a?(OpenSSL::X509::Certificate) &&
                  certificate.check_private_key(key))
    leaf = certificate.to_der
    public_key = certificate.public_key.public_to_der
    require_value(leaf.bytesize.between?(1, CERTIFICATE_LIMIT) &&
                  public_key.bytesize.between?(1, SPKI_LIMIT) &&
                  Digest::SHA256.hexdigest(leaf) == expected &&
                  public_key == key.public_to_der)
    certificates = archive.ca_certs || []
    require_value(certificates.is_a?(Array) && certificates.length <= CHAIN_LIMIT)
    chain = certificates.map do |item|
      require_value(item.is_a?(OpenSSL::X509::Certificate))
      der = item.to_der
      require_value(der.bytesize.between?(1, CERTIFICATE_LIMIT) && der != leaf)
      der
    end
    require_value(chain.uniq.length == chain.length)
    # These are PUBLIC certificate/SPKI facts, not a trust or private-key
    # export. The existing Apple chain/profile validator remains necessary.
    frame = MAGIC + [leaf.bytesize, public_key.bytesize, chain.length].pack('NNC')
    frame << leaf << public_key
    chain.each { |der| frame << [der.bytesize].pack('N') << der }
    frame
  ensure
    # Best-effort retirement of THIS Ruby string only; no process-wide secure
    # erasure or native-original-finality claim is made by this helper.
    password&.clear if password.is_a?(String) && !password.frozen?
  end

  def main(argv)
    require_value(argv.length == 3 && File.dirname(argv[0]) == File.dirname(argv[1]))
    p12_bytes = read_original(argv[0], 'distribution.p12', P12_LIMIT)
    password = read_original(argv[1], 'p12-password', PASSWORD_LIMIT)
    frame = public_frame(p12_bytes, password, argv[2])
    STDOUT.binmode
    require_value(STDOUT.write(frame) == frame.bytesize)
    STDOUT.flush
    0
  rescue StandardError
    # No exception interpolation, OpenSSL diagnostics, path, password or
    # private key can reach stderr/stdout. The parent reports a fixed refusal.
    1
  ensure
    password&.clear if password.is_a?(String) && !password.frozen?
    p12_bytes&.clear if p12_bytes.is_a?(String) && !p12_bytes.frozen?
  end
end

exit MRKProvisioningP12.main(ARGV) if $PROGRAM_NAME == __FILE__
