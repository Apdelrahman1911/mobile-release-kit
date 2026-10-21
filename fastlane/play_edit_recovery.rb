# frozen_string_literal: true

# Fixed private hosted companion. OpenSSL owns AEAD; the existing Play reader
# owns the sole token/DELETE. No ID in argv, diagnostics or this helper's output.
require 'openssl'
require_relative 'android_store_versions'

module MobileReleaseKit
  module PlayEditRecovery
    Read = AndroidStoreVersions
    PURPOSE = 'hosted-play-edit-recovery/1'
    KEY = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_BASE64'
    VERSION = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_VERSION'
    AAD = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_AAD'
    CAPSULE = 'MOBILE_RELEASE_PLAY_EDIT_RECOVERY_CAPSULE'
    KEYS = [KEY, VERSION, AAD, CAPSULE].freeze
    PLAIN_LIMIT = 2048
    CAPSULE_LIMIT = 4096

    def self.canonical(value)
      ordered = case value
                when Hash then value.keys.sort.to_h { |key| [key, canonical_value(value.fetch(key))] }
                else value
                end
      JSON.generate(ordered, ascii_only: true)
    end
    def self.canonical_value(value)
      case value
      when Hash then value.keys.sort.to_h { |key| [key, canonical_value(value.fetch(key))] }
      when Array then value.map { |entry| canonical_value(entry) }
      else value
      end
    end
    def self.base64(value, maximum, exact = nil)
      Read.need(value.instance_of?(String) && value.ascii_only? && value.bytesize.between?(1, 4 * ((maximum + 2) / 3)))
      raw = Base64.strict_decode64(value)
      Read.need(raw.bytesize.between?(1, maximum) && (!exact || raw.bytesize == exact) && Base64.strict_encode64(raw) == value)
      raw
    end

    class Selection
      attr_reader :aad, :version
      def initialize(input)
        @input = input
        env = input.recovery_environment
        @version = env[VERSION]
        Read.need(@version.instance_of?(String) && @version.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z/))
        @key = PlayEditRecovery.base64(env[KEY], 32, 32)
        @aad = env[AAD]
        row = Read.object(@aad, CAPSULE_LIMIT)
        Read.need(row.keys.sort == %w[attemptId authority candidateId contextSha256 identityRevision keyVersion localProjectId purpose requestSha256 schemaVersion source] &&
          row['schemaVersion'] == 1 && row['purpose'] == PURPOSE && row['keyVersion'] == @version &&
          row['contextSha256'] == input.context && PlayEditRecovery.canonical(row) == @aad)
        %w[contextSha256 identityRevision requestSha256].each { |key| Read.need(row[key].instance_of?(String) && row[key].match?(/\A[0-9a-f]{64}\z/)) }
        %w[attemptId candidateId].each { |key| Read.need(row[key].instance_of?(String) && row[key].match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/)) }
        Read.need(row['localProjectId'].instance_of?(String) && row['localProjectId'].match?(/\A[0-9a-f]{32}\z/))
        @used = false
      end
      def inspect = '#<PlayEditRecovery::Selection private>'
      def seal(edit)
        Read.need(!@used && edit.instance_of?(String) && edit.match?(/\A[A-Za-z0-9_-]{1,128}\z/))
        @used = true # No second nonce/cipher attempt after failure.
        plaintext = PlayEditRecovery.canonical('schemaVersion' => 1, 'editId' => edit,
          'packageName' => @input.package, 'google' => @input.recovery_identity)
        Read.need(plaintext.bytesize.between?(1, PLAIN_LIMIT))
        nonce = OpenSSL::Random.random_bytes(12)
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = @key
        cipher.iv = nonce
        cipher.auth_data = @aad
        encrypted = cipher.update(plaintext) + cipher.final
        value = { 'schemaVersion' => 1, 'algorithm' => 'AES-256-GCM', 'keyVersion' => @version,
          'nonce' => Base64.strict_encode64(nonce), 'ciphertext' => Base64.strict_encode64(encrypted),
          'tag' => Base64.strict_encode64(cipher.auth_tag(16)), 'aadSha256' => Digest::SHA256.hexdigest(@aad) }
        Read.need(PlayEditRecovery.canonical(value).bytesize <= CAPSULE_LIMIT)
        value
      ensure
        plaintext&.clear # No claim of allocator/OpenSSL/Ruby heap zeroization.
      end
      def open
        value = Read.object(@input.recovery_environment[CAPSULE], CAPSULE_LIMIT)
        Read.need(value.keys.sort == %w[aadSha256 algorithm ciphertext keyVersion nonce schemaVersion tag] &&
          value['schemaVersion'] == 1 && value['algorithm'] == 'AES-256-GCM' && value['keyVersion'] == @version &&
          value['aadSha256'] == Digest::SHA256.hexdigest(@aad) &&
          PlayEditRecovery.canonical(value) == @input.recovery_environment[CAPSULE])
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = @key
        cipher.iv = PlayEditRecovery.base64(value['nonce'], 12, 12)
        cipher.auth_tag = PlayEditRecovery.base64(value['tag'], 16, 16)
        cipher.auth_data = @aad
        # Authentication must finish BEFORE parsing or using the plaintext ID.
        plaintext = cipher.update(PlayEditRecovery.base64(value['ciphertext'], PLAIN_LIMIT)) + cipher.final
        row = Read.object(plaintext, PLAIN_LIMIT)
        Read.need(row.keys.sort == %w[editId google packageName schemaVersion] && row['schemaVersion'] == 1 &&
          row['packageName'] == @input.package && row['google'] == @input.recovery_identity &&
          row['editId'].instance_of?(String) && row['editId'].match?(/\A[A-Za-z0-9_-]{1,128}\z/) &&
          PlayEditRecovery.canonical(row) == plaintext)
        [row['editId'].dup.freeze, Digest::SHA256.hexdigest(PlayEditRecovery.canonical(value))]
      ensure
        plaintext&.clear
      end
    end

    class Verified
      def self.open(input)
        Read.need(input.instance_of?(Read::Input))
        selection = Selection.new(input)
        edit, digest = selection.open
        new(input, edit, digest, Digest::SHA256.hexdigest(selection.aad))
      end
      def initialize(input, edit, digest, aad_digest)
        @input, @edit, @digest, @aad_digest, @taken = input, edit, digest, aad_digest, false
      end
      private_class_method :new
      def inspect = '#<PlayEditRecovery::Verified private>'
      def take(input)
        Read.need(input.equal?(@input) && !@taken)
        @taken = true
        @edit
      end
      def output(mode, **facts)
        value = { 'schemaVersion' => 1, 'scope' => PURPOSE, 'mode' => mode,
          'capsuleSha256' => @digest, 'aadSha256' => @aad_digest }.merge(facts.transform_keys(&:to_s))
        raw = PlayEditRecovery.canonical(value) + "\n"
        Read.need(raw.bytesize <= 1024)
        raw
      end
    end

    def self.capture(input)
      env = input.recovery_environment
      return nil if [KEY, VERSION, AAD, CAPSULE].all? { |key| env[key].nil? || env[key].empty? }
      Read.need(env[CAPSULE].nil? || env[CAPSULE].empty?)
      Selection.new(input)
    end

    def self.main(arguments, environment, output)
      Read.need(arguments == ['verify'] || arguments == ['delete'])
      input = Read::Input.new(environment) # Known private snapshot; no SDK/token here.
      verified = Verified.open(input)
      Read.need(Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) < input.read_end)
      raw = if arguments == ['verify']
              verified.output('verify', verified: true)
            else
              Read::Operation.new(input).execute_cleanup(verified)
            end
      Read.need(Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) < input.hard_end)
      Read.need(output.write(raw) == raw.bytesize)
      output.flush
      0
    rescue StandardError
      70 # Never disclose auth/tag/provider/parser/credential/ID diagnostics.
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::PlayEditRecovery.main(ARGV, ENV, STDOUT)
  rescue Exception
    Process.exit!(70)
  end
  exit(code)
end
