# frozen_string_literal: true

# Real maintained OpenSSL and private fixture files. Existing SDK/HTTP ABI
# doubles only: no real signer, token, Google request or native receipt.
require_relative 'test_android_store_versions'
require_relative '../../fastlane/play_edit_recovery'

class PlayEditRecoveryTest < Minitest::Test
  Read = MobileReleaseKit::AndroidStoreVersions
  Recovery = MobileReleaseKit::PlayEditRecovery
  Fake = PlayInventoryFakeSDK

  def setup
    Fake.reset
    @sdk_forbidden = false
  end

  def fixture
    Dir.mktmpdir('mrk-play-recovery-inert-') do |root|
      path = File.join(root, 'google.json')
      value = { 'type' => 'service_account', 'project_id' => 'inert-project', 'private_key_id' => 'a' * 40,
        'private_key' => "-----BEGIN PRIVATE KEY-----\nINERT NOT A PRIVATE KEY\n-----END PRIVATE KEY-----\n",
        'client_email' => 'inert@inert-project.iam.gserviceaccount.com', 'client_id' => '123', 'token_uri' => Read::TOKEN }
      File.write(path, JSON.generate(value), mode: 'wx', perm: 0o600)
      aad = { 'schemaVersion' => 1, 'purpose' => Recovery::PURPOSE, 'keyVersion' => 'inert-v1',
        'authority' => { 'repositoryId' => '123', 'projectId' => 'p' * 32 }, 'localProjectId' => 'a' * 32,
        'candidateId' => '00000000-0000-4000-8000-000000000001', 'requestSha256' => 'b' * 64,
        'attemptId' => '00000000-0000-4000-8000-000000000002', 'source' => { 'commit' => 'c' * 40 },
        'contextSha256' => 'd' * 64, 'identityRevision' => 'e' * 64 }
      env = { Recovery::KEY => Base64.strict_encode64('K' * 32), Recovery::VERSION => 'inert-v1',
        Recovery::AAD => Recovery.canonical(aad), 'GOOGLE_APPLICATION_CREDENTIALS' => path,
        'MOBILE_RELEASE_PLAY_PACKAGE' => 'com.example.version', 'MOBILE_RELEASE_PLAY_CONTEXT' => 'd' * 64,
        'MOBILE_RELEASE_PLAY_READ_END_NS' => (51 * Read::SECOND).to_s,
        'MOBILE_RELEASE_PLAY_HARD_END_NS' => (61 * Read::SECOND).to_s }
      Process.stub(:clock_gettime, ->(*_args) { Fake.current * Read::SECOND }) do
        Read.stub(:load_sdk!, -> { raise 'verify must not load provider SDK' if @sdk_forbidden }) { yield env, path }
      end
    end
  end

  def capsule(env)
    Fake.statuses['delete'] = 500
    original = Read::Operation.new(Read::Input.new(env))
    value = JSON.parse(original.execute)
    assert_equal %w[token insert tracks bundles apks delete], Fake.wire.map(&:first)
    refute value['temporaryEdit']['deleteConfirmed']
    assert_raises(Read::Error) { original.execute }
    value.fetch('hostedRecovery')
  end

  def test_original_known_insert_failure_seals_once_and_explicit_verifier_has_no_sdk
    fixture do |env, _|
      encrypted = capsule(env)
      refute_includes Recovery.canonical(encrypted), 'synthetic-edit-1'
      refute_includes Recovery.canonical(encrypted), env[Recovery::KEY]
      refute_includes Recovery.canonical(encrypted), 'client_email'
      assert_operator Recovery.canonical(encrypted).bytesize, :<=, 4096
      assert_equal 12, Base64.strict_decode64(encrypted['nonce']).bytesize
      assert_equal 16, Base64.strict_decode64(encrypted['tag']).bytesize
      Fake.reset
      env[Recovery::CAPSULE] = Recovery.canonical(encrypted)
      output = StringIO.new
      @sdk_forbidden = true
      assert_equal 0, Recovery.main(['verify'], env, output)
      result = JSON.parse(output.string)
      assert_equal true, result['verified']
      assert_equal Digest::SHA256.hexdigest(Recovery.canonical(encrypted)), result['capsuleSha256']
      refute_includes output.string, 'synthetic-edit-1'
      assert_empty Fake.wire
      assert_equal 0, Fake.auths
    end
  end

  def test_fresh_nonce_for_each_original_and_single_sealing_attempt
    fixture do |env, _|
      first = capsule(env)
      Fake.reset
      second = capsule(env)
      refute_equal first['nonce'], second['nonce']
      refute_equal first['ciphertext'], second['ciphertext']
      selected = Recovery::Selection.new(Read::Input.new(env))
      selected.seal('synthetic-edit-1')
      assert_raises(Read::Error) { selected.seal('synthetic-edit-1') }
    end
  end

  def test_wrong_key_aad_repository_candidate_attempt_account_and_tag_never_send_or_output
    fixture do |env, path|
      encrypted = capsule(env)
      Fake.reset
      env[Recovery::CAPSULE] = Recovery.canonical(encrypted)
      changes = [
        { Recovery::KEY => Base64.strict_encode64('X' * 32) }, { Recovery::VERSION => 'different-v1' },
        { Recovery::CAPSULE => Recovery.canonical(encrypted.merge('tag' => Base64.strict_encode64('X' * 16))) },
        { Recovery::CAPSULE => Recovery.canonical(encrypted.merge('nonce' => Base64.strict_encode64('X' * 11))) },
        { Recovery::CAPSULE => Recovery.canonical(encrypted.merge('algorithm' => 'other')) },
        { Recovery::CAPSULE => Recovery.canonical(encrypted.merge('ciphertext' => Base64.strict_encode64('X' * 2049))) }
      ]
      %w[authority candidateId attemptId source].each do |name|
        aad = JSON.parse(env[Recovery::AAD])
        aad[name] = case name
                    when 'authority' then { 'repositoryId' => '124', 'projectId' => 'p' * 32 }
                    when 'source' then { 'commit' => 'd' * 40 }
                    else '00000000-0000-4000-8000-000000000099'
                    end
        changes << { Recovery::AAD => Recovery.canonical(aad) }
      end
      changes.each do |change|
        output = StringIO.new
        assert_equal 70, Recovery.main(['verify'], env.merge(change), output)
        assert_empty output.string
        assert_empty Fake.wire
      end
      account = JSON.parse(File.read(path)); account['client_id'] = '124'
      File.write(path, JSON.generate(account))
      output = StringIO.new
      assert_equal 70, Recovery.main(['verify'], env, output)
      assert_empty output.string
      assert_empty Fake.wire
    end
  end

  def test_cleanup_uses_actual_token_then_only_one_delete_and_no_plaintext_output
    fixture do |env, _|
      env[Recovery::CAPSULE] = Recovery.canonical(capsule(env))
      Fake.reset
      input = Read::Input.new(env)
      verified = Recovery::Verified.open(input)
      operation = Read::Operation.new(input)
      result = JSON.parse(operation.execute_cleanup(verified))
      assert_equal %w[token delete], Fake.wire.map(&:first)
      assert_equal 1, Fake.auths
      assert_equal true, result['deleteAttempted']
      assert_equal true, result['deleteConfirmed']
      refute_includes JSON.generate(result), 'synthetic-edit-1'
      refute_includes JSON.generate(result), 'SYNTHETIC_TOKEN'
      assert_raises(Read::Error) { operation.execute_cleanup(verified) }
      assert_raises(Read::Error) { Read::Operation.new(input).execute_cleanup(verified) }
      assert_equal 2, Fake.wire.length
    end
  end

  def test_cleanup_refusal_lost_body_repeat_and_expired_id_do_not_become_success
    fixture do |env, _|
      env[Recovery::CAPSULE] = Recovery.canonical(capsule(env))
      %w[404 403 500 body repeat late token].each do |failure|
        Fake.reset
        Fake.statuses['delete'] = failure.to_i if failure.match?(/\A[0-9]+\z/)
        Fake.statuses['token'] = 401 if failure == 'token'
        Fake.chunks['delete'] = ['not empty'] if failure == 'body'
        Fake.repeat = 'delete' if failure == 'repeat'
        Fake.before_return = ->(step) { Fake.current = 62 if step == 'delete' } if failure == 'late'
        output = StringIO.new
        result = Recovery.main(['delete'], env, output)
        if failure == 'late'
          assert_equal 70, result
          assert_empty output.string
        else
          assert_equal 0, result
          refute JSON.parse(output.string)['deleteConfirmed']
        end
        assert_operator Fake.wire.count { |row| row.first == 'delete' }, :<=, 1
        refute_includes Fake.wire.map(&:first), 'insert'
      end
    end
  end

  def test_failed_insert_cannot_seal_and_default_frames_stay_unchanged
    fixture do |env, _|
      Fake.statuses['insert'] = 500
      value = JSON.parse(Read::Operation.new(Read::Input.new(env)).execute)
      assert_nil value['hostedRecovery']
      assert_nil value['temporaryEdit']['editId']
      Fake.reset
      plain = env.reject { |key, _| Recovery::KEYS.include?(key) }
      value = JSON.parse(Read::Operation.new(Read::Input.new(plain)).execute)
      refute value.key?('hostedRecovery')
      assert_equal true, value['temporaryEdit']['deleteConfirmed']
      assert_equal %w[token insert tracks bundles apks delete], Fake.wire.map(&:first)
    end
  end
end
