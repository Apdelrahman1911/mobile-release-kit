# frozen_string_literal: true
# Inert ABI fixtures only: no Google gems, JWT signer, sockets or native owner.
require 'minitest/autorun'
require 'ostruct'
require 'tmpdir'
require_relative '../../fastlane/android_store_versions'

module PlayInventoryFakeSDK
  class << self
    attr_accessor :wire, :before_return, :chunks, :statuses, :repeat, :auths, :last_client, :clock, :current
    def reset
      self.wire, self.before_return, self.repeat, self.auths, self.current = [], nil, nil, 0, 1
      self.statuses, self.chunks = {}, {
        'token' => [JSON.generate('access_token' => 'SYNTHETIC_TOKEN', 'token_type' => 'Bearer', 'expires_in' => 3600)],
        'insert' => [JSON.generate('id' => 'synthetic-edit-1', 'expiryTimeSeconds' => '99999')],
        'tracks' => ['{"tracks":[]}'], 'bundles' => ['{"bundles":[]}'], 'apks' => ['{"apks":[]}'], 'delete' => [] }
    end
  end
end

class HTTPClient
  attr_accessor :proxy, :debug_dev, :transparent_gzip_decompression, :follow_redirect_count,
                :connect_timeout, :send_timeout, :receive_timeout
  Header = Struct.new(:request_method, :request_uri, :request_query, :request_absolute_uri, :values) do
    def [](key) = Array(values[key])
  end
  def initialize
    @request_filter = []
    PlayInventoryFakeSDK.last_client = self
  end
  def request(method, url, query:, body:, header:, follow_redirect:, &stream)
    raise 'must be synchronous streamed and no redirects' unless stream && !follow_redirect
    request = OpenStruct.new(header: Header.new(method, URI(url), query, false, header), http_body: OpenStruct.new(content: body))
    step = url == MobileReleaseKit::AndroidStoreVersions::TOKEN ? 'token' :
      method == 'POST' ? 'insert' : method == 'DELETE' ? 'delete' : URI(url).path.split('/').last
    result = nil
    (PlayInventoryFakeSDK.repeat == step ? 2 : 1).times do
      # Mirrors pinned HTTPClient do_get_block: filter precedes EVERY query.
      @request_filter.each { |filter| filter.filter_request(request) }
      PlayInventoryFakeSDK.wire << [step, method, url, body]
      result = OpenStruct.new(status: PlayInventoryFakeSDK.statuses.fetch(step, step == 'delete' ? 204 : 200))
      PlayInventoryFakeSDK.chunks.fetch(step).each { |part| stream.call(result, part) }
    end
    PlayInventoryFakeSDK.before_return&.call(step)
    result
  end
end

module Google
  module Auth
    class ServiceAccountCredentials
      def self.make_creds(**values)
        raise 'ambient discovery' unless values.keys.sort == %i[audience enable_self_signed_jwt json_key_io scope token_credential_uri] &&
          values[:audience] == MobileReleaseKit::AndroidStoreVersions::TOKEN && values[:token_credential_uri] == values[:audience] &&
          values[:enable_self_signed_jwt] == false && values[:scope] == MobileReleaseKit::AndroidStoreVersions::PLAY_SCOPE
        JSON.parse(values[:json_key_io].read) # Fixture only, no real signer.
        new
      end
      def fetch_access_token(connection:)
        PlayInventoryFakeSDK.auths += 1
        reply = connection.post(MobileReleaseKit::AndroidStoreVersions::TOKEN,
          'assertion' => 'INERT_ASSERTION', 'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer')
        raise 'PRIVATE_TOKEN_PROVIDER_ERROR' unless reply.status_code == 200
        JSON.parse(reply.body)
      end
      def fetch_access_token! = raise('retrying auth must never be used')
    end
  end
  module Apis
    module Core
      class ApiCommand
        attr_accessor :options
        attr_reader :method, :url, :header, :body
        def initialize(method, url, body, authorization)
          @method, @url, @body, @header = method, url, body, {}
          @options = OpenStruct.new(authorization: authorization)
        end
        def apply_request_options(header) = (header['Authorization'] = 'Bearer ' + options.authorization)
        def execute(client) = execute_once(client)
      end
    end
    module AndroidpublisherV3
      class AppEdit; end
      class AndroidPublisherService
        attr_accessor :root_url, :universe_domain, :authorization
        attr_reader :client_options
        def initialize
          @client_options = OpenStruct.new
        end
        def client = (@client ||= HTTPClient.new)
        def current_batch = nil
        def insert_edit(package, value)
          raise unless value.instance_of?(AppEdit)
          call('POST', package, nil, nil, '{}')
        end
        def list_edit_tracks(package, edit) = call('GET', package, edit, 'tracks', '')
        def list_edit_bundles(package, edit) = call('GET', package, edit, 'bundles', '')
        def list_edit_apks(package, edit) = call('GET', package, edit, 'apks', '')
        def delete_edit(package, edit) = call('DELETE', package, edit, nil, '')
        def call(method, package, edit, collection, body)
          url = root_url + "androidpublisher/v3/applications/#{package}/edits"
          url += "/#{edit}" if edit
          url += "/#{collection}" if collection
          execute_or_queue_command(Core::ApiCommand.new(method, url, body, authorization))
        end
      end
    end
  end
end

class AndroidStoreVersionsTest < Minitest::Test
  Read = MobileReleaseKit::AndroidStoreVersions
  Fake = PlayInventoryFakeSDK
  def setup
    Fake.reset
  end
  def input
    value = Read::Input.allocate # DATA fixture, not native admission or a credential receipt.
    { package: 'com.example.version', context: 'a' * 64, read_end: 51, hard_end: 61, json: '{"project_id":"fixture"}' }.each do |key, item|
      value.instance_variable_set("@#{key}", %i[read_end hard_end].include?(key) ? item * Read::SECOND : item)
    end
    value
  end
  def run_query
    Read.stub(:load_sdk!, nil) do
      Process.stub(:clock_gettime, ->(*_args) { Fake.current * Read::SECOND }) do
        operation = Read::Operation.new(input)
        value = JSON.parse(operation.execute)
        yield(operation, value) if block_given?
        value
      end
    end
  end
  def test_fixed_original_client_token_and_five_api_slots_zero_redirects_or_refresh
    value = run_query do |operation, _|
      assert_raises(Read::Error) { operation.execute }
    end
    assert_equal %w[token insert tracks bundles apks delete], Fake.wire.map(&:first)
    assert_equal 1, Fake.auths
    assert_equal true, value['queryFinished']
    assert_equal({ 'insertAttempted' => true, 'editId' => 'synthetic-edit-1', 'deleteAttempted' => true, 'deleteConfirmed' => true }, value['temporaryEdit'])
    assert_equal 5, value['pages'].size
    assert_nil Fake.last_client.debug_dev
    assert_nil Fake.last_client.proxy
    refute_includes JSON.generate(value), 'SYNTHETIC_TOKEN'
    refute_includes JSON.generate(value), 'INERT_ASSERTION'
  end
  def test_underlying_keepalive_or_protocol_retry_cannot_send_insert_twice
    Fake.repeat = 'insert'
    value = run_query
    assert_equal %w[token insert], Fake.wire.map(&:first)
    assert_equal true, value['temporaryEdit']['insertAttempted']
    assert_nil value['temporaryEdit']['editId']
    refute value['queryFinished']
    assert_nil value['pages'].first['response']['bodyBase64']
    assert_equal Read::PRIVATE_FAILURE, value['pages'].first['response']['failure']
  end
  def test_second_token_wire_is_refused_and_cannot_start_edit
    Fake.repeat = 'token'
    value = run_query
    assert_equal ['token'], Fake.wire.map(&:first)
    assert_empty value['pages']
    refute value['temporaryEdit']['insertAttempted']
  end
  def test_success_error_and_token_chunks_are_capped_before_retention
    %w[token insert tracks delete].each do |step|
      setup
      Fake.chunks[step] = ['X' * (step == 'tracks' ? Read::RAW_LIMIT + 1 : Read::SMALL_LIMIT + 1)]
      value = run_query
      refute value['queryFinished'] if step != 'delete'
      assert_equal 1, Fake.wire.count { |wire| wire.first == step }
      refute_includes JSON.generate(value), 'XXXXX'
      if step == 'tracks'
        assert_equal true, value['temporaryEdit']['deleteConfirmed']
        assert_equal 'inventory_limit', value['pages'][1]['response']['failure']
      end
    end
  end
  def test_complete_insert_id_retained_before_late_stop_and_deleted_once
    Fake.before_return = ->(step) { Fake.current = 52 if step == 'insert' }
    value = run_query
    assert_equal %w[token insert delete], Fake.wire.map(&:first)
    assert_equal 'synthetic-edit-1', value['temporaryEdit']['editId']
    assert value['temporaryEdit']['deleteConfirmed']
    refute value['queryFinished']
  end
  def test_malformed_insert_cannot_guess_cleanup_and_empty_204_differs_from_failed_delete
    Fake.chunks['insert'] = ['{"id":"synthetic-edit-1"']
    value = run_query
    assert_equal %w[token insert], Fake.wire.map(&:first)
    assert_nil value['temporaryEdit']['editId']
    setup
    Fake.statuses['delete'] = 500
    Fake.chunks['delete'] = ['PRIVATE_PROVIDER_ERROR']
    value = run_query
    refute value['temporaryEdit']['deleteConfirmed']
    assert_equal 1, Fake.wire.count { |row| row.first == 'delete' }
    # Private raw error retained only as bounded capture; no text/backtrace log.
    refute_includes JSON.generate(value), 'PRIVATE_PROVIDER_ERROR'
  end
  def test_failed_list_auth_redirect_or_unknown_pagination_only_attempts_cleanup
    [401, 403, 302, 500].each do |status|
      setup; Fake.statuses['tracks'] = status
      value = run_query
      assert_equal %w[token insert tracks delete], Fake.wire.map(&:first)
      refute value['queryFinished']
      assert value['temporaryEdit']['deleteConfirmed']
      assert_equal 1, Fake.auths
    end
    setup; Fake.chunks['tracks'] = ['{"tracks":[],"nextPageToken":"another"}']
    assert_equal false, run_query['queryFinished']
    assert_equal %w[token insert tracks delete], Fake.wire.map(&:first)
  end
  def test_expired_cleanup_does_not_create_new_grace_or_another_delete
    Fake.before_return = ->(step) { Fake.current = 62 if step == 'insert' }
    value = run_query
    assert_equal %w[token insert], Fake.wire.map(&:first)
    refute value['temporaryEdit']['deleteConfirmed']
    refute value['temporaryEdit']['deleteAttempted']
    assert_equal 'synthetic-edit-1', value['temporaryEdit']['editId']
    setup
    Fake.before_return = ->(step) { Fake.current = 62 if step == 'delete' }
    value = run_query
    assert value['temporaryEdit']['deleteConfirmed'] # Retain the actual returned fact.
    refute value['queryFinished'] # But late return is not usable inventory.
    assert_equal 1, Fake.wire.count { |row| row.first == 'delete' }
  end
  def test_original_snapshot_bounded_read_and_environment_only_no_adc
    Dir.mktmpdir('mrk-android-inventory-fixture-') do |directory|
      path = File.join(directory, 'service-account.json')
      raw = JSON.generate(type: 'service_account', project_id: 'fixture-project', private_key_id: 'a' * 40,
        private_key: "-----BEGIN PRIVATE KEY-----\nINERT_NOT_A_KEY\n-----END PRIVATE KEY-----\n",
        client_email: 'test@fixture-project.iam.gserviceaccount.com', client_id: '12345', token_uri: Read::TOKEN)
      File.write(path, raw); File.chmod(0o600, path)
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      environment = { 'GOOGLE_APPLICATION_CREDENTIALS' => path, 'MOBILE_RELEASE_PLAY_PACKAGE' => 'com.example.version',
        'MOBILE_RELEASE_PLAY_CONTEXT' => 'a' * 64, 'MOBILE_RELEASE_PLAY_READ_END_NS' => (now + 50 * Read::SECOND).to_s,
        'MOBILE_RELEASE_PLAY_HARD_END_NS' => (now + 60 * Read::SECOND).to_s }
      assert_instance_of Read::Input, Read::Input.new(environment)
      assert_raises(Read::Error) { Read::Input.new(environment.merge('https_proxy' => 'https://ignored.invalid')) }
      File.write(path, ' ' * (Read::SMALL_LIMIT + 1))
      assert_raises(Read::Error) { Read::Input.new(environment) }
    end
  end
end
