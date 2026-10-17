# frozen_string_literal: true
# Existing Runtime/Invocation local-admission and DATA tests only. Native exit,
# protected runtime admission and resource lookup are explicit inert boundaries;
# no Fastlane/Google/native child or credential use occurs in this test.
require 'minitest/autorun'
require 'minitest/mock'
require 'tmpdir'
require 'fileutils'
require_relative '../../fastlane/store_lane_runtime'
require_relative '../../fastlane/release_support'
require_relative '../../fastlane/android_upload_validation'
require_relative '../../fastlane/ios_upload_validation'
class LocalStoreExecutionRuntimeTest < Minitest::Test
  M=MobileReleaseKit
  R=M::StoreLaneRuntime
  L=M::StoreLaneLifetime
  KEY='MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE'
  def setup
    @env=ENV.to_h;@previous=R.instance_variable_get(:@runtime)
    @root=Dir.mktmpdir('mrk-execute-model-');@identity=File.stat(@root).then { |s| [s.dev,s.ino] }
    @raw=File.binread(File.expand_path('../fixtures/local-intent-candidate-valid.json',__dir__))
    @intent=JSON.parse(@raw);@digest=@intent.fetch('integrity').fetch('sha256')
    @authority=@intent.fetch('preparedBy').merge('purpose'=>'execute','authorizationId'=>'55555555-5555-4555-8555-555555555555','intentSha256'=>@digest)
    @path=File.join(@root,'intent.json');File.binwrite(@path,@raw)
    @tool={'schemaVersion'=>2,'profile'=>'android-registered-macos-arm64-v1','root'=>'/not-a-native-grant'}
    ENV.update('MOBILE_RELEASE_APP_ROOT'=>@root,'MOBILE_RELEASE_OPERATION_INTENT_PATH'=>@path,
      'MOBILE_RELEASE_CONFIRMATION'=>@intent.fetch('confirmation'),'MOBILE_RELEASE_APP_IDENTITY'=>@intent.fetch('application').fetch('id'),
      'MOBILE_RELEASE_MARKETING_VERSION'=>@intent.fetch('version').fetch('marketing'),
      'MOBILE_RELEASE_BUILD_NUMBER'=>@intent.fetch('version').fetch('build').to_s,
      KEY=>M.canonical_json({'authority'=>@authority,'expectedIntentSha256'=>@digest,'toolchain'=>@tool}))
    R.instance_variable_set(:@runtime,nil)
  end
  def teardown
    R.instance_variable_set(:@runtime,@previous);ENV.replace(@env)
    value=File.lstat(@root);assert value.directory? && !value.symlink? && [value.dev,value.ino]==@identity
    FileUtils.remove_entry(@root) # Exclusive test originals, no product owners.
  end
  def model(mode:'execute',lane:'android_internal_upload')
    boundary=R.const_get(:ExitBoundary,false).allocate
    boundary.instance_variable_set(:@pid,Process.pid);boundary.instance_variable_set(:@thread,Thread.current)
    runtime=R::Runtime.new(boundary)
    invocation=L::Invocation.new(lane:lane,nonce:'a'*16,output:File.join(@root,'receipt.json'),mode:mode,run_deadline_ns:60_000_000_000)
    binding={'lane'=>lane,'mode'=>mode,'run_deadline_ns'=>60_000_000_000}
    inventory=M::StoreLaneResources::Inventory.new(invocation:invocation,binding:binding)
    # No filesystem/native admission claim: model exactly that already-returned
    # boundary, while real identity matching and local admission remain active.
    inventory.instance_variable_set(:@admitted,true)
    invocation.bind_resources!(inventory)
    {:@state=>:admitting,:@environment=>ENV.to_h.freeze,:@binding=>binding,
     :@invocation=>invocation,:@resources=>inventory}.each { |name,value| runtime.instance_variable_set(name,value) }
    R.instance_variable_set(:@runtime,runtime)
    [runtime,invocation]
  end
  def admit(runtime)
    runtime.send(:admit_local_execution!)
    runtime.instance_variable_set(:@state,:running);runtime.instance_variable_set(:@bridges_installed,true)
  end
  def test_direct_environment_or_foreign_invocation_cannot_select_local_origin
    assert_raises(R::Error) { R.local_execution_context }
    ENV.delete(KEY);assert_nil R.local_execution_context
    runtime,invocation=model
    assert_raises(R::Error) { invocation.bind_local_execution!(runtime,{}) }
    assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::AndroidUploadValidation) }
  end
  def test_original_admission_freezes_full_context_and_inherited_nested_clock
    runtime,invocation=model;admit(runtime)
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      context=R.local_execution_context
      assert_equal @digest,context.fetch(:digest);assert_equal @authority,context.fetch(:authority)
      assert context.frozen?;assert context.fetch(:authority).frozen?
      assert_same context,invocation.instance_variable_get(:@local_execution)
      value=JSON.parse(invocation.local_current_validation_request(adapter:M::AndroidUploadValidation))
      assert_equal({'schemaVersion'=>1,'toolchain'=>@tool,'runDeadlineNs'=>'55000000000','hardDeadlineNs'=>'60000000000'},value)
      other=L::Invocation.new(lane:'android_internal_upload',nonce:'b'*16,output:File.join(@root,'other.json'),mode:'execute',run_deadline_ns:60_000_000_000)
      assert_raises(L::LifetimeError) { other.bind_local_execution!(runtime,context) }
      assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:Object.new) }
      assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    end
  end
  def test_cross_purpose_digest_duplicate_and_ordinary_lane_fail_before_body
    changes=[lambda { |v| v['authority']['purpose']='recover' },lambda { |v| v['expectedIntentSha256']='f'*64 },
      lambda { |v| v['authority']['assignment']['expectedRevision']=99 }]
    changes.each do |change|
      value=JSON.parse(ENV.fetch(KEY));change.call(value);original=ENV.fetch(KEY);ENV[KEY]=JSON.generate(value)
      runtime,_=model
      assert_raises(M::ContractError) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution);ENV[KEY]=original
    end
    original=ENV.fetch(KEY);ENV[KEY]='{"authority":{},'+original.delete_prefix('{')
    runtime,_=model;assert_raises(M::ContractError) { runtime.send(:admit_local_execution!) };ENV[KEY]=original
    [{mode:'prepare'},{lane:'android_external_promote'}].each do |arguments|
      runtime,_=model(**arguments);assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    end
  end
  def reconcile_transport
    ENV.delete(KEY)
    @authority=@authority.merge('purpose'=>'recover')
    ENV[R::LOCAL_RECONCILE_KEY]=M.canonical_json({'authority'=>@authority,'expectedIntentSha256'=>@digest})
  end
  def test_reconcile_admits_only_original_readback_transport_without_upload_tools
    reconcile_transport
    assert_raises(R::Error) { R.local_execution_context }
    runtime,invocation=model;admit(runtime)
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      context=R.local_execution_context
      assert_equal @authority,context.fetch(:authority)
      assert_equal [:authority,:digest,:payload],context.keys.sort
      assert_same context,invocation.instance_variable_get(:@local_execution)
      assert context.frozen?;assert context.fetch(:authority).frozen?
      assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::AndroidUploadValidation) }
      assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
      ENV[R::LOCAL_RECONCILE_KEY]+=' '
      assert_raises(R::Error) { R.local_execution_context }
      assert invocation.unknown?
    end
  end
  def test_reconcile_real_admission_env_gate_preserves_exact_private_roster
    reconcile_transport
    %w[NONCE ROOT ROOT_ID CLOCK RUN_DEADLINE_NS HARD_DEADLINE_NS].each { |name| ENV['MOBILE_RELEASE_STORE_LANE_'+name]='inert' }
    ENV['MOBILE_RELEASE_OPERATION']='android_internal_upload';ENV['MOBILE_RELEASE_STORE_MODE']='execute'
    # Actual admit! must pass its exact env gate, then deliberately refuse the
    # invalid nonce before any native/filesystem/runtime acquisition.
    runtime,_=model
    assert_equal :nonce,assert_raises(R::Error) { runtime.send(:admit!,'android_internal_upload') }.reason
    ENV[KEY]=ENV.fetch(R::LOCAL_RECONCILE_KEY)
    runtime,_=model
    assert_equal :environment,assert_raises(R::Error) { runtime.send(:admit!,'android_internal_upload') }.reason
    ENV.delete(KEY);ENV['MOBILE_RELEASE_STORE_LANE_FOREIGN']='inert'
    runtime,_=model
    assert_equal :environment,assert_raises(R::Error) { runtime.send(:admit!,'android_internal_upload') }.reason
  end
  def test_reconcile_transport_rejects_execute_purpose_hybrid_extra_and_mismatch
    reconcile_transport
    original=ENV.fetch(R::LOCAL_RECONCILE_KEY)
    changes=[lambda { |v| v['authority']['purpose']='execute' },lambda { |v| v['toolchain']=@tool },
      lambda { |v| v['expectedIntentSha256']='f'*64 },lambda { |v| v['authority']['assignment']['expectedRevision']=99 }]
    changes.each do |change|
      value=JSON.parse(original);change.call(value);ENV[R::LOCAL_RECONCILE_KEY]=M.canonical_json(value)
      runtime,_=model
      assert_raises(R::Error,M::ContractError) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution)
    end
    ENV[R::LOCAL_RECONCILE_KEY]=original;ENV[KEY]=original
    runtime,_=model;assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    assert_nil runtime.instance_variable_get(:@local_execution)
    ENV.delete(KEY)
    [{mode:'prepare'},{lane:'android_external_promote'}].each do |arguments|
      runtime,_=model(**arguments);assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    end
  end
  def test_changed_transport_or_original_thread_refuses_and_latches_unknown
    runtime,invocation=model;admit(runtime)
    ENV[KEY]+=' '
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      assert_raises(R::Error) { R.local_execution_context }
      assert invocation.unknown?
    end
    runtime,invocation=model;admit(runtime)
    runtime.instance_variable_set(:@pid,Process.pid+1)
    assert_raises(R::Error) { invocation.local_current_validation_request(adapter:M::AndroidUploadValidation) }
  end
  def ios_transport
    @raw=File.binread(File.expand_path('../fixtures/local-intent-ios-candidate-valid.json',__dir__))
    @intent=JSON.parse(@raw);@digest=@intent.fetch('integrity').fetch('sha256');File.binwrite(@path,@raw)
    @authority=@intent.fetch('preparedBy').merge('purpose'=>'execute','authorizationId'=>'55555555-5555-4555-8555-555555555555','intentSha256'=>@digest)
    tool={'device'=>'1','inode'=>'2','mode'=>0100555,'uid'=>0,'gid'=>0,'links'=>1,'size'=>100,'mtimeNs'=>'3','ctimeNs'=>'4'}
    @tool=%w[security codesign openssl].to_h { |name| [name,tool.dup] }
    ENV.update('MOBILE_RELEASE_CONFIRMATION'=>@intent.fetch('confirmation'),
      'MOBILE_RELEASE_ASC_APP_ID'=>@intent.fetch('application').fetch('storeAppId'),
      KEY=>M.canonical_json({'authority'=>@authority,'expectedIntentSha256'=>@digest,'signingTools'=>@tool}))
  end
  def test_ios_original_runtime_only_getter_platform_and_absolute_nested_tuple
    ios_transport;runtime,invocation=model(lane:'ios_testflight_internal');admit(runtime)
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      value=JSON.parse(invocation.local_current_validation_request(adapter:M::IosUploadValidation))
      assert_equal({'schemaVersion'=>1,'signingTools'=>@tool,'runDeadlineNs'=>'55000000000','hardDeadlineNs'=>'60000000000'},value)
      assert_equal @tool,R.local_execution_context.fetch(:signing_tools)
      assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::AndroidUploadValidation) }
      ENV['MOBILE_RELEASE_ASC_APP_ID']='1'
      assert_raises(R::Error) { R.local_execution_context }
      assert invocation.unknown?
    end
  end
  def test_ios_shape_mode_recover_and_tool_mismatch_refuse_original_admission
    ios_transport;original=ENV.fetch(KEY)
    changes=[->(v) {v['toolchain']=v.delete('signingTools')},->(v) {v['signingTools']['security']['uid']=501},
      ->(v) {v['signingTools']['codesign']['inode']='01'},->(v) {v['signingTools']['openssl']['mode']=0100777},
      ->(v) {v['authority']['purpose']='recover'}]
    changes.each do |change|
      value=JSON.parse(original);change.call(value);ENV[KEY]=M.canonical_json(value)
      runtime,_=model(lane:'ios_testflight_internal')
      assert_raises(R::Error,M::ContractError) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution)
    end
    ENV[KEY]=original
    runtime,_=model(lane:'ios_testflight_internal',mode:'prepare')
    assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    ENV[R::LOCAL_RECONCILE_KEY]=ENV.delete(KEY)
    runtime,_=model(lane:'ios_testflight_internal')
    assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
  end
  def test_ios_local_adapter_actual_reservation_binds_same_tuple_and_one_slot
    ios_transport;runtime,invocation=model(lane:'ios_testflight_internal');admit(runtime)
    seen=[]
    # Deliberate stop immediately AFTER original reservation: no native process,
    # no result/retirement fabricated. The retained slot proves actual dispatch.
    stop=Class.new(StandardError)
    capture=lambda do |env,argv,root,store_binding:|
      seen << [env,argv,root,store_binding]
      raise stop
    end
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      L.stub(:current_invocation,invocation) do
        M::NativeUploadValidation.stub(:module_origin!,'/repo/src') do
          M::IosUploadValidation.stub(:capture_validator,capture) do
            assert_raises(stop) { M::IosUploadValidation.current_local!(python:'/usr/bin/python3',module_root:'/repo/src',app_root:@root,
              config_path:@path,intent_path:@path,ipa_path:@path,intent_sha256:@digest,environment:{'HOME'=>@root,'ASC_SECRET'=>'never forwarded'},tooling_directory:@root) }
          end
        end
      end
      assert_equal 1,seen.length
      assert_same invocation.instance_variable_get(:@nested),seen[0][3]
      assert_equal '--local-operation-intent',seen[0][1][10]
      assert_equal ['--local-registered-tools-json',M.canonical_json({'schemaVersion'=>1,'signingTools'=>@tool,'runDeadlineNs'=>'55000000000','hardDeadlineNs'=>'60000000000'})],seen[0][1][-2,2]
      refute seen[0][0].key?('ASC_SECRET')
      assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::IosUploadValidation) }
    end
  end

end
