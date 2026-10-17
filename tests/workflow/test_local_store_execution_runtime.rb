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
end
