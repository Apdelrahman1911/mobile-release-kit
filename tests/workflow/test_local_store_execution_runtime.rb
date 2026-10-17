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
require_relative '../../fastlane/apple_create_retry'
require_relative 'local_stage_runtime_fixture'
class LocalStoreExecutionRuntimeTest < Minitest::Test
  include LocalStageRuntimeFixture
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


  def test_ios_transport_nomination_is_exact_and_bound_before_original_admission
    ios_transport
    tool=@tool.fetch('security')
    root=tool.slice('device','inode','mode','uid','gid').merge('mode'=>0040755)
    selection={'schemaVersion'=>1,'developerDirectory'=>'/Applications/Xcode_26.app/Contents/Developer',
      'appIdentity'=>root,'developerIdentity'=>root,'xcrun'=>tool}
    transport={'selection'=>selection,'altoolPath'=>'/Applications/Xcode_26.app/Contents/SharedFrameworks/Delivery/Support/altool','altoolIdentity'=>tool}
    ENV['DEVELOPER_DIR']=selection.fetch('developerDirectory')
    ENV['MOBILE_RELEASE_ASC_KEY_ID']='KEY123'
    ENV['MOBILE_RELEASE_ASC_ISSUER_ID']='11111111-1111-4111-8111-111111111111'
    ENV['MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64']=Base64.strict_encode64('inert original PEM bytes')
    value=JSON.parse(ENV.fetch(KEY));value['transportTools']=transport;ENV[KEY]=M.canonical_json(value)
    runtime,invocation=model(lane:'ios_testflight_internal');seen=[]
    # Only protected original acquisition is inert here. The actual Runtime
    # context/shape/environment gate and original identity handoff are exercised.
    runtime.resources.stub(:bind_local_transport!,->(c) { seen << c }) { admit(runtime) }
    assert_same runtime.instance_variable_get(:@local_execution),seen.fetch(0)
    assert_equal transport,seen[0].fetch(:transport_tools)
    assert invocation.local_ios_context?(seen[0]);refute invocation.local_ios_context?(seen[0].dup)
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      runtime.resources.stub(:check_local_transport!,true) do
        key={key_id:'KEY123',issuer_id:ENV.fetch('MOBILE_RELEASE_ASC_ISSUER_ID'),key:'inert original PEM bytes'}
        assert_same key,runtime.local_ios_key!(key)
        [:key_id,:issuer_id,:key].each do |field|
          assert_raises(R::Error) { runtime.local_ios_key!(key.merge(field=>'foreign value')) }
        end
      end
      assert_equal @tool,JSON.parse(invocation.local_current_validation_request(adapter:M::IosUploadValidation)).fetch('signingTools')
      ENV['DEVELOPER_DIR']='/Applications/Xcode_Other.app/Contents/Developer'
      assert_raises(R::Error) { runtime.local_execution_context }
    end
    ENV['DEVELOPER_DIR']=selection.fetch('developerDirectory')
    shim=JSON.parse(M.canonical_json(value))
    shim['transportTools']['altoolPath']=transport.fetch('altoolPath')+'Shim'
    ENV[KEY]=M.canonical_json(shim)
    shim_runtime,shim_invocation=model(lane:'ios_testflight_internal');shim_seen=[]
    shim_runtime.resources.stub(:bind_local_transport!,->(c) { shim_seen << c }) { admit(shim_runtime) }
    assert_equal shim.fetch('transportTools'),shim_seen.fetch(0).fetch(:transport_tools)
    assert shim_invocation.local_ios_context?(shim_seen.fetch(0))
    [->(v){v['transportTools']['selection']['xcrun']['uid']=501},
     ->(v){v['transportTools']['selection']['appIdentity']['mode']=0040777},
     ->(v){v['transportTools']['altoolPath']='/tmp/altool'},
     ->(v){v['transportTools']['altoolPath']+='ShimUnexpected'},
     ->(v){v['transportTools']['altoolPath']+='shim'},
     ->(v){v['transportTools']['altoolPath']+='Shim/../altool'},
     ->(v){v['transportTools']['altoolPath']='/Applications/Xcode_26.app/Contents/../altool'},
     ->(v){v['transportTools']['extra']=true}].each do |mutate|
      bad=JSON.parse(M.canonical_json(value));mutate.call(bad);ENV[KEY]=M.canonical_json(bad)
      rt,_=model(lane:'ios_testflight_internal');rt.resources.stub(:bind_local_transport!,->(*) { flunk 'invalid tuple reached original opens' }) do
        assert_raises(R::Error) { rt.send(:admit_local_execution!) }
      end
    end
    ENV[KEY]=M.canonical_json(value);ENV['DELIVER_ALTOOL_ADDITIONAL_UPLOAD_PARAMETERS']='--anything'
    rt,_=model(lane:'ios_testflight_internal');assert_raises(R::Error) { rt.send(:admit_local_execution!) }
  end

  def test_ios_reconcile_original_admission_is_readonly_and_requires_exact_app
    ios_transport;reconcile_transport
    runtime,invocation=model(lane:'ios_testflight_internal');admit(runtime)
    M::NativeProcessSpawn.stub(:monotonic_ns,1) do
      context=R.local_execution_context
      assert_equal [:authority,:digest,:payload],context.keys.sort
      assert_equal 'recover',context.fetch(:authority).fetch('purpose')
      assert_equal 'ios',context.fetch(:payload).fetch('platform')
      assert_same context,invocation.instance_variable_get(:@local_execution)
      [M::IosUploadValidation,M::AndroidUploadValidation].each do |adapter|
        assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:adapter) }
      end
      assert_raises(R::Error) { runtime.local_ios_transport! }
      ENV['MOBILE_RELEASE_ASC_APP_ID']='foreign'
      assert_raises(R::Error) { R.local_execution_context }
      assert invocation.unknown?
    end
    # Re-enter a fresh inert original: app mismatch is also refused at admission,
    # before a current context or any protected tool acquisition is published.
    runtime,_=model(lane:'ios_testflight_internal')
    assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
    assert_nil runtime.instance_variable_get(:@local_execution)
  end
  def test_ios_reconcile_actual_initial_env_gate_and_closed_transport
    ios_transport;reconcile_transport
    %w[NONCE ROOT ROOT_ID CLOCK RUN_DEADLINE_NS HARD_DEADLINE_NS].each { |name| ENV['MOBILE_RELEASE_STORE_LANE_'+name]='inert' }
    ENV['MOBILE_RELEASE_OPERATION']='ios_testflight_internal';ENV['MOBILE_RELEASE_STORE_MODE']='execute'
    runtime,_=model(lane:'ios_testflight_internal')
    assert_equal :nonce,assert_raises(R::Error) { runtime.send(:admit!,'ios_testflight_internal') }.reason
    original=ENV.fetch(R::LOCAL_RECONCILE_KEY)
    ENV[KEY]=original;runtime,_=model(lane:'ios_testflight_internal')
    assert_equal :environment,assert_raises(R::Error) { runtime.send(:admit!,'ios_testflight_internal') }.reason
    ENV.delete(KEY)
    [->(v){v['signingTools']=@tool},->(v){v['transportTools']={}},->(v){v['toolchain']={}},
     ->(v){v['authority']['purpose']='execute'},->(v){v['expectedIntentSha256']='f'*64}].each do |change|
      value=JSON.parse(original);change.call(value);ENV[R::LOCAL_RECONCILE_KEY]=M.canonical_json(value)
      runtime,_=model(lane:'ios_testflight_internal')
      assert_raises(R::Error,M::ContractError) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution)
    end
  end

  def stage_metadata
    @stage_case=(@stage_case||0)+1
    parent=File.join(@root,"metadata-#{@stage_case}");Dir.mkdir(parent,0700)
    tree=File.join(parent,"metadata-tree");Dir.mkdir(tree,0700)
    %w[android ios testflight review].each { |name| Dir.mkdir(File.join(tree,name),0700) }
    File.write(File.join(tree,'testflight','what-to-test.txt'),'original snapshot only')
    File.chmod(0444,File.join(tree,'testflight','what-to-test.txt'))
    value=File.stat(tree)
    {'schemaVersion'=>1,'root'=>tree,'rootIdentity'=>{'device'=>value.dev.to_s,'inode'=>value.ino.to_s,
      'mode'=>value.mode,'uid'=>value.uid,'gid'=>value.gid},'metadataSha256'=>'a'*64,'rosterSha256'=>'b'*64}
  end
  def stage_prepare(platform,stage,metadata)
    ENV.delete(KEY);ENV.delete(R::LOCAL_RECONCILE_KEY)
    ENV[R::LOCAL_STAGE_KEY]=M.canonical_json({'stage'=>stage,'platform'=>platform,'metadataInputs'=>metadata})
    runtime,invocation=model(mode:'prepare',lane:M.local_stage_lane(platform,stage))
    M::NativeProcessSpawn.stub(:monotonic_ns,1) { runtime.send(:admit_local_stage_prepare!) }
    runtime.instance_variable_set(:@state,:running);runtime.instance_variable_set(:@bridges_installed,true)
    [runtime,invocation]
  end
  def close_metadata(runtime)
    slots=runtime.resources.instance_variable_get(:@handles)
    runtime.resources.close_independent!
    assert slots.all? { |slot| !slot.open? },'test originals must actually close before fixture removal'
  end
  def test_later_prepare_has_no_execute_authority_and_borrows_actual_snapshot_originals
    %w[android ios].product(%w[external-testing production-submit]).each do |platform,stage|
      data=stage_metadata;runtime=nil
      begin
        runtime,invocation=stage_prepare(platform,stage,data)
        M::NativeProcessSpawn.stub(:monotonic_ns,1) do
          assert_nil R.local_execution_context
          context=R.local_stage_context
          assert_equal [:metadata,:platform,:stage],context.keys.sort
          assert_same context,invocation.instance_variable_get(:@local_stage)
          assert_equal data['root'],runtime.local_metadata_root!
          assert_equal 'original snapshot only',File.read(File.join(runtime.local_metadata_root!,'testflight','what-to-test.txt'))
          assert_raises(R::Error) { runtime.local_stage_execution_context!(stage) }
          assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::IosUploadValidation) }
        end
      ensure
        close_metadata(runtime) if runtime
      end
      assert File.directory?(data['root']),'borrower must never delete Python-owned metadata'
    end
    data=stage_metadata
    with_original_stage_runtime(stage:'external-testing',tree:data['root'],mode:'prepare',output:'shared-fixture.json') do |runtime|
      assert_equal data['root'],runtime.local_metadata_root!
      assert_same runtime.invocation,L.current_invocation
    end
  end
  def test_later_metadata_swap_quote_and_unknown_close_do_not_become_current_snapshot
    [:swap,:quote,:close].each do |fault|
      data=stage_metadata;runtime=nil
      begin
        runtime,invocation=stage_prepare('ios','external-testing',data)
        slots=runtime.resources.instance_variable_get(:@handles)
        if fault==:swap
          File.rename(data['root'],data['root']+'-original');Dir.mkdir(data['root'],0700)
          M::NativeProcessSpawn.stub(:monotonic_ns,1) do
            assert_raises(M::StoreLaneResources::Error) { runtime.local_metadata_root! }
          end
          assert invocation.unknown?
        elsif fault==:quote
          # A distinct admitted original attempts a too-large pre-open reserve.
          close_metadata(runtime)
          runtime,invocation=model(mode:'prepare',lane:'ios_testflight_external')
          handles=runtime.resources.instance_variable_get(:@handles)
          256.times { handles << M::StoreLaneResources::FileSlot.new }
          M::NativeProcessSpawn.stub(:monotonic_ns,1) do
            error=assert_raises(M::StoreLaneResources::Error) { runtime.send(:admit_local_stage_prepare!) }
            assert_equal :local_metadata_quote,error.reason
          end
          assert handles.none?(&:open?),'overflow must refuse before any metadata open'
        else
          io=slots.last.io;original=io.method(:close);calls=0
          io.define_singleton_method(:close) { calls+=1;original.call;raise IOError,'fixed original close return loss' }
          close_metadata(runtime)
          assert_equal 1,calls;assert invocation.unknown?
          M::NativeProcessSpawn.stub(:monotonic_ns,1) { assert_raises(L::LifetimeError) { runtime.local_metadata_root! } }
        end
      ensure
        close_metadata(runtime) if runtime
      end
    end
  end
  def test_later_prepare_wrong_lane_hybrid_and_changed_supplemental_input_refuse
    data=stage_metadata
    value={'stage'=>'external-testing','platform'=>'ios','metadataInputs'=>data}
    ENV.delete(KEY);ENV[R::LOCAL_STAGE_KEY]=M.canonical_json(value)
    [:candidate,:execute,:wrong_platform,:extra,:identity].each do |fault|
      runtime,=model(mode:fault==:execute ? 'execute' : 'prepare',lane:fault==:candidate ? 'ios_testflight_internal' : 'ios_testflight_external')
      bad=Marshal.load(Marshal.dump(value))
      bad['platform']='android' if fault==:wrong_platform
      bad['authority']={} if fault==:extra
      bad['metadataInputs']['rootIdentity']['inode']='1' if fault==:identity
      runtime.instance_variable_set(:@environment,ENV.to_h.merge(R::LOCAL_STAGE_KEY=>M.canonical_json(bad)).freeze)
      begin
        M::NativeProcessSpawn.stub(:monotonic_ns,1) { assert_raises(R::Error,M::StoreLaneResources::Error) { runtime.send(:admit_local_stage_prepare!) } }
      ensure
        close_metadata(runtime)
      end
    end
    ENV[R::LOCAL_STAGE_KEY]=M.canonical_json(value)
    runtime=nil
    begin
      runtime,invocation=stage_prepare('ios','external-testing',data)
      ENV['MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD']='changed original field'
      M::NativeProcessSpawn.stub(:monotonic_ns,1) { assert_raises(R::Error) { runtime.local_metadata_root! } }
      assert invocation.unknown?
    ensure
      close_metadata(runtime) if runtime
    end
    ENV[KEY]='{}'
    %w[NONCE ROOT ROOT_ID CLOCK RUN_DEADLINE_NS HARD_DEADLINE_NS].each { |name| ENV['MOBILE_RELEASE_STORE_LANE_'+name]='inert' }
    ENV['MOBILE_RELEASE_OPERATION']='ios_testflight_external';ENV['MOBILE_RELEASE_STORE_MODE']='prepare'
    runtime,=model(mode:'prepare',lane:'ios_testflight_external')
    assert_equal :environment,assert_raises(R::Error) { runtime.send(:admit!,'ios_testflight_external') }.reason
  end

  def stage_execute(platform,stage)
    prefix=File.expand_path("../fixtures/local-#{platform}-#{stage}",__dir__)
    raw=File.binread(prefix+'-intent.json');intent=JSON.parse(raw)
    authority=JSON.parse(File.binread(prefix+'-authority.json'));digest=intent.fetch('integrity').fetch('sha256')
    data=stage_metadata;data['metadataSha256']=intent.fetch('configuration').fetch('metadataSha256')
    File.binwrite(@path,raw);ENV.delete(R::LOCAL_STAGE_KEY);ENV.delete(R::LOCAL_RECONCILE_KEY)
    ENV.update('MOBILE_RELEASE_CONFIRMATION'=>intent.fetch('confirmation'),
      'MOBILE_RELEASE_APP_IDENTITY'=>intent.fetch('application').fetch('id'),
      'MOBILE_RELEASE_MARKETING_VERSION'=>intent.fetch('version').fetch('marketing'),
      'MOBILE_RELEASE_BUILD_NUMBER'=>intent.fetch('version').fetch('build').to_s,
      KEY=>M.canonical_json({'authority'=>authority,'expectedIntentSha256'=>digest,'metadataInputs'=>data}))
    ENV['MOBILE_RELEASE_ASC_APP_ID']=intent.fetch('application').fetch('storeAppId') if platform=='ios'
    runtime,invocation=model(lane:M.local_stage_lane(platform,stage))
    M::NativeProcessSpawn.stub(:monotonic_ns,1) { admit(runtime) }
    [runtime,invocation,intent]
  end
  def test_later_execute_four_lanes_bind_original_metadata_and_never_current_upload_tools
    %w[android ios].product(%w[external-testing production-submit]).each do |platform,stage|
      runtime=nil
      begin
        runtime,invocation,intent=stage_execute(platform,stage)
        M::NativeProcessSpawn.stub(:monotonic_ns,1) do
          context=R.local_execution_context
          assert_same context,R.local_stage_context
          assert_same context,runtime.local_stage_execution_context!(stage)
          assert_equal intent.fetch('candidateOperationId'),context.fetch(:payload).fetch('candidateOperationId')
          assert_equal [:authority,:digest,:metadata,:payload,:platform,:stage],context.keys.sort
          assert_equal 'original snapshot only',File.read(File.join(runtime.local_metadata_root!,'testflight','what-to-test.txt'))
          assert_raises(R::Error) { runtime.local_ios_transport! }
          assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::IosUploadValidation) }
          assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::AndroidUploadValidation) }
        end
      ensure
        close_metadata(runtime) if runtime
      end
    end
    data=stage_metadata;intent=JSON.parse(File.binread(@path))
    with_original_stage_runtime(stage:'production-submit',tree:data['root'],mode:'execute',output:'shared-stage-receipt.json',intent:intent) do |runtime|
      assert_equal intent.fetch('integrity').fetch('sha256'),runtime.local_stage_execution_context!('production-submit').fetch(:digest)
      assert_same runtime.invocation,L.current_invocation
    end
  end
  def test_local_apple_original_guard_claims_once_and_cannot_retry_or_borrow_foreign_runtime
    %w[external-testing production-submit].each do |stage|
      runtime=nil
      begin
        runtime,invocation,intent=stage_execute('ios',stage);journal=[]
        M::NativeProcessSpawn.stub(:monotonic_ns,1) do
          args={runtime:runtime,stage:stage,build_id:intent.dig('storePrecondition','snapshot','build','id'),
            journal:->(phase,data) { journal << [phase,data] }}
          assert_raises(M::AppleCreateRetry::Denied) { M::AppleCreateRetry.local_first_send(**args.merge(build_id:'foreign-build')) }
          guard=M::AppleCreateRetry.local_first_send(**args)
          assert_raises(L::LifetimeError) { M::AppleCreateRetry.local_first_send(**args) }
          type='betaBuildLocalizations';locator={'locale'=>'en-US'};parent=guard.present('builds',args.fetch(:build_id))
          node=guard.node(type,locator:locator,parent:parent,target:{'whatsNew'=>'retained original'})
          assert_raises(M::AppleCreateRetry::Denied) { guard.arm!(public_state:{},nodes:[node],resuming:true) }
          assert_empty journal
          guard.arm!(public_state:{},nodes:[node],resuming:false)
          assert_equal 'execution-claimed',journal.first[0]
          assert_raises(M::AppleCreateRetry::Denied) { guard.consume!(type,locator:locator,parent_id:'foreign-parent') }
          guard.consume!(type,locator:locator,parent_id:args.fetch(:build_id))
          assert_equal 'create-dispatched',journal.last[0]
          assert_raises(M::AppleCreateRetry::Denied) { guard.consume!(type,locator:locator,parent_id:args.fetch(:build_id)) }
          guard.observe!(type,locator:locator,id:'created-1');assert_nil guard.retry_evidence
          R.instance_variable_set(:@runtime,nil)
          assert_raises(R::Error) { guard.retry_evidence }
          R.instance_variable_set(:@runtime,runtime)
          ENV['MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION']='changed original revision '+stage
          assert_raises(R::Error) { guard.retry_evidence };assert invocation.unknown?
        end
      ensure
        R.instance_variable_set(:@runtime,runtime) if runtime
        close_metadata(runtime) if runtime
      end
    end
  end

  def readiness_transport
    previous,_,intent=stage_execute('ios','external-testing');close_metadata(previous)
    value=JSON.parse(ENV.delete(KEY));value['executionReceiptSha256']='9'*64
    value['authority'].merge!('purpose'=>'external-readiness','executionReceiptSha256'=>'9'*64)
    ENV[R::LOCAL_READINESS_KEY]=M.canonical_json(value)
    intent
  end
  def test_readiness_same_runtime_metadata_and_fresh_authority_never_grant_mutation
    intent=readiness_transport;runtime=nil
    begin
      runtime,invocation=model(lane:'ios_testflight_external')
      M::NativeProcessSpawn.stub(:monotonic_ns,1) do
        admit(runtime);context=R.local_readiness_context
        assert_same context,R.local_stage_context
        assert_same context,invocation.instance_variable_get(:@local_execution)
        assert_equal '9'*64,context.fetch(:execution_receipt_sha256)
        assert_equal 'external-readiness',context.fetch(:authority).fetch('purpose')
        assert_equal 'original snapshot only',File.read(File.join(runtime.local_metadata_root!,'testflight','what-to-test.txt'))
        assert_raises(R::Error) { runtime.local_stage_execution_context!('external-testing') }
        assert_raises(R::Error) { runtime.local_ios_transport! }
        assert_raises(L::LifetimeError) { invocation.local_current_validation_request(adapter:M::IosUploadValidation) }
        assert_raises(R::Error) { M::AppleCreateRetry.local_first_send(runtime:runtime,stage:'external-testing',
          build_id:intent.dig('storePrecondition','snapshot','build','id'),journal:->(*) { flunk 'no create journal' }) }
        ENV['MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME']='changed original'
        assert_raises(R::Error) { R.local_readiness_context };assert invocation.unknown?
      end
    ensure
      close_metadata(runtime) if runtime
    end
  end
  def test_readiness_initial_prefix_and_transport_refuse_hybrid_foreign_or_upload_grants
    readiness_transport;original=ENV.fetch(R::LOCAL_READINESS_KEY)
    %w[NONCE ROOT ROOT_ID CLOCK RUN_DEADLINE_NS HARD_DEADLINE_NS].each { |n| ENV['MOBILE_RELEASE_STORE_LANE_'+n]='inert' }
    ENV['MOBILE_RELEASE_OPERATION']='ios_testflight_external';ENV['MOBILE_RELEASE_STORE_MODE']='execute'
    runtime,=model(lane:'ios_testflight_external')
    assert_equal :nonce,assert_raises(R::Error) { runtime.send(:admit!,'ios_testflight_external') }.reason
    [KEY,R::LOCAL_RECONCILE_KEY,R::LOCAL_STAGE_KEY,'MOBILE_RELEASE_STORE_LANE_UNKNOWN'].each do |key|
      ENV[key]='{}';runtime,=model(lane:'ios_testflight_external')
      assert_equal :environment,assert_raises(R::Error) { runtime.send(:admit!,'ios_testflight_external') }.reason
      ENV.delete(key)
    end
    [->(v){v['toolchain']={}},->(v){v['signingTools']={}},->(v){v['transportTools']={}},
     ->(v){v['authority']['purpose']='execute'},->(v){v['executionReceiptSha256']='8'*64}].each do |change|
      value=JSON.parse(original);change.call(value);ENV[R::LOCAL_READINESS_KEY]=M.canonical_json(value)
      runtime,=model(lane:'ios_testflight_external')
      assert_raises(R::Error,M::ContractError) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution)
    end
    ENV[R::LOCAL_READINESS_KEY]=original
    ['ios_testflight_internal','ios_app_store_submit','android_external_promote'].each do |lane|
      runtime,=model(lane:lane)
      assert_raises(R::Error) { runtime.send(:admit_local_execution!) }
      assert_nil runtime.instance_variable_get(:@local_execution)
    end
    R.instance_variable_set(:@runtime,nil)
    assert_raises(R::Error) { R.local_readiness_context }
  end
  def test_readiness_original_metadata_close_loss_remains_unknown_without_publication
    readiness_transport;runtime=nil
    begin
      runtime,invocation=model(lane:'ios_testflight_external')
      M::NativeProcessSpawn.stub(:monotonic_ns,1) do
        admit(runtime);runtime.local_metadata_root!
        io=runtime.resources.instance_variable_get(:@handles).last.io;original=io.method(:close);calls=0
        io.define_singleton_method(:close) { calls+=1;original.call;raise IOError,'fixed close return loss' }
        close_metadata(runtime);assert_equal 1,calls;assert invocation.unknown?
        assert_raises(L::LifetimeError) { R.local_readiness_context }
        refute File.exist?(File.join(@root,'receipt.json'))
      end
    ensure
      close_metadata(runtime) if runtime
    end
  end

end
