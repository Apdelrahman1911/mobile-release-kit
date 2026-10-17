# frozen_string_literal: true
# Shared inert entry boundary only. The real Runtime local decoder, original
# Invocation, borrowed metadata FileSlots and independent closes remain active.
# No native/credential/process qualification is inferred from this fixture.
require_relative '../../fastlane/store_lane_runtime'
require_relative '../../fastlane/release_support'
module LocalStageRuntimeFixture
  def stage_metadata_copy(source, parent: @root)
    tree=File.join(parent,'metadata-tree');FileUtils.cp_r(source,tree)
    ([tree]+Dir.glob(File.join(tree,'**','*'),File::FNM_DOTMATCH)).each do |path|
      next if ['.','..'].include?(File.basename(path))
      File.chmod(File.directory?(path) ? 0700 : 0444,path)
    end
    tree
  end
  def with_original_stage_runtime(stage:,tree:,mode:,output:,intent:nil)
    m=MobileReleaseKit;r=m::StoreLaneRuntime;l=m::StoreLaneLifetime
    old_runtime=r.instance_variable_get(:@runtime);old_invocation=l.instance_variable_get(:@invocation)
    keys=[r::LOCAL_STAGE_KEY,r::LOCAL_EXECUTE_KEY,r::LOCAL_RECONCILE_KEY]
    old_keys=keys.to_h { |key| [key,ENV[key]] };keys.each { |key| ENV.delete(key) }
    stat=File.stat(tree)
    metadata={'schemaVersion'=>1,'root'=>tree,'rootIdentity'=>{'device'=>stat.dev.to_s,'inode'=>stat.ino.to_s,
      'mode'=>stat.mode,'uid'=>stat.uid,'gid'=>stat.gid},'metadataSha256'=>intent ? intent.fetch('configuration').fetch('metadataSha256') : 'a'*64,'rosterSha256'=>'b'*64}
    lane=m.local_stage_lane('ios',stage)
    ENV.update('MOBILE_RELEASE_OPERATION'=>lane,'MOBILE_RELEASE_STORE_MODE'=>mode,'MOBILE_RELEASE_STORE_RECEIPT_PATH'=>output)
    if intent
      digest=intent.fetch('integrity').fetch('sha256')
      authority=intent.fetch('preparedBy').merge('purpose'=>'execute','authorizationId'=>'55555555-5555-4555-8555-555555555555','intentSha256'=>digest)
      ENV.update('MOBILE_RELEASE_CONFIRMATION'=>intent.fetch('confirmation'),'MOBILE_RELEASE_APP_IDENTITY'=>intent.fetch('application').fetch('id'),
        'MOBILE_RELEASE_ASC_APP_ID'=>intent.fetch('application').fetch('storeAppId'),'MOBILE_RELEASE_MARKETING_VERSION'=>intent.fetch('version').fetch('marketing'),
        'MOBILE_RELEASE_BUILD_NUMBER'=>intent.fetch('version').fetch('build').to_s,
        r::LOCAL_EXECUTE_KEY=>m.canonical_json({'authority'=>authority,'expectedIntentSha256'=>digest,'metadataInputs'=>metadata}))
    else
      ENV[r::LOCAL_STAGE_KEY]=m.canonical_json({'stage'=>stage,'platform'=>'ios','metadataInputs'=>metadata})
    end
    boundary=r.const_get(:ExitBoundary,false).allocate
    boundary.instance_variable_set(:@pid,Process.pid);boundary.instance_variable_set(:@thread,Thread.current)
    runtime=r::Runtime.new(boundary)
    invocation=l::Invocation.new(lane:lane,nonce:'a'*16,output:File.expand_path(output,@root),mode:mode,run_deadline_ns:60_000_000_000)
    binding={'lane'=>lane,'mode'=>mode,'run_deadline_ns'=>60_000_000_000}
    inventory=m::StoreLaneResources::Inventory.new(invocation:invocation,binding:binding)
    inventory.instance_variable_set(:@admitted,true) # native/root admission modeled, never executed
    invocation.bind_resources!(inventory)
    {:@state=>:admitting,:@environment=>ENV.to_h.freeze,:@binding=>binding,:@invocation=>invocation,:@resources=>inventory}.each { |k,v| runtime.instance_variable_set(k,v) }
    r.instance_variable_set(:@runtime,runtime);l.instance_variable_set(:@invocation,invocation)
    m::NativeProcessSpawn.stub(:monotonic_ns,1) do
      begin
        runtime.send(intent ? :admit_local_execution! : :admit_local_stage_prepare!)
        runtime.instance_variable_set(:@state,:running);runtime.instance_variable_set(:@bridges_installed,true)
        yield runtime
        invocation.seal_uploads!;inventory.finish!
      ensure
        inventory.close_independent!
        assert inventory.instance_variable_get(:@handles).all? { |slot| !slot.open? },'fixture cannot retire live borrowed originals'
      end
    end
  ensure
    r.instance_variable_set(:@runtime,old_runtime);l.instance_variable_set(:@invocation,old_invocation)
    old_keys&.each { |key,value| value ? ENV[key]=value : ENV.delete(key) }
  end
  def stage_intent_for_fixture(stage,precondition)
    path=File.expand_path("../fixtures/local-ios-#{stage}-intent.json",__dir__)
    value=JSON.parse(File.binread(path));value.delete('integrity')
    value['application']={'id'=>'test.example.release','storeAppId'=>'12345'}
    value['version']={'marketing'=>'1.2.3','build'=>123};value['storePrecondition']=precondition
    value['privateStateCommitments']=precondition.fetch('snapshot').fetch('privateStateCommitments')
    value['confirmation']="#{stage}:ios:1.2.3:123"
    value['preparedBy']['confirmationSha256']=Digest::SHA256.hexdigest(value.fetch('confirmation'))
    digest=Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(value))
    value['integrity']={'algorithm'=>'sha256','sha256'=>digest}
    MobileReleaseKit.local_operation_intent(MobileReleaseKit.canonical_json(value),expected_sha256:digest,platform:'ios',stage:stage)
    value
  end
end
