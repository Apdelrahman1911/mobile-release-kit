# frozen_string_literal: true
# Inert public contract DATA, never native/Store permission or original custody.
require "minitest/autorun"
require "tmpdir"
require_relative "../../fastlane/release_support"

class LocalStoreIntentContractTest < Minitest::Test
  M = MobileReleaseKit
  ROOT = File.expand_path("../fixtures", __dir__)
  def setup
    @raw = File.binread(File.join(ROOT, "local-intent-candidate-valid.json"))
    @intent = JSON.parse(@raw)
    @digest = @intent.fetch("integrity").fetch("sha256")
  end
  def clone_value(value); Marshal.load(Marshal.dump(value)); end
  def sealed(value)
    payload=value.reject { |k,_| k=="integrity" }
    payload.merge("integrity"=>{"algorithm"=>"sha256","sha256"=>Digest::SHA256.hexdigest(M.canonical_json(payload))})
  end
  def read(value, digest: nil)
    value=sealed(value)
    M.local_operation_intent(JSON.generate(value),expected_sha256: digest || value.fetch("integrity").fetch("sha256"))
  end
  def authority(purpose="execute")
    clone_value(@intent.fetch("preparedBy")).merge("purpose"=>purpose,"authorizationId"=>"55555555-5555-4555-8555-555555555555","intentSha256"=>@digest)
  end
  def test_exact_python_fixture_unicode_digest_and_explicit_authority_binding
    payload,digest=M.local_operation_intent(@raw,expected_sha256:@digest)
    assert_equal @digest,digest
    assert_equal @intent.reject { |k,_| k=="integrity" },payload
    assert_includes M.canonical_json(payload),"日本語"
    %w[execute recover].each do |purpose|
      value=authority(purpose)
      assert_equal value,M.local_execution_authority(JSON.generate(value),intent_content:@raw,expected_intent_sha256:@digest,purpose:purpose)
    end
  end
  def test_existing_ci_reader_rejects_local_and_relabel_hybrids
    %w[candidate external production].each do |stage|
      path=File.join(ROOT,"intent-#{stage}-valid.json")
      payload,digest=M.operation_intent(ROOT,path)
      assert_equal "store-operation-intent",payload["documentType"]
      assert_equal JSON.parse(File.read(path))["integrity"]["sha256"],digest
      assert_raises(M::ContractError) { M.local_operation_intent(File.binread(path),expected_sha256:digest) }
    end
    Dir.mktmpdir do |root|
      path=File.join(root,"intent.json")
      local=clone_value(@intent)
      [local,local.merge("documentType"=>"store-operation-intent")].each do |hybrid|
        File.write(path,JSON.generate(sealed(hybrid)))
        assert_raises(M::ContractError) { M.operation_intent(root,path) }
      end
    end
    ci=JSON.parse(File.read(File.join(ROOT,"intent-candidate-valid.json")))
    {"repository"=>ci["repository"],"authorizedBy"=>ci["authorizedBy"],"origin"=>"github-actions",
     "stage"=>"external-testing","platform"=>"ios"}.each do |key,value|
      assert_raises(M::ContractError) { read(@intent.merge(key=>value)) }
    end
  end
  def test_substitution_and_new_id_do_not_prove_intent_or_prior_dispatch
    changes={"intentSha256"=>"f"*64,"authorizationId"=>@intent["preparedBy"]["authorizationId"],
      "candidateSha256"=>"f"*64,"operationId"=>"66666666-6666-4666-8666-666666666666",
      "source"=>@intent["operationSource"].merge("tree"=>"f"*40),
      "assignment"=>@intent["preparedBy"]["assignment"].merge("expectedRevision"=>2),
      "project"=>@intent["project"].merge("keyId"=>"66666666-6666-4666-8666-666666666666"),
      "confirmationSha256"=>"f"*64,"purpose"=>"recover"}
    changes.each do |key,value|
      assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(authority.merge(key=>value)),
        intent_content:@raw,expected_intent_sha256:@digest,purpose:"execute") }
    end
    changed=clone_value(@intent);changed["artifacts"][0]["sha256"]="f"*64
    assert_raises(M::ContractError) { read(changed,digest:@digest) }
    changed=clone_value(@intent);changed["preparedBy"]["candidateSha256"]="f"*64
    assert_raises(M::ContractError) { read(changed) }
  end
  def test_complete_duplicate_utf8_bounds_and_strict_authority_types
    duplicate='{"origin":"local-desktop",'+@raw.lstrip.delete_prefix("{")
    [duplicate,"\xff".b,"[]",@raw+" "*(2*1024*1024)].each do |bad|
      assert_raises(M::ContractError) { M.local_operation_intent(bad,expected_sha256:@digest) }
    end
    assert_equal @digest,M.local_operation_intent(@raw+" "*(2*1024*1024-@raw.bytesize),expected_sha256:@digest)[1]
    [true,0,2**32-1,1.0].each do |revision|
      value=authority;value["assignment"]["expectedRevision"]=revision
      assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(value),intent_content:@raw,expected_intent_sha256:@digest,purpose:"execute") }
    end
    value=authority;value["extra"]="SECRET_SENTINEL"
    error=assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(value),intent_content:@raw,expected_intent_sha256:@digest,purpose:"execute") }
    assert_equal "Invalid local Store intent or authority DATA",error.message
  end
  def test_local_attempt_key_matches_python_fixture_without_ci_dispatch_authority
    args={intent_content:@raw, authority_content:JSON.generate(authority),expected_intent_sha256:@digest,purpose:"execute"}
    expected="4ac8941d05da26dbe491363baeb9cf501558b5c49efd93b2dded2683c687128f"
    assert_equal expected,M.local_execution_attempt_key(**args)
    assert_equal expected,M.local_execution_attempt_key(**args.merge(authority_content:JSON.pretty_generate(authority)))
    assert_equal @digest,JSON.parse(File.binread(File.join(ROOT,"local-execution-receipt-valid.json")))["operationIntentSha256"]
    recovered=args.merge(authority_content:JSON.generate(authority("recover")),purpose:"recover")
    refute_equal expected,M.local_execution_attempt_key(**recovered)
    value=authority.merge("authorizationId"=>"66666666-6666-4666-8666-666666666666")
    refute_equal expected,M.local_execution_attempt_key(**args.merge(authority_content:JSON.generate(value)))
    assert_raises(M::ContractError) { M.execution_authority({"MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"=>JSON.generate(authority)}) }
  end
  def test_local_attempt_key_refuses_invalid_originals_and_wrong_purpose
    args={intent_content:@raw,authority_content:JSON.generate(authority),expected_intent_sha256:@digest,purpose:"execute"}
    ci=JSON.parse(File.read(File.join(ROOT,"intent-candidate-valid.json")))
    [{expected_intent_sha256:"f"*64},{intent_content:JSON.generate(ci)},
     {authority_content:JSON.generate(ci["authorizedBy"])},{purpose:"prepare"},
     {authority_content:JSON.generate(authority.merge("intentSha256"=>"f"*64))}].each do |change|
      error=assert_raises(M::ContractError) { M.local_execution_attempt_key(**args.merge(change)) }
      assert_equal "Invalid local Store receipt or attempt DATA",error.message
    end
  end

  def ios_data
    raw=File.binread(File.join(ROOT,"local-intent-ios-candidate-valid.json"))
    receipt=JSON.parse(File.binread(File.join(ROOT,"local-ios-execution-receipt-valid.json")))
    value=JSON.parse(raw)
    [raw,value,receipt,{intent_content:raw,authority_content:JSON.generate(receipt.fetch("executedBy")),
      expected_intent_sha256:value.fetch("integrity").fetch("sha256")}]
  end
  def test_explicit_ios_fixture_and_attempt_key_keep_default_android_route_closed
    raw,value,receipt,args=ios_data
    payload,digest=M.local_operation_intent(raw,expected_sha256:args[:expected_intent_sha256],platform:"ios")
    assert_equal value.reject { |k,_| k=="integrity" },payload
    assert_equal args[:expected_intent_sha256],digest
    assert_equal receipt["executedBy"],M.local_execution_authority(args[:authority_content],
      intent_content:raw,expected_intent_sha256:digest,purpose:"execute",platform:"ios")
    assert_equal "1e926ffd3eeff5f02b6460c52266d0ff44db38e01ee73318a651cf9d0314a3c9",
      M.local_execution_attempt_key(**args,purpose:"execute",platform:"ios")
    assert_raises(M::ContractError) { M.local_operation_intent(raw,expected_sha256:digest) }
    assert_raises(M::ContractError) { M.local_execution_attempt_key(**args,purpose:"execute") }
    recovered=receipt["executedBy"].merge("purpose"=>"recover")
    assert_equal recovered,M.local_execution_authority(JSON.generate(recovered),
      intent_content:raw,expected_intent_sha256:digest,purpose:"recover",platform:"ios")
    assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(recovered),
      intent_content:raw,expected_intent_sha256:digest,purpose:"recover") }
    assert_raises(M::ContractError) { M.local_operation_intent(@raw,expected_sha256:@digest,platform:"ios") }
  end
  def test_ios_archive_directory_is_not_a_ci_file_or_zip_and_signing_is_complete
    _,value,_,_=ios_data
    changes=[->(d){d["artifacts"].last["fileName"]="archive.zip"},->(d){d["artifacts"].last["size"]=12},
      ->(d){d["artifacts"].last["entries"]=true},->(d){d["artifacts"].last["entries"]=100001},
      ->(d){d["artifacts"].last["bytes"]=(8<<30)+1},->(d){d["artifacts"].first["size"]=(4<<30)+1},
      ->(d){d["artifacts"].first["fileName"]="export/Reader.ipa"},->(d){d["artifacts"].reverse!},
      ->(d){d["signing"].first.delete("profileUuid")},->(d){d["signing"].first["teamId"]=1234567890},
      ->(d){d["signing"].first["profileExpiresAt"]="2027-02-30T00:00:00Z"},
      ->(d){d["storePrecondition"]["snapshot"].delete("build")},
      ->(d){d["storePrecondition"]["snapshot"]["build"]={}},
      ->(d){d["preparedBy"]["assignment"]["kind"]="google-service-account"}]
    changes.each do |change|
      bad=clone_value(value);change.call(bad);bad=sealed(bad)
      assert_raises(M::ContractError) { M.local_operation_intent(JSON.generate(bad),
        expected_sha256:bad["integrity"]["sha256"],platform:"ios") }
    end
    maximum=clone_value(value);maximum["artifacts"].last.merge!("entries"=>100000,"bytes"=>8<<30)
    maximum["artifacts"].first["size"]=4<<30;maximum=sealed(maximum)
    assert_equal maximum["integrity"]["sha256"],M.local_operation_intent(JSON.generate(maximum),
      expected_sha256:maximum["integrity"]["sha256"],platform:"ios")[1]
    Dir.mktmpdir do |root|
      path=File.join(root,"intent.json");File.write(path,JSON.generate(value))
      assert_raises(M::ContractError) { M.operation_intent(root,path) }
    end
  end
  def test_ios_receipt_body_and_independent_authority_are_required_data_only
    _,_,receipt,args=ios_data
    assert_equal receipt,M.local_ios_execution_receipt(JSON.generate(receipt),**args)
    changed=receipt.merge("result"=>"reconciled","state"=>"available-to-testers")
    assert_equal changed,M.local_ios_execution_receipt(JSON.generate(changed),**args)
    receipt.keys.each do |key|
      bad=clone_value(receipt);bad.delete(key)
      assert_raises(M::ContractError) { M.local_ios_execution_receipt(JSON.generate(bad),**args) }
    end
    {"appStoreAppId"=>"foreign","buildResourceId"=>"","processingState"=>"PROCESSING",
      "autoNotifyEnabled"=>0,"state"=>"submitted-for-review","buildNumber"=>42.0,
      "result"=>"operator_authorized_retry","observedAt"=>"yesterday","versionCode"=>42,
      "executedBy"=>receipt["executedBy"].merge("authorizationId"=>"66666666-6666-4666-8666-666666666666"),
      "authorizedBy"=>receipt["executedBy"]}.each do |key,bad|
      error=assert_raises(M::ContractError) { M.local_ios_execution_receipt(JSON.generate(receipt.merge(key=>bad)),**args) }
      assert_equal "Invalid local Store receipt or attempt DATA",error.message
    end
    assert_raises(M::ContractError) { M.local_ios_execution_receipt(JSON.generate(receipt),**args.merge(expected_intent_sha256:"f"*64)) }
  end

  # Real existing shared stage body, with explicit LOCAL envelope/independent
  # stage authority. This DATA test cannot authorize a lane or old receipt.
  def later_data(stage, platform="android")
    candidate=platform=="android" ? clone_value(@intent) : JSON.parse(File.binread(File.join(ROOT,"local-intent-ios-candidate-valid.json")))
    body=JSON.parse(File.binread(File.join(ROOT,stage=="external-testing" ? "intent-external-valid.json" : "intent-production-valid.json")))
    data=candidate.merge(body.slice("destination","storePrecondition","privateStateCommitments","predecessors"))
    data["stage"]=stage
    data["candidateOperationId"]=candidate["operationId"]
    data["operationId"]="66666666-6666-4666-8666-666666666666"
    data["predecessors"]["candidateManifestSha256"]=candidate["candidateSha256"]
    data["confirmation"]="#{stage}:#{platform}:#{data["version"]["marketing"]}:#{data["version"]["build"]}"
    if stage=="production-submit"
      data["operationSource"]=candidate["operationSource"].merge("commit"=>"e"*40,"tree"=>"f"*40,"ref"=>"refs/heads/release/production")
    end
    data["preparedBy"]=data["preparedBy"].merge("operationId"=>data["operationId"],"source"=>data["operationSource"],
      "confirmationSha256"=>Digest::SHA256.hexdigest(data["confirmation"]))
    sealed(data)
  end

  def test_later_stage_requires_explicit_stage_and_keeps_original_candidate_source
    %w[external-testing production-submit].each do |stage|
      data=later_data(stage);raw=JSON.generate(data);digest=data["integrity"]["sha256"]
      args={intent_content:raw,expected_intent_sha256:digest,purpose:"execute",stage:stage}
      auth=data["preparedBy"].merge("purpose"=>"execute","authorizationId"=>"77777777-7777-4777-8777-777777777777","intentSha256"=>digest)
      assert_equal data.reject { |k,_| k=="integrity" },M.local_operation_intent(raw,expected_sha256:digest,stage:stage)[0]
      assert_equal auth,M.local_execution_authority(JSON.generate(auth),**args)
      assert_raises(M::ContractError) { M.local_operation_intent(raw,expected_sha256:digest) }
      assert_raises(M::ContractError) { M.local_operation_intent(raw,expected_sha256:digest,stage:stage=="external-testing" ? "production-submit" : "external-testing") }
      assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(auth.merge("purpose"=>"recover")),**args.merge(purpose:"recover")) }
      key=M.local_execution_attempt_key(**args,authority_content:JSON.generate(auth))
      assert_match(/\A[0-9a-f]{64}\z/,key)
      candidate_only=JSON.generate(@intent)
      assert_raises(M::ContractError) { M.local_operation_intent(candidate_only,expected_sha256:@digest,stage:stage) }
      [:same_candidate,:wrong_manifest,:missing_predecessor,:foreign_lane].each do |kind|
        bad=clone_value(data)
        case kind
        when :same_candidate then bad["candidateOperationId"]=bad["operationId"]
        when :wrong_manifest then bad["predecessors"]["candidateManifestSha256"]="f"*64
        when :missing_predecessor then bad["predecessors"].delete("candidateReceiptSha256")
        when :foreign_lane then bad["storePrecondition"]["operation"]="android_internal_upload"
        end
        bad=sealed(bad)
        assert_raises(M::ContractError) { M.local_operation_intent(JSON.generate(bad),expected_sha256:bad["integrity"]["sha256"],stage:stage) }
      end
    end
  end

  def test_later_apple_authority_requires_same_context_fixed_supplemental_records
    value=JSON.parse(File.binread(File.join(ROOT,"local-intent-ios-candidate-valid.json")))["preparedBy"]
    value["supplementalAssignments"]=%w[apple-review-contact operation-commitment].each_with_index.map do |kind,i|
      {"kind"=>kind,"recordId"=>(i+6).to_s*32,"expectedRevision"=>1,"contextRevision"=>value["assignment"]["contextRevision"]}
    end
    assert_equal value,M.local_authority_data(value,purpose:"prepare",platform:"ios",stage:"external-testing")
    assert_raises(M::ContractError) { M.local_authority_data(value,purpose:"prepare",platform:"ios") }
    [->(v){v["supplementalAssignments"].reverse!},->(v){v["supplementalAssignments"].pop},
     ->(v){v["supplementalAssignments"][0]["contextRevision"]+=1},
     ->(v){v["supplementalAssignments"][0]["recordId"]=v["assignment"]["recordId"]},
     ->(v){v["supplementalAssignments"][0]["expectedRevision"]=true}].each do |change|
      bad=clone_value(value);change.call(bad)
      assert_raises(M::ContractError) { M.local_authority_data(bad,purpose:"prepare",platform:"ios",stage:"external-testing") }
    end
  end

  def test_shared_later_fixtures_match_explicit_platform_stage_authority
    %w[android ios].product(%w[external-testing production-submit]).each do |platform,stage|
      prefix=File.join(ROOT,"local-#{platform}-#{stage}")
      raw=File.binread(prefix+'-intent.json');value=JSON.parse(raw);digest=value.fetch('integrity').fetch('sha256')
      auth=File.binread(prefix+'-authority.json')
      decoded,actual=M.local_operation_intent(raw,expected_sha256:digest,platform:platform,stage:stage)
      assert_equal digest,actual;assert_equal stage,decoded.fetch('stage')
      assert_equal JSON.parse(auth),M.local_execution_authority(auth,intent_content:raw,expected_intent_sha256:digest,
        purpose:'execute',platform:platform,stage:stage)
      assert_raises(M::ContractError) { M.local_operation_intent(raw,expected_sha256:digest,platform:platform) }
      assert_raises(M::ContractError) { M.local_execution_authority(auth,intent_content:raw,expected_intent_sha256:digest,
        purpose:'recover',platform:platform,stage:stage) }
    end
  end

end
