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
    assert_raises(M::ContractError) { M.local_execution_authority(JSON.generate(recovered),
      intent_content:raw,expected_intent_sha256:digest,purpose:"recover",platform:"ios") }
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

end
