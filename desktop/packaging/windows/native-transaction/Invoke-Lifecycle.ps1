# Run as SYSTEM only in a fresh disposable runner. Never run on a user machine.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Stage,
      [Parameter(Mandatory)][ValidateSet('fresh','occupied','partial','corrupt','parent-death','msi','replaced-runtime','replaced-record','corrupt-record','pending')][string]$Scenario,
      [Parameter(Mandatory)][string]$Evidence)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM disposable lifecycle context required'}
if($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'Apdelrahman1911/mobile-release-kit' -or $env:GITHUB_WORKFLOW_SHA -cne $env:GITHUB_SHA -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Exact disposable source/workflow/host context required'}
New-Item -ItemType Directory -Path $Evidence -ErrorAction Stop | Out-Null
Start-Transcript -Path (Join-Path $Evidence 'native-original.log') | Out-Null
try {
 $binding=Get-Content (Join-Path $Stage 'binding.json') -Raw | ConvertFrom-Json
 if($binding.sourceCommit -cne $env:GITHUB_SHA -or $binding.sourceTree -cne $env:MRK_EXPECTED_TREE){throw 'Exact lifecycle source binding refused'}
 $app=Join-Path $env:ProgramFiles 'Mobile Release Kit'
 $control=Join-Path $env:ProgramData 'Mobile Release Kit Installer'
 if((Test-Path $app) -or (Test-Path $control)){throw 'Fresh disposable machine required; never deletes existing state'}
 $manifest=$binding.manifestSha256
 $target=Join-Path $app ('versions\x86_64-pc-windows-msvc\'+$manifest)
 if($Scenario -eq 'msi'){
  $msi=Join-Path $Stage 'MobileReleaseKit-NONSHIPPING.msi'
  $mst=Join-Path $Stage 'DISPOSABLE-VALIDATION-ONLY.mst'
  $transformReceipt=Get-Content (Join-Path $Stage 'DISPOSABLE-VALIDATION-ONLY.json') -Raw | ConvertFrom-Json
  $originalHash=(Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()
  if($originalHash -cne $transformReceipt.originalMsiSha256 -or (Get-FileHash $mst -Algorithm SHA256).Hash.ToLowerInvariant() -cne $transformReceipt.transformSha256){throw 'Exact MSI/MST binding failed'}
  function Invoke-Msi([string]$Name,[string]$Operation,[bool]$Transformed,[int]$Expected=0){
   $log=Join-Path $Evidence ($Name+'.msi-original.log')
   $arguments="$Operation `"$msi`" /qn /norestart /L*V `"$log`""
   if($Transformed){$arguments+=" TRANSFORMS=`"$mst`" TRANSFORMSSECURE=1"}
   $process=Start-Process 'C:\Windows\System32\msiexec.exe' -ArgumentList $arguments -PassThru
   if(!$process.WaitForExit(120000)){throw 'Original MSI session timeout; result UNKNOWN'}
   if($process.ExitCode -ne $Expected){throw "$Name original exit $($process.ExitCode) expected $Expected"}
  }
  Invoke-Msi 'shipping-refusal' '/i' $false 1603
  if((Test-Path $app) -or (Test-Path $control)){throw 'Shipping refusal created native state'}
  Invoke-Msi 'transformed-install' '/i' $true
  $completion=Join-Path $control "$manifest.complete"
  $receipt=Get-Content $completion -Raw
  Invoke-Msi 'transformed-repair' '/fa' $true
  if((Get-Content $completion -Raw) -cne $receipt){throw 'Repair changed original completion'}
  Invoke-Msi 'transformed-uninstall' '/x' $true
  if(!(Test-Path $target) -or (Get-Content $completion -Raw) -cne $receipt){throw 'Uninstall deleted or changed retained native authority'}
  if(Test-Path (Join-Path $app 'mrk-windows-runtime-publish.exe')){throw 'MSI uninstall retained its managed publisher unexpectedly'}
  Invoke-Msi 'transformed-reinstall' '/i' $true
  if((Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $originalHash){throw 'Original shipping MSI mutated'}
  [ordered]@{schema=1;scenario='msi';status='PASS';msiInstalled=$true;msiRepaired=$true;msiUninstalled=$true;msiReinstalled=$true;transformedValidationOnly=$true;originalShippingRefusalPreserved=$true;shippingAccepted=$false;msiSha256=$originalHash} | ConvertTo-Json | Set-Content (Join-Path $Evidence 'result.json')
  return
 }
 New-Item -ItemType Directory -Path $app | Out-Null
 Copy-Item (Join-Path $Stage 'payload\mobile-release-kit-desktop.exe') $app
 Copy-Item (Join-Path $Stage 'payload\mrk-windows-runtime-publish.exe') $app
 $inputRoot=Join-Path $app ('runtime-input\x86_64-pc-windows-msvc\'+$manifest)
 New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
 Copy-Item (Join-Path $Stage 'payload\runtime\*') $inputRoot -Recurse
 # Input immutability must satisfy the original fixed native publisher, with
 # SYSTEM/Admin write authority and ordinary consumer read/execute only.
 & icacls.exe $app /setowner '*S-1-5-18' /T /C
 if($LASTEXITCODE){throw 'owner setup failed'}
 & icacls.exe $app /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /C
 if($LASTEXITCODE){throw 'ACL setup failed'}
 $test=Join-Path $Stage 'native-build\Release\MrkTransactionNativeTests.exe'
 function Invoke-Native([string]$Action,[int]$Expected=0){
  $previousPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
  try {& $test $Action;$actual=$LASTEXITCODE} finally {$ErrorActionPreference=$previousPreference}
  if($actual -ne $Expected){throw "Native $Action returned $actual expected $Expected"}
 }
 $previousPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try {& $test;$primitiveExit=$LASTEXITCODE} finally {$ErrorActionPreference=$previousPreference}
 if($primitiveExit){throw 'native primitives failed'}
 if($Scenario -eq 'occupied'){
  # An identical fully sealed published runtime without our completion record
  # still refuses: exit2/equal bytes never authenticates transaction ownership.
  & (Join-Path $app 'mrk-windows-runtime-publish.exe')
  if($LASTEXITCODE){throw 'original publisher fixture failed'}
  Invoke-Native 'publish' 1603
  if(Test-Path (Join-Path $control "$manifest.complete")){throw 'occupied target adopted'}
 } elseif($Scenario -eq 'partial'){
  Invoke-Native 'crash-after-start' 77
  Invoke-Native 'guard' 1603
  Invoke-Native 'publish' 1603
  if(Test-Path (Join-Path $control "$manifest.complete")){throw 'partial transaction adopted'}
 } elseif($Scenario -eq 'pending'){
  Invoke-Native 'crash-after-pending' 77
  if(!(Test-Path $target) -or !(Test-Path (Join-Path $control "$manifest.pending"))){throw 'Original staged publication fault boundary missing'}
  Invoke-Native 'guard' 1603;Invoke-Native 'publish' 1603
  if(Test-Path (Join-Path $control "$manifest.complete")){throw 'Pending record or identical bytes adopted after interruption'}
 } elseif($Scenario -eq 'parent-death'){
  $parent=Start-Process $test -ArgumentList 'publish' -PassThru
  $until=[DateTime]::UtcNow.AddSeconds(30)
  while(!(Test-Path (Join-Path $control "$manifest.started")) -and [DateTime]::UtcNow -lt $until -and !$parent.HasExited){Start-Sleep -Milliseconds 10}
  if(!(Test-Path (Join-Path $control "$manifest.started"))){throw 'original started boundary unobserved'}
  if($parent.HasExited){throw 'Parent completed before death injection; test inconclusive'}
  # Census is used solely to place the fault while an original child is live;
  # it never authenticates completion or clears an unknown transaction.
  $child=$null
  while(!$parent.HasExited -and [DateTime]::UtcNow -lt $until -and !$child){
   $rows=@(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($parent.Id)" | Where-Object {$_.Name -eq 'mrk-windows-runtime-publish.exe'})
   if($rows.Count -eq 1){$child=[Diagnostics.Process]::GetProcessById($rows[0].ProcessId);$null=$child.Handle}
  }
  if(!$child -or $child.HasExited -or $parent.HasExited){throw 'No live original child observed; death test inconclusive'}
  $parent.Kill();if(!$parent.WaitForExit(10000)){throw 'Original parent did not settle'}
  if(!$child.WaitForExit(10000)){throw 'Kill-on-parent-close original child remained live'}
  if(Test-Path (Join-Path $control "$manifest.complete")){throw 'Death injection missed completion boundary'}
  Invoke-Native 'guard' 1603
  Invoke-Native 'publish' 1603
 } else {
  Invoke-Native 'guard'
  Invoke-Native 'publish'
  Invoke-Native 'fullwalk'
  $receipt=Get-Content (Join-Path $control "$manifest.complete") -Raw
  Invoke-Native 'guard';Invoke-Native 'publish'
  if((Get-Content (Join-Path $control "$manifest.complete") -Raw) -cne $receipt){throw 'Repeated configuration rewrote original completion'}
  if($Scenario -eq 'corrupt'){
   # Privileged fault injection is confined to this disposable fresh runner.
   [IO.File]::AppendAllText((Join-Path $target 'manifest.json'),'x')
   Invoke-Native 'guard' 1603;Invoke-Native 'publish' 1603
  } elseif($Scenario -eq 'corrupt-record'){
   [IO.File]::AppendAllText((Join-Path $control "$manifest.complete"),'x')
   Invoke-Native 'guard' 1603;Invoke-Native 'publish' 1603
  } elseif($Scenario -eq 'replaced-runtime' -or $Scenario -eq 'replaced-record'){
   $selected=if($Scenario -eq 'replaced-runtime'){Join-Path $target 'core.zip'}else{Join-Path $control "$manifest.complete"}
   $bytes=[IO.File]::ReadAllBytes($selected);$originalAcl=Get-Acl $selected
   $beforeHash=(Get-FileHash $selected -Algorithm SHA256).Hash
   $replacement=$selected+'.replacement'
   [IO.File]::WriteAllBytes($replacement,$bytes);Set-Acl $replacement $originalAcl
   Remove-Item $selected -Force;Move-Item $replacement $selected
   if((Get-FileHash $selected -Algorithm SHA256).Hash -cne $beforeHash){throw 'Identity replacement fixture changed bytes'}
   Invoke-Native 'guard' 1603;Invoke-Native 'publish' 1603
  }
 }
 [ordered]@{schema=1;scenario=$Scenario;status='PASS';nativeExecuted=$true;msiInstalled=$false;shippingAccepted=$false} | ConvertTo-Json | Set-Content (Join-Path $Evidence 'result.json')
} finally {Stop-Transcript | Out-Null}
