# Fixed original owner for one retained-shell role. Dot-sourced by the reviewed
# workflow, never a general executable/argument interface or an installer.
# Timeout is the workflow's isolated-platform fail-stop, NOT successful finality.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('probe-balanced','probe-overflow','probe-writer-fault',
    'fresh-stage','fresh-app','fresh-observe','reuse-stage','reuse-app','reuse-observe',
    'stop-copy-stage','stop-copy-app','stop-copy-observe',
    'wrong-caller-stage','wrong-caller-app','wrong-caller-observe',
    'bad-manifest-stage','bad-manifest-corrupt','bad-manifest-app','bad-manifest-observe',
    'stage-fresh',
    'preview-fresh',
    'preview-fresh-observe',
    'select-fresh',
    'select-fresh-observe',
    'stage-reuse',
    'preview-reuse',
    'preview-reuse-observe',
    'select-reuse',
    'select-reuse-observe',
    'preview-verify-reuse',
    'preview-verify-reuse-observe',
    'verify-reuse',
    'verify-reuse-observe',
    'preview-remove-reuse',
    'preview-remove-reuse-observe',
    'remove-reuse',
    'remove-reuse-observe',
    'refuse-stale-repair',
    'refuse-stale-repair-observe',
    'preview-repair-reuse',
    'preview-repair-reuse-observe',
    'repair-reuse',
    'repair-reuse-observe',
    'preview-registry-conflict',
    'preview-registry-conflict-observe',
    'registry-conflict',
    'registry-conflict-observe',
    'stage-wrong-caller',
    'preview-stop-old',
    'preview-stop-old-observe',
    'stop-old',
    'stop-old-observe',
    'preview-previous',
    'preview-previous-observe',
    'recover-previous',
    'recover-previous-observe',
    'stage-bad-manifest',
    'preview-stop-new',
    'preview-stop-new-observe',
    'stop-new',
    'stop-new-observe',
    'preview-current',
    'preview-current-observe',
    'recover-current',
    'recover-current-observe',
    'damage-owned-shell',
    'preview-remove-damaged',
    'preview-remove-damaged-observe',
    'remove-damaged',
    'remove-damaged-observe',
    'stage-owned-foreign-selector',
    'refuse-foreign-selector',
    'refuse-foreign-selector-observe'')]
  [string]$Role
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:OriginalInputs = [System.Collections.Generic.List[System.IO.FileStream]]::new()
$script:InputErrors = [System.Collections.Generic.List[string]]::new()
$script:InputCloseAttempted = $false
$script:StartUnknown = $false
$script:OriginalUnknown = $false
$script:OriginalCustody = $null
$script:RawResult = $null

# Closed54-role episode DATA; never an executable/argv dispatch interface.
$script:SelectionRoles = @(
  'stage-fresh',
  'preview-fresh',
  'preview-fresh-observe',
  'select-fresh',
  'select-fresh-observe',
  'stage-reuse',
  'preview-reuse',
  'preview-reuse-observe',
  'select-reuse',
  'select-reuse-observe',
  'preview-verify-reuse',
  'preview-verify-reuse-observe',
  'verify-reuse',
  'verify-reuse-observe',
  'preview-remove-reuse',
  'preview-remove-reuse-observe',
  'remove-reuse',
  'remove-reuse-observe',
  'refuse-stale-repair',
  'refuse-stale-repair-observe',
  'preview-repair-reuse',
  'preview-repair-reuse-observe',
  'repair-reuse',
  'repair-reuse-observe',
  'preview-registry-conflict',
  'preview-registry-conflict-observe',
  'registry-conflict',
  'registry-conflict-observe',
  'stage-wrong-caller',
  'preview-stop-old',
  'preview-stop-old-observe',
  'stop-old',
  'stop-old-observe',
  'preview-previous',
  'preview-previous-observe',
  'recover-previous',
  'recover-previous-observe',
  'stage-bad-manifest',
  'preview-stop-new',
  'preview-stop-new-observe',
  'stop-new',
  'stop-new-observe',
  'preview-current',
  'preview-current-observe',
  'recover-current',
  'recover-current-observe',
  'damage-owned-shell',
  'preview-remove-damaged',
  'preview-remove-damaged-observe',
  'remove-damaged',
  'remove-damaged-observe',
  'stage-owned-foreign-selector',
  'refuse-foreign-selector',
  'refuse-foreign-selector-observe'
)
$script:SelectionRoutes = [ordered]@{
  'stage-fresh' = @('native-stage','qualification_fixture::installer::selection::stage_fresh')
  'preview-fresh' = @('app','windows_installer_controller::selection_fixture::preview_fresh')
  'preview-fresh-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_fresh')
  'select-fresh' = @('app','windows_installer_controller::selection_fixture::select_fresh')
  'select-fresh-observe' = @('native-observe','qualification_fixture::installer::selection::observe_select_fresh')
  'stage-reuse' = @('native-stage','qualification_fixture::installer::selection::stage_reuse')
  'preview-reuse' = @('app','windows_installer_controller::selection_fixture::preview_reuse')
  'preview-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_reuse')
  'select-reuse' = @('app','windows_installer_controller::selection_fixture::select_reuse')
  'select-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_select_reuse')
  'preview-verify-reuse' = @('app','windows_installer_controller::selection_fixture::preview_verify_reuse')
  'preview-verify-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_verify_reuse')
  'verify-reuse' = @('app','windows_installer_controller::selection_fixture::verify_reuse')
  'verify-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_verify_reuse')
  'preview-remove-reuse' = @('app','windows_installer_controller::selection_fixture::preview_remove_reuse')
  'preview-remove-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_remove_reuse')
  'remove-reuse' = @('app','windows_installer_controller::selection_fixture::remove_reuse')
  'remove-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_remove_reuse')
  'refuse-stale-repair' = @('app','windows_installer_controller::selection_fixture::refuse_stale_repair')
  'refuse-stale-repair-observe' = @('native-observe','qualification_fixture::installer::selection::observe_refuse_stale_repair')
  'preview-repair-reuse' = @('app','windows_installer_controller::selection_fixture::preview_repair_reuse')
  'preview-repair-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_repair_reuse')
  'repair-reuse' = @('app','windows_installer_controller::selection_fixture::repair_reuse')
  'repair-reuse-observe' = @('native-observe','qualification_fixture::installer::selection::observe_repair_reuse')
  'preview-registry-conflict' = @('app','windows_installer_controller::selection_fixture::preview_registry_conflict')
  'preview-registry-conflict-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_registry_conflict')
  'registry-conflict' = @('app','windows_installer_controller::selection_fixture::registry_conflict')
  'registry-conflict-observe' = @('native-observe','qualification_fixture::installer::selection::observe_registry_conflict')
  'stage-wrong-caller' = @('native-stage','qualification_fixture::installer::selection::stage_wrong_caller')
  'preview-stop-old' = @('app','windows_installer_controller::selection_fixture::preview_stop_old')
  'preview-stop-old-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_stop_old')
  'stop-old' = @('app','windows_installer_controller::selection_fixture::stop_old')
  'stop-old-observe' = @('native-observe','qualification_fixture::installer::selection::observe_stop_old')
  'preview-previous' = @('app','windows_installer_controller::selection_fixture::preview_previous')
  'preview-previous-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_previous')
  'recover-previous' = @('app','windows_installer_controller::selection_fixture::recover_previous')
  'recover-previous-observe' = @('native-observe','qualification_fixture::installer::selection::observe_recover_previous')
  'stage-bad-manifest' = @('native-stage','qualification_fixture::installer::selection::stage_bad_manifest')
  'preview-stop-new' = @('app','windows_installer_controller::selection_fixture::preview_stop_new')
  'preview-stop-new-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_stop_new')
  'stop-new' = @('app','windows_installer_controller::selection_fixture::stop_new')
  'stop-new-observe' = @('native-observe','qualification_fixture::installer::selection::observe_stop_new')
  'preview-current' = @('app','windows_installer_controller::selection_fixture::preview_current')
  'preview-current-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_current')
  'recover-current' = @('app','windows_installer_controller::selection_fixture::recover_current')
  'recover-current-observe' = @('native-observe','qualification_fixture::installer::selection::observe_recover_current')
  'damage-owned-shell' = @('native-setup','qualification_fixture::installer::selection::damage_owned_shell')
  'preview-remove-damaged' = @('app','windows_installer_controller::selection_fixture::preview_remove_damaged')
  'preview-remove-damaged-observe' = @('native-observe','qualification_fixture::installer::selection::observe_preview_remove_damaged')
  'remove-damaged' = @('app','windows_installer_controller::selection_fixture::remove_damaged')
  'remove-damaged-observe' = @('native-observe','qualification_fixture::installer::selection::observe_remove_damaged')
  'stage-owned-foreign-selector' = @('native-setup','qualification_fixture::installer::selection::stage_owned_foreign_selector')
  'refuse-foreign-selector' = @('app','windows_installer_controller::selection_fixture::refuse_foreign_selector')
  'refuse-foreign-selector-observe' = @('native-observe','qualification_fixture::installer::selection::observe_refuse_foreign_selector')
}
$script:SelectionCases = [ordered]@{
  'preview-fresh' = @('fresh','install-activated',$null,$null,$true,$false,$false)
  'select-fresh' = @('fresh','install-activated','preview-fresh',$null,$false,$true,$false)
  'preview-reuse' = @('reuse','install-activated',$null,$null,$true,$false,$false)
  'select-reuse' = @('reuse','install-activated','preview-reuse',$null,$false,$true,$false)
  'preview-verify-reuse' = @('reuse','verify-and-restore-launch-entries',$null,$null,$true,$false,$false)
  'verify-reuse' = @('reuse','verify-and-restore-launch-entries','preview-verify-reuse',$null,$false,$false,$false)
  'preview-remove-reuse' = @('reuse','remove-launch-entries',$null,$null,$true,$false,$false)
  'remove-reuse' = @('reuse','remove-launch-entries','preview-remove-reuse',$null,$false,$false,$false)
  'refuse-stale-repair' = @('reuse','verify-and-restore-launch-entries','preview-verify-reuse',$null,$false,$false,$false)
  'preview-repair-reuse' = @('reuse','verify-and-restore-launch-entries',$null,$null,$true,$false,$false)
  'repair-reuse' = @('reuse','verify-and-restore-launch-entries','preview-repair-reuse',$null,$false,$false,$false)
  'preview-registry-conflict' = @('reuse','remove-launch-entries',$null,$null,$true,$false,$false)
  'registry-conflict' = @('reuse','remove-launch-entries','preview-registry-conflict',$null,$false,$false,$false)
  'preview-stop-old' = @('wrong-caller','install-activated',$null,$null,$true,$false,$false)
  'stop-old' = @('wrong-caller','install-activated','preview-stop-old',$null,$false,$true,$true)
  'preview-previous' = @('wrong-caller','recover-previous-launch-selection',$null,'stop-old',$true,$false,$false)
  'recover-previous' = @('wrong-caller','recover-previous-launch-selection','preview-previous','stop-old',$false,$false,$false)
  'preview-stop-new' = @('bad-manifest','install-activated',$null,$null,$true,$false,$false)
  'stop-new' = @('bad-manifest','install-activated','preview-stop-new',$null,$false,$true,$true)
  'preview-current' = @('bad-manifest','recover-current-launch-selection',$null,'stop-new',$true,$false,$false)
  'recover-current' = @('bad-manifest','recover-current-launch-selection','preview-current','stop-new',$false,$false,$false)
  'preview-remove-damaged' = @('bad-manifest','remove-launch-entries',$null,$null,$true,$false,$false)
  'remove-damaged' = @('bad-manifest','remove-launch-entries','preview-remove-damaged',$null,$false,$false,$false)
  'refuse-foreign-selector' = @('reuse','verify-and-restore-launch-entries',$null,$null,$false,$false,$false)
}
$script:SelectionReadbacks = @{}

function Require-Retained([bool]$Condition, [string]$Code) {
  if (-not $Condition) { throw $Code }
}
function Get-RetainedSha([byte[]]$Bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}
function Open-RetainedInput([string]$Path, [long]$Limit) {
  Require-Retained ([IO.Path]::IsPathFullyQualified($Path) -and
    $Path -cnotmatch '(^|[\\/])\.\.?([\\/]|$)') 'input-path'
  $at = [IO.Path]::GetDirectoryName($Path)
  while ($at) {
    $attributes = [IO.File]::GetAttributes($at)
    Require-Retained (($attributes -band [IO.FileAttributes]::Directory) -ne 0 -and
      ($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'input-ancestor'
    $at = [IO.Path]::GetDirectoryName($at)
  }
  $before = [IO.FileInfo]::new($Path)
  $before.Refresh()
  Require-Retained ($before.Exists -and $before.Length -le $Limit -and
    ($before.Attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -eq 0) 'input-kind'
  $stamp = @($before.Length, $before.CreationTimeUtc.Ticks, $before.LastWriteTimeUtc.Ticks, [int]$before.Attributes)
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $script:OriginalInputs.Add($stream)
  $before.Refresh()
  Require-Retained ($stream.Length -eq $stamp[0] -and $before.Length -eq $stamp[0] -and
    $before.CreationTimeUtc.Ticks -eq $stamp[1] -and $before.LastWriteTimeUtc.Ticks -eq $stamp[2] -and
    [int]$before.Attributes -eq $stamp[3]) 'input-change'
  return $stream
}
function Read-RetainedBytes([string]$Path, [int]$Limit) {
  $stream = Open-RetainedInput $Path $Limit
  $bytes = [byte[]]::new([int]$stream.Length)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $count = $stream.Read($bytes, $offset, [Math]::Min(4096, $bytes.Length - $offset))
    Require-Retained ($count -gt 0) 'input-short'
    $offset += $count
  }
  Require-Retained ($stream.ReadByte() -eq -1) 'input-grew'
  return ,$bytes
}
function Assert-RetainedFile([string]$Path, [long]$Length, [string]$Sha256) {
  Require-Retained ($Length -gt 0 -and $Sha256 -cmatch '^[0-9a-f]{64}$') 'file-pin'
  $stream = Open-RetainedInput $Path $Length
  Require-Retained ($stream.Length -eq $Length -and
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() -ceq $Sha256) 'file-digest'
}
function Read-RetainedWire([byte[]]$Raw, [string]$Header, [string[]]$Keys) {
  Require-Retained ($Raw.Length -gt 0 -and $Raw.Length -le 65536 -and $Raw[-1] -eq 10) 'wire-bound'
  foreach ($byte in $Raw) { Require-Retained ($byte -eq 10 -or ($byte -ge 32 -and $byte -le 126)) 'wire-ascii' }
  $lines = [Text.Encoding]::ASCII.GetString($Raw).Substring(0, $Raw.Length-1).Split([char]10)
  Require-Retained ($lines.Count -eq $Keys.Count + 1 -and $lines[0] -ceq $Header) 'wire-header'
  $values = [ordered]@{}
  for ($i=0; $i -lt $Keys.Count; $i++) {
    $prefix = $Keys[$i] + '='
    Require-Retained ($lines[$i+1].StartsWith($prefix, [StringComparison]::Ordinal)) 'wire-order'
    $value = $lines[$i+1].Substring($prefix.Length)
    Require-Retained ($value.Length -gt 0 -and -not $value.Contains('=')) 'wire-value'
    $values[$Keys[$i]] = $value
  }
  return $values
}

# Fixed prior-output DATA transport. No process/custody is delegated here.
function Get-SelectionRoute([string]$Name) {
  Require-Retained ($script:SelectionRoles -ccontains $Name) 'selection-role'
  return ,$script:SelectionRoutes[$Name]
}
function Read-SelectionOriginal([string]$Name) {
  $route = Get-SelectionRoute $Name
  if ($script:SelectionReadbacks.ContainsKey($Name)) { return ,$script:SelectionReadbacks[$Name] }
  $bytes = Read-RetainedBytes ([IO.Path]::Combine($root,"retained-$Name.private.txt")) 65536
  $exitRaw = Read-RetainedBytes ([IO.Path]::Combine($root,"retained-$Name-exit.private.txt")) 8192
  $closed = Read-RetainedWire $exitRaw 'MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1' $exitKeys
  $kind = if ($route[0] -ceq 'app') { 'app' } else { 'native' }
  $command = '"'+$pre[$kind+'Artifact']+'" '+$route[1]+' --exact --ignored --nocapture --test-threads=1'
  Require-Retained ($closed.role -ceq $Name -and $closed.profile -ceq $profile -and
    $closed.sourceSha -ceq $owner.sourceSha -and $closed.sourceTree -ceq $owner.sourceTree -and
    $closed.runId -ceq $owner.runId -and $closed.attempt -ceq '1' -and
    $closed.artifactSha256 -ceq $pre[$kind+'ArtifactSha256'] -and
    $closed.precheckSha256 -ceq (Get-RetainedSha $preRaw) -and
    $closed.commandSha256 -ceq (Get-RetainedSha ([Text.Encoding]::Unicode.GetBytes($command))) -and
    $closed.resultBytes -cmatch '^[1-9][0-9]{0,4}$' -and [int]$closed.resultBytes -eq $bytes.Length -and
    $closed.resultSha256 -ceq (Get-RetainedSha $bytes) -and $closed.originalWaitReturned -ceq 'true' -and
    $closed.exitCode -ceq '0' -and $closed.writerCloseGate -ceq 'original-owner-closed-output') 'selection-original-binding'
  $script:SelectionReadbacks.Add($Name,$bytes)
  return ,$bytes
}
function Get-SelectionLine([byte[]]$Bytes, [string]$Prefix) {
  Require-Retained ($Prefix -cin @('MRK_WINDOWS_SELECTION_PREVIEW_V1=','MRK_WINDOWS_SELECTION_RECOVERY_V1=')) 'selection-field'
  $text = [Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
  $found = @($text.Split([char]10) | Where-Object { $_.StartsWith($Prefix,[StringComparison]::Ordinal) })
  Require-Retained ($found.Count -eq 1) 'selection-field-count'
  $value = $found[0].Substring($Prefix.Length)
  Require-Retained ($value.Length -gt 0 -and -not $value.Contains([char]0) -and -not $value.Contains([char]13)) 'selection-field-bytes'
  return $value
}
function Read-SelectionHeader([string]$Name) {
  $route = Get-SelectionRoute $Name
  Require-Retained ($route[0] -cne 'app') 'selection-header-role'
  $bytes = Read-SelectionOriginal $Name
  foreach ($byte in $bytes) { Require-Retained ($byte -eq 10 -or ($byte -ge 32 -and $byte -le 126)) 'selection-snapshot-ascii' }
  $text = [Text.Encoding]::ASCII.GetString($bytes)
  $keys = @('profile','sourceSha','sourceTree','runId','attempt','role','precheckSha256',
    'profilesSha256','rosterSha256','programFiles','commonPrograms','candidate','freshMrkAbsent',
    'selectorImage','registrationImage','registrationSha256','registrationSecurityDigest','registrationParentSha256',
    'registrationWrite','trees','objects','damagedShell','foreignSelector','accountedRuns','fileOriginals',
    'fileOriginalsClosed','parentBookSettled','selectionPrimitivesClosed','unknown','resultCloseGate')
  $lines = $text.Split([char]10)
  Require-Retained ($lines.Count -gt $keys.Count) 'selection-header-count'
  $head = [Text.Encoding]::ASCII.GetBytes(($lines[0..$keys.Count] -join "`n")+"`n")
  $record = Read-RetainedWire $head 'MRK_WINDOWS_SELECTION_SNAPSHOT_V1' $keys
  Require-Retained ($record.profile -ceq $profile -and $record.sourceSha -ceq $owner.sourceSha -and
    $record.sourceTree -ceq $owner.sourceTree -and $record.runId -ceq $owner.runId -and $record.attempt -ceq '1' -and
    $record.role -ceq $Name -and $record.precheckSha256 -ceq (Get-RetainedSha $preRaw) -and
    $record.profilesSha256 -ceq $pre.profilesSha256 -and $record.rosterSha256 -ceq $pre.rosterSha256 -and
    $record.fileOriginals -cmatch '^[1-9][0-9]{0,2}$' -and [int]$record.fileOriginals -le 804 -and
    $record.fileOriginalsClosed -ceq $record.fileOriginals -and $record.parentBookSettled -ceq 'true' -and
    $record.selectionPrimitivesClosed -ceq 'true' -and $record.unknown -ceq 'false' -and
    $record.resultCloseGate -ceq 'original-fixture-exit-zero-required') 'selection-header-binding'
  return $record
}
function Get-SelectionPreview([string]$Name, [string]$ExpectedMode) {
  Require-Retained ($script:SelectionCases.Contains($Name) -and $script:SelectionCases[$Name][4]) 'selection-preview-role'
  $bytes = Read-SelectionOriginal $Name
  $raw = Get-SelectionLine $bytes 'MRK_WINDOWS_SELECTION_PREVIEW_V1='
  Require-Retained ([Text.Encoding]::UTF8.GetByteCount($raw) -le 16384) 'selection-preview-bound'
  $options = [Text.Json.JsonDocumentOptions]::new()
  $options.MaxDepth = 4; $options.AllowTrailingCommas = $false
  $document = [Text.Json.JsonDocument]::Parse($raw,$options)
  try {
    $value = $document.RootElement
    Require-Retained ($value.ValueKind -eq [Text.Json.JsonValueKind]::Object) 'selection-preview-object'
    $keys = @('version','mode','beforeImage','afterImage','runtime','coreVersion','shortcutPath','registrationPath',
      'observationSha256','preservedPaths','retainedImageBytesObserved','warning')
    $properties = @($value.EnumerateObject())
    Require-Retained ($properties.Count -eq $keys.Count) 'selection-preview-fields'
    for ($i=0; $i -lt $keys.Count; $i++) {
      Require-Retained ($properties[$i].Name -ceq $keys[$i]) 'selection-preview-field-order'
    }
    Require-Retained ($value.GetProperty('version').GetRawText() -ceq '1' -and
      $value.GetProperty('mode').GetString() -ceq $ExpectedMode -and
      $value.GetProperty('observationSha256').GetString() -cmatch '^[0-9a-f]{64}$' -and
      $value.GetProperty('registrationPath').GetString() -ceq 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MobileReleaseKit' -and
      $value.GetProperty('warning').GetString() -ceq ('Launch entries can be partially changed if Windows refuses a later step. '+
        'Existing application images, runtime files, projects, credentials and evidence remain retained. '+
        'Recovery requires a new preview and verification; this is not a full uninstall.')) 'selection-preview-binding'
    foreach ($key in @('beforeImage','afterImage','runtime')) {
      $field = $value.GetProperty($key)
      Require-Retained ($field.ValueKind -eq [Text.Json.JsonValueKind]::Null -or
        ($field.ValueKind -eq [Text.Json.JsonValueKind]::String -and $field.GetString() -cmatch '^[0-9a-f]{64}$')) 'selection-preview-nullable-digest'
    }
    $field = $value.GetProperty('coreVersion')
    Require-Retained ($field.ValueKind -eq [Text.Json.JsonValueKind]::Null -or
      ($field.ValueKind -eq [Text.Json.JsonValueKind]::String -and $field.GetString() -cmatch '^[A-Za-z0-9._+\-]{1,64}$')) 'selection-preview-version'
    $field = $value.GetProperty('retainedImageBytesObserved')
    Require-Retained ($field.ValueKind -eq [Text.Json.JsonValueKind]::Null -or
      ($field.ValueKind -eq [Text.Json.JsonValueKind]::Number -and $field.GetRawText() -cmatch '^(0|[1-9][0-9]{0,9})$' -and
       $field.GetInt64() -le 2147483648)) 'selection-preview-bytes'
    $paths = $value.GetProperty('preservedPaths')
    Require-Retained ($paths.ValueKind -eq [Text.Json.JsonValueKind]::Array -and $paths.GetArrayLength() -eq 4) 'selection-preview-path-count'
    $strings = @($value.GetProperty('shortcutPath').GetString())
    foreach ($item in $paths.EnumerateArray()) { $strings += $item.GetString() }
    foreach ($path in $strings) {
      Require-Retained ([IO.Path]::IsPathFullyQualified($path) -and $path -cmatch '^[A-Za-z]:\\' -and
        $path.Length -lt 8192 -and $path -cnotmatch '(^|\\)\.\.?(\\|$)' -and
        $path.IndexOfAny([char[]]@([char]0,[char]10,[char]13,[char]34,[char]37,[char]47)) -lt 0) 'selection-preview-fixed-path-shape'
    }
  } finally { $document.Dispose() }
  # Preserve actual original canonical bytes, including every explicit null.
  # Never ConvertTo-Json, normalize, sort, escape or reconstruct this DATA.
  return $raw
}

function Close-RetainedInputs {
  if ($script:InputCloseAttempted) { return }
  $script:InputCloseAttempted = $true
  for ($i=$script:OriginalInputs.Count-1; $i -ge 0; $i--) {
    try { $script:OriginalInputs[$i].Dispose() } catch { $script:InputErrors.Add('input-close') }
  }
  # A failed consuming close is never retried or mistaken for a released original.
  if ($script:InputErrors.Count -eq 0) { $script:OriginalInputs.Clear() }
}
function Write-RetainedReceipt([string]$Path, [byte[]]$Raw) {
  Require-Retained ($Raw.Length -gt 0 -and $Raw.Length -le 8192) 'receipt-bound'
  $writer = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $errors = [System.Collections.Generic.List[string]]::new()
  try {
    try { $writer.Write($Raw, 0, $Raw.Length) } catch { $errors.Add('receipt-write') }
    try { $writer.Flush($true) } catch { $errors.Add('receipt-flush') }
  } finally {
    try { $writer.Dispose() } catch { $errors.Add('receipt-close') }
  }
  Require-Retained ($errors.Count -eq 0) 'receipt-not-final'
}

# No function parameter accepts an executable, argv, environment, timeout or
# arbitrary fault. All choices below are resolved from one closed workflow role.
function Invoke-RetainedOriginal {
  $errors = [ordered]@{}
  $slots = @(
    @{ Name='stdout'; Reader=$null; Task=$null; Buffer=[byte[]]::new(4096);
       Eof=$false; ReaderCloseAttempted=$false; ReaderClosed=$false;
       Writer=$null; WriterCloseAttempted=$false; WriterClosed=$false;
       FlushReturned=$false; Observed=[long]0; Retained=[long]0; WriteFailed=$false },
    @{ Name='stderr'; Reader=$null; Task=$null; Buffer=[byte[]]::new(4096);
       Eof=$false; ReaderCloseAttempted=$false; ReaderClosed=$false;
       Writer=$null; WriterCloseAttempted=$false; WriterClosed=$false;
       FlushReturned=$false; Observed=[long]0; Retained=[long]0; WriteFailed=$false }
  )
  $process = [Diagnostics.Process]::new()
  $script:OriginalCustody = @{ Process=$process; Slots=$slots; Errors=$errors }
  $started = $false; $waitReturned = $false; $exitCode = $null; $processClosed = $false
  $injected = $false; $aggregate = [long]0; $observedAggregate = [long]0
  try {
    $slots[0].Writer = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $slots[1].Writer = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $executable
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
    $info.Environment.Clear()
    foreach ($name in $childEnvironment.Keys) { $info.Environment.Add($name, $childEnvironment[$name]) }
    $process.StartInfo = $info
    try {
      $started = $process.Start()
      if (-not $started) { $errors['original-start-return'] = $true; $script:StartUnknown = $true }
    } catch { $errors['original-start'] = $true; $script:StartUnknown = $true }
  } catch { $errors['owner-prepare'] = $true }
  if ($script:StartUnknown) {
    # No inference of absence, retry, receipt or consuming-cleanup authority.
    # This exact owner fails; the isolated workflow platform owns fail-stop.
    return @{ StartUnknown=$true; FinalityUnknown=$true; Errors=$errors }
  }
  try {
  if ($started) {
    for ($i=0; $i -lt 2; $i++) {
      try {
        $slots[$i].Reader = if ($i -eq 0) { $process.StandardOutput } else { $process.StandardError }
      } catch { $errors[$slots[$i].Name + '-reader'] = $true }
    }
    # Exactly one pending ReadAsync per original endpoint. The byte buffer is
    # not reused until THAT task's original result has been consumed.
    for ($i=0; $i -lt 2; $i++) {
      $slot = $slots[$i]
      if ($null -ne $slot.Reader) {
        try { $slot.Task = $slot.Reader.BaseStream.ReadAsync($slot.Buffer, 0, 4096) }
        catch { $errors[$slot.Name + '-read-start'] = $true }
      }
    }
    foreach ($slot in $slots) {
      if ($null -ne $slot.Reader -and $null -eq $slot.Task) {
        $slot.ReaderCloseAttempted = $true
        try { $slot.Reader.Dispose(); $slot.ReaderClosed = $true } catch { $errors[$slot.Name + '-reader-close'] = $true }
      }
    }
    while ($null -ne $slots[0].Task -or $null -ne $slots[1].Task) {
      $pending = [Collections.Generic.List[Threading.Tasks.Task]]::new()
      $indices = [Collections.Generic.List[int]]::new()
      for ($i=0; $i -lt 2; $i++) {
        if ($null -ne $slots[$i].Task) { $pending.Add($slots[$i].Task); $indices.Add($i) }
      }
      $selected = [Threading.Tasks.Task]::WaitAny($pending.ToArray())
      $slot = $slots[$indices[$selected]]
      $count = -1
      try { $count = $slot.Task.GetAwaiter().GetResult() }
      catch { $errors[$slot.Name + '-read-result'] = $true }
      # GetResult returned or threw: this actual task is settled and consumed.
      $slot.Task = $null
      if ($count -eq 0) { $slot.Eof = $true }
      elseif ($count -gt 0 -and $count -le 4096) {
        $slot.Observed += $count; $observedAggregate += $count
        if ($slot.Observed -gt 65536) { $errors[$slot.Name + '-overflow'] = $true }
        if ($observedAggregate -gt 65536) { $errors['aggregate-overflow'] = $true }
        $keep = [int][Math]::Max(0, [Math]::Min($count, [Math]::Min(65536-$slot.Retained, 65536-$aggregate)))
        if ($keep -gt 0 -and -not $slot.WriteFailed) {
          # One explicit test-only seam closes the ORIGINAL empty owned sink,
          # then the COMMON write really fails. No fabricated error receipt.
          if ($Role -ceq 'probe-writer-fault' -and $slot.Name -ceq 'stdout' -and -not $injected) {
            $injected = $true
            try { $slot.Writer.Flush($true); $slot.FlushReturned = $true }
            catch { $errors['injected-flush'] = $true }
            $slot.WriterCloseAttempted = $true
            try { $slot.Writer.Dispose(); $slot.WriterClosed = $true } catch { $errors['injected-close'] = $true }
          }
          try {
            # Charge the entire attempted write BEFORE entry. A failed write
            # may have persisted a prefix; unconfirmed bytes still use budget.
            $slot.Retained += $keep; $aggregate += $keep
            $slot.Writer.Write($slot.Buffer, 0, $keep)
          } catch {
            $errors[$slot.Name + '-write'] = $true
            $slot.WriteFailed = $true
          }
        }
        # Overflow and sink faults remain latched, but finite reads continue
        # to actual EOF. Discard never becomes accepted/truncated output.
        try { $slot.Task = $slot.Reader.BaseStream.ReadAsync($slot.Buffer, 0, 4096) }
        catch { $errors[$slot.Name + '-read-start'] = $true }
      } else { $errors[$slot.Name + '-read-count'] = $true }
      if ($null -eq $slot.Task -and -not $slot.ReaderCloseAttempted) {
        $slot.ReaderCloseAttempted = $true
        try { $slot.Reader.Dispose(); $slot.ReaderClosed = $true } catch { $errors[$slot.Name + '-reader-close'] = $true }
      }
    }
    # Endpoint failures before a pending task existed must not hide or abandon
    # the other original slot. Close once only after no task can still use it.
    foreach ($slot in $slots) {
      if ($null -ne $slot.Reader -and -not $slot.ReaderCloseAttempted) {
        $slot.ReaderCloseAttempted = $true
        try { $slot.Reader.Dispose(); $slot.ReaderClosed = $true } catch { $errors[$slot.Name + '-reader-close'] = $true }
      }
    }
    try { $process.WaitForExit(); $waitReturned = $true }
    catch { $errors['original-wait'] = $true; $script:OriginalUnknown = $true }
    if (-not $waitReturned) { return @{ StartUnknown=$false; FinalityUnknown=$true; Errors=$errors } }

    if ($waitReturned) {
      try { $exitCode = $process.ExitCode }
      catch { $errors['original-exit-code'] = $true }
    }
  }
  foreach ($slot in $slots) {
    if ($null -ne $slot.Writer -and -not $slot.WriterCloseAttempted) {
      try { $slot.Writer.Flush($true); $slot.FlushReturned = $true }
      catch { $errors[$slot.Name + '-flush'] = $true }
      $slot.WriterCloseAttempted = $true
      try { $slot.Writer.Dispose(); $slot.WriterClosed = $true } catch { $errors[$slot.Name + '-writer-close'] = $true }
    }
  }
  try { $process.Dispose(); $processClosed = $true }
  catch { $errors['process-close'] = $true }
  return @{
    StartUnknown=$false; FinalityUnknown=$false; Started=$started; WaitReturned=$waitReturned; ExitCode=$exitCode;
    ProcessClosed=$processClosed; Slots=$slots; Errors=$errors; Injected=$injected;
    AggregateRetained=$aggregate; AggregateObserved=$observedAggregate
  }
  } catch {
    # An unexpected infrastructure exception must not drop pending tasks or
    # dispose/reopen an unproved original. Exact custody remains script-owned.
    $errors['owner-unexpected'] = $true
    $script:OriginalUnknown = $true
    return @{ StartUnknown=$false; FinalityUnknown=$true; Errors=$errors }
  }
}

try {
  $selection = $env:MRK_DESKTOP_DISPATCH_SCOPE -ceq 'windows-installer-selection'
  $profile = if ($selection) { 'windows-installer-selection-v1' } else { 'windows-installer-retained-shell-v1' }
  $root = [IO.Path]::Combine($env:RUNNER_TEMP, "mrk-windows-installed-native-$($env:GITHUB_RUN_ID)-1")
  Require-Retained ($env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and
    $env:RUNNER_OS -ceq 'Windows' -and $env:RUNNER_ARCH -ceq 'X64' -and $env:ImageOS -ceq 'win25-vs2026' -and
    $env:GITHUB_JOB -ceq 'windows-installed-native' -and $env:GITHUB_RUN_ATTEMPT -ceq '1' -and
    $env:GITHUB_RUN_ID -cmatch '^[1-9][0-9]{0,19}$' -and $env:GITHUB_SHA -cmatch '^[0-9a-f]{40}$' -and
    $env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch' -and
    $env:GITHUB_REF -ceq 'refs/heads/verify/desktop-windows-installer-retained-shell' -and
    $env:MRK_DESKTOP_DISPATCH_SCOPE -cin @('windows-installer-retained-shell','windows-installer-selection') -and
    $env:MRK_DESKTOP_HOSTED_CHECKS -ceq 'windows-installed-native-v1' -and
    $env:MRK_DESKTOP_EXPECTED_SHA -ceq $env:GITHUB_SHA -and $env:GITHUB_WORKFLOW_SHA -ceq $env:GITHUB_SHA -and
    $env:GITHUB_WORKFLOW_REF -ceq ($env:GITHUB_REPOSITORY + '/.github/workflows/desktop-foundation.yml@' + $env:GITHUB_REF) -and
    $env:MRK_DESKTOP_CI_ROOT -ceq $root -and $env:MRK_RETAINED_PREVIOUS_OUTCOME -ceq 'success') 'route'
  $ownerRaw = Read-RetainedBytes ([IO.Path]::Combine($root, 'retained-shell-owner-input.private.json')) 16384
  Require-Retained ((Get-RetainedSha $ownerRaw) -ceq $env:MRK_RETAINED_OWNER_INPUT_SHA256) 'owner-pin'
  $owner = [Text.UTF8Encoding]::new($false,$true).GetString($ownerRaw) | ConvertFrom-Json -AsHashtable -Depth 8
  Require-Retained ($owner.schemaVersion -eq 1 -and $owner.profile -ceq $profile -and
    $owner.sourceSha -ceq $env:GITHUB_SHA -and $owner.runId -ceq $env:GITHUB_RUN_ID -and
    $owner.attempt -eq 1 -and $owner.root -ceq $root -and $owner.source -ceq $env:GITHUB_WORKSPACE -and
    $owner.sourceTree -cmatch '^[0-9a-f]{40}$') 'owner-binding'
  $contextRaw = Read-RetainedBytes ([IO.Path]::Combine($root, 'context.json')) 1048576
  Require-Retained ((Get-RetainedSha $contextRaw) -ceq $owner.contextSha256) 'context-pin'
  $source = $owner.source
  Assert-RetainedFile ([IO.Path]::Combine($source, 'desktop','tools','windows_installer_fixture_owner.ps1')) $owner.owner.size $owner.owner.sha256
  $childEnvironment = [ordered]@{
    SystemRoot=$env:SystemRoot; WINDIR=$env:SystemRoot;
    TEMP=[IO.Path]::Combine($root,'tmp'); TMP=[IO.Path]::Combine($root,'tmp');
    USERPROFILE=[IO.Path]::Combine($root,'home'); HOME=[IO.Path]::Combine($root,'home');
    APPDATA=[IO.Path]::Combine($root,'appdata'); LOCALAPPDATA=[IO.Path]::Combine($root,'localappdata');
    PATH=[IO.Path]::Combine($env:SystemRoot,'System32');
    GITHUB_SHA=$env:GITHUB_SHA; GITHUB_RUN_ID=$env:GITHUB_RUN_ID;
    GITHUB_RUN_ATTEMPT='1'; MRK_WINDOWS_SOURCE_TREE=$owner.sourceTree;
    MRK_DESKTOP_CI_ROOT=$root; MRK_DESKTOP_HOSTED_CHECKS='windows-installed-native-v1';
    MRK_DESKTOP_DISPATCH_SCOPE=$env:MRK_DESKTOP_DISPATCH_SCOPE; MRK_DESKTOP_EXPECTED_SHA=$env:GITHUB_SHA;
    GITHUB_ACTIONS='true'; GITHUB_EVENT_NAME='workflow_dispatch'; GITHUB_JOB='windows-installed-native';
    GITHUB_REF='refs/heads/verify/desktop-windows-installer-retained-shell'; GITHUB_WORKFLOW_SHA=$env:GITHUB_SHA;
    RUNNER_ENVIRONMENT='github-hosted'; RUNNER_OS='Windows'; RUNNER_ARCH='X64'; ImageOS='win25-vs2026';
    RUNNER_TEMP=$env:RUNNER_TEMP

  }
  # Platform-owned job cleanup tracking is not a credential or finality receipt.
  if ($env:RUNNER_TRACKING_ID) {
    Require-Retained ($env:RUNNER_TRACKING_ID.Length -le 128 -and $env:RUNNER_TRACKING_ID -cmatch '^[A-Za-z0-9_-]+$') 'tracking'
    $childEnvironment.RUNNER_TRACKING_ID = $env:RUNNER_TRACKING_ID
  }
  $probe = $Role.StartsWith('probe-', [StringComparison]::Ordinal)
  if ($probe) {
    $probeName = $Role.Substring(6)
    $executable = $owner.python.path
    Require-Retained ($executable -ceq $env:MRK_PYTHON) 'python-path'
    Assert-RetainedFile $executable $owner.python.size $owner.python.sha256
    $emitter = [IO.Path]::Combine($source,'desktop','tools','windows_installer_fixture_pipe_probe.py')
    Assert-RetainedFile $emitter $owner.emitter.size $owner.emitter.sha256
    $arguments = @('-I','-S','-B',$emitter,$probeName)
    $stdoutPath = [IO.Path]::Combine($root, "$Role.stdout.private.bin")
    $stderrPath = [IO.Path]::Combine($root, "$Role.stderr.private.bin")
    $receiptPath = [IO.Path]::Combine($root, "$Role-result.private.json")
  } elseif ($selection) {

    $position = [Array]::IndexOf($script:SelectionRoles,$Role)
    Require-Retained ($position -ge 0 -and $script:SelectionRoles.Count -eq 54) 'selection-role'
    $route = Get-SelectionRoute $Role
    $operation = if ($route[0] -ceq 'app') { 'app' } else { 'native' }
    $preRaw = Read-RetainedBytes ([IO.Path]::Combine($root,'retained-shell-precheck.private.txt')) 16384
    Require-Retained ((Get-RetainedSha $preRaw) -ceq $env:MRK_RETAINED_PRECHECK_SHA256) 'precheck-pin'
    $preKeys = @('profile','sourceSha','sourceTree','runId','attempt','sourceInventorySha256','profilesSha256','rosterSha256',
      'nativeArtifact','nativeArtifactBytes','nativeArtifactSha256','nativeArtifactIdentity','nativeCompileMessagesSha256','nativeCompileArgvSha256',
      'appArtifact','appArtifactBytes','appArtifactSha256','appArtifactIdentity','appCompileMessagesSha256','appCompileArgvSha256','preparedRuntimeSha256')
    $pre = Read-RetainedWire $preRaw 'MRK_WINDOWS_RETAINED_SHELL_PRECHECK_V1' $preKeys
    Require-Retained ($pre.profile -ceq $profile -and $pre.sourceSha -ceq $owner.sourceSha -and
      $pre.sourceTree -ceq $owner.sourceTree -and $pre.runId -ceq $owner.runId -and $pre.attempt -ceq '1' -and
      $pre.sourceInventorySha256 -ceq $owner.sourceInventorySha256) 'precheck-binding'
    $exitKeys = @('profile','sourceSha','sourceTree','runId','attempt','role','artifactSha256','precheckSha256','commandSha256',
      'resultBytes','resultSha256','originalWaitReturned','exitCode','writerCloseGate')
    if ($position -gt 0) { $null = Read-SelectionOriginal ($script:SelectionRoles[$position-1]) }
    $artifactRole = if ($operation -ceq 'app') { 'app' } else { 'native' }
    $executable = $pre[$artifactRole+'Artifact']
    $expectedDeps = [IO.Path]::Combine($root,'target','x86_64-pc-windows-msvc','debug','deps')
    $prefix = if ($artifactRole -ceq 'app') { 'mobile_release_desktop-' } else { 'mrk_windows_installed_native-' }
    Require-Retained ([IO.Path]::GetDirectoryName($executable) -ceq $expectedDeps -and
      [IO.Path]::GetFileName($executable) -cmatch ('^'+$prefix+'[0-9a-f]{16}\.exe$')) 'artifact-role'
    Assert-RetainedFile $executable ([long]$pre[$artifactRole+'ArtifactBytes']) $pre[$artifactRole+'ArtifactSha256']
    $arguments = @($route[1],'--exact','--ignored','--nocapture','--test-threads=1')
    if ($operation -ceq 'app') {
      Require-Retained ($script:SelectionCases.Contains($Role)) 'selection-case'
      $caseData = $script:SelectionCases[$Role]
      if ($null -ne $caseData[2]) {
        $childEnvironment.MRK_WINDOWS_SELECTION_FIXTURE_PREVIEW = Get-SelectionPreview ($caseData[2]) ($caseData[1])
      }
      if ($null -ne $caseData[3]) {
        $stop = $caseData[3]
        $stopRaw = Read-SelectionOriginal $stop
        $recovery = Get-SelectionLine $stopRaw 'MRK_WINDOWS_SELECTION_RECOVERY_V1='
        Require-Retained ($recovery -cmatch '^[0-9a-f]{32}$') 'selection-recovery-name'
        $observed = Read-SelectionHeader ($stop+'-observe')
        $observedRaw = Read-SelectionOriginal ($stop+'-observe')
        $observedText = [Text.Encoding]::ASCII.GetString($observedRaw)
        $expectedFiles = if ($stop -ceq 'stop-old') { @(0,1) } else { @(0,1,2,3) }
        foreach ($index in $expectedFiles) {
          $prefix = 'observed=selection/recovery/'+$recovery+'/record-'+$index.ToString('00')+'.bin|file|'
          Require-Retained (@($observedText.Split([char]10) | Where-Object {
            $_.StartsWith($prefix,[StringComparison]::Ordinal) }).Count -eq 1) 'selection-recovery-owned-record'
        }
        $childEnvironment.MRK_WINDOWS_SELECTION_FIXTURE_RECOVERY = $recovery
      }
      if ($caseData[5]) {
        $stage = Read-SelectionHeader ('stage-'+$caseData[0])
        Require-Retained ($stage.candidate -cmatch '^[A-Za-z]:\\.+\\MRK Installer Fixture [0-9a-f]{64}$' -and
          $stage.candidate.StartsWith($stage.programFiles+'\MRK Installer Fixture ',[StringComparison]::Ordinal)) 'selection-staged-source'
        $childEnvironment.MRK_WINDOWS_RETAINED_FIXTURE_SOURCE = $stage.candidate
      }
    }
    $resultPath = [IO.Path]::Combine($root,"retained-$Role.private.txt")
    $stdoutPath = if ($operation -ceq 'app') { $resultPath } else { [IO.Path]::Combine($root,"retained-$Role.stdout.private.bin") }
    $stderrPath = [IO.Path]::Combine($root,"retained-$Role.stderr.private.bin")
    $receiptPath = [IO.Path]::Combine($root,"retained-$Role-exit.private.txt")
    Require-Retained (-not [IO.File]::Exists($resultPath) -and -not [IO.Directory]::Exists($resultPath)) 'result-collision'
  } else {
    $cases = @('fresh','reuse','stop-copy','wrong-caller','bad-manifest')
    $roles = @('stage','app','observe')
    $chain = [Collections.Generic.List[string]]::new()
    foreach ($caseName in $cases) {
      $chain.Add("$caseName-stage")
      if ($caseName -ceq 'bad-manifest') { $chain.Add('bad-manifest-corrupt') }
      $chain.Add("$caseName-app"); $chain.Add("$caseName-observe")
    }
    $position = $chain.IndexOf($Role)
    Require-Retained ($position -ge 0 -and $chain.Count -eq 16) 'role'
    $caseName = $Role.Substring(0,$Role.LastIndexOf('-'))
    $operation = $Role.Substring($Role.LastIndexOf('-')+1)
    $preRaw = Read-RetainedBytes ([IO.Path]::Combine($root,'retained-shell-precheck.private.txt')) 16384
    Require-Retained ((Get-RetainedSha $preRaw) -ceq $env:MRK_RETAINED_PRECHECK_SHA256) 'precheck-pin'
    $preKeys = @('profile','sourceSha','sourceTree','runId','attempt','sourceInventorySha256','profilesSha256','rosterSha256',
      'nativeArtifact','nativeArtifactBytes','nativeArtifactSha256','nativeArtifactIdentity','nativeCompileMessagesSha256','nativeCompileArgvSha256',
      'appArtifact','appArtifactBytes','appArtifactSha256','appArtifactIdentity','appCompileMessagesSha256','appCompileArgvSha256','preparedRuntimeSha256')
    $pre = Read-RetainedWire $preRaw 'MRK_WINDOWS_RETAINED_SHELL_PRECHECK_V1' $preKeys
    Require-Retained ($pre.profile -ceq $profile -and $pre.sourceSha -ceq $owner.sourceSha -and
      $pre.sourceTree -ceq $owner.sourceTree -and $pre.runId -ceq $owner.runId -and $pre.attempt -ceq '1' -and
      $pre.sourceInventorySha256 -ceq $owner.sourceInventorySha256) 'precheck-binding'
    $exitKeys = @('profile','sourceSha','sourceTree','runId','attempt','role','artifactSha256','precheckSha256','commandSha256',
      'resultBytes','resultSha256','originalWaitReturned','exitCode','writerCloseGate')
    if ($position -gt 0) {
      $previous = $chain[$position-1]
      $priorRaw = Read-RetainedBytes ([IO.Path]::Combine($root,"retained-$previous-exit.private.txt")) 8192
      $prior = Read-RetainedWire $priorRaw 'MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1' $exitKeys
      Require-Retained ($prior.role -ceq $previous -and $prior.profile -ceq $profile -and
        $prior.sourceSha -ceq $owner.sourceSha -and $prior.sourceTree -ceq $owner.sourceTree -and
        $prior.runId -ceq $owner.runId -and $prior.attempt -ceq '1' -and
        $prior.precheckSha256 -ceq (Get-RetainedSha $preRaw) -and $prior.originalWaitReturned -ceq 'true' -and
        $prior.exitCode -ceq '0' -and $prior.writerCloseGate -ceq 'original-owner-closed-output') 'predecessor-record'
    }
    $artifactRole = if ($operation -ceq 'app') { 'app' } else { 'native' }
    $executable = $pre[$artifactRole+'Artifact']
    $expectedDeps = [IO.Path]::Combine($root,'target','x86_64-pc-windows-msvc','debug','deps')
    $prefix = if ($artifactRole -ceq 'app') { 'mobile_release_desktop-' } else { 'mrk_windows_installed_native-' }
    Require-Retained ([IO.Path]::GetDirectoryName($executable) -ceq $expectedDeps -and
      [IO.Path]::GetFileName($executable) -cmatch ('^'+$prefix+'[0-9a-f]{16}\.exe$')) 'artifact-role'
    Assert-RetainedFile $executable ([long]$pre[$artifactRole+'ArtifactBytes']) $pre[$artifactRole+'ArtifactSha256']
    $selector = if ($operation -ceq 'app') {
      'windows_installer_controller::retained_fixture::owned_' + $caseName.Replace('-','_')
    } elseif ($operation -ceq 'corrupt') {
      'qualification_fixture::installer::corrupt_owned_manifest_last'
    } else { 'qualification_fixture::installer::'+$operation+'_'+$caseName.Replace('-','_') }
    $arguments = @($selector,'--exact','--ignored','--nocapture','--test-threads=1')
    if ($operation -ceq 'app') {
      $stageRaw = Read-RetainedBytes ([IO.Path]::Combine($root,"retained-$caseName-stage.private.txt")) 65536
      $stageText = [Text.UTF8Encoding]::new($false,$true).GetString($stageRaw)
      $snapKeys = @('profile','sourceSha','sourceTree','runId','attempt','case','phase','precheckSha256',
        'profilesSha256','rosterSha256','image','manifest','candidate','freshMrkAbsent','objects',
        'fileOriginals','fileOriginalsClosed','parentBookSettled','unknown','resultCloseGate')
      $stageLines = $stageText.Split([char]10)
      Require-Retained ($stageLines.Count -gt $snapKeys.Count) 'stage-frame'
      $headerRaw = [Text.Encoding]::UTF8.GetBytes(($stageLines[0..$snapKeys.Count] -join "`n")+"`n")
      $stage = Read-RetainedWire $headerRaw 'MRK_WINDOWS_RETAINED_SHELL_SNAPSHOT_V1' $snapKeys
      $stageExitRaw = Read-RetainedBytes ([IO.Path]::Combine($root,"retained-$caseName-stage-exit.private.txt")) 8192
      $stageExit = Read-RetainedWire $stageExitRaw 'MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1' $exitKeys
      Require-Retained ($stage.case -ceq $caseName -and $stage.phase -ceq 'stage' -and
        $stage.precheckSha256 -ceq (Get-RetainedSha $preRaw) -and $stage.profile -ceq $profile -and
        $stage.sourceSha -ceq $owner.sourceSha -and $stage.sourceTree -ceq $owner.sourceTree -and
        $stage.runId -ceq $owner.runId -and $stage.attempt -ceq '1' -and
        $stage.unknown -ceq 'false' -and $stage.parentBookSettled -ceq 'true' -and
        $stageExit.role -ceq "$caseName-stage" -and $stageExit.exitCode -ceq '0' -and
        $stageExit.resultSha256 -ceq (Get-RetainedSha $stageRaw) -and [long]$stageExit.resultBytes -eq $stageRaw.Length) 'stage-result'
      # Only a source hint from the genuine native stage. The app's original
      # acquisition still derives and admits protected paths/identities itself.
      $childEnvironment.MRK_WINDOWS_RETAINED_FIXTURE_SOURCE = $stage.candidate
    }
    $resultPath = [IO.Path]::Combine($root,"retained-$Role.private.txt")
    $stdoutPath = if ($operation -ceq 'app') { $resultPath } else { [IO.Path]::Combine($root,"retained-$Role.stdout.private.bin") }
    $stderrPath = [IO.Path]::Combine($root,"retained-$Role.stderr.private.bin")
    $receiptPath = [IO.Path]::Combine($root,"retained-$Role-exit.private.txt")
    Require-Retained (-not [IO.File]::Exists($resultPath) -and -not [IO.Directory]::Exists($resultPath)) 'result-collision'
  }
  Require-Retained (-not [IO.File]::Exists($receiptPath) -and -not [IO.Directory]::Exists($receiptPath)) 'receipt-collision'
  $script:RawResult = Invoke-RetainedOriginal
  Require-Retained (-not $script:RawResult.StartUnknown) 'original-start-unknown'
  Require-Retained (-not $script:RawResult.FinalityUnknown) 'original-finality-unknown'
  $r = $script:RawResult
  Require-Retained ($r.Started -and $r.WaitReturned -and $r.ExitCode -eq 0 -and $r.ProcessClosed -and
    $r.Slots[0].Eof -and $r.Slots[1].Eof -and $r.Slots[0].ReaderClosed -and $r.Slots[1].ReaderClosed -and
    $r.Slots[0].WriterClosed -and $r.Slots[1].WriterClosed -and
    $r.Slots[0].FlushReturned -and $r.Slots[1].FlushReturned) 'original-not-settled'
  if ($probe) {
    $stdout = Read-RetainedBytes $stdoutPath 65536
    $stderr = Read-RetainedBytes $stderrPath 65536
    $expectedErrors = if ($probeName -ceq 'overflow') { @('aggregate-overflow','stdout-overflow') }
      elseif ($probeName -ceq 'writer-fault') { @('stdout-write') } else { @() }
    $actualErrors = @($r.Errors.Keys | Sort-Object)
    Require-Retained (($actualErrors -join ',') -ceq ($expectedErrors -join ',')) 'probe-failure-set'
    $outBytes = if ($probeName -ceq 'overflow') { 65536 } elseif ($probeName -ceq 'writer-fault') { 0 } else { 30720 }
    $errBytes = if ($probeName -ceq 'overflow') { 0 } else { 30720 }
    $expectedOut = [Text.Encoding]::ASCII.GetBytes(('O' * $outBytes))
    $expectedErr = [Text.Encoding]::ASCII.GetBytes(('E' * $errBytes))
    Require-Retained ($stdout.Length -eq $outBytes -and $stderr.Length -eq $errBytes -and
      (Get-RetainedSha $stdout) -ceq (Get-RetainedSha $expectedOut) -and
      (Get-RetainedSha $stderr) -ceq (Get-RetainedSha $expectedErr) -and
      $r.Slots[0].Observed -eq $(if ($probeName -ceq 'overflow') { 81920 } else { 30720 }) -and
      $r.Slots[1].Observed -eq $errBytes -and $r.Injected -eq ($probeName -ceq 'writer-fault')) 'probe-bytes'
    $record = [ordered]@{
      schemaVersion=1; profile=$profile; sourceSha=$owner.sourceSha; sourceTree=$owner.sourceTree;
      runId=$owner.runId; attempt=1; probe=$probeName; ownerInputSha256=(Get-RetainedSha $ownerRaw);
      stdoutBytes=$stdout.Length; stdoutSha256=(Get-RetainedSha $stdout);
      stderrBytes=$stderr.Length; stderrSha256=(Get-RetainedSha $stderr);
      stdoutObserved=$r.Slots[0].Observed; stderrObserved=$r.Slots[1].Observed;
      errors=$actualErrors; originalWaitReturned=$true; exitCode=0; bothEof=$true;
      readersClosed=$true; writersClosed=$true; processClosed=$true;
      behavioralAcceptance=$false; refusalExpected=($probeName -cne 'balanced')
    }
    $receipt = [Text.UTF8Encoding]::new($false,$true).GetBytes(($record | ConvertTo-Json -Depth 4 -Compress)+"`n")
  } else {
    Require-Retained ($r.Errors.Count -eq 0 -and $r.Slots[1].Observed -eq 0) 'behavioral-output-failed'
    $result = Read-RetainedBytes $resultPath 65536
    $testOutput = if ($operation -ceq 'app') { $result } else { Read-RetainedBytes $stdoutPath 65536 }
    $testText = [Text.UTF8Encoding]::new($false,$true).GetString($testOutput)
    Require-Retained ([regex]::Matches($testText,'(?m)^running 1 test\r?$').Count -eq 1 -and
      [regex]::Matches($testText,'(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$').Count -eq 1) 'one-actual-test'
    $command = '"'+$executable+'" '+($arguments -join ' ')
    $commandSha = Get-RetainedSha ([Text.Encoding]::Unicode.GetBytes($command))
    $lines = @('MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1',"profile=$profile",
      "sourceSha=$($owner.sourceSha)","sourceTree=$($owner.sourceTree)","runId=$($owner.runId)",'attempt=1',
      "role=$Role","artifactSha256=$($pre[$artifactRole+'ArtifactSha256'])","precheckSha256=$(Get-RetainedSha $preRaw)",
      "commandSha256=$commandSha","resultBytes=$($result.Length)","resultSha256=$(Get-RetainedSha $result)",
      'originalWaitReturned=true','exitCode=0','writerCloseGate=original-owner-closed-output')
    $receipt = [Text.UTF8Encoding]::new($false,$true).GetBytes(($lines -join "`n")+"`n")
  }
  Close-RetainedInputs
  Require-Retained ($script:InputErrors.Count -eq 0) 'input-finality'
  Write-RetainedReceipt $receiptPath $receipt
  # THIS subsequent actual workflow step success, not the file, permits a successor.
  exit 0
} catch {
  if (-not $script:StartUnknown -and -not $script:OriginalUnknown) { Close-RetainedInputs }
  [Console]::Error.WriteLine('MRK_WINDOWS_RETAINED_OWNER_REFUSED=original-or-binding-or-finality')
  exit 1
}
