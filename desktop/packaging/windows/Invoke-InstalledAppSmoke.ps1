# Disposable hosted-runner observation of the ACTUAL installed Desktop app.
# Installs the exact built MSI with the recorded test-only transform, launches
# the installed executable as the ordinary runner session, records window/UI
# text/screenshot, requests a normal close, reopens, closes again, uninstalls.
# Observation only: it never edits the MSI, never qualifies shipping and never
# runs on an owner machine.
param(
  [Parameter(Mandatory=$true)][string]$Stage,
  [Parameter(Mandatory=$true)][string]$Evidence
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') { throw 'Disposable hosted runner required' }
New-Item -ItemType Directory -Path $Evidence | Out-Null
Add-Type -AssemblyName System.Drawing, System.Windows.Forms, UIAutomationClient, UIAutomationTypes

$result = [ordered]@{ schema = 1; steps = @(); installedExecutable = $null; shippingQualified = $false; firstFailure = $null }
function Step($name, $data) { $result.steps += [ordered]@{ name = $name; utc = [DateTime]::UtcNow.ToString('o'); data = $data } }
function Save { $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Evidence 'result.json') -Encoding utf8 }
function Shot($name) {
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $bmp.Save((Join-Path $Evidence "$name.png"), [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
}
function UiText($proc) {
  $names = New-Object System.Collections.Generic.List[string]
  try {
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
    $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($e in $all) { $n = $e.Current.Name; if ($n -and $n.Length -le 300 -and $names.Count -lt 400) { $names.Add($n) } }
  } catch { $names.Add('UIA-UNAVAILABLE: ' + $_.Exception.GetType().Name) }
  return ,$names.ToArray()
}
function Session($label) {
  $exe = $result.installedExecutable
  $p = Start-Process -FilePath $exe -PassThru
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do { Start-Sleep -Milliseconds 500; $p.Refresh() } while (!$p.HasExited -and $p.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline)
  if ($p.HasExited) { Step "$label-launch" @{ exited = $true; exitCode = $p.ExitCode }; throw "$label exited before showing a window" }
  if ($p.MainWindowHandle -eq 0) { Shot "$label-no-window"; throw "$label showed no window within 60 s" }
  Start-Sleep -Seconds 25; $p.Refresh()   # let the bundled runtime start and the UI render
  if ($p.HasExited) { Step "$label-after-start" @{ exitCode = $p.ExitCode }; throw "$label exited during startup" }
  Shot "$label-running"
  $text = UiText $p
  $text | Set-Content (Join-Path $Evidence "$label-ui-text.txt") -Encoding utf8
  Step "$label-running" @{ pid = $p.Id; title = $p.MainWindowTitle; uiTextCount = $text.Count; workingSetBytes = $p.WorkingSet64 }
  $closed = $p.CloseMainWindow()
  $exited = $p.WaitForExit(30000)
  if (!$exited) { Shot "$label-close-pending"; $text2 = UiText $p; $text2 | Set-Content (Join-Path $Evidence "$label-close-ui-text.txt") -Encoding utf8 }
  Step "$label-close" @{ closeMessageSent = $closed; exitedWithin30s = $exited; exitCode = $(if ($exited) { $p.ExitCode } else { $null }) }
  if (!$exited) { $p.Kill(); throw "$label did not exit within 30 s after a normal close request" }
  $left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith((Split-Path $exe), [StringComparison]::OrdinalIgnoreCase) })
  Step "$label-after-exit" @{ remainingProductProcesses = $left.Count }
}
try {
  $msi = Join-Path $Stage 'MobileReleaseKit-NONSHIPPING.msi'; $mst = Join-Path $Stage 'DISPOSABLE-VALIDATION-ONLY.mst'
  Step 'inputs' @{ msiSha256 = (Get-FileHash $msi -Algorithm SHA256).Hash; mstSha256 = (Get-FileHash $mst -Algorithm SHA256).Hash }
  $log = Join-Path $Evidence 'install.log'
  $i = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", "TRANSFORMS=`"$mst`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
  Step 'install' @{ exitCode = $i.ExitCode }
  if ($i.ExitCode -ne 0) { throw "msiexec install returned $($i.ExitCode)" }
  $exe = Join-Path ${env:ProgramFiles} 'Mobile Release Kit\mobile-release-kit-desktop.exe'
  if (!(Test-Path $exe)) { throw 'Installed executable missing' }
  $result.installedExecutable = $exe
  Step 'installed' @{ exeSha256 = (Get-FileHash $exe -Algorithm SHA256).Hash; files = @(Get-ChildItem (Split-Path $exe) -Recurse -File).Count }
  Session 'first-launch'
  Session 'reopen'
  $u = Start-Process msiexec.exe -ArgumentList @('/x', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$(Join-Path $Evidence 'uninstall.log')`"") -Wait -PassThru
  Step 'uninstall' @{ exitCode = $u.ExitCode; executableRemains = (Test-Path $exe) }
  if ($u.ExitCode -ne 0) { throw "msiexec uninstall returned $($u.ExitCode)" }
} catch {
  $result.firstFailure = $_.Exception.Message
  try { Shot 'failure' } catch {}
  Save; throw
}
Save
