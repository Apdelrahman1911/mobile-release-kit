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
# Hosted runners execute every step as an ELEVATED administrator, but the app
# (correctly) admits only the ordinary, non-elevated token Explorer gives a real
# user. A SAFER token derived from the elevated token still reports elevated
# (run 43730392908), so ask Task Scheduler to start it for the logged-on runner
# account with RunLevel Limited: the account's own filtered (UAC) token, in its
# interactive session. stderr is captured as evidence. App checks unchanged.
$script:ErrPaths = @{}
$script:Mode = 'limited-task'
# The hosted runner account is the built-in Administrator (RID 500), which is
# exempt from UAC filtering: RunLevel Limited still yields a High token (run
# 43735533769 whoami). Fallback: a disposable STANDARD local user, started by
# the secondary-logon service on this same interactive desktop (as runas does).
# Its random password is generated here, never printed, and the runner is
# discarded after the job.
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class MrkLogonLaunch {
  [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithLogonW(string user, string domain, string password, uint logonFlags, string app, StringBuilder cmd, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32", SetLastError=true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  public static int Start(string user, string password, string exe, string dir, IntPtr stdio) {
    // lpDesktop stays NULL: only then does the secondary-logon service grant the
    // new logon SID access to this interactive window station and desktop
    // (an explicit desktop failed with 0xC0000142 in run 43735533769).
    var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
    if (stdio != IntPtr.Zero) { SetHandleInformation(stdio, 1, 1); si.dwFlags = 0x100; si.hStdOutput = stdio; si.hStdError = stdio; }
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithLogonW(user, ".", password, 1 /*LOGON_WITH_PROFILE*/, exe, new StringBuilder("\"" + exe + "\""), 0, IntPtr.Zero, dir, ref si, out pi))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithLogonW");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return pi.dwProcessId;
  }
}
'@
$script:StdUser = 'mrksmoke'; $script:StdPassword = $null
function EnsureStandardUser {
  if ($script:StdPassword) { return }
  $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
  $script:StdPassword = (-join (1..24 | ForEach-Object { $chars[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })) + 'a7#Q'
  $null = & net.exe user $script:StdUser $script:StdPassword /add /y 2>&1
  if ($LASTEXITCODE) { throw 'standard test user could not be created' }
  $groups = (& net.exe user $script:StdUser) -join ' '
  Step 'standard-user' @{ user = $script:StdUser; administrator = ($groups -match '\*Administrators') }
}
function RunLimitedCapture($label, $cmdline, $out) {
  $task = "MRK-smoke-$label"
  $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/d /c $cmdline > `"$out`" 2>&1"
  $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName $task
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do { Start-Sleep -Milliseconds 500 } while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
  Start-Sleep -Seconds 1
}
function StartOrdinary($exe, $label) {
  $dir = Join-Path $env:TEMP 'mrk-smoke'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $err = Join-Path $dir "$label-stderr.txt"; Remove-Item $err -ErrorAction SilentlyContinue; $script:ErrPaths[$label] = $err
  $before = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | ForEach-Object Id)
  if ($script:Mode -eq 'standard-user') {
    EnsureStandardUser
    $fs = [System.IO.File]::Open($err, 'Create', 'Write', 'ReadWrite')
    try { $id = [MrkLogonLaunch]::Start($script:StdUser, $script:StdPassword, $exe, (Split-Path $exe), $fs.SafeFileHandle.DangerousGetHandle()) } finally { $fs.Dispose() }
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (!$p) { Start-Sleep -Milliseconds 300; $e = StderrText $label; Step "$label-launch" @{ exited = $true; stderr = $e; launcher = 'standard user via secondary logon' }; throw "$label exited before showing a window: $e" }
    $null = $p.Handle
    Step "$label-token" @{ pid = $id; launcher = 'standard user via secondary logon'; account = $script:StdUser }
    return $p
  }
  $task = "MRK-smoke-$label"
  $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/d /c `"`"$exe`" 2>`"$err`"`"" -WorkingDirectory (Split-Path $exe)
  $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
  Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName $task
  $p = $null; $deadline = [DateTime]::UtcNow.AddSeconds(45); $sawRunning = $false
  while (!$p -and [DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Milliseconds 200
    $p = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe -and $before -notcontains $_.Id } | Select-Object -First 1
    $state = (Get-ScheduledTask -TaskName $task).State
    if ($state -eq 'Running') { $sawRunning = $true } elseif ($sawRunning -and !$p) { break }
  }
  if (!$p) {
    Start-Sleep -Seconds 1
    $info = Get-ScheduledTaskInfo -TaskName $task; $e = StderrText $label
    Step "$label-launch" @{ exited = $true; exitCode = $info.LastTaskResult; stderr = $e; launcher = 'TaskScheduler RunLevel Limited' }
    if ($e -match 'non-elevated') {
      # Evidence of the token Task Scheduler actually gave, then fall back.
      RunLimitedCapture 'whoami' 'whoami /all' (Join-Path $Evidence 'limited-task-whoami.txt')
      $script:Mode = 'standard-user'
      return StartOrdinary $exe "$label-standard-user"
    }
    throw "$label exited before showing a window (task result $($info.LastTaskResult)): $e"
  }
  $null = $p.Handle  # keep a handle so ExitCode stays readable
  Step "$label-token" @{ pid = $p.Id; launcher = 'TaskScheduler RunLevel Limited'; account = "$env:USERDOMAIN\$env:USERNAME" }
  return $p
}
function StderrText($label) {
  $f = $script:ErrPaths[$label]
  if ($f -and (Test-Path $f)) { Copy-Item $f (Join-Path $Evidence "$label-stderr.txt") -Force -ErrorAction SilentlyContinue; ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + '').Trim() } else { '' }
}

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
function AnswerQuit($proc, $label) {
  # The shipped app always asks before quitting. Answer it like a user: OK.
  $A = [System.Windows.Automation.AutomationElement]; $T = [System.Windows.Automation.TreeScope]
  $byPid = New-Object System.Windows.Automation.PropertyCondition($A::ProcessIdProperty, $proc.Id)
  $okCond = New-Object System.Windows.Automation.AndCondition(
    (New-Object System.Windows.Automation.PropertyCondition($A::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
    (New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, 'OK')))
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  while (!$proc.HasExited -and [DateTime]::UtcNow -lt $deadline) {
    try {
      foreach ($w in $A::RootElement.FindAll($T::Children, $byPid)) {
        $quit = $w.FindFirst($T::Subtree, (New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, 'Quit and discard unsaved drafts?')))
        if (!$quit) { continue }
        $ok = $w.FindFirst($T::Descendants, $okCond)
        if ($ok) {
          Shot "$label-quit-confirmation"
          $ok.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
          return $true
        }
      }
    } catch { }
    Start-Sleep -Milliseconds 500; $proc.Refresh()
  }
  return $false
}
function Session($label) {
  $exe = $result.installedExecutable
  $p = StartOrdinary $exe $label
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do { Start-Sleep -Milliseconds 500; $p.Refresh() } while (!$p.HasExited -and $p.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline)
  if ($p.HasExited) { $e = StderrText $label; Step "$label-launch" @{ exited = $true; exitCode = $p.ExitCode; stderr = $e }; throw "$label exited before showing a window: $e" }
  if ($p.MainWindowHandle -eq 0) { Shot "$label-no-window"; throw "$label showed no window within 60 s" }
  Start-Sleep -Seconds 25; $p.Refresh()   # let the bundled runtime start and the UI render
  if ($p.HasExited) { $e = StderrText $label; Step "$label-after-start" @{ exitCode = $p.ExitCode; stderr = $e }; throw "$label exited during startup: $e" }
  Shot "$label-running"
  $text = UiText $p
  $text | Set-Content (Join-Path $Evidence "$label-ui-text.txt") -Encoding utf8
  Step "$label-running" @{ pid = $p.Id; title = $p.MainWindowTitle; uiTextCount = $text.Count; workingSetBytes = $p.WorkingSet64 }
  $closed = $p.CloseMainWindow()
  $answered = AnswerQuit $p $label
  Step "$label-quit-confirmation" @{ shown = $answered; clickedOk = $answered }
  $exited = $p.WaitForExit(60000)
  if (!$exited) { Shot "$label-close-pending"; $text2 = UiText $p; $text2 | Set-Content (Join-Path $Evidence "$label-close-ui-text.txt") -Encoding utf8 }
  Step "$label-close" @{ closeMessageSent = $closed; exitedWithin60s = $exited; exitCode = $(if ($exited) { $p.ExitCode } else { $null }) }
  if (!$exited) { $p.Kill(); throw "$label did not exit within 60 s after close and OK" }
  if ($p.ExitCode -ne 0) { throw "$label exited with $($p.ExitCode) after quit" }
  $left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith((Split-Path $exe), [StringComparison]::OrdinalIgnoreCase) })
  Step "$label-after-exit" @{ remainingProductProcesses = $left.Count }
}
try {
  $msi = Join-Path $Stage 'MobileReleaseKit-NONSHIPPING.msi'; $mst = Join-Path $Stage 'DISPOSABLE-VALIDATION-ONLY.mst'
  Step 'inputs' @{ msiSha256 = (Get-FileHash $msi -Algorithm SHA256).Hash; mstSha256 = (Get-FileHash $mst -Algorithm SHA256).Hash; runnerEnableLua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA }
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
