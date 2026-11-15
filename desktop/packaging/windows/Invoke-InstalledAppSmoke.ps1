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
# (correctly) admits only an ordinary, non-elevated, medium-integrity token,
# which is what Explorer gives a real user. Launch it like that: a SAFER
# "Normal User" token (same as runas /trustlevel:0x20000) with an explicit
# Medium label, on the interactive desktop, stderr captured as evidence.
# The app's own admission checks are unchanged.
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class MrkOrdinaryLaunch {
  [DllImport("advapi32", SetLastError=true)] static extern bool SaferCreateLevel(uint scope, uint level, uint flags, out IntPtr h, IntPtr r);
  [DllImport("advapi32", SetLastError=true)] static extern bool SaferComputeTokenFromLevel(IntPtr level, IntPtr inTok, out IntPtr outTok, uint flags, IntPtr r);
  [DllImport("advapi32", SetLastError=true)] static extern bool SaferCloseLevel(IntPtr h);
  [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ConvertStringSidToSidW(string s, out IntPtr sid);
  [DllImport("advapi32")] static extern int GetLengthSid(IntPtr sid);
  [DllImport("advapi32", SetLastError=true)] static extern bool SetTokenInformation(IntPtr t, int cls, IntPtr info, int len);
  [DllImport("advapi32", SetLastError=true)] static extern bool GetTokenInformation(IntPtr t, int cls, out int value, int len, out int ret);
  [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessAsUserW(IntPtr tok, string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32", SetLastError=true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
  [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr p);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  public static int Elevated, ElevationType;
  static void Need(bool ok, string what) { if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), what); }
  public static int Start(string exe, string dir, IntPtr stdio) {
    IntPtr level, tok, sid;
    Need(SaferCreateLevel(2, 0x20000, 1, out level, IntPtr.Zero), "SaferCreateLevel");
    try { Need(SaferComputeTokenFromLevel(level, IntPtr.Zero, out tok, 0, IntPtr.Zero), "SaferComputeTokenFromLevel"); } finally { SaferCloseLevel(level); }
    try {
      Need(ConvertStringSidToSidW("S-1-16-8192", out sid), "ConvertStringSidToSid");
      IntPtr label = Marshal.AllocHGlobal(16);
      try {
        Marshal.WriteIntPtr(label, 0, sid); Marshal.WriteInt32(label, 8, 0x20); // SE_GROUP_INTEGRITY
        Need(SetTokenInformation(tok, 25, label, 16 + GetLengthSid(sid)), "SetTokenInformation(IntegrityLevel)");
      } finally { Marshal.FreeHGlobal(label); LocalFree(sid); }
      int ret; GetTokenInformation(tok, 20, out Elevated, 4, out ret); GetTokenInformation(tok, 18, out ElevationType, 4, out ret);
      Need(SetHandleInformation(stdio, 1, 1), "SetHandleInformation");
      var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si); si.lpDesktop = "winsta0\\default";
      si.dwFlags = 0x100; si.hStdOutput = stdio; si.hStdError = stdio; si.hStdInput = IntPtr.Zero;
      PROCESS_INFORMATION pi;
      Need(CreateProcessAsUserW(tok, exe, new StringBuilder("\"" + exe + "\""), IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, dir, ref si, out pi), "CreateProcessAsUser");
      CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
      return pi.dwProcessId;
    } finally { CloseHandle(tok); }
  }
}
'@
function StartOrdinary($exe, $label) {
  $errPath = Join-Path $Evidence "$label-stderr.txt"
  $fs = [System.IO.File]::Open($errPath, 'Create', 'Write', 'ReadWrite')
  try { $id = [MrkOrdinaryLaunch]::Start($exe, (Split-Path $exe), $fs.SafeFileHandle.DangerousGetHandle()) } finally { $fs.Dispose() }
  $p = [System.Diagnostics.Process]::GetProcessById($id); $null = $p.Handle  # keep a handle so ExitCode stays readable
  Step "$label-token" @{ pid = $id; elevated = [MrkOrdinaryLaunch]::Elevated; elevationType = [MrkOrdinaryLaunch]::ElevationType; integrity = 'S-1-16-8192 (medium)'; saferLevel = 'NormalUser' }
  return $p
}
function StderrText($label) { $f = Join-Path $Evidence "$label-stderr.txt"; if (Test-Path $f) { ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + '').Trim() } else { '' } }

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
