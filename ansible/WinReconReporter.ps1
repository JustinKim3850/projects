<#
WinReconReporter.ps1
Author: Justin Kim
Purpose: Collect key Windows host reconnaissance data, including users, processes, and services.
         Saves results to the current user's Downloads folder.
#>

param(
    [string]$Target = "",
    [System.Management.Automation.PSCredential]$Credential = $null,
    [string]$ProcessList = "",
    [int]$TimeoutSeconds = 30
)

function Log {
    param($msg)
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "[$t] $msg"
}

$IsRemote = ($Target -ne "" -and $Target -ne $env:COMPUTERNAME -and $Target -ne "localhost")
$Downloads = Join-Path $env:USERPROFILE "Downloads"
if (-not (Test-Path $Downloads)) { New-Item -Path $Downloads -ItemType Directory | Out-Null }

$timestamp = (Get-Date -Format "yyyy-MM-dd_HHmmss")
$outPath = Join-Path $Downloads "WinReconReport_$timestamp.txt"

$collectScript = {
    param($ProcessList)

    function SafeInvoke { param($code) try { & $code } catch { "ERROR: $($_.Exception.Message)" } }

    $report = @()

    # --- System Info ---
    $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, LastBootUpTime
    $sys = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Domain, UserName
    $report += "=== System Information ==="
    $report += "Hostname: $env:COMPUTERNAME"
    $report += "OS: $($os.Caption)"
    $report += "Version: $($os.Version)"
    $report += "Architecture: $($os.OSArchitecture)"
    $report += "Domain: $($sys.Domain)"
    $report += "User: $($sys.UserName)"
    $report += "Last Boot: $($os.LastBootUpTime)"
    $report += ""

    $users = SafeInvoke { Get-LocalUser | Sort-Object Name }
    $report += "=== Local Users (Alphabetical) ==="
    foreach ($u in $users) {
        $report += "{0,-25} Enabled: {1}" -f $u.Name, $u.Enabled
    }
    $report += ""

    $procs = SafeInvoke { Get-Process | Sort-Object ProcessName }
    $report += "=== Running Processes (Alphabetical) ==="
    foreach ($p in $procs) {
        try {
            $desc = ""
            try { $desc = $p.MainModule.FileVersionInfo.FileDescription } catch {}
            $report += ("PID: {0,-6}  ProcessName: {1,-30}  DisplayName: {2}" -f $p.Id, $p.ProcessName, $desc)
        } catch {}
    }
    $report += ""

    $services = SafeInvoke { Get-Service | Sort-Object Name }
    $report += "=== Services (Alphabetical) ==="
    foreach ($s in $services) {
        $report += ("{0,-40} Status: {1,-10} StartType: {2}" -f $s.DisplayName, $s.Status, $s.StartType)
    }
    $report += ""

    if ($ProcessList -and $ProcessList.Trim() -ne "") {
        $names = $ProcessList.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        $report += "=== Custom Process Check ==="
        foreach ($n in $names) {
            $proc = Get-Process -Name $n -ErrorAction SilentlyContinue
            if ($proc) {
                $pids = ($proc | Select-Object -ExpandProperty Id) -join ", "
                $report += "Process '$n' is RUNNING (PID: $pids)"
            } else {
                $report += "Process '$n' is NOT running"
            }
        }
        $report += ""
    }

    $Downloads = Join-Path $env:USERPROFILE "Downloads"
    if (-not (Test-Path $Downloads)) { New-Item -Path $Downloads -ItemType Directory | Out-Null }
    $timestamp = (Get-Date -Format "yyyy-MM-dd_HHmmss")
    $outFile = Join-Path $Downloads "WinReconReport_$timestamp.txt"
    $report | Out-File -FilePath $outFile -Encoding UTF8
    return "Report saved to $outFile"
}

try {
    if ($IsRemote) {
        Log "Running remotely on $Target..."
        $params = @{
            ComputerName = $Target
            ScriptBlock  = $collectScript
            ArgumentList = @($ProcessList)
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $params['Credential'] = $Credential }
        $result = Invoke-Command @params
        Log $result
    } else {
        Log "Running locally..."
        & $collectScript $ProcessList
    }
} catch {
    Log "Error: $($_.Exception.Message)"
}

Log "Done."
