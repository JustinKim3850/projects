<#
WinReconReporter.ps1
Author: Justin Kim <jyk3850@g.rit.edu>
Purpose: Collect reconnaissance info from a local or remote Windows host and save as JSON and plain text.
         Use -Target to specify IP or hostname.

Notes:
- Remote collection uses PowerShell Remoting (Invoke-Command). Ensure WinRM/PSRemoting is enabled on the target.
- Run as an account with sufficient privileges on the target for best results.
#>

param(
    [string]$OutDir = ".\WinReconOutput",
    [string]$Target = "",                # IP or hostname; empty = local
    [System.Management.Automation.PSCredential]$Credential = $null,
    [switch]$Zip = $true,
    [switch]$VerboseOutput = $false,
    [int]$TimeoutSeconds = 30
)

function Log {
    param($msg)
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "[$t] $msg"
}

function ThrowIf {
    param($cond, $msg)
    if ($cond) { throw $msg }
}

# Prepare output folder
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outFolder = Join-Path -Path $OutDir -ChildPath $timestamp
New-Item -Path $outFolder -ItemType Directory -Force | Out-Null

# Decide local vs remote
$IsRemote = ($Target -ne "" -and $Target -ne $env:COMPUTERNAME -and $Target -ne "localhost")

if ($IsRemote) {
    Log "Target specified: $Target (remote). Will attempt PowerShell Remoting."
} else {
    Log "No remote target specified. Running locally."
}

# ScriptBlock that performs collection on the target (local context when invoked directly)
$collectScript = {
    param($VerboseOutput)
    function SafeInvokeLocal { param($sb) try { & $sb } catch { "ERROR: $($_.Exception.Message)" } }

    $sysinfo = SafeInvokeLocal { Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime }
    $computerSystem = SafeInvokeLocal { Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,Domain,Name,UserName }
    $bios = SafeInvokeLocal { Get-CimInstance -ClassName Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber }

    $ipconfig = SafeInvokeLocal { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState }
    $routes = SafeInvokeLocal { Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,RouteMetric,ifIndex }
    $netstat = SafeInvokeLocal { netstat -ano }

    $localUsers = SafeInvokeLocal { Get-LocalUser | Select-Object Name,Enabled,Description,LastLogon }
    $localGroups = SafeInvokeLocal { Get-LocalGroup | Select-Object Name,Description }

    $groupMemberships = @{}
    if ($localGroups -isnot [string] -and $localGroups) {
        foreach ($g in $localGroups) {
            $name = $g.Name
            $members = SafeInvokeLocal { Get-LocalGroupMember -Group $name -ErrorAction SilentlyContinue | Select-Object Name,PrincipalSource }
            $groupMemberships[$name] = $members
        }
    }

    $processes = SafeInvokeLocal { Get-Process | Sort-Object CPU -Descending | Select-Object Id,ProcessName,CPU,FileVersion }
    $services = SafeInvokeLocal { Get-Service | Select-Object Name,DisplayName,Status,StartType }
    $tasks = SafeInvokeLocal { Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author }

    function Get-InstalledSoftwareLocal {
        $results = @()
        $hives = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($h in $hives) {
            try {
                Get-ItemProperty -Path $h -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DisplayName) {
                        $results += [PSCustomObject]@{
                            DisplayName = $_.DisplayName
                            DisplayVersion = $_.DisplayVersion
                            Publisher = $_.Publisher
                            InstallDate = $_.InstallDate
                            UninstallString = $_.UninstallString
                        }
                    }
                }
            } catch {}
        }
        return $results
    }
    $installed = SafeInvokeLocal { Get-InstalledSoftwareLocal }

    $fw = SafeInvokeLocal { Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object DisplayName,Direction,Action,Enabled,Profile }

    $domainInfo = @{}
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domainInfo['Domain'] = $cs.Domain
        if ($cs.Domain -and $cs.Domain -ne $env:COMPUTERNAME) {
            $domainInfo['DNSHostName'] = $cs.DNSHostName
            $domainInfo['DomainRole'] = $cs.DomainRole
        }
    } catch {
        $domainInfo['error'] = $_.Exception.Message
    }

    $usersDirs = SafeInvokeLocal { Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | Select-Object Name,FullName }

    [PSCustomObject]@{
        CollectedAt = (Get-Date).ToString("o")
        Hostname = $env:COMPUTERNAME
        SystemInfo = $sysinfo
        ComputerSystem = $computerSystem
        BIOS = $bios
        Network = @{
            IPAddresses = $ipconfig
            Routes = $routes
            Netstat = $netstat
        }
        LocalUsers = $localUsers
        LocalGroups = $localGroups
        GroupMemberships = $groupMemberships
        Processes = $processes
        Services = $services
        ScheduledTasks = $tasks
        InstalledSoftware = $installed
        FirewallRules = $fw
        DomainInfo = $domainInfo
        UsersDirs = $usersDirs
        Notes = "No credentials are collected by this tool. Intended for red-team recon only."
    }
}

# Perform collection: local vs remote
try {
    if ($IsRemote) {
        # Try a short test connection first (optional)
        Log "Testing remote connectivity to $Target..."
        $pingOk = $false
        try {
            $p = Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction Stop
            $pingOk = $p
        } catch {
            if ($VerboseOutput) { Write-Output "Ping/test-connection failed: $($_.Exception.Message)" }
        }

        # Build Invoke-Command parameters
        $invParams = @{
            ComputerName = $Target
            ScriptBlock  = $collectScript
            ArgumentList = @($VerboseOutput)
            ErrorAction  = 'Stop'
            # you can add -SessionOption or -UseSSL here if needed
        }
        if ($Credential) { $invParams['Credential'] = $Credential }

        Log "Invoking remote collection on $Target (timeout ${TimeoutSeconds}s)..."
        # Invoke-Command with a timeout by running it in a job if needed
        $job = Start-Job -ScriptBlock {
            param($p)
            Invoke-Command @p
        } -ArgumentList (New-Object PSObject -Property $invParams)

        $finished = $job | Wait-Job -Timeout $TimeoutSeconds
        if (-not $finished) {
            Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
            Stop-Job $job -Force | Out-Null
            Remove-Job $job -Force | Out-Null
            throw "Remote collection timed out after $TimeoutSeconds seconds."
        }
        $result = Receive-Job $job -ErrorAction Stop
        Remove-Job $job -Force | Out-Null

        if (-not $result) { throw "No data returned from remote host $Target." }

    } else {
        Log "Collecting data locally..."
        $result = & $collectScript $VerboseOutput
    }
} catch {
    $err = $_.Exception.Message
    Log "ERROR during collection: $err"
    $result = [PSCustomObject]@{ CollectedAt = (Get-Date).ToString("o"); Error = "Collection failed: $err"; Hostname = $Target }
}

# Save JSON
$jsonPath = Join-Path $outFolder "winrecon_report.json"
try {
    $result | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
    Log "Saved JSON -> $jsonPath"
} catch {
    Log "Failed to save JSON: $($_.Exception.Message)"
}

# Save human-readable summary
$txtPath = Join-Path $outFolder "winrecon_summary.txt"
try {
    "WinReconReporter Summary - $(Get-Date -Format 'u')" | Out-File $txtPath
    "Target: $($result.Hostname)" | Out-File $txtPath -Append
    "" | Out-File $txtPath -Append

    "=== System ===" | Out-File $txtPath -Append
    $result.SystemInfo | Format-List | Out-String | Out-File $txtPath -Append

    "" | Out-File $txtPath -Append
    "=== Local Users ===" | Out-File $txtPath -Append
    if ($result.LocalUsers) { $result.LocalUsers | Format-Table -AutoSize | Out-String | Out-File $txtPath -Append } else { "No local users enumerated or query failed." | Out-File $txtPath -Append }

    "" | Out-File $txtPath -Append
    "=== Running Processes (top 25 by CPU) ===" | Out-File $txtPath -Append
    if ($result.Processes) { $result.Processes | Select-Object -First 25 | Format-Table Id,ProcessName,CPU | Out-String | Out-File $txtPath -Append }

    "" | Out-File $txtPath -Append
    "=== Services (some) ===" | Out-File $txtPath -Append
    if ($result.Services) { $result.Services | Format-Table Name,DisplayName,Status,StartType -AutoSize | Out-String | Out-File $txtPath -Append }

    Log "Saved summary -> $txtPath"
} catch {
    Log "Failed to save summary: $($_.Exception.Message)"
}

# Optionally zip
if ($Zip) {
    try {
        $zipFile = Join-Path $OutDir ("WinRecon_" + $timestamp + ".zip")
        if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
        Compress-Archive -Path (Join-Path $outFolder "*") -DestinationPath $zipFile
        Log "Created zip: $zipFile"
    } catch {
        Log "Failed to create zip: $($_.Exception.Message)"
    }
}

Log "Done."
