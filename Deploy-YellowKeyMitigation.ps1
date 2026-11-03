#region Header
<#
#====================================#
# Title: Deploy-YellowKeyMitigation  #
#                                    #
# Contributors: PorygonPhD           #
#                                    #
# Version: 0.01                      #
# Date: 5/14/2026                    #
#====================================#

## Usage ##

- Deploys across every Windows 11, Server 2022, and Server 2025 asset on the domain.
  - `.\Deploy-YellowKeyMitigation.ps1`
- Deploys to only the specified machines (bypasses the `Get-ADComputer` lookup so no RSAT tools are required).
  - `.\Deploy-YellowKeyMitigation.ps1 -mitigationTarget PC1,PC2,PC3`
- Uses a separate admin credential for the remote sessions.
  - `.\Deploy-YellowKeyMitigation.ps1 -useCredential`

## Prerequisites ##

- RSAT tools installed locally or run the script on a domain controller (only needed if you don't pass `-mitigationTarget`, since that's how it enumerates affected assets via `Get-ADComputer`).
- WinRM enabled on the targets.

#>
#endregion
#* ----------------- Parameters -----------------
#region Parameters
param (
    [string]$logDirectory = "C:\temp\Logs",
    [string[]]$mitigationTarget = $null,
    [switch]$useCredential
)

#endregion

# ----------------- Variable & Variable Verification -----------------
#region Variables

# Checks if activationTarget was defined but the user only inputted spaces instead of commas.
if ($mitigationTarget.Count -eq 1 -and $mitigationTarget -match '\s') {
    $mitigationTarget = $mitigationTarget -split '\s+'
}

# We're targeting Windows 11, Server 2022, and Server 2025 (all of which are affected by YellowKey)
if ($null -eq $mitigationTarget) {
    $mitigationTarget = Get-ADComputer -Filter "(OperatingSystem -like 'Windows 11*' -or OperatingSystem -like 'Windows Server 2022*' -or OperatingSystem -like 'Windows Server 2025*') -and Enabled -eq '$true'" | Select-Object -ExpandProperty Name
}

#endregion

#* ----------------- Logging -----------------
#region Logging
# Creates log directory (if it doesn't exist)
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory | Out-Null
}

# Declares timestamp of the filename; creates the logfile.
$timestamp = Get-Date -Format "ddMMMyyyy"
$logFile   = Join-Path $logDirectory "Deploy-YellowKeyMitigation-$timestamp.log"

# Function that writes txtlogs, formally called "Write-Log" but there's an alias in PS Core (PS 6+), that now matches this.
function Write-TxtLog {
    param (
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$computerName = $($env:ComputerName),
        [string]$logFile = $script:logFile
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$ts] [$Level] [$ComputerName] $Message"

    switch ($Level.ToUpper()) {
        'INFO'    { Write-Host $logEntry -ForegroundColor Gray }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'DEBUG'   { Write-Host $logEntry -ForegroundColor Cyan }
        default   { Write-Host $logEntry }
    }
    if ($logFile) {
        Add-Content -Path $logFile -Value $logEntry
    }
}
#endregion

# ----------------- Asset Enumeration -----------------

#region Computer Recon
#* Gathers all computers defined within the filter then check to see which ones are actually accessible through pings and WinRM then stores the successful hits within a variable. Very useful.
function Get-AccessibleComputers {
    param (
        [string[]]$computerList
    )

    $reachable = @()
    foreach ($computer in $computerList) {
        Write-Host "Checking $computer..." -ForegroundColor Yellow

        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            Write-Warning "$computer is offline or not responding to ping."
            continue
        }

        try {
            $null = Test-WSMan -ComputerName $computer -ErrorAction Stop
            Write-Host "$computer is accessible." -ForegroundColor Green
            $reachable += $computer
        } catch {
            Write-Warning "$computer is online but not accessible via WinRM: $_"
        }
    }
    return $reachable
}
$computers = Get-AccessibleComputers -ComputerList $mitigationTarget
#endregion

# ----------------- Credentials -----------------

#region Credentials
#* Exists because some networks have strict security controls and demand separate admin accounts for different tasks.
if ($UseCredential) {
    Write-TxtLog -Message "VERIFY THAT YOUR CREDENTIALS ARE VALID OTHERWISE LOCKOUT CAN OCCUR" -Level "WARN"
    $cred = Get-Credential
} else {
    Write-TxtLog -Message "Credentials were NOT passed, using current user context." -Level "DEBUG"
    Write-TxtLog -Message "If you are trying to mount a remote share, credentials need to be passed." -Level "DEBUG"
    $cred = $null
}
#endregion

# ----------------- Remote Functions -----------------

#region Remote Functions
# Passes functions within this variable to each PSSession it is passed to.

$remoteFunctions = {
    # A Write-Host wrapper that keeps the same formatting as Write-Log.
    function Write-TxtLog {
        param (
            [string]$Message,
            [string]$Level = 'INFO',
            [string]$ComputerName = $env:COMPUTERNAME
        )
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$ts] [$Level] [$ComputerName] $Message"

        switch ($Level.ToUpper()) {
            'INFO'    { Write-Host $logEntry -ForegroundColor Gray }
            'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
            'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
            'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
            'DEBUG'   { Write-Host $logEntry -ForegroundColor Cyan }
            default   { Write-Host $logEntry }
        }
    }
}

#endregion

# ----------------- Create PSSessions -----------------
#region Create PSSessions

# Create PSSessions and if useCredential is true, use the credential.
if ($useCredential) {
    $sessions = New-PSSession -ComputerName $computers -Credential $cred
} else {
    $sessions = New-PSSession -ComputerName $computers
}

#endregion

# ----------------- Inject Functions -----------------

# Injects all functions defined within $remoteFunctions for every open PSSession.
Invoke-Command -Session $sessions -ScriptBlock $remoteFunctions

#endregion

# ----------------- Disable WinRE -----------------
#region Disable WinRE

# Runs reagentc /disable on every reachable computer; captures per-host status so we can report failures.
$winreResults = Invoke-Command -Session $sessions -ScriptBlock {
    $result = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'Unknown'
        WinREState   = $null
        Reason       = $null
    }

    try {
        # Capture current WinRE state before changing it.
        $infoBefore = & reagentc.exe /info 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reagentc /info failed: $($infoBefore -join '; ')"
        }

        # If WinRE is already disabled, no work to do.
        if ($infoBefore -match 'Windows RE status:\s*Disabled') {
            $result.Status     = 'AlreadyDisabled'
            $result.WinREState = 'Disabled'
            Write-TxtLog -Message "WinRE already disabled." -Level 'INFO'
            return $result
        }

        $disableOutput = & reagentc.exe /disable 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reagentc /disable exited with code $LASTEXITCODE : $($disableOutput -join '; ')"
        }

        # Verify the state actually flipped to Disabled.
        $infoAfter = & reagentc.exe /info 2>&1
        if ($infoAfter -match 'Windows RE status:\s*Disabled') {
            $result.Status     = 'Disabled'
            $result.WinREState = 'Disabled'
            Write-TxtLog -Message "WinRE successfully disabled." -Level 'SUCCESS'
        } else {
            $result.Status     = 'Failed'
            $result.WinREState = ($infoAfter | Where-Object { $_ -match 'Windows RE status' }) -join ' '
            $result.Reason     = "reagentc reported non-Disabled state after /disable."
            Write-TxtLog -Message $result.Reason -Level 'ERROR'
        }
    } catch {
        $result.Status = 'Failed'
        $result.Reason = $_.Exception.Message
        Write-TxtLog -Message "Failed to disable WinRE: $($_.Exception.Message)" -Level 'ERROR'
    }

    return $result
}

# Anything that didn't end up Disabled/AlreadyDisabled is a failure. Also include hosts we never reached.
$reachedNames    = $winreResults | Select-Object -ExpandProperty ComputerName
$unreachedHosts  = $mitigationTarget | Where-Object { $reachedNames -notcontains $_ } | ForEach-Object {
    [PSCustomObject]@{
        ComputerName = $_
        Status       = 'Unreachable'
        WinREState   = $null
        Reason       = 'Host was offline or WinRM was not accessible.'
    }
}

$failures = @()
$failures += $winreResults | Where-Object { $_.Status -notin @('Disabled', 'AlreadyDisabled') }
$failures += $unreachedHosts

if ($failures.Count -gt 0) {
    Write-TxtLog -Message "The following computers failed to disable WinRE:" -Level 'WARN'
    $failures | Format-Table ComputerName, Status, WinREState, Reason -AutoSize -Wrap
} else {
    Write-TxtLog -Message "WinRE was disabled (or already disabled) on all targeted computers." -Level 'SUCCESS'
}

#endregion

# ----------------- Cleanup -----------------------
#region Cleanup
if ($sessions) {
    Remove-PSSession -Session $sessions
}
#endregion
