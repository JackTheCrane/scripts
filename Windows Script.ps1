<#
.SYNOPSIS
    Password and account lockout policy hardening for a Windows 11 CyberPatriot image.

.DESCRIPTION
    Sets local password policy and account lockout policy, enforces complexity,
    and disables reversible encryption. Creates a backup of the previous
    security policy so you can roll back.

    ALWAYS read the competition README first. If it specifies different values
    (or says a particular user needs a specific setting), follow the README.

.USAGE
    Right-click PowerShell > Run as administrator, then:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\Set-PasswordPolicy.ps1

    Optional: also clear "Password never expires" on local user accounts
        .\Set-PasswordPolicy.ps1 -FixUserFlags
#>

[CmdletBinding()]
param(
    [switch]$FixUserFlags
)

# ---------- Adjustable values ----------
$MinPasswordLength   = 12   # characters (CyberPatriot usually wants 10+)
$MaxPasswordAge      = 60   # days (30-90 is typical)
$MinPasswordAge      = 7    # days (1-30 is typical)
$PasswordHistory     = 24   # remembered passwords (max on Windows)
$LockoutThreshold    = 5    # failed attempts before lockout
$LockoutDuration     = 30   # minutes
$LockoutWindow       = 30   # minutes (reset counter after)
# ---------------------------------------

# Require admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$workDir = Join-Path $env:USERPROFILE "Desktop\PolicyBackup"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$backupInf = Join-Path $workDir "secpol_backup.inf"
$editInf   = Join-Path $workDir "secpol_edit.inf"
$dbFile    = Join-Path $workDir "secedit.sdb"

# ---------- Backup ----------
Write-Host "[*] Backing up current security policy to $backupInf" -ForegroundColor Cyan
secedit /export /cfg $backupInf /areas SECURITYPOLICY | Out-Null

# ---------- net accounts (length, age, history, lockout) ----------
Write-Host "[*] Applying password and lockout settings via net accounts" -ForegroundColor Cyan
net accounts /minpwlen:$MinPasswordLength   | Out-Null
net accounts /maxpwage:$MaxPasswordAge      | Out-Null
net accounts /minpwage:$MinPasswordAge      | Out-Null
net accounts /uniquepw:$PasswordHistory     | Out-Null
net accounts /lockoutthreshold:$LockoutThreshold | Out-Null
net accounts /lockoutduration:$LockoutDuration   | Out-Null
net accounts /lockoutwindow:$LockoutWindow       | Out-Null

# ---------- secedit (complexity + reversible encryption) ----------
Write-Host "[*] Enabling complexity and disabling reversible encryption via secedit" -ForegroundColor Cyan
secedit /export /cfg $editInf /areas SECURITYPOLICY | Out-Null

$content = Get-Content $editInf

function Set-InfValue {
    param([string[]]$Lines, [string]$Key, [string]$Value)
    if ($Lines -match "^\s*$Key\s*=") {
        return $Lines -replace "^\s*$Key\s*=.*", "$Key = $Value"
    }
    # Add key under [System Access] if missing
    $idx = [array]::IndexOf($Lines, ($Lines | Where-Object { $_ -match '^\[System Access\]' } | Select-Object -First 1))
    if ($idx -ge 0) {
        $before = $Lines[0..$idx]
        $after  = if ($idx + 1 -lt $Lines.Count) { $Lines[($idx + 1)..($Lines.Count - 1)] } else { @() }
        return @($before + "$Key = $Value" + $after)
    }
    return $Lines
}

$content = Set-InfValue $content "PasswordComplexity"        "1"
$content = Set-InfValue $content "ClearTextPassword"         "0"   # reversible encryption OFF
$content = Set-InfValue $content "MinimumPasswordLength"     "$MinPasswordLength"
$content = Set-InfValue $content "MaximumPasswordAge"        "$MaxPasswordAge"
$content = Set-InfValue $content "MinimumPasswordAge"        "$MinPasswordAge"
$content = Set-InfValue $content "PasswordHistorySize"       "$PasswordHistory"
$content = Set-InfValue $content "LockoutBadCount"           "$LockoutThreshold"
$content = Set-InfValue $content "ResetLockoutCount"         "$LockoutWindow"
$content = Set-InfValue $content "LockoutDuration"           "$LockoutDuration"

$content | Set-Content $editInf -Encoding Unicode

secedit /configure /db $dbFile /cfg $editInf /areas SECURITYPOLICY /quiet | Out-Null

# ---------- Optional: per-user flags ----------
if ($FixUserFlags) {
    Write-Host "[*] Clearing 'Password never expires' on enabled local users" -ForegroundColor Cyan
    Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
        try {
            Set-LocalUser -Name $_.Name -PasswordNeverExpires $false -ErrorAction Stop
            Write-Host "    - $($_.Name): PasswordNeverExpires = False"
        } catch {
            Write-Host "    - $($_.Name): could not change ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
}

# ---------- Force policy refresh ----------
gpupdate /force | Out-Null

# ---------- Verify ----------
Write-Host "`n[+] Current policy:" -ForegroundColor Green
net accounts

$verify = Join-Path $workDir "secpol_verify.inf"
secedit /export /cfg $verify /areas SECURITYPOLICY | Out-Null
Get-Content $verify | Select-String "PasswordComplexity|ClearTextPassword" | ForEach-Object { Write-Host $_ }

Write-Host "`n[+] Done. Backup saved in $workDir" -ForegroundColor Green
Write-Host "    To roll back: secedit /configure /db secedit.sdb /cfg `"$backupInf`" /areas SECURITYPOLICY"











#----------Change Password for all users----------
Get-Localuser | Foreach-object {net user $_.Name “123!@#qweQWE”}












<#
.SYNOPSIS
    Resets passwords for enabled local users on a Windows 11 CyberPatriot image.

.DESCRIPTION
    By default:
      - Targets every ENABLED local account
      - SKIPS the account you are currently logged in as (so you don't lock yourself out)
      - Generates a unique random password for each user (meets complexity rules)
      - Saves the results to a CSV on your Desktop so you can record them

    Read the README first. It may say which users are authorized, which to keep,
    and whether a specific user's password must NOT be changed. Use -Exclude for those.

.USAGE
    Run as Administrator:
        Set-ExecutionPolicy -Scope Process Bypass -Force

    Preview only (changes nothing):
        .\Set-UserPasswords.ps1 -Preview

    Random unique password per user:
        .\Set-UserPasswords.ps1

    Same password for everyone (easier, less secure):
        .\Set-UserPasswords.ps1 -SharedPassword "Your!Str0ngPass#2026"

    Skip specific users:
        .\Set-UserPasswords.ps1 -Exclude "alice","bob"

    Include the account you're logged in as (careful):
        .\Set-UserPasswords.ps1 -IncludeCurrentUser
#>

[CmdletBinding()]
param(
    [string]$SharedPassword,
    [string[]]$Exclude = @(),
    [switch]$IncludeCurrentUser,
    [switch]$Preview,
    [int]$Length = 16
)

# ---------- Require admin ----------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

# ---------- Build target list ----------
$currentUser = $env:USERNAME
$builtins    = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')

$targets = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.Name -notin $builtins -and
    $_.Name -notin $Exclude -and
    ($IncludeCurrentUser -or $_.Name -ne $currentUser)
}

# Built-in Administrator is only touched if it's enabled (and not excluded)
$adminAcct = Get-LocalUser | Where-Object {
    $_.Name -eq 'Administrator' -and $_.Enabled -and 'Administrator' -notin $Exclude -and
    ($IncludeCurrentUser -or $_.Name -ne $currentUser)
}
if ($adminAcct) { $targets = @($targets) + @($adminAcct) }

if (-not $targets) {
    Write-Host "[!] No matching accounts found." -ForegroundColor Yellow
    exit 0
}

Write-Host "`nCurrent user (skipped unless -IncludeCurrentUser): $currentUser" -ForegroundColor Cyan
Write-Host "Accounts to update:" -ForegroundColor Cyan
$targets | ForEach-Object { Write-Host "  - $($_.Name)" }

if ($Preview) {
    Write-Host "`n[Preview] No changes made." -ForegroundColor Green
    exit 0
}

Write-Host ""
$confirm = Read-Host "Proceed with password changes? (y/N)"
if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled."; exit 0 }

# ---------- Apply ----------
$results = @()
foreach ($user in $targets) {
    $plain = if ($SharedPassword) { $SharedPassword } else { New-StrongPassword -Length $Length }
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force

    try {
        Set-LocalUser -Name $user.Name -Password $secure -ErrorAction Stop
        Write-Host "[+] $($user.Name): password changed" -ForegroundColor Green
        $results += [PSCustomObject]@{ User = $user.Name; Password = $plain; Status = "Changed" }
    } catch {
        Write-Host "[-] $($user.Name): FAILED - $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{ User = $user.Name; Password = ""; Status = "Failed: $($_.Exception.Message)" }
    }
}

# ---------- Save results ----------
$outFile = Join-Path $env:USERPROFILE "Desktop\NewPasswords.csv"
$results | Export-Csv -Path $outFile -NoTypeInformation
Write-Host "`n[+] Passwords saved to $outFile" -ForegroundColor Green
Write-Host "    Record them, then DELETE this file when you're done." -ForegroundColor Yellow





#-----------Local Security Policy Settings----------
<#
.SYNOPSIS
    Local security policy hardening for a Windows 11 CyberPatriot image.

.DESCRIPTION
    PART 1 - Audit policy (auditpol)
    PART 2 - Security options (registry): logon screen, inactivity lock, UAC,
             SMB signing, AutoRun, Remote Assistance, anonymous access
    PART 3 - User rights assignments (secedit): who can log on, shut down,
             debug, take ownership, etc.

    A backup of the current policy is saved to Desktop\PolicyBackup first.
    READ THE README FIRST. If it says a user or group needs a specific right
    (for example, Remote Desktop), adjust the values below or use -SkipUserRights.

.USAGE
    Run PowerShell as Administrator:
        Set-ExecutionPolicy -Scope Process Bypass -Force

    Preview only:            .\Set-LocalSecurityPolicy.ps1 -Preview
    Apply everything:        .\Set-LocalSecurityPolicy.ps1
    Skip user rights part:   .\Set-LocalSecurityPolicy.ps1 -SkipUserRights
    Custom lock timeout:     .\Set-LocalSecurityPolicy.ps1 -InactivitySeconds 600
#>

[CmdletBinding()]
param(
    [switch]$Preview,
    [switch]$SkipAudit,
    [switch]$SkipSecurityOptions,
    [switch]$SkipUserRights,
    [int]$InactivitySeconds = 900
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$workDir = Join-Path $env:USERPROFILE "Desktop\PolicyBackup"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if ($Preview) { Write-Host "    [preview] $Name = $Value"; return }
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Host "    set $Name = $Value"
    } catch {
        Write-Host "    [-] $Name failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ===================== BACKUP =====================
if (-not $Preview) {
    Write-Host "[*] Backing up current policy to $workDir" -ForegroundColor Cyan
    secedit /export /cfg (Join-Path $workDir "localpolicy_backup.inf") | Out-Null
    auditpol /backup /file:(Join-Path $workDir "auditpol_backup.csv") | Out-Null
}

# =====================================================
# PART 1: AUDIT POLICY
# =====================================================
if (-not $SkipAudit) {
    Write-Host "`n=== PART 1: Audit policy ===" -ForegroundColor Cyan

    # Subcategory settings override legacy category settings
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1

    # name, success, failure
    $audit = @(
        @("Credential Validation",           $true,  $true),
        @("Security Group Management",        $true,  $true),
        @("User Account Management",          $true,  $true),
        @("Computer Account Management",      $true,  $true),
        @("Process Creation",                 $true,  $false),
        @("Account Lockout",                  $false, $true),
        @("Logoff",                           $true,  $false),
        @("Logon",                            $true,  $true),
        @("Special Logon",                    $true,  $false),
        @("Other Logon/Logoff Events",        $true,  $true),
        @("File Share",                       $true,  $true),
        @("Removable Storage",                $true,  $true),
        @("Audit Policy Change",              $true,  $true),
        @("Authentication Policy Change",     $true,  $false),
        @("MPSSVC Rule-Level Policy Change",  $true,  $true),
        @("Other Policy Change Events",       $false, $true),
        @("Sensitive Privilege Use",          $true,  $true),
        @("IPsec Driver",                     $true,  $true),
        @("Security State Change",            $true,  $false),
        @("Security System Extension",        $true,  $false),
        @("System Integrity",                 $true,  $true)
    )

    foreach ($a in $audit) {
        $s = if ($a[1]) { "enable" } else { "disable" }
        $f = if ($a[2]) { "enable" } else { "disable" }
        if ($Preview) {
            Write-Host "    [preview] $($a[0]): success=$s failure=$f"
        } else {
            $out = auditpol /set /subcategory:"$($a[0])" /success:$s /failure:$f 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Host "    $($a[0]): success=$s failure=$f" }
            else { Write-Host "    [-] $($a[0]) failed: $out" -ForegroundColor Yellow }
        }
    }
}

# =====================================================
# PART 2: SECURITY OPTIONS
# =====================================================
if (-not $SkipSecurityOptions) {
    Write-Host "`n=== PART 2: Security options ===" -ForegroundColor Cyan

    $sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    Write-Host "[*] Interactive logon" -ForegroundColor Cyan
    Set-RegValue $sys "DontDisplayLastUserName"   1
    Set-RegValue $sys "DisableCAD"                0                     # require Ctrl+Alt+Del
    Set-RegValue $sys "InactivityTimeoutSecs"     $InactivitySeconds    # lock after inactivity
    Set-RegValue $sys "ShutdownWithoutLogon"      0                     # no shutdown from logon screen
    Set-RegValue $sys "DontDisplayLockedUserId"   3                     # hide account details when locked

    Write-Host "[*] User Account Control" -ForegroundColor Cyan
    Set-RegValue $sys "EnableLUA"                    1
    Set-RegValue $sys "ConsentPromptBehaviorAdmin"   2    # prompt for consent on secure desktop
    Set-RegValue $sys "ConsentPromptBehaviorUser"    0    # standard users: auto-deny elevation
    Set-RegValue $sys "PromptOnSecureDesktop"        1
    Set-RegValue $sys "EnableInstallerDetection"     1
    Set-RegValue $sys "EnableSecureUIAPaths"         1
    Set-RegValue $sys "EnableVirtualization"         1
    Set-RegValue $sys "FilterAdministratorToken"     1

    Write-Host "[*] Network access / anonymous" -ForegroundColor Cyan
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegValue $lsa "RestrictAnonymous"            1
    Set-RegValue $lsa "RestrictAnonymousSAM"         1
    Set-RegValue $lsa "EveryoneIncludesAnonymous"    0
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess" 1
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 1
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0

    Write-Host "[*] AutoRun / AutoPlay" -ForegroundColor Cyan
    $exp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-RegValue $exp "NoDriveTypeAutoRun" 255
    Set-RegValue $exp "NoAutorun"          1
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1

    Write-Host "[*] Remote Assistance" -ForegroundColor Cyan
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"       0
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"     0
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"       "fAllowToGetHelp"       0
}

# =====================================================
# PART 3: USER RIGHTS ASSIGNMENTS
# =====================================================
if (-not $SkipUserRights) {
    Write-Host "`n=== PART 3: User rights assignments ===" -ForegroundColor Cyan

    # Well-known SIDs
    $admins   = "*S-1-5-32-544"
    $users    = "*S-1-5-32-545"
    $guests   = "*S-1-5-32-546"
    $backupOp = "*S-1-5-32-551"
    $rdUsers  = "*S-1-5-32-555"
    $localSvc = "*S-1-5-19"
    $wmGroup  = "*S-1-5-90-0"

    # Right name = comma-separated SIDs ("" = no one)
    $rights = [ordered]@{
        "SeNetworkLogonRight"               = "$admins,$rdUsers"        # Access this computer from the network
        "SeDenyNetworkLogonRight"           = "$guests"                 # Deny access from the network
        "SeInteractiveLogonRight"           = "$admins,$backupOp,$users"# Allow log on locally
        "SeDenyInteractiveLogonRight"       = "$guests"                 # Deny log on locally
        "SeRemoteInteractiveLogonRight"     = "$admins,$rdUsers"        # Allow log on through Remote Desktop
        "SeDenyRemoteInteractiveLogonRight" = "$guests"                 # Deny log on through Remote Desktop
        "SeShutdownPrivilege"               = "$admins,$users"
        "SeRemoteShutdownPrivilege"         = "$admins"
        "SeTakeOwnershipPrivilege"          = "$admins"
        "SeBackupPrivilege"                 = "$admins"
        "SeRestorePrivilege"                = "$admins"
        "SeDebugPrivilege"                  = "$admins"
        "SeLoadDriverPrivilege"             = "$admins"
        "SeSecurityPrivilege"               = "$admins"
        "SeSystemEnvironmentPrivilege"      = "$admins"
        "SeProfileSingleProcessPrivilege"   = "$admins"
        "SeIncreaseBasePriorityPrivilege"   = "$admins,$wmGroup"
        "SeSystemtimePrivilege"             = "$admins,$localSvc"
        "SeCreateSymbolicLinkPrivilege"     = "$admins"
        "SeManageVolumePrivilege"           = "$admins"
        "SeTcbPrivilege"                    = ""                        # Act as part of the OS
        "SeCreateTokenPrivilege"            = ""
        "SeCreatePermanentPrivilege"        = ""
        "SeLockMemoryPrivilege"             = ""
        "SeTrustedCredManAccessPrivilege"   = ""
        "SeEnableDelegationPrivilege"       = ""
    }

    if ($Preview) {
        foreach ($k in $rights.Keys) { Write-Host "    [preview] $k = $($rights[$k])" }
    } else {
        $infPath = Join-Path $workDir "userrights_edit.inf"
        $dbPath  = Join-Path $workDir "userrights.sdb"

        secedit /export /cfg $infPath /areas USER_RIGHTS | Out-Null
        $script:inf = [System.Collections.Generic.List[string]](Get-Content $infPath)

        function Set-InfEntry {
            param([string]$Section, [string]$Key, [string]$Value)
            $start = -1
            for ($i = 0; $i -lt $script:inf.Count; $i++) {
                if ($script:inf[$i].Trim() -eq "[$Section]") { $start = $i; break }
            }
            if ($start -lt 0) {
                $script:inf.Add("[$Section]")
                $script:inf.Add("$Key = $Value")
                return
            }
            $end = $script:inf.Count
            for ($i = $start + 1; $i -lt $script:inf.Count; $i++) {
                if ($script:inf[$i] -match '^\[') { $end = $i; break }
            }
            for ($i = $start + 1; $i -lt $end; $i++) {
                if ($script:inf[$i] -match "^\s*$([regex]::Escape($Key))\s*=") {
                    $script:inf[$i] = "$Key = $Value"
                    return
                }
            }
            $script:inf.Insert($end, "$Key = $Value")
        }

        foreach ($k in $rights.Keys) {
            Set-InfEntry -Section "Privilege Rights" -Key $k -Value $rights[$k]
            Write-Host "    $k = $($rights[$k])"
        }

        $script:inf | Set-Content $infPath -Encoding Unicode
        secedit /configure /db $dbPath /cfg $infPath /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "[+] User rights applied" -ForegroundColor Green }
        else { Write-Host "[-] secedit returned $LASTEXITCODE. Check $env:windir\security\logs\scesrv.log" -ForegroundColor Yellow }
    }
}

# ===================== REFRESH + VERIFY =====================
if (-not $Preview) {
    gpupdate /force | Out-Null
    Write-Host "`n=== Verification ===" -ForegroundColor Green
    Write-Host "Audit policy (sample):"
    auditpol /get /category:"Logon/Logoff","Account Management" | Select-Object -First 25
    Write-Host "`nBackups: $workDir"
    Write-Host "Roll back rights: secedit /configure /db rollback.sdb /cfg `"$workDir\localpolicy_backup.inf`" /areas USER_RIGHTS" -ForegroundColor Yellow
    Write-Host "Roll back audit:  auditpol /restore /file:`"$workDir\auditpol_backup.csv`"" -ForegroundColor Yellow
    Write-Host "A reboot is recommended for everything to take effect." -ForegroundColor Yellow
} else {
    Write-Host "`n[Preview] No changes made." -ForegroundColor Green
}