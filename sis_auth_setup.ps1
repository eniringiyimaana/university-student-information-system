#Requires -RunAsAdministrator
<#
  University Student Information System - authentication design demo (PowerShell)
  Run in an elevated PowerShell window on a TEST machine or VM, not on your daily PC.
  Usage:  powershell -ExecutionPolicy Bypass -File .\sis_auth_setup.ps1
#>

$root = 'C:\SIS'

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

# 1. Users and roles --------------------------------------------------------
Step '1. Create role groups and sample accounts'

$groups = 'SIS_Students', 'SIS_Lecturers', 'SIS_Admins', 'SIS_Integrations'
foreach ($g in $groups) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $g -Description "SIS role: $g" | Out-Null
    }
}

$accounts = @(
    @{ Name = 'student01';   Group = 'SIS_Students' },
    @{ Name = 'lecturer01';  Group = 'SIS_Lecturers' },
    @{ Name = 'admin01';     Group = 'SIS_Admins' },
    @{ Name = 'svc_library'; Group = 'SIS_Integrations' }
)
foreach ($a in $accounts) {
    if (-not (Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue)) {
        $pw = Read-Host -Prompt "Set a password for $($a.Name) (12+ characters)" -AsSecureString
        New-LocalUser -Name $a.Name -Password $pw -Description "SIS $($a.Group)" | Out-Null
    }
    Add-LocalGroupMember -Group $a.Group -Member $a.Name -ErrorAction SilentlyContinue
}

# 2. Password policy and lockout -------------------------------------------
Step '2. Password policy and account lockout'

net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null

# Turn on password complexity (not available through "net accounts")
$cfg = Join-Path $env:TEMP 'sis_sec.cfg'
secedit /export /cfg $cfg | Out-Null
(Get-Content $cfg) -replace 'PasswordComplexity\s*=\s*0', 'PasswordComplexity = 1' | Set-Content $cfg
secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfg /areas SECURITYPOLICY | Out-Null
Remove-Item $cfg -ErrorAction SilentlyContinue
net accounts

# 3. MFA ----------------------------------------------------------------------
Step '3. MFA (see note)'
Write-Host @'
Local Windows accounts cannot do MFA on their own. In a real deployment MFA is
enforced by the identity provider:
  - Microsoft Entra ID Conditional Access: require MFA for lecturers, admins,
    any off-campus sign-in, and sensitive actions for students.
  - Admins: FIDO2 security keys or smart cards.
On an Active Directory domain, the admin smart card rule would be:
  Set-ADUser -Identity admin01 -SmartcardLogonRequired $true
'@

# 4. Authorization by role (folder permissions) -----------------------------
Step '4. Role-based folder permissions'

$folders = 'Results', 'Grades', 'Finance', 'Enrollment', 'AuditExports'
foreach ($f in $folders) { New-Item -Path "$root\$f" -ItemType Directory -Force | Out-Null }

# Students: read results only. Lecturers: read results, change grades.
# Admins (IT): manage results, read-only on grades. Integrations: enrollment only.
icacls "$root\Results" /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'SIS_Admins:(OI)(CI)M' 'SIS_Lecturers:(OI)(CI)RX' 'SIS_Students:(OI)(CI)RX' | Out-Null
icacls "$root\Grades" /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'SIS_Lecturers:(OI)(CI)M' 'SIS_Admins:(OI)(CI)RX' | Out-Null
icacls "$root\Finance" /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'SIS_Admins:(OI)(CI)M' | Out-Null
icacls "$root\Enrollment" /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'SIS_Admins:(OI)(CI)M' 'SIS_Integrations:(OI)(CI)RX' | Out-Null
icacls "$root\AuditExports" /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
icacls "$root\Grades"

# 5. Logging -------------------------------------------------------------------
Step '5. Audit logging'

$subcats = 'Logon', 'Logoff', 'Account Lockout', 'User Account Management',
           'Security Group Management', 'File System'
foreach ($s in $subcats) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# Record every change to the grades folder (who changed what, and when)
$acl  = Get-Acl "$root\Grades"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    'Everyone', 'Modify,Delete', 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
$acl.AddAuditRule($rule)
Set-Acl -Path "$root\Grades" -AclObject $acl

# Bigger security log so entries are kept longer (200 MB)
wevtutil sl Security /ms:209715200
auditpol /get /category:'Logon/Logoff','Account Management','Object Access' | Out-Null

# 6. Recovery helpers ----------------------------------------------------------
Step '6. Recovery functions'

function Reset-SisPassword {
    param([Parameter(Mandatory)][string]$User)
    # Run only after the person has verified their identity (ID at the help desk).
    $pw = Read-Host -Prompt "New temporary password for $User" -AsSecureString
    Set-LocalUser -Name $User -Password $pw
    net user $User /logonpasswordchg:yes | Out-Null
    Write-Host "$User must change this password at next sign-in." -ForegroundColor Green
}

function Unlock-SisAccount {
    param([Parameter(Mandatory)][string]$User)
    net user $User /active:yes | Out-Null
    Write-Host "$User unlocked." -ForegroundColor Green
}

function Revoke-SisIntegration {
    param([Parameter(Mandatory)][string]$User)
    Disable-LocalUser -Name $User
    Write-Host "$User disabled. Reissue credentials through the system owner." -ForegroundColor Yellow
}

Write-Host 'Available: Reset-SisPassword, Unlock-SisAccount, Revoke-SisIntegration (dot-source this script to keep them).'

# 7. Review the logs -----------------------------------------------------------
function Show-SisLogs {
    $events = @(
        @{ Label = 'Failed sign-ins';       Id = 4625 },
        @{ Label = 'Account lockouts';      Id = 4740 },
        @{ Label = 'Accounts created';      Id = 4720 },
        @{ Label = 'Password reset';        Id = 4724 },
        @{ Label = 'Group membership added'; Id = 4732 }
    )
    foreach ($e in $events) {
        Write-Host "`n--- $($e.Label) (Event $($e.Id)) ---" -ForegroundColor Cyan
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $e.Id } -MaxEvents 5 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Format-List
    }
}

Step 'Verification'
Get-LocalGroupMember -Group 'SIS_Lecturers'
Write-Host "`nSetup finished. Run Show-SisLogs to view recent security events." -ForegroundColor Green
