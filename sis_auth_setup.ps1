<#
  sis_auth_setup.ps1
  Implements the SIS authentication design on a Windows machine (PowerShell).
  Run as Administrator, on a VM or a CI runner, NOT on your everyday computer.

  Usage:
    ./sis_auth_setup.ps1                       # random test passwords are generated
    ./sis_auth_setup.ps1 -TestPassword 'Xx...' # or supply your own throwaway password

  Passwords are never printed or stored in this file.
  Note: local Windows accounts cannot do MFA. In a real deployment MFA would come from
  an identity provider such as Microsoft Entra ID Conditional Access, with FIDO2
  hardware keys for administrators.
#>
param(
    [string]$TestPassword
)

$ErrorActionPreference = 'Continue'

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------
# 0. Check we are running as Administrator
# ---------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this script as Administrator." -ForegroundColor Red; exit 1 }

# If no password was given, build a random one that meets the complexity rules
if (-not $TestPassword) {
    $TestPassword = 'Sis!' + (-join ((48..57 + 65..90 + 97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })) + 'a9'
}
$SecurePwd = ConvertTo-SecureString $TestPassword -AsPlainText -Force

# ---------------------------------------------------------------
# 1. Roles (local groups) and one sample account per role
# ---------------------------------------------------------------
Step "1. Create role groups and sample accounts"

$roles = @{
    'SIS_Students'     = 'SIS_Student1'
    'SIS_Lecturers'    = 'SIS_Lecturer1'
    'SIS_Admins'       = 'SIS_ITAdmin1'
    'SIS_Integrations' = 'SIS_Moodle'
}

foreach ($group in $roles.Keys) {
    if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $group -Description "SIS role: $group" | Out-Null
    }
    $user = $roles[$group]
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $user -Password $SecurePwd -Description "Sample $group account" `
            -PasswordNeverExpires | Out-Null
    }
    Add-LocalGroupMember -Group $group -Member $user -ErrorAction SilentlyContinue
}
Get-LocalGroup -Name 'SIS_*' | Select-Object Name, Description | Format-Table -AutoSize
Get-LocalUser  -Name 'SIS_*' | Select-Object Name, Enabled | Format-Table -AutoSize

# ---------------------------------------------------------------
# 2. Password and lockout policy
# ---------------------------------------------------------------
Step "2. Password and lockout policy"

net accounts /minpwlen:12 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null

# Turn on password complexity (not available through 'net accounts', so use secedit)
$cfg = "$env:TEMP\secpol.cfg"
secedit /export /cfg $cfg /quiet
(Get-Content $cfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' | Set-Content $cfg
secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $cfg /areas SECURITYPOLICY /quiet
Remove-Item $cfg -ErrorAction SilentlyContinue

net accounts

# ---------------------------------------------------------------
# 3. Role permissions on folders (authorization / least privilege)
# ---------------------------------------------------------------
Step "3. Folder permissions per role"

$root = 'C:\SIS'
$folders = 'Results','Grades','Enrollment'
foreach ($f in $folders) { New-Item -ItemType Directory -Path "$root\$f" -Force | Out-Null }

# Start clean: remove inherited permissions, keep only SYSTEM and Administrators
foreach ($f in $folders) {
    icacls "$root\$f" /inheritance:r | Out-Null
    icacls "$root\$f" /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
}

# Results: students READ only, lecturers can change
icacls "$root\Results"    /grant 'SIS_Students:(OI)(CI)R'  'SIS_Lecturers:(OI)(CI)M' | Out-Null
# Grades: lecturers can change, IT admins READ only, students no access
icacls "$root\Grades"     /grant 'SIS_Lecturers:(OI)(CI)M' 'SIS_Admins:(OI)(CI)R'    | Out-Null
# Enrollment: integrations READ only (e.g. library checks enrolment), lecturers read
icacls "$root\Enrollment" /grant 'SIS_Integrations:(OI)(CI)R' 'SIS_Lecturers:(OI)(CI)R' | Out-Null

foreach ($f in $folders) { Write-Host "`n$root\$f"; icacls "$root\$f" }

# ---------------------------------------------------------------
# 4. Logging (auditing)
# ---------------------------------------------------------------
Step "4. Turn on audit logging"

auditpol /set /subcategory:"Logon"                    /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Account Lockout"          /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"User Account Management"  /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File System"              /success:enable /failure:enable | Out-Null

# Record every write or delete in the Grades folder (who changed what, and when)
$acl  = Get-Acl "$root\Grades"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    'Everyone', 'Write,Delete,ChangePermissions', 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
$acl.AddAuditRule($rule)
Set-Acl "$root\Grades" $acl

# Show the setting of each audit subcategory we turned on
foreach ($s in 'Logon','Account Lockout','User Account Management','Security Group Management','File System') {
    auditpol /get /subcategory:"$s" | Select-String -Pattern 'Success|Failure|No Auditing'
}

# ---------------------------------------------------------------
# 5. Prove the controls work
# ---------------------------------------------------------------
Step "5a. Authorization test: can each role write to the Grades folder?"

# Checks the folder's access list to see whether a role's group can write.
# (Logging in as each test user would hang on a CI runner, so we read the
#  permissions that Windows will enforce instead. The result is the same.)
function Test-Write($user, $group, $folder) {
    # Only the "write" bits count. (Modify/FullControl also contain read bits, so
    # including them made a read-only group look like it could write.)
    $writeRights = [System.Security.AccessControl.FileSystemRights]'WriteData,AppendData'
    $allowed = $false
    foreach ($rule in (Get-Acl $folder).Access) {
        if ($rule.IdentityReference.Value -like "*\$group" -and
            $rule.AccessControlType -eq 'Allow' -and
            ($rule.FileSystemRights -band $writeRights)) { $allowed = $true }
    }
    $r = if ($allowed) { 'ALLOWED' } else { 'DENIED' }
    Write-Host ("{0,-15} ({1,-16}) write to Grades: {2}" -f $user, $group, $r)
}
Test-Write 'SIS_Student1'  'SIS_Students'     "$root\Grades"
Test-Write 'SIS_Lecturer1' 'SIS_Lecturers'    "$root\Grades"
Test-Write 'SIS_ITAdmin1'  'SIS_Admins'       "$root\Grades"
Test-Write 'SIS_Moodle'    'SIS_Integrations' "$root\Grades"
Write-Host "(Expected: Student DENIED, Lecturer ALLOWED, IT admin DENIED, Moodle DENIED)"

Step "5b. Lockout test: 5 wrong passwords lock the student account"
1..6 | ForEach-Object { cmd /c "net use \\localhost\IPC$ /user:SIS_Student1 WrongPassword!$_ 2>nul" | Out-Null }
net user SIS_Student1 | Select-String 'Account active','Lockout','locked'
Get-LocalUser SIS_Student1 | Select-Object Name, Enabled

Step "5c. Recent security events"
# 4625 failed logon, 4740 account locked, 4720 account created, 4732 added to group
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4740,4720,4732} -MaxEvents 15 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n='Message';e={($_.Message -split "`n")[0]}} | Format-Table -AutoSize -Wrap

# ---------------------------------------------------------------
# 6. Recovery commands (shown, with the unlock actually run)
# ---------------------------------------------------------------
Step "6. Recovery"
Write-Host "Unlock the locked student account:"
net user SIS_Student1 /active:yes
Write-Host "`nOther recovery commands you can run on a real system:"
Write-Host "  Reset password : Set-LocalUser -Name SIS_Student1 -Password (Read-Host -AsSecureString)"
Write-Host "  Disable account: Disable-LocalUser -Name SIS_Moodle      # revoke an integration"
Write-Host "  Enable account : Enable-LocalUser  -Name SIS_Moodle"

Step "MFA note"
Write-Host "Local Windows accounts cannot do MFA. In a real deployment it comes from an identity provider"
Write-Host "such as Microsoft Entra ID Conditional Access, with FIDO2 hardware keys for administrators."

Write-Host "`nDone." -ForegroundColor Green
