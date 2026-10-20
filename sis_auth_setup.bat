@echo off
rem University Student Information System - authentication design demo (Command Prompt)
rem Run from an elevated Command Prompt on a TEST machine or VM.

net session >nul 2>&1
if errorlevel 1 (
    echo Please run this from a Command Prompt opened as Administrator.
    exit /b 1
)

set ROOT=C:\SIS

echo.
echo === 1. Create role groups and sample accounts ===
for %%G in (SIS_Students SIS_Lecturers SIS_Admins SIS_Integrations) do (
    net localgroup %%G >nul 2>&1 || net localgroup %%G /add /comment:"SIS role" >nul
)

rem The * makes Windows prompt for each password, so none are stored in this file.
net user student01   >nul 2>&1 || net user student01 * /add
net user lecturer01  >nul 2>&1 || net user lecturer01 * /add
net user admin01     >nul 2>&1 || net user admin01 * /add
net user svc_library >nul 2>&1 || net user svc_library * /add

net localgroup SIS_Students     student01   /add >nul 2>&1
net localgroup SIS_Lecturers    lecturer01  /add >nul 2>&1
net localgroup SIS_Admins       admin01     /add >nul 2>&1
net localgroup SIS_Integrations svc_library /add >nul 2>&1

echo.
echo === 2. Password policy and account lockout ===
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15

rem Turn on password complexity (not available through "net accounts")
secedit /export /cfg "%TEMP%\sis_sec.cfg" >nul
powershell -NoProfile -Command "(Get-Content '%TEMP%\sis_sec.cfg') -replace 'PasswordComplexity\s*=\s*0','PasswordComplexity = 1' | Set-Content '%TEMP%\sis_sec.cfg'"
secedit /configure /db "%windir%\security\local.sdb" /cfg "%TEMP%\sis_sec.cfg" /areas SECURITYPOLICY >nul
del "%TEMP%\sis_sec.cfg" >nul 2>&1

echo.
echo === 3. MFA ===
echo Local Windows accounts cannot do MFA on their own. In a real deployment it is
echo enforced by the identity provider (for example Microsoft Entra ID Conditional
echo Access, with FIDO2 security keys for administrators).

echo.
echo === 4. Role-based folder permissions ===
for %%F in (Results Grades Finance Enrollment AuditExports) do mkdir "%ROOT%\%%F" 2>nul

rem Students: read results. Lecturers: change grades. IT admins: read-only on grades.
rem Integrations: enrollment data only.
icacls "%ROOT%\Results" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "SIS_Admins:(OI)(CI)M" "SIS_Lecturers:(OI)(CI)RX" "SIS_Students:(OI)(CI)RX" >nul
icacls "%ROOT%\Grades" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "SIS_Lecturers:(OI)(CI)M" "SIS_Admins:(OI)(CI)RX" >nul
icacls "%ROOT%\Finance" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "SIS_Admins:(OI)(CI)M" >nul
icacls "%ROOT%\Enrollment" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "SIS_Admins:(OI)(CI)M" "SIS_Integrations:(OI)(CI)RX" >nul
icacls "%ROOT%\AuditExports" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" >nul
icacls "%ROOT%\Grades"

echo.
echo === 5. Audit logging ===
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable

rem Log every change to the grades folder
powershell -NoProfile -Command "$a=Get-Acl '%ROOT%\Grades'; $r=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','Modify,Delete','ContainerInherit,ObjectInherit','None','Success,Failure'); $a.AddAuditRule($r); Set-Acl '%ROOT%\Grades' $a"

rem Bigger security log (200 MB) so entries are kept longer
wevtutil sl Security /ms:209715200

echo.
echo === 6. Recovery commands (run these when needed) ===
echo   Reset a password, forcing a change at next sign-in:
echo       net user USERNAME * ^&^& net user USERNAME /logonpasswordchg:yes
echo   Unlock an account:        net user USERNAME /active:yes
echo   Disable an integration:   net user svc_library /active:no

echo.
echo === 7. Review the logs ===
echo Failed sign-ins (4625):
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:5 /rd:true /f:text
echo Account lockouts (4740):
wevtutil qe Security /q:"*[System[(EventID=4740)]]" /c:5 /rd:true /f:text
echo Accounts created (4720):
wevtutil qe Security /q:"*[System[(EventID=4720)]]" /c:5 /rd:true /f:text

echo.
echo === Verification ===
net localgroup SIS_Lecturers
net accounts
echo Setup finished.
