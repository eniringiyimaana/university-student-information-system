@echo off
REM ====================================================================
REM  sis_auth_setup.bat
REM  Implements the SIS authentication design from Command Prompt.
REM  Run from an elevated (Administrator) Command Prompt, on a VM or CI runner.
REM
REM  Usage:   sis_auth_setup.bat                 (random test password)
REM           sis_auth_setup.bat MyThrowaway!Pw1 (your own throwaway password)
REM
REM  Local Windows accounts cannot do MFA. In a real deployment it comes from
REM  an identity provider such as Microsoft Entra ID Conditional Access, with
REM  FIDO2 hardware keys for administrators.
REM ====================================================================
setlocal EnableDelayedExpansion

REM --- 0. Must be Administrator ---
net session >nul 2>&1
if errorlevel 1 (
    echo Run this script as Administrator.
    exit /b 1
)

REM --- Test password: argument 1, or a random one that meets complexity rules ---
set "PWD=%~1"
if "%PWD%"=="" set "PWD=Sis!%RANDOM%%RANDOM%aB9x"

echo.
echo === 1. Create role groups and sample accounts ===
for %%G in (SIS_Students SIS_Lecturers SIS_Admins SIS_Integrations) do (
    net localgroup %%G >nul 2>&1 || net localgroup %%G /add /comment:"SIS role" >nul
)
call :makeuser SIS_Student1  SIS_Students
call :makeuser SIS_Lecturer1 SIS_Lecturers
call :makeuser SIS_ITAdmin1  SIS_Admins
call :makeuser SIS_Moodle    SIS_Integrations
net localgroup SIS_Students
net localgroup SIS_Lecturers

echo.
echo === 2. Password and lockout policy ===
REM 12-character minimum, lock after 5 bad attempts for 15 minutes
net accounts /minpwlen:12 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 >nul

REM Turn on password complexity with secedit
secedit /export /cfg "%TEMP%\secpol.cfg" /quiet
powershell -NoProfile -Command "(Get-Content '%TEMP%\secpol.cfg') -replace 'PasswordComplexity\s*=\s*\d','PasswordComplexity = 1' | Set-Content '%TEMP%\secpol.cfg'"
secedit /configure /db "%TEMP%\secpol.sdb" /cfg "%TEMP%\secpol.cfg" /areas SECURITYPOLICY /quiet
del "%TEMP%\secpol.cfg" >nul 2>&1
net accounts

echo.
echo === 3. Folder permissions per role ===
for %%F in (Results Grades Enrollment) do (
    if not exist "C:\SIS\%%F" mkdir "C:\SIS\%%F"
    REM remove inherited permissions, keep SYSTEM and Administrators only
    icacls "C:\SIS\%%F" /inheritance:r >nul
    icacls "C:\SIS\%%F" /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" >nul
)
REM Results: students read only, lecturers can change
icacls "C:\SIS\Results"    /grant "SIS_Students:(OI)(CI)R" "SIS_Lecturers:(OI)(CI)M" >nul
REM Grades: lecturers can change, IT admins read only, students none
icacls "C:\SIS\Grades"     /grant "SIS_Lecturers:(OI)(CI)M" "SIS_Admins:(OI)(CI)R" >nul
REM Enrollment: integrations read only, lecturers read
icacls "C:\SIS\Enrollment" /grant "SIS_Integrations:(OI)(CI)R" "SIS_Lecturers:(OI)(CI)R" >nul
for %%F in (Results Grades Enrollment) do (
    echo.
    echo C:\SIS\%%F
    icacls "C:\SIS\%%F"
)

echo.
echo === 4. Audit logging ===
auditpol /set /subcategory:"Logon"                     /success:enable /failure:enable >nul
auditpol /set /subcategory:"Account Lockout"           /success:enable /failure:enable >nul
auditpol /set /subcategory:"User Account Management"   /success:enable /failure:enable >nul
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable >nul
auditpol /set /subcategory:"File System"               /success:enable /failure:enable >nul
REM Audit every write/delete in the Grades folder (file auditing rule via PowerShell)
powershell -NoProfile -Command "$a=Get-Acl 'C:\SIS\Grades'; $r=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','Write,Delete,ChangePermissions','ContainerInherit,ObjectInherit','None','Success,Failure'); $a.AddAuditRule($r); Set-Acl 'C:\SIS\Grades' $a"
auditpol /get /subcategory:"Logon","Account Lockout","User Account Management","File System"

echo.
echo === 5. Lockout test: wrong passwords lock the student account ===
for /L %%I in (1,1,6) do net use \\localhost\IPC$ /user:SIS_Student1 WrongPassword!%%I >nul 2>&1
net user SIS_Student1 | findstr /i "active locked lockout"

echo.
echo === 5b. Recent security events (failed logon 4625, lockout 4740, account created 4720) ===
wevtutil qe Security /q:"*[System[(EventID=4625 or EventID=4740 or EventID=4720)]]" /c:10 /rd:true /f:text | more

echo.
echo === 6. Recovery ===
echo Unlocking the student account:
net user SIS_Student1 /active:yes
echo.
echo Other recovery commands:
echo   Reset password : net user SIS_Student1 NewThrowawayPw!1
echo   Disable account: net user SIS_Moodle /active:no     (revoke an integration)
echo   Enable account : net user SIS_Moodle /active:yes

echo.
echo Done.
endlocal
exit /b 0

REM --- helper: create a user if missing, then add to a group ---
:makeuser
net user %1 >nul 2>&1 || net user %1 "%PWD%" /add /passwordchg:no /expires:never >nul
net localgroup %2 %1 /add >nul 2>&1
exit /b 0
