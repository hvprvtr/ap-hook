# unregister.ps1  -  revert ApHook. RUN AS ADMINISTRATOR.
#
# Removes "ApHook" from Security Packages and deletes the DLL from
# System32. A reboot is required (the package stays loaded in lsass until then).

$ErrorActionPreference = 'Stop'
$pkg = 'ApHook'
$dst = "$env:WINDIR\System32\ApHook.dll"
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { throw 'Administrator rights required.' }

$cur = (Get-ItemProperty $lsa -Name 'Security Packages' -ErrorAction SilentlyContinue).'Security Packages'
$cur = @([string[]]$cur | Where-Object { $_ -ne '' })

$new = [string[]]@($cur | Where-Object { $_ -ne $pkg })

Set-ItemProperty $lsa -Name 'Security Packages' -Value $new -Type MultiString
Write-Host "[+] Security Packages -> $($new -join ', ')"

if (Test-Path $dst) {
    try { Remove-Item $dst -Force; Write-Host "[+] Removed $dst" }
    catch { Write-Warning "Could not delete $dst (still loaded in lsass until reboot)." }
}

Write-Host "[i] Reboot now: Restart-Computer"
