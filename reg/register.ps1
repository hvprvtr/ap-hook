# register.ps1  -  install ApHook. RUN AS ADMINISTRATOR.
#
# 1) copies the CMake-built ApHook.dll to C:\Windows\System32
#    (from out\build\<preset>\; defaults to x64-release, falls back to x64-debug;
#     override with -Config <presetName>)
# 2) appends "ApHook" to HKLM\...\Lsa\Security Packages so LSA loads our
#    package into lsass at boot and calls our SpLsaModeInitialize.
#
# We do NOT add msv1_0 to the list: msv1_0 is a default package that LSA always
# loads, and our hook works by inline-patching the bytes of msv1_0!LogonUserEx2
# in the already-mapped module (we LoadLibrary + self-harvest its function table
# ourselves). So list ORDER relative to msv1_0 is irrelevant, and touching the
# default-package machinery would risk a double load. Just register ourselves.
#
# A REBOOT is required afterwards - the list is read at lsass.exe startup.

param([string]$Config)

$ErrorActionPreference = 'Stop'
$pkg  = 'ApHook'
$root = Join-Path $PSScriptRoot '..'
$dst  = "$env:WINDIR\System32\ApHook.dll"
$lsa  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { throw 'Administrator rights required.' }

# Locate the CMake-built DLL under out\build\<preset>\. Prefer an explicit
# -Config, else x64-release, else x64-debug, else the newest match anywhere.
$candidates = @()
if ($Config) { $candidates += (Join-Path $root "out\build\$Config\ApHook.dll") }
$candidates += (Join-Path $root 'out\build\x64-release\ApHook.dll')
$src = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $src) {
    $src = Get-ChildItem (Join-Path $root 'out\build') -Recurse -Filter ApHook.dll -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $src) {
    throw "ApHook.dll not found under out\build\. Build first in VS (Open Folder -> Build All), or: cmake --preset x64-release && cmake --build --preset x64-release"
}
Write-Host "[i] Using DLL: $src"

$ppl = (Get-ItemProperty $lsa -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
if ($ppl) { Write-Warning "RunAsPPL=$ppl : LSA Protection is ON - unsigned DLL will not load." }

# --- 1) copy DLL (handle the case where an old copy is loaded in lsass) ---
try {
    Copy-Item $src $dst -Force -ErrorAction Stop
} catch {
    # File is in use (loaded in lsass). A loaded DLL can be RENAMED but not
    # overwritten; rename it aside, then copy the new one into place. The stale
    # .old is cleaned up on the next boot (or delete manually after reboot).
    $old = "$dst.old"
    if (Test-Path $old) { Remove-Item $old -Force -ErrorAction SilentlyContinue }
    Move-Item $dst $old -Force
    Copy-Item $src $dst -Force
    Write-Host "[i] Old DLL was in use -> renamed to $old"
}
Write-Host "[+] DLL copied: $dst"

# --- 2) append our package to Security Packages (idempotent) ---
$cur = (Get-ItemProperty $lsa -Name 'Security Packages' -ErrorAction SilentlyContinue).'Security Packages'
$cur = @([string[]]$cur | Where-Object { $_ -ne '' })

# @() is mandatory: a single-match Where-Object returns a SCALAR string, and
# "$scalar + 'x'" would CONCATENATE strings instead of appending array elements.
$rest = @($cur | Where-Object { $_ -ne $pkg })
$new  = [string[]]($rest + $pkg)

Set-ItemProperty $lsa -Name 'Security Packages' -Value $new -Type MultiString
Write-Host "[+] Security Packages -> $($new -join ', ')"

Write-Host ""
Write-Host "[i] Done. Reboot now: Restart-Computer"
Write-Host "[i] After reboot check log: C:\ap-hook\policy.log"
