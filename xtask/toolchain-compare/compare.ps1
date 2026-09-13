# Compare toolchains and Rust versions for rustHashTab.
#
# Usage:
#   pwsh xtask/toolchain-compare/compare.ps1 noise   [-Passes 40]   # MSVC vs GNU, with a noise floor
#   pwsh xtask/toolchain-compare/compare.ps1 version [-Passes 40]   # pinned vs installed stable
#
# Why this exists: throughput claims are only meaningful with a measured noise
# floor. A single A/B run differs by ~10% run to run, which is larger than any
# real toolchain delta found so far. Every comparison runs each configuration
# twice and reports the same-configuration spread next to the cross ratio.
#
# Findings are written up in docs/internal/TOOLCHAIN-EVALUATION.md.
# Re-run after changing rust-toolchain.toml or .cargo/config.toml.

param(
    [Parameter(Position = 0)]
    [ValidateSet('noise', 'version')]
    [string]$Mode = 'noise',

    [int]$Passes = 40
)

Set-Location (Resolve-Path "$PSScriptRoot\..\..")

# NOTE: no `$ErrorActionPreference = 'Stop'` -- cargo writes progress to stderr
# and PowerShell turns that into a terminating error.
$outDir = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Invoke-Capture([string]$exe, [string[]]$argv) {
    $lines = & $exe @argv 2>&1 | ForEach-Object { "$_" }
    return @{ Lines = $lines; Exit = $LASTEXITCODE }
}

function Parse-Bench($lines) {
    $map = @{}
    foreach ($line in $lines) {
        if ($line -match '^([A-Za-z].*?)\s{2,}([\d.]+)\s*$') { $map[$matches[1].Trim()] = [double]$matches[2] }
    }
    return $map
}

$vs = 'C:\Program Files\Microsoft Visual Studio\2022\Community'
if (-not (Test-Path $vs)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) { $vs = (& $vswhere -property installationPath | Select-Object -First 1) }
}
$vc = Get-ChildItem "$vs\VC\Tools\MSVC" -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVer = Get-ChildItem "$sdkRoot\Lib" -Directory | Sort-Object Name -Descending | Select-Object -First 1

$origPath = $env:PATH
$msvcPath = "$($vc.FullName)\bin\Hostx64\x64;$sdkRoot\bin\$($sdkVer.Name)\x64;$origPath"
$msvcLib = "$($vc.FullName)\lib\x64;$sdkRoot\Lib\$($sdkVer.Name)\ucrt\x64;$sdkRoot\Lib\$($sdkVer.Name)\um\x64"
$msvcInc = "$($vc.FullName)\include;$sdkRoot\Include\$($sdkVer.Name)\ucrt;$sdkRoot\Include\$($sdkVer.Name)\um;$sdkRoot\Include\$($sdkVer.Name)\shared"

function Use-MsvcEnv {
    $env:PATH = $msvcPath; $env:LIB = $msvcLib; $env:INCLUDE = $msvcInc
}
function Use-CleanEnv {
    $env:PATH = $origPath
    Remove-Item Env:LIB, Env:INCLUDE -ErrorAction SilentlyContinue
}

function Run-Bench([string]$toolchain, [string]$target, [string]$label) {
    Write-Host "  $label ..."
    if ($target -like '*msvc*') { Use-MsvcEnv } else { Use-CleanEnv }
    $r = Invoke-Capture 'cargo' @("+$toolchain", 'run', '--release', '--target', $target,
        '-p', 'xtask', '--', 'bench', '--passes', "$Passes")
    $r.Lines | Set-Content (Join-Path $outDir "$label.txt")
    return Parse-Bench $r.Lines
}

function Show-Comparison($a, $b, $c, $d, $labelA, $labelB) {
    Write-Host ''
    Write-Host ('{0,-14} {1,>10} {2,>10} {3,>8}   {4,>10} {5,>10} {6,>8}   {7,>9}' -f `
        'ALGORITHM', "$labelA#1", "$labelA#2", 'noise', "$labelB#1", "$labelB#2", 'noise', "$labelB/$labelA")
    Write-Host ('-' * 94)

    $ratios = @(); $noiseA = @(); $noiseB = @()
    foreach ($name in ($a.Keys | Sort-Object)) {
        if (-not ($b.ContainsKey($name) -and $c.ContainsKey($name) -and $d.ContainsKey($name))) { continue }
        $a1 = $a[$name]; $b1 = $b[$name]; $c1 = $c[$name]; $d1 = $d[$name]
        $nA = [Math]::Abs($b1 - $a1) / [Math]::Max($a1, $b1)
        $nB = [Math]::Abs($d1 - $c1) / [Math]::Max($c1, $d1)
        $ratio = (($c1 + $d1) / 2) / (($a1 + $b1) / 2)
        $noiseA += $nA; $noiseB += $nB; $ratios += $ratio
        Write-Host ('{0,-14} {1,10:N0} {2,10:N0} {3,8:P0}   {4,10:N0} {5,10:N0} {6,8:P0}   {7,9:P0}' -f `
            $name, $a1, $b1, $nA, $c1, $d1, $nB, $ratio)
    }
    Write-Host ('-' * 94)

    $mA = ($noiseA | Measure-Object -Average).Average
    $mB = ($noiseB | Measure-Object -Average).Average
    $r = $ratios | Measure-Object -Average -Minimum -Maximum
    Write-Host ''
    Write-Host ('mean run-to-run noise:  {0} {1:P1}   {2} {3:P1}' -f $labelA, $mA, $labelB, $mB)
    Write-Host ('{0}/{1} ratio:  mean {2:P0}   range {3:P0} .. {4:P0}' -f $labelB, $labelA, $r.Average, $r.Minimum, $r.Maximum)
    Write-Host ''
    $worst = [Math]::Max($mA, $mB)
    if ($worst -gt 0.15) {
        Write-Host ("WARNING: noise {0:P0} exceeds 15%. Raise -Passes before trusting any delta." -f $worst)
    } else {
        Write-Host ("Noise {0:P0}. Any delta below that is not a result." -f $worst)
    }
}

Write-Host "mode=$Mode passes=$Passes toolset=$($vc.Name) sdk=$($sdkVer.Name)"
Write-Host ''

if ($Mode -eq 'noise') {
    Write-Host 'measuring:'
    $a = Run-Bench 'stable-x86_64-pc-windows-msvc' 'x86_64-pc-windows-msvc' 'msvc-a'
    $b = Run-Bench 'stable-x86_64-pc-windows-msvc' 'x86_64-pc-windows-msvc' 'msvc-b'
    $c = Run-Bench 'stable-x86_64-pc-windows-gnu' 'x86_64-pc-windows-gnu' 'gnu-a'
    $d = Run-Bench 'stable-x86_64-pc-windows-gnu' 'x86_64-pc-windows-gnu' 'gnu-b'
    Show-Comparison $a $b $c $d 'MSVC' 'GNU'
} else {
    # Both runs use the GNU target so one host toolchain serves both sides,
    # isolating the Rust version rather than the target.
    $pinned = (Select-String -Path 'rust-toolchain.toml' -Pattern '^channel\s*=\s*"(.+)"').Matches[0].Groups[1].Value
    Write-Host "pinned channel: $pinned"
    Write-Host 'measuring:'
    $a = Run-Bench $pinned 'x86_64-pc-windows-gnu' 'pinned-a'
    $b = Run-Bench $pinned 'x86_64-pc-windows-gnu' 'pinned-b'
    $c = Run-Bench 'stable' 'x86_64-pc-windows-gnu' 'stable-a'
    $d = Run-Bench 'stable' 'x86_64-pc-windows-gnu' 'stable-b'
    Show-Comparison $a $b $c $d 'pinned' 'stable'
}

Write-Host ''
Write-Host "raw output in $outDir"
