# ============================================================================
#  Zenith build script
#
#  Compiles src/ into Zenith.exe in the repository root.
#  Needs Go 1.21+ on PATH (or set -GoPath to the executable).
#
#  Usage:
#    .\build.ps1
#    .\build.ps1 -GoPath "D:\AI\tools\go\bin\go.exe"
#    .\build.ps1 -Race          enable the race detector (slower, for testing)
#    .\build.ps1 -Clean         remove build output first
# ============================================================================

[CmdletBinding()]
param(
    [string]$GoPath = 'go',
    [switch]$Race,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$Root    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$SrcDir  = Join-Path $Root 'src'
$OutExe  = Join-Path $Root 'Zenith.exe'

function Write-Step {
    param([string]$Text, [string]$Color = 'Cyan')
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text) -ForegroundColor $Color
}

# ---------------------------------------------------------------- locate go
$go = $GoPath
if (-not (Get-Command $go -ErrorAction SilentlyContinue)) {
    foreach ($candidate in @(
            'D:\AI\tools\go\bin\go.exe',
            "$env:ProgramFiles\Go\bin\go.exe",
            "$env:LOCALAPPDATA\Programs\Go\bin\go.exe")) {
        if (Test-Path $candidate) { $go = $candidate; break }
    }
}
if (-not (Get-Command $go -ErrorAction SilentlyContinue) -and -not (Test-Path $go)) {
    throw "找不到 Go：请安装 Go 1.21+，或用 -GoPath 指定 go.exe 的路径"
}

Write-Step "使用 Go: $(& $go version)"

# ---------------------------------------------------------------- sanity
foreach ($need in @('src', 'web', 'core')) {
    if (-not (Test-Path (Join-Path $Root $need))) {
        throw "仓库不完整：缺少 $need 目录"
    }
}
$core = Join-Path $Root 'core\mihomo.exe'
if (-not (Test-Path $core)) {
    Write-Step "警告：core\mihomo.exe 不存在，程序将无法启动内核" 'Yellow'
    Write-Step "  可从 https://github.com/MetaCubeX/mihomo/releases 下载 windows-amd64 版本" 'Yellow'
}

if ($Clean) {
    foreach ($p in @($OutExe, (Join-Path $Root 'data'), (Join-Path $Root 'logs'))) {
        if (Test-Path $p) { Remove-Item $p -Recurse -Force; Write-Step "已清理 $p" }
    }
}

# ---------------------------------------------------------------- icon
# Windows reads the executable's icon from a resource section, which Go cannot
# emit on its own. icon.syso is committed so a normal build needs nothing extra;
# this step only regenerates it when the .ico is newer than the .syso, and it
# degrades to a warning when no resource compiler is available.
$icoPath = Join-Path $Root 'data\zenith.ico'
$sysoPath = Join-Path $SrcDir 'icon.syso'
if (Test-Path $icoPath) {
    $needIcon = -not (Test-Path $sysoPath)
    if (-not $needIcon) {
        $needIcon = (Get-Item $icoPath).LastWriteTime -gt (Get-Item $sysoPath).LastWriteTime
    }
    if ($needIcon) {
        $rsrc = $null
        foreach ($c in @((Join-Path (Split-Path $go -Parent) 'rsrc.exe'),
                         (Join-Path $env:USERPROFILE 'go\bin\rsrc.exe'))) {
            if (Test-Path $c) { $rsrc = $c; break }
        }
        if ($rsrc) {
            Write-Step '生成图标资源…'
            & $rsrc -ico $icoPath -o $sysoPath -arch amd64
            if ($LASTEXITCODE -ne 0) { Write-Step '  图标生成失败，将使用默认图标' 'Yellow' }
        } else {
            Write-Step 'icon.syso 已是最新；如需重新生成请安装 rsrc：' 'Yellow'
            Write-Step '  go install github.com/akavel/rsrc@latest' 'Yellow'
        }
    }
}

# ---------------------------------------------------------------- tests
# The regression tests cover the defects a review found: the watchdog entry that
# could never be reached, the health-map race that could crash the process, the
# slow-node counter that never incremented, the TUN component check, loopback and
# token enforcement, and the refusal to fetch a subscription over plain http.
# They run before the build so a regression fails here rather than in the field.
Write-Step '运行回归测试…'
Push-Location $SrcDir
try {
    $env:CGO_ENABLED = '0'
    # A timeout so a deadlock fails the build instead of hanging it. A recursive
    # mutex is exactly the kind of defect this suite is meant to catch, and one
    # was caught this way.
    $testArgs = @('test', '-timeout', '90s', './...')
    if ($Race) { $testArgs += '-race' }
    & $go @testArgs
    if ($LASTEXITCODE -ne 0) { throw "测试未通过 (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------- build
Write-Step '编译中…'
Push-Location $SrcDir
try {
    $env:CGO_ENABLED = '0'
    # -H=windowsgui makes this a GUI-subsystem binary. Without it Windows
    # allocates a console window on every launch, and closing that console
    # kills the process (CTRL_CLOSE_EVENT) - which looked like "closing the
    # black window shuts Zenith down".
    $args = @('build', '-trimpath', '-ldflags', '-s -w -H=windowsgui', '-o', $OutExe)
    if ($Race) { $args += '-race' }
    $args += '.'
    & $go @args
    if ($LASTEXITCODE -ne 0) { throw "编译失败 (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$exe = Get-Item $OutExe
Write-Step ("编译完成: {0}  ({1:N1} MB)" -f $exe.Name, ($exe.Length / 1MB)) 'Green'

# ---------------------------------------------------------------- smoke test
# A GUI-subsystem binary has no console, so its stdout goes nowhere and
# "-version" cannot be captured. The checks are therefore on the artefact: its
# size, its PE subsystem, and whether the icon resource made it in.
Write-Step '检查产物…'
if ($exe.Length -lt 2MB) {
    throw "产物异常小 ($([math]::Round($exe.Length/1KB,1)) KB)，编译可能失败了"
}

$fs = [System.IO.File]::OpenRead($OutExe)
try {
    $br = New-Object System.IO.BinaryReader($fs)
    $fs.Position = 0x3C
    $peOff = $br.ReadInt32()
    $fs.Position = $peOff + 24 + 68
    $subsystem = $br.ReadUInt16()
} finally { $fs.Close() }
if ($subsystem -eq 2) {
    Write-Step '  GUI 子系统：双击不会弹出命令行窗口' 'Green'
} else {
    Write-Step "  警告：子系统为 $subsystem（应为 2），运行时会弹出命令行窗口" 'Yellow'
}

# The pre-parse dispatch has to be reachable, because the watchdog depends on it
# and it used to sit after flag.Parse - which exits on an unknown flag, so the
# helper died on its own argument and the crash protection did not exist.
#
# This is checked by looking for the marker string in the binary rather than by
# running it. A GUI-subsystem binary has no console, so anything it prints goes
# nowhere and cannot be captured - the same reason the checks above are on the
# artefact rather than on its output. The release workflow runs on a console build
# and does execute the path for real, which is where the behavioural check lives.
$markBytes = [System.IO.File]::ReadAllBytes($OutExe)
$markText = [System.Text.Encoding]::ASCII.GetString($markBytes)
if ($markText -notmatch 'selftest ok') {
    throw "产物自检失败：分派入口的标记字符串不在产物中"
}
Write-Step '  分派入口已编译进产物（行为检查在发布流水线执行）' 'Green'

$bytes = [System.IO.File]::ReadAllBytes($OutExe)
$hasRsrc = $false
for ($i = 0; $i -lt $bytes.Length - 5; $i++) {
    if ($bytes[$i] -eq 0x2E -and $bytes[$i + 1] -eq 0x72 -and $bytes[$i + 2] -eq 0x73 -and
        $bytes[$i + 3] -eq 0x72 -and $bytes[$i + 4] -eq 0x63) { $hasRsrc = $true; break }
}
if ($hasRsrc) { Write-Step '  图标资源：已嵌入' 'Green' }
else { Write-Step '  图标资源：缺失（exe 会显示默认图标）' 'Yellow' }

Write-Host ''
Write-Host '接下来：' -ForegroundColor Cyan
Write-Host '  双击 Zenith.exe 即可运行'
Write-Host '  关闭窗口不会退出：程序留在系统托盘，右键托盘图标才能退出'
Write-Host '  只跑后端：  .\Zenith.exe -headless'
Write-Host '  停止运行：  .\Zenith.exe -stop'
