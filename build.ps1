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

# ---------------------------------------------------------------- build
Write-Step '编译中…'
Push-Location $SrcDir
try {
    $env:CGO_ENABLED = '0'
    $args = @('build', '-trimpath', '-ldflags', '-s -w', '-o', $OutExe)
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
Write-Step '快速自检…'
$ver = & $OutExe -version 2>&1
Write-Step "  $ver" 'Green'

Write-Host ''
Write-Host '接下来：' -ForegroundColor Cyan
Write-Host '  双击 Zenith.exe 即可运行'
Write-Host '  只跑后端：  .\Zenith.exe -headless'
Write-Host '  停止运行：  .\Zenith.exe -stop'
