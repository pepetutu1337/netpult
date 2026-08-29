# Установщик netpult для Windows: качает готовый бинарь из релизов и кладёт в PATH.
#
#   irm https://raw.githubusercontent.com/pepetutu1337/netpult/main/install.ps1 | iex
#
# Переменные окружения:
#   NETPULT_VERSION=v0.1.0      поставить конкретную версию
#   NETPULT_BIN_DIR=C:\bin      куда класть
#   NETPULT_MIRROR=https://...  своё зеркало GitHub
#   NETPULT_NO_CORE=1           не качать ядро sing-box

$ErrorActionPreference = 'Stop'

$repo   = 'pepetutu1337/netpult'
$binDir = if ($env:NETPULT_BIN_DIR) { $env:NETPULT_BIN_DIR } else { "$env:LOCALAPPDATA\netpult\bin" }

# GitHub из России часто недоступен, а netpult — утилита ровно для этого случая.
# Каждая ссылка пробуется напрямую, потом через зеркала.
$mirrors = @()
if ($env:NETPULT_MIRROR) { $mirrors += $env:NETPULT_MIRROR }
$mirrors += @('', 'https://ghproxy.net/', 'https://gh-proxy.com/', 'https://ghfast.top/')

function Get-Url($url, $outFile) {
    foreach ($m in $mirrors) {
        try {
            if ($outFile) {
                Invoke-WebRequest -Uri "$m$url" -OutFile $outFile -UseBasicParsing -TimeoutSec 300
                return $true
            } else {
                return (Invoke-WebRequest -Uri "$m$url" -UseBasicParsing -TimeoutSec 60).Content
            }
        } catch { continue }
    }
    return $null
}

if ([Environment]::Is64BitOperatingSystem -eq $false) {
    throw 'netpult собирается только под 64-битную Windows'
}
$asset = 'netpult-windows-x86_64.zip'

$version = $env:NETPULT_VERSION
if (-not $version) {
    Write-Host 'Ищу последний релиз...'
    $json = Get-Url "https://api.github.com/repos/$repo/releases/latest" $null
    if (-not $json) { throw 'Не достучаться до GitHub. Укажи версию руками: $env:NETPULT_VERSION="v0.1.0", либо своё зеркало через $env:NETPULT_MIRROR' }
    $version = ($json | ConvertFrom-Json).tag_name
}

$url = "https://github.com/$repo/releases/download/$version/$asset"
$tmp = Join-Path $env:TEMP ("netpult-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    Write-Host "Качаю netpult $version..."
    if (-not (Get-Url $url "$tmp\$asset")) { throw "Не скачалось: $url" }

    $sums = Get-Url "$url.sha256" $null
    if ($sums) {
        $expected = ($sums -split '\s+')[0]
        $actual = (Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash
        if ($expected -and $expected.ToLower() -ne $actual.ToLower()) {
            throw 'Контрольная сумма не сошлась — файл битый или подменён'
        }
        Write-Host 'Контрольная сумма сошлась.'
    }

    Expand-Archive -Path "$tmp\$asset" -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Copy-Item "$tmp\netpult.exe" (Join-Path $binDir 'netpult.exe') -Force

    # Ядро sing-box — половина пульта: без него нет ни туннеля, ни выбора ноды.
    # Качаем сразу, чтобы «поставил и работает» было правдой.
    if (-not $env:NETPULT_NO_CORE) {
        $stateDir = "$env:LOCALAPPDATA\netpult"
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
        Write-Host ''
        Write-Host 'Качаю ядро sing-box (~45 МБ, один раз)...'
        $coreUrl = "https://github.com/$repo/releases/download/$version/sing-box-windows-x86_64.exe"
        if (Get-Url $coreUrl "$tmp\sing-box.exe") {
            Copy-Item "$tmp\sing-box.exe" (Join-Path $stateDir 'sing-box.exe') -Force
            Write-Host "Ядро: $stateDir\sing-box.exe"
        } else {
            Write-Warning 'Ядро не скачалось — поставить потом: netpult vpn core install'
        }
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Готово: $binDir\netpult.exe"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir", 'User')
    Write-Host "Каталог добавлен в PATH — открой новое окно терминала."
} else {
    & "$binDir\netpult.exe" version
}

Write-Host ''
Write-Host 'Движок обхода (winws/WinDivert) ставится отдельно и требует прав администратора — см. README.'
