# Сборка приложения на Windows-хосте разработки.
# Тот же результат, что и build/build.sh: build/out/DnsOverrideApp.zip.
# Целевая платформа приложения — Ubuntu 24.04+, но сборка платформонезависима.

$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src/DnsOverrideApp/DnsOverrideApp.csproj'
$publish = Join-Path $root 'build/publish'
$out     = Join-Path $root 'build/out'
$zip     = Join-Path $out 'DnsOverrideApp.zip'

# Библиотеки сервера в архив не кладутся (конфликт типов при загрузке).
# DnsOverrideApp.deps.json обязателен: по *.deps.json сервер находит приложение.
$files = @('DnsOverrideApp.dll', 'DnsOverrideApp.deps.json', 'dnsApp.config', 'README.md')

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
if (Test-Path $out)     { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Force -Path $out | Out-Null

dotnet publish $project -c Release -f net10.0 -o $publish --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish завершился с кодом $LASTEXITCODE" }

$paths = foreach ($file in $files) {
    $path = Join-Path $publish $file
    if (-not (Test-Path $path)) { throw "нет файла $file в $publish" }
    $path
}

Compress-Archive -Path $paths -DestinationPath $zip -CompressionLevel Optimal

$version = ([xml](Get-Content $project)).Project.PropertyGroup.Version | Where-Object { $_ }

Write-Output ''
Write-Output "версия:  $version"
Write-Output "архив:   $zip ($([math]::Round((Get-Item $zip).Length / 1KB, 1)) КБ)"
