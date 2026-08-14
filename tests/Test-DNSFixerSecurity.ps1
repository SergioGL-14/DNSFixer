$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\DNSFixer.Security.ps1')
$application = Get-Content (Join-Path $PSScriptRoot '..\DNSFixer.ps1') -Raw

$dangerousTargets = @(
    'host;whoami',
    'host&whoami',
    'host`$(whoami)',
    'host..example',
    'host name',
    '\\server\share',
    '10.0.0.1/24'
)

foreach ($target in $dangerousTargets) {
    if (Test-ComputerTarget $target) {
        throw "Target peligroso aceptado: $target"
    }
}

foreach ($target in @('PC-001', 'pc-001.example.local', '10.0.0.1', '2001:db8::1')) {
    if (-not (Test-ComputerTarget $target)) {
        throw "Target legitimo rechazado: $target"
    }
}

if ($application -match '(?i)cmd\s*/c|ExecutionPolicy\s+Bypass') {
    throw 'La aplicación contiene una ejecución insegura o un bypass de ExecutionPolicy.'
}

if ($application -notmatch '&\s*\$psexecPath') {
    throw 'La invocación remota no usa el operador de llamada con argumentos separados.'
}

Write-Output 'PASS: validación de objetivos y ejecución remota segura'
