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
        throw "Unsafe target accepted: $target"
    }
}

foreach ($target in @('PC-001', 'pc-001.example.local', '10.0.0.1', '2001:db8::1')) {
    if (-not (Test-ComputerTarget $target)) {
        throw "Legitimate target rejected: $target"
    }
}

if ($application -match '(?i)cmd\s*/c|ExecutionPolicy\s+Bypass') {
    throw 'The application contains unsafe execution or an ExecutionPolicy bypass.'
}

if ($application -notmatch '&\s*\$psexecPath') {
    throw 'Remote invocation does not use the call operator with separate arguments.'
}

Write-Output 'PASS: target validation and safe remote execution'
