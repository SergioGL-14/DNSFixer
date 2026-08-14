function Test-ComputerTarget {
    <#
    Validates a host name or IP literal accepted by the diagnostics.
    #>
    param(
        [AllowNull()]
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target) -or $Target.Length -gt 253) {
        return $false
    }

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($Target, [ref]$parsedAddress)) {
        return $true
    }

    if ($Target -match '[\s\\/;|&`$<>"'']' -or $Target.EndsWith('.') -or $Target.StartsWith('.')) {
        return $false
    }

    foreach ($label in $Target -split '\.') {
        if ($label.Length -lt 1 -or $label.Length -gt 63 -or
            $label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') {
            return $false
        }
    }

    return $true
}
