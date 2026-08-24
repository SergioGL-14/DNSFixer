# DNSFixer

Windows GUI tool to diagnose and repair DNS problems on local or remote
machines. Written in PowerShell with a WPF interface, aimed at IT support
work: stale DNS records, resolutions that point to the wrong network, cache
issues.

## Features

| Feature | What it does |
|---|---|
| Basic diagnostic | Active IPs, configured DNS server, `nslookup`, PTR records, TTL |
| Advanced diagnostic | Everything above plus `ipconfig /all`, IPv4 configuration and active adapters |
| Repair | Detects stale records and runs `ipconfig /registerdns` plus a cache flush, then re-checks |
| Cache flush | `Clear-DnsClientCache` locally or remotely |
| Log analysis | Scans the diagnostic log and reports errors, alerts and recommendations |
| Export | Saves the full log to a `.txt` file |
| Remote execution | Runs diagnostics and repairs on remote machines through PsExec |

The interface has four tabs (Diagnostics, Repair, Analysis, Settings) with an
activity log on the right side.

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 10 / 11 / Server 2016+ |
| PowerShell | 5.1 or later |
| .NET Framework | 4.5+ (included in Windows 10+) |
| Privileges | Administrator recommended for repair and cache flush |
| PsExec | Only needed for remote execution |

## Usage

```powershell
cd C:\path\to\DNSFixer
.\DNSFixer.ps1
```

The script never changes the execution policy. If a policy blocks it, an
administrator has to authorize it according to your own rules.

### Expected IP prefixes

This is the central setting. When the diagnostic resolves a computer name,
it compares the returned IP against the prefix list configured in the
Settings tab (`10.` and `69.` by default):

- The IP starts with one of the prefixes: the DNS record is considered valid.
- It does not match any prefix: alert, likely a stale record.

Adjust the list when your network uses different ranges, when you manage
several sites, or after network migrations. Changes apply to the current
session only.

### Remote execution

Enter a remote computer name or IP and DNSFixer runs the same commands there
through PsExec instead of locally:

```
psexec.exe \\REMOTE-PC powershell.exe -NoProfile -Command "..."
```

Requirements for remote mode:

1. `psexec.exe` available at `C:\temp\PsTools\` (path is configurable in
   `$App.Config.PsExecPath`)
2. The remote machine reachable over the network
3. Administrator permissions and the `ADMIN$` share enabled on it

Local execution is detected automatically when the target matches the local
computer name or one of its IPs.

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| "Non-existent domain" when resolving | No DNS record for that computer | Normal in home networks. In corporate networks run Repair |
| Prefixes always report alerts | Current network not in the prefix list | Add your prefix in Settings |
| Repair applies no changes | Insufficient permissions | Run PowerShell as Administrator |
| PsExec fails | Not found or blocked | Check path and network permissions |
| Cache flushed but problem persists | Stale record on the DNS server | Contact the DNS administrator |

## How it works

All state lives in a single `$Global:DNSFixerApp` object (controls,
configuration, active tab). Every action function receives the target
computer and the log control as parameters, and `Invoke-LocalOrRemote`
decides whether a script block runs locally or through PsExec. Log writes go
through `Write-Log`, which marshals calls to the UI thread via the WPF
dispatcher.

Input validation lives in `DNSFixer.Security.ps1`: host names and IPs are
checked before they reach `nslookup` or PsExec, so shell metacharacters
cannot be injected through the computer field.

## Project structure

```
DNSFixer/
├── DNSFixer.ps1              # Main application (WPF)
├── DNSFixer.Security.ps1     # Input validation helpers
├── tests/
│   └── Test-DNSFixerSecurity.ps1
├── LICENSE
└── README.md
```

The test suite validates the security helpers and scans the main script for
unsafe patterns. It runs in CI on every push and can be executed directly:

```powershell
./tests/Test-DNSFixerSecurity.ps1
```

## Changelog

### v2.0 (2026-03-10)

- Windows Forms replaced with WPF: resizable layout, tab bar, Material-based palette
- Log analysis rewritten with contextual detection and recommendations
- PTR lookups and TTL reporting moved to `Resolve-DnsName`
- Fixed active IP retrieval (flat IPv4 array) and nslookup output filtering
- Adapter listing filtered to connected interfaces
- Centralized application state in `$Global:DNSFixerApp`
- Input validation and safe PsExec invocation hardened

### v1.0

- Initial version (Windows Forms): basic diagnostic, repair, cache flush, export

## License

MIT — see [LICENSE](LICENSE). PsExec is part of
[Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
by Microsoft.
