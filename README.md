# SCCMHound-py

Python BloodHound collector for Microsoft Configuration Manager (SCCM/MCM). Cross-platform reimplementation of [SCCMHound](https://github.com/CrowdStrike/sccmhound) using impacket, ldap3, and requests-ntlm.

Collects users, computers, groups, sessions, and local administrator data from SCCM and outputs BloodHound-compatible JSON files. Highly recommended to import alongside data from another collector (SharpHound, bloodhound.py, SOAPHound, etc.) for comprehensive AD coverage.

## Features

- **Cross-platform** — runs on Linux, macOS, and Windows (no .NET or Windows WMI dependency)
- **Multiple auth methods** — password, pass-the-hash (`-H`), Kerberos (`-k`), ccache ticket reuse (`--ccache`)
- **WMI collection via impacket** — queries SMS_R_System, SMS_R_User, SMS_R_UserGroup, SMS_CombinedDeviceResources over DCOM
- **CMPivot collection** — local administrators and current sessions via AdminService REST API
- **MSSQL EPA check** — detect whether the SCCM site database enforces Extended Protection for Authentication (channel binding), indicating NTLM relay resistance
- **BloodHound v5 JSON output** — compatible with BloodHound CE and Legacy

## Requirements

- Python >= 3.10
- Network access to the SCCM site server (WMI/DCOM + HTTPS for AdminService)
- Domain credentials with sufficient SCCM access (varies by collection method)

## Installation

```bash
git clone https://github.com/yourorg/sccmhound-py.git
cd sccmhound-py
pip install .
```

For development:
```bash
pip install -e ".[dev]"
```

## Usage

### Basic collection (WMI only)
```bash
sccmhound --server sccm01.corp.local --sitecode PS1 -u admin -p 'Password123' -d CORP
```

### Pass-the-hash
```bash
sccmhound --server sccm01 --sitecode PS1 -u admin -H :e0fb1fb85756ce429227d5b380fcef18 -d CORP
```

### Kerberos (with ccache)
```bash
export KRB5CCNAME=/tmp/krb5cc_admin
sccmhound --server sccm01.corp.local --sitecode PS1 --ccache /tmp/krb5cc_admin
```

### All collection methods (including CMPivot)
```bash
sccmhound --server sccm01 --sitecode PS1 -u admin -p pass -d CORP -c All
```

### Loop collection for session coverage
```bash
sccmhound --server sccm01 --sitecode PS1 -u admin -p pass -d CORP --loop --loopduration 01:00:00 --loopsleep 120
```

### Health check
```bash
sccmhound --server sccm01 --sitecode PS1 -u admin -p pass -d CORP --hc
```

### MSSQL EPA / channel binding check
```bash
sccmhound --server sccm01 --sitecode PS1 -u admin -p pass -d CORP --check-epa --sql-server db01.corp.local
```

## CLI Arguments

```
Required:
  --server              SCCM server hostname/IP
  --sitecode            SCCM site code

Collection:
  -c, --collectionmethods  {Default,LocalAdmins,CurrentSessions,All}
  --loop                Enable loop collection
  --loopduration        Loop duration HH:MM:SS (default: 00:30:00)
  --loopsleep           Sleep between loops in seconds (default: 60)
  --hc                  Health check: test auth and exit

Authentication:
  -u, --username        Username
  -p, --password        Password
  -d, --domain          Domain
  -H, --hash            NTLM hash (LMHASH:NTHASH or :NTHASH)
  -k, --kerberos        Use Kerberos authentication
  --ccache              Path to ccache file
  --dc-ip               Domain Controller IP for Kerberos

Security Checks:
  --check-epa           Check MSSQL EPA/channel binding on site DB
  --sql-server          MSSQL server for EPA check (default: --server)
  --sql-port            MSSQL port (default: 1433)

Output:
  -o, --output-dir      Output directory for JSON files (default: .)
  -v, --verbose         Verbose output
  --debug               Debug output (implies verbose)
```

## Collection Methods

### Default
Collects computers, users, groups, and session data using only WMI queries. Reports the currently logged-on user per computer as reported by SCCM. Use `--loop` for better session coverage over time.

### LocalAdmins (CMPivot)
Default collection plus local Administrators group membership for all online SCCM-managed computers via CMPivot. Requires SCCM "Full Administrator" role.

### CurrentSessions (CMPivot)
Default collection plus real-time session data for all online computers via CMPivot. Requires SCCM "Full Administrator" role.

### All
Runs all collection methods.

## MSSQL EPA Check

The `--check-epa` flag probes the SCCM site database server to determine if Extended Protection for Authentication is enforced. When EPA is not enforced, NTLM relay attacks against the MSSQL service may be possible (see [Misconfiguration Manager TAKEOVER-1/2](https://github.com/subat0mik/Misconfiguration-Manager)).

## Output

SCCMHound-py generates four BloodHound v5 JSON files:
- `computers-<timestamp>.json`
- `users-<timestamp>.json`
- `groups-<timestamp>.json`
- `domains-<timestamp>.json`

Import these into BloodHound CE or Legacy alongside your SharpHound/bloodhound.py dataset.

SCCMHound populates collected objects with additional SCCM-specific properties (prefixed with `sccm`) visible in BloodHound's Node Info tab, including IP addresses, AD site name, decommissioned status, and last logon information.

## Custom BloodHound Queries

[customqueries.json](customqueries.json) provides Cypher queries for analyzing SCCMHound datasets. Copy to `~/.config/bloodhound/customqueries.json` and restart BloodHound.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check sccmhound/

# Type check
mypy sccmhound/
```

## Credits

Python port of [SCCMHound](https://github.com/CrowdStrike/sccmhound) by Chris Elliott (CrowdStrike Red Team). Leverages patterns from [SCCMHunter](https://github.com/garrettfoster13/sccmhunter), [bloodhound.py](https://github.com/dirkjanm/BloodHound.py), and [impacket](https://github.com/fortra/impacket).

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
