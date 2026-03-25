# SCCMHound-py

Python BloodHound collector for Microsoft Configuration Manager (SCCM/MCM). Cross-platform reimplementation of [SCCMHound](https://github.com/CrowdStrike/sccmhound) using impacket, ldap3, and requests-ntlm.

Collects users, computers, groups, sessions, and local administrator data from SCCM, maps SCCM attack paths as BloodHound graph edges, and outputs both standard BloodHound JSON and OpenGraph JSON for BloodHound CE.

Highly recommended to import alongside data from another collector (SharpHound, bloodhound.py, SOAPHound, etc.) for comprehensive AD coverage.

## Features

- **Auto-discovery** — just provide domain creds and a DC, SCCM infrastructure is discovered automatically via LDAP
- **Cross-platform** — runs on Linux, macOS, and Windows (no .NET or Windows WMI dependency)
- **Multiple auth methods** — password, pass-the-hash (`-H`), Kerberos (`-k`), ccache ticket reuse (`--ccache`)
- **SCCM attack path mapping** — outputs BloodHound CE OpenGraph JSON with SCCM-specific nodes, edges, and relay indicators
- **Misconfiguration detection** — checks for NTLM relay conditions (EPA, SMB signing) on SCCM database servers
- **16 pre-built Cypher queries** — ready-to-use BloodHound queries for SCCM attack path analysis

## Requirements

- Python >= 3.10
- Network access to the domain controller (LDAP) and SCCM site server (WMI/DCOM + HTTPS for AdminService)
- Domain credentials (any domain user for discovery; SCCM access for collection)

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

## Quick Start

```bash
# Auto-discover SCCM and collect everything
sccmhound -d CORP.LOCAL -u admin -p 'Password123' -c All

# Import ALL output files into BloodHound CE:
#   computers-*.json, users-*.json, groups-*.json, domains-*.json  (standard)
#   sccm-opengraph-*.json  (SCCM attack paths — this is the important one)
```

## Usage

### Auto-discovery (recommended)

Just provide domain credentials — SCCMHound discovers SCCM infrastructure automatically:

```bash
sccmhound -d CORP.LOCAL -u admin -p 'Password123'
```

With a specific DC:
```bash
sccmhound -d CORP.LOCAL -u admin -p 'Password123' --dc-ip 10.0.0.1
```

### Pass-the-hash
```bash
sccmhound -d CORP.LOCAL -u admin -H :e0fb1fb85756ce429227d5b380fcef18
```

### Kerberos (with ccache)
```bash
sccmhound -d CORP.LOCAL --ccache /tmp/krb5cc_admin
```

### All collection methods (including CMPivot)
```bash
sccmhound -d CORP.LOCAL -u admin -p pass -c All
```

### Manual server override (skip discovery)
```bash
sccmhound -d CORP.LOCAL -u admin -p pass --server sccm01.corp.local --sitecode PS1
```

### Loop collection for session coverage
```bash
sccmhound -d CORP.LOCAL -u admin -p pass --loop --loopduration 01:00:00 --loopsleep 120
```

### Health check
```bash
sccmhound -d CORP.LOCAL -u admin -p pass --hc
```

### Force EPA check (also runs automatically when DB server is discovered)
```bash
sccmhound -d CORP.LOCAL -u admin -p pass --check-epa --sql-server db01.corp.local
```

## What SCCMHound Detects

SCCMHound maps its findings to attack techniques from [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager). Everything detected is output as BloodHound graph data — not just console text.

### Detectable Attack Techniques

| Technique | Description | How SCCMHound detects it | What appears in BloodHound |
|---|---|---|---|
| **RECON-1** | SCCM infrastructure enumeration via LDAP | Queries `mSSMSManagementPoint`, `mSSMSSite`, System Management container DACL | `SCCMSite` node + `SCCMSiteServerFor`, `SCCMManagementPointFor`, `SCCMDistributionPointFor` edges linking computers to sites |
| **RECON-5** | Locate users via SMS Provider | WMI query `SMS_CombinedDeviceResources` for `CurrentLogonUser` | `HasSession` edges between users and computers |
| **RECON-6** | SCCM site database discovery via remote registry | Reads `HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER` on site server | `SCCMDBServerFor` edge from DB server computer to site |
| **CRED-1** | PXE boot credential theft risk | LDAP query for `connectionPoint` objects with `netbootserver` attribute | `SCCMDistributionPointFor` edge with `pxe_enabled: true` property |
| **EXEC-1** | Code execution via SCCM application deployment | All managed computers discovered via WMI `SMS_R_System` | `SCCMManages` edges from site to every managed computer |
| **EXEC-2** | Code execution via SCCM script deployment | Same as EXEC-1 (same scope of managed clients) | Same `SCCMManages` edges |
| **TAKEOVER-1** | Hierarchy takeover via NTLM relay to MSSQL | EPA check against site database (TDS prelogin + NTLM probe) | `SCCMRelayTarget` edge with `epa_enforced: false` when relay is possible |
| **TAKEOVER-2** | Hierarchy takeover via NTLM relay to SMB on DB server | SMB signing check on discovered database server | `SCCMRelayTarget` edge with `smb_signing_required: false` when relay is possible |

### What SCCMHound Cannot Detect

These techniques require active exploitation, local access, or out-of-scope protocols. They are **not** something an enumeration tool can safely check:

| Technique | Why it can't be detected |
|---|---|
| CRED-2 (fake client policy request) | Requires registering a rogue SCCM client and decrypting policy — active exploitation |
| CRED-3 (DPAPI NAA extraction) | Requires local admin on an SCCM client + DPAPI system key |
| CRED-4 (CIM repository secrets) | Requires local filesystem access to `OBJECTS.DATA` on a client |
| CRED-5 (site DB credential dump) | Requires `sysadmin` on the site DB + RSA private key from site server |
| CRED-7 (AdminService credential dump) | Requires Full Admin + site server decryption keys |
| CRED-8 (MP relay to site DB) | Active NTLM relay attack |
| ELEVATE-1/2/3 (NTLM relay escalation) | Active relay/coercion attacks |
| ELEVATE-4/5 (DP takeover via PXE/OSD) | Requires PXE boot media recovery |
| ELEVATE-6 (ccmcache LPE) | Requires local access to client filesystem |
| TAKEOVER-3 through 8 | Active NTLM relay attacks against various targets |
| TAKEOVER-9 (SQL linked server crawl) | Requires DB access |
| COERCE-1/2 | Active NTLM coercion attacks |

## How to Interpret the BloodHound Output

### Output Files

SCCMHound produces **5 files** — import all of them into BloodHound CE:

| File | Format | Contains |
|---|---|---|
| `computers-*.json` | Standard BH v5 | Computer objects with SCCM properties, sessions, local admins |
| `users-*.json` | Standard BH v5 | User objects with SCCM properties |
| `groups-*.json` | Standard BH v5 | Group objects with membership |
| `domains-*.json` | Standard BH v5 | Domain objects |
| `sccm-opengraph-*.json` | BH CE OpenGraph | **SCCM attack paths** — this is where the SCCM-specific graph data lives |

### Understanding the OpenGraph Edges

After importing into BloodHound CE, you'll see these new relationship types in the graph:

#### `SCCMSiteServerFor` (Computer → SCCMSite)

This computer is the SCCM site server for a site. **Compromising this machine gives you control over the entire SCCM hierarchy.** From here you can deploy applications and scripts to every managed client.

- Look for: shortest paths from your current access to this computer
- Properties: `smb_signing_required` — if false, the site server itself may be targetable via SMB relay

#### `SCCMManagementPointFor` (Computer → SCCMSite)

This computer is a management point. MPs handle client communication, policy delivery, and the AdminService API. Useful for identifying where to aim CMPivot queries and AdminService attacks.

- Properties: `is_default` — the primary MP that clients talk to

#### `SCCMDistributionPointFor` (Computer → SCCMSite)

This computer is a distribution point. DPs serve software packages and OS deployment media to clients.

- Properties: `pxe_enabled` — **if true, this DP is vulnerable to CRED-1 (PXE credential theft)**. An attacker on the same network segment can intercept PXE boot media and extract Network Access Account credentials or task sequence secrets.

#### `SCCMDBServerFor` (Computer → SCCMSite)

This computer hosts the SCCM site database (MSSQL). The site database contains all SCCM configuration, credentials, and role assignments.

- Properties: `smb_signing_required`, `epa_enforced` — these indicate relay vulnerability

#### `SCCMManages` (SCCMSite → Computer)

**The most important edge for attack path analysis.** This means the SCCM site can deploy software and scripts to this computer as SYSTEM. If you compromise the site server, you can execute code on every computer with this edge.

In BloodHound, query paths like:
```
Your User → HasSession → Computer → AdminTo → SiteServer → SCCMSiteServerFor → SCCMSite → SCCMManages → Target Computer
```

#### `SCCMRelayTarget` (SCCMSite → Computer)

**This edge only exists when a relay vulnerability is detected.** It means the SCCM site's database server is vulnerable to NTLM relay, which can lead to full SCCM hierarchy takeover.

- `epa_enforced: false` → **TAKEOVER-1**: Coerce the site server's machine account and relay to MSSQL on the DB server. The attacker can grant themselves Full Administrator in SCCM, then deploy code to every managed client.
- `smb_signing_required: false` → **TAKEOVER-2**: Same coercion, but relay to SMB instead. The site server's machine account is typically local admin on the DB server.
- `relay_reasons` — human-readable list of why this target is relayable

### Understanding the SCCM Properties on Standard Objects

Computers, users, and groups have additional `sccm*` properties visible in BloodHound's Node Info tab:

| Property | On | Meaning |
|---|---|---|
| `sccmIPAddresses` | Computer | All IP addresses reported by the SCCM client — useful for network targeting |
| `sccmLastLogonUserName` | Computer | Last user logged into this machine per SCCM — historical session data |
| `sccmLastLogonUserDomain` | Computer | Domain of that user |
| `sccmActive` | Computer | Whether SCCM considers this client active |
| `sccmDecomissioned` | Computer | Decommissioned flag — may indicate stale but still-joined machines |
| `sccmSystemRoles` | Computer | SCCM roles (SMS Provider, SQL Server, etc.) — helps identify infrastructure |
| `sccmADSiteName` | Computer | AD site — useful for network segmentation understanding |
| `sccmClient` | Computer | Whether SCCM client agent is installed |
| `sccmUniqueUserName` | User | `DOMAIN\username` format as tracked by SCCM |
| `sccmCreationDate` | User | When SCCM first discovered this user |

## Custom BloodHound Queries

Copy [customqueries.json](customqueries.json) to `~/.config/bloodhound/customqueries.json` and restart BloodHound. The queries appear under the "Analysis" tab organized into categories:

### SCCMHound - Infrastructure
| Query | What it shows |
|---|---|
| All SCCM Sites and Their Infrastructure | Complete view: sites, site servers, MPs, DPs, DB servers |
| SCCM Site Servers | Which computers are site servers |
| SCCM Management Points | Which computers are management points |
| SCCM Database Servers | Which computers host the site database |

### SCCMHound - Attack Paths
| Query | What it shows |
|---|---|
| TAKEOVER-1: DB Servers Relayable via MSSQL | DB servers where EPA is not enforced — NTLM relay to MSSQL possible |
| TAKEOVER-2: DB Servers Relayable via SMB | DB servers where SMB signing is not required — NTLM relay to SMB possible |
| EXEC-1/EXEC-2: All Computers Manageable by SCCM Site | Every computer the SCCM site can deploy code to |
| SCCM PXE Distribution Points (CRED-1 risk) | DPs with PXE enabled — credential theft target |
| Shortest Path to SCCM Site Server | How to reach the site server from anywhere in the graph |
| Shortest Path from SCCM Site to Domain Admins | Whether SCCM compromise leads to DA |
| Shortest Paths via SCCM | Paths using MemberOf, HasSession, AdminTo, and SCCMManages together |
| Full SCCM Attack Path | Traces from any user through AD relationships to site server, then to every managed computer |

### SCCMHound - Recon
| Query | What it shows |
|---|---|
| Users with Sessions on SCCM-Managed Computers | Who is logged into SCCM-managed machines |
| Local Admins on SCCM-Managed Computers | Who has admin on SCCM-managed machines |
| Computers with Specified IP | Find computers by IP address (edit `10.0.0` in query) |
| Computers with Unresolvable Sessions | Sessions that couldn't be matched to AD users — may indicate local/service accounts |

## How Auto-Discovery Works

SCCMHound queries Active Directory via LDAP to discover SCCM infrastructure — no prior knowledge of server names or site codes required. Discovery uses techniques from [SCCMHunter](https://github.com/garrettfoster13/sccmhunter) (RECON-1) and [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager):

1. **Site Servers** — Parses the DACL on `CN=System Management,CN=System,<baseDN>` for FullControl ACEs. Computer accounts with FullControl are SCCM site servers.
2. **Management Points** — Queries `(objectClass=mSSMSManagementPoint)` for `dNSHostName` and `mSSMSSiteCode`.
3. **Sites** — Queries `(objectClass=mSSMSSite)` for site codes. Sites without a management point are flagged as Central Administration Sites (CAS).
4. **PXE Distribution Points** — Queries `(&(objectClass=connectionPoint)(netbootserver=*))`.
5. **SCCM Accounts** — Fuzzy search for accounts with `sccm`/`mecm` in their name or description.
6. **Database Server** — Reads remote registry on site server (`SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER`) to find the DB server hostname.
7. **SMB Signing** — Checks SMB signing enforcement on site server and database server.
8. **MSSQL EPA** — Probes the database server's TDS port to determine if Extended Protection for Authentication is enforced.

## CLI Arguments

```
Target:
  -d, --domain          Target domain (required, e.g. CORP.LOCAL)
  --dc-ip               Domain Controller IP (if omitted, domain name used for DNS)
  --server              SCCM server override (skip auto-discovery)
  --sitecode            SCCM site code override (skip auto-discovery)

Collection:
  -c, --collectionmethods  {Default,LocalAdmins,CurrentSessions,All}
  --loop                Enable loop collection
  --loopduration        Loop duration HH:MM:SS (default: 00:30:00)
  --loopsleep           Sleep between loops in seconds (default: 60)
  --hc                  Health check: test auth and exit

Authentication:
  -u, --username        Username
  -p, --password        Password
  -H, --hash            NTLM hash (LMHASH:NTHASH or :NTHASH)
  -k, --kerberos        Use Kerberos authentication
  --ccache              Path to ccache file

Security Checks:
  --check-epa           Force MSSQL EPA check (also runs automatically when DB server is discovered)
  --sql-server          MSSQL server for EPA check (auto-discovered if omitted)
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

Python port of [SCCMHound](https://github.com/CrowdStrike/sccmhound) by Chris Elliott (CrowdStrike Red Team). Auto-discovery based on techniques from [SCCMHunter](https://github.com/garrettfoster13/sccmhunter), [SCOMHound](https://github.com/SpecterOps/SCOMHound), and [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager). Leverages [bloodhound.py](https://github.com/dirkjanm/BloodHound.py) and [impacket](https://github.com/fortra/impacket).

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
