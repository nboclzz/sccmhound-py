"""Auto-discover SCCM infrastructure from Active Directory via LDAP.

Given only domain credentials and a DC, discovers:
- Site servers (from System Management container DACL)
- Management points + site codes (mSSMSManagementPoint objects)
- Sites and CAS detection (mSSMSSite objects)
- PXE distribution points (connectionPoint with netbootserver)
- SCCM-related accounts (fuzzy name search)

Based on techniques from SCCMHunter (RECON-1), NetExec sccm module, and SCOMHound.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

from ldap3 import ALL, NTLM, SASL, SUBTREE, Connection, Server
from ldap3.protocol.microsoft import security_descriptor_control

from sccmhound.auth.credentials import AuthMethod, Credentials

logger = logging.getLogger(__name__)

# Well-known SIDs to skip during DACL parsing
WELL_KNOWN_SIDS = {
    "S-1-5-18",  # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-9",  # Enterprise Domain Controllers
    "S-1-5-10",  # Self
    "S-1-5-11",  # Authenticated Users
    "S-1-3-0",  # Creator Owner
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
}

# sAMAccountType values
SAM_MACHINE_ACCOUNT = 805306369
SAM_GROUP_OBJECT = 268435456
SAM_USER_OBJECT = 805306368

# ACE access mask for FullControl
FULL_CONTROL = 0xF01FF

# ACE type constants
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05


@dataclass
class SCCMSiteServer:
    hostname: str = ""
    sid: str = ""


@dataclass
class SCCMManagementPoint:
    hostname: str = ""
    site_code: str = ""
    is_default: bool = False


@dataclass
class SCCMSite:
    site_code: str = ""
    name: str = ""
    is_cas: bool = False


@dataclass
class SCCMDistributionPoint:
    hostname: str = ""
    is_pxe: bool = False


@dataclass
class SCCMInfrastructure:
    """All discovered SCCM infrastructure components."""
    site_servers: list[SCCMSiteServer] = field(default_factory=list)
    management_points: list[SCCMManagementPoint] = field(default_factory=list)
    sites: list[SCCMSite] = field(default_factory=list)
    distribution_points: list[SCCMDistributionPoint] = field(default_factory=list)
    sccm_accounts: list[dict] = field(default_factory=list)

    @property
    def primary_site_code(self) -> str | None:
        """Return the first non-CAS site code, or None."""
        for site in self.sites:
            if not site.is_cas:
                return site.site_code
        # Fall back to first MP site code
        for mp in self.management_points:
            if mp.site_code:
                return mp.site_code
        return None

    @property
    def primary_server(self) -> str | None:
        """Return the best server target for WMI (prefer site server, then MP)."""
        if self.site_servers:
            return self.site_servers[0].hostname
        if self.management_points:
            return self.management_points[0].hostname
        return None

    @property
    def primary_mp(self) -> str | None:
        """Return the best management point for AdminService."""
        for mp in self.management_points:
            if mp.is_default:
                return mp.hostname
        if self.management_points:
            return self.management_points[0].hostname
        return None

    def summary(self) -> str:
        lines = []
        if self.site_servers:
            lines.append(f"  Site Servers: {', '.join(s.hostname for s in self.site_servers)}")
        if self.management_points:
            for mp in self.management_points:
                default = " (default)" if mp.is_default else ""
                lines.append(f"  Management Point: {mp.hostname} [site: {mp.site_code}]{default}")
        if self.sites:
            for site in self.sites:
                cas = " (CAS)" if site.is_cas else ""
                lines.append(f"  Site: {site.site_code}{cas}")
        if self.distribution_points:
            for dp in self.distribution_points:
                pxe = " (PXE)" if dp.is_pxe else ""
                lines.append(f"  Distribution Point: {dp.hostname}{pxe}")
        if self.sccm_accounts:
            lines.append(f"  SCCM-related accounts: {len(self.sccm_accounts)}")
        return "\n".join(lines) if lines else "  No SCCM infrastructure found"


def _domain_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _connect_ldap(dc_ip: str | None, domain: str, credentials: Credentials) -> Connection | None:
    """Establish LDAP connection to DC."""
    target = dc_ip or domain
    try:
        server = Server(target, get_info=ALL)
        if credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE):
            credentials.setup_ccache()
            conn = Connection(server, authentication=SASL, sasl_mechanism="GSSAPI")
        else:
            user = f"{credentials.domain}\\{credentials.username}"
            password = credentials.password or credentials.ntlm_hash
            conn = Connection(server, user=user, password=password, authentication=NTLM)

        conn.bind()
        if not conn.bound:
            logger.error("LDAP bind failed")
            return None
        logger.info("LDAP connection established to %s", target)
        return conn
    except Exception:
        logger.error("Failed to connect to LDAP on %s", target, exc_info=True)
        return None


def _parse_sid(raw_sid: bytes) -> str:
    """Convert a binary SID to string format S-1-..."""
    if not raw_sid or len(raw_sid) < 8:
        return ""
    revision = raw_sid[0]
    sub_authority_count = raw_sid[1]
    authority = int.from_bytes(raw_sid[2:8], byteorder="big")
    sid_str = f"S-{revision}-{authority}"
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        if offset + 4 > len(raw_sid):
            break
        sub_auth = struct.unpack("<I", raw_sid[offset:offset + 4])[0]
        sid_str += f"-{sub_auth}"
    return sid_str


def _parse_acl_for_full_control(raw_sd: bytes) -> list[str]:
    """Parse a security descriptor's DACL for FullControl ACEs, return SIDs."""
    sids = []
    if not raw_sd or len(raw_sd) < 20:
        return sids

    # Security descriptor header
    # Byte 0: revision, Byte 1: sbz, Bytes 2-3: control
    # Bytes 4-7: owner offset, 8-11: group offset, 12-15: SACL offset, 16-19: DACL offset
    dacl_offset = struct.unpack("<I", raw_sd[16:20])[0]
    if dacl_offset == 0 or dacl_offset >= len(raw_sd):
        return sids

    # DACL header: revision (1), sbz (1), size (2), ace_count (2), sbz2 (2)
    dacl = raw_sd[dacl_offset:]
    if len(dacl) < 8:
        return sids

    ace_count = struct.unpack("<H", dacl[4:6])[0]
    offset = 8  # Start of first ACE

    for _ in range(ace_count):
        if offset + 4 > len(dacl):
            break

        ace_type = dacl[offset]
        ace_size = struct.unpack("<H", dacl[offset + 2:offset + 4])[0]

        if ace_type == ACCESS_ALLOWED_ACE_TYPE:
            # ACCESS_ALLOWED_ACE: type(1) + flags(1) + size(2) + mask(4) + SID(variable)
            if offset + 8 <= len(dacl):
                mask = struct.unpack("<I", dacl[offset + 4:offset + 8])[0]
                if mask & FULL_CONTROL == FULL_CONTROL:
                    sid_bytes = dacl[offset + 8:offset + ace_size]
                    sid = _parse_sid(sid_bytes)
                    if sid and sid not in WELL_KNOWN_SIDS:
                        sids.append(sid)

        elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            # ACCESS_ALLOWED_OBJECT_ACE: type(1) + flags(1) + size(2) + mask(4) + object flags(4) + ...
            if offset + 8 <= len(dacl):
                mask = struct.unpack("<I", dacl[offset + 4:offset + 8])[0]
                if mask & FULL_CONTROL == FULL_CONTROL:
                    # Object flags determine layout: 0=no GUIDs, 1=ObjectType, 2=InheritedObjectType, 3=both
                    obj_flags = struct.unpack("<I", dacl[offset + 8:offset + 12])[0] if offset + 12 <= len(dacl) else 0
                    sid_offset_in_ace = 12
                    if obj_flags & 0x01:
                        sid_offset_in_ace += 16  # Skip ObjectType GUID
                    if obj_flags & 0x02:
                        sid_offset_in_ace += 16  # Skip InheritedObjectType GUID
                    sid_start = offset + sid_offset_in_ace
                    sid_bytes = dacl[sid_start:offset + ace_size]
                    sid = _parse_sid(sid_bytes)
                    if sid and sid not in WELL_KNOWN_SIDS:
                        sids.append(sid)

        offset += ace_size

    return sids


def _resolve_sid(conn: Connection, base_dn: str, sid: str) -> list[SCCMSiteServer]:
    """Resolve a SID to hostname(s). If it's a group, recursively resolve members."""
    servers = []
    # ldap3 expects the SID in a specific escaped binary format for search
    # Use string SID matching instead
    conn.search(base_dn, f"(objectSid={sid})", attributes=[
        "sAMAccountName", "sAMAccountType", "dNSHostName", "member", "objectSid"
    ])

    if not conn.entries:
        logger.debug("Could not resolve SID: %s", sid)
        return servers

    entry = conn.entries[0]
    sam_type = int(entry.sAMAccountType.value) if hasattr(entry, "sAMAccountType") and entry.sAMAccountType.value else 0
    hostname = str(entry.dNSHostName.value) if hasattr(entry, "dNSHostName") and entry.dNSHostName.value else ""
    sam_name = str(entry.sAMAccountName.value) if hasattr(entry, "sAMAccountName") and entry.sAMAccountName.value else ""

    if sam_type == SAM_MACHINE_ACCOUNT:
        if hostname:
            servers.append(SCCMSiteServer(hostname=hostname, sid=sid))
        elif sam_name:
            servers.append(SCCMSiteServer(hostname=sam_name.rstrip("$"), sid=sid))
    elif sam_type == SAM_GROUP_OBJECT:
        # Recursively resolve group members
        members = entry.member.values if hasattr(entry, "member") and entry.member.value else []
        for member_dn in members:
            conn.search(base_dn, f"(distinguishedName={member_dn})", attributes=[
                "sAMAccountName", "sAMAccountType", "dNSHostName", "objectSid"
            ])
            if conn.entries:
                m_entry = conn.entries[0]
                m_type = int(m_entry.sAMAccountType.value) if hasattr(m_entry, "sAMAccountType") and m_entry.sAMAccountType.value else 0
                m_hostname = str(m_entry.dNSHostName.value) if hasattr(m_entry, "dNSHostName") and m_entry.dNSHostName.value else ""
                m_sid = str(m_entry.objectSid.value) if hasattr(m_entry, "objectSid") and m_entry.objectSid.value else ""
                m_sam = str(m_entry.sAMAccountName.value) if hasattr(m_entry, "sAMAccountName") and m_entry.sAMAccountName.value else ""
                if m_type == SAM_MACHINE_ACCOUNT:
                    servers.append(SCCMSiteServer(hostname=m_hostname or m_sam.rstrip("$"), sid=m_sid))

    return servers


def discover_site_servers(conn: Connection, base_dn: str) -> list[SCCMSiteServer]:
    """Discover SCCM site servers via System Management container DACL (RECON-1)."""
    search_dn = f"CN=System Management,CN=System,{base_dn}"
    logger.info("Checking System Management container: %s", search_dn)

    conn.search(
        base_dn,
        f"(distinguishedName={search_dn})",
        attributes=["nTSecurityDescriptor"],
        controls=security_descriptor_control(sdflags=0x04),
    )

    if not conn.entries:
        logger.warning("System Management container not found — SCCM may not be installed")
        return []

    raw_sd = conn.entries[0].nTSecurityDescriptor.raw_values[0]
    sids = _parse_acl_for_full_control(raw_sd)
    logger.info("Found %d FullControl ACEs on System Management container", len(sids))

    servers = []
    for sid in sids:
        resolved = _resolve_sid(conn, base_dn, sid)
        servers.extend(resolved)

    logger.info("Discovered %d site server(s)", len(servers))
    return servers


def discover_management_points(conn: Connection, base_dn: str) -> list[SCCMManagementPoint]:
    """Discover SCCM management points via mSSMSManagementPoint objects."""
    conn.search(
        base_dn,
        "(objectClass=mSSMSManagementPoint)",
        search_scope=SUBTREE,
        attributes=["dNSHostName", "msSMSSiteCode", "mSSMSDefaultMP", "cn"],
    )

    mps = []
    for entry in conn.entries:
        hostname = str(entry.dNSHostName.value) if hasattr(entry, "dNSHostName") and entry.dNSHostName.value else ""
        site_code = str(entry.msSMSSiteCode.value) if hasattr(entry, "msSMSSiteCode") and entry.msSMSSiteCode.value else ""
        is_default = bool(entry.mSSMSDefaultMP.value) if hasattr(entry, "mSSMSDefaultMP") and entry.mSSMSDefaultMP.value else False

        if hostname:
            mps.append(SCCMManagementPoint(hostname=hostname, site_code=site_code, is_default=is_default))

    logger.info("Discovered %d management point(s)", len(mps))
    return mps


def discover_sites(conn: Connection, base_dn: str, mp_site_codes: set[str]) -> list[SCCMSite]:
    """Discover SCCM sites. Sites with codes not matching any MP are flagged as CAS."""
    conn.search(
        base_dn,
        "(objectClass=mSSMSSite)",
        search_scope=SUBTREE,
        attributes=["mSSMSSiteCode", "cn"],
    )

    sites = []
    for entry in conn.entries:
        code = str(entry.mSSMSSiteCode.value) if hasattr(entry, "mSSMSSiteCode") and entry.mSSMSSiteCode.value else ""
        name = str(entry.cn.value) if hasattr(entry, "cn") and entry.cn.value else ""
        is_cas = code not in mp_site_codes if code else False
        sites.append(SCCMSite(site_code=code, name=name, is_cas=is_cas))

    logger.info("Discovered %d site(s)", len(sites))
    return sites


def discover_distribution_points(conn: Connection, base_dn: str) -> list[SCCMDistributionPoint]:
    """Discover PXE distribution points via connectionPoint objects."""
    conn.search(
        base_dn,
        "(&(objectClass=connectionPoint)(netbootserver=*))",
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )

    dps = []
    for entry in conn.entries:
        dn = str(entry.entry_dn)
        # Parent object is the computer — strip first CN component
        parts = dn.split(",", 1)
        if len(parts) == 2:
            parent_dn = parts[1]
            # Strip leading "CN=" from parent
            if parent_dn.startswith("CN="):
                parent_dn_full = parent_dn
            else:
                parent_dn_full = parent_dn

            conn.search(base_dn, f"(distinguishedName={parent_dn_full})", attributes=["dNSHostName"])
            if conn.entries:
                hostname = str(conn.entries[0].dNSHostName.value) if conn.entries[0].dNSHostName.value else ""
                if hostname:
                    dps.append(SCCMDistributionPoint(hostname=hostname, is_pxe=True))

    logger.info("Discovered %d PXE distribution point(s)", len(dps))
    return dps


def discover_sccm_accounts(conn: Connection, base_dn: str) -> list[dict]:
    """Fuzzy search for accounts with sccm/mecm in their name or description."""
    search_filter = (
        "(|(samaccountname=*sccm*)(samaccountname=*mecm*)"
        "(description=*sccm*)(description=*mecm*)"
        "(name=*sccm*)(name=*mecm*))"
    )
    conn.search(
        base_dn,
        search_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "sAMAccountType", "distinguishedName", "dNSHostName", "description"],
    )

    accounts = []
    for entry in conn.entries:
        sam_name = str(entry.sAMAccountName.value) if hasattr(entry, "sAMAccountName") and entry.sAMAccountName.value else ""
        sam_type = int(entry.sAMAccountType.value) if hasattr(entry, "sAMAccountType") and entry.sAMAccountType.value else 0
        hostname = str(entry.dNSHostName.value) if hasattr(entry, "dNSHostName") and entry.dNSHostName.value else ""
        desc = str(entry.description.value) if hasattr(entry, "description") and entry.description.value else ""

        type_label = "computer" if sam_type == SAM_MACHINE_ACCOUNT else "user" if sam_type == SAM_USER_OBJECT else "group" if sam_type == SAM_GROUP_OBJECT else "other"

        accounts.append({
            "name": sam_name,
            "type": type_label,
            "hostname": hostname,
            "description": desc,
        })

    logger.info("Found %d SCCM-related account(s)", len(accounts))
    return accounts


def discover_sccm(credentials: Credentials, dc_ip: str | None = None) -> SCCMInfrastructure:
    """Main entry point: discover all SCCM infrastructure from AD.

    Args:
        credentials: Domain credentials (password, hash, kerberos, or ccache)
        dc_ip: Domain controller IP. If None, uses the domain name for DNS resolution.

    Returns:
        SCCMInfrastructure with all discovered components.
    """
    domain = credentials.domain
    if not domain:
        raise ValueError("Domain is required for SCCM discovery")

    base_dn = _domain_to_base_dn(domain)
    infra = SCCMInfrastructure()

    conn = _connect_ldap(dc_ip, domain, credentials)
    if not conn:
        return infra

    try:
        # Phase 1: Site servers from System Management container DACL
        infra.site_servers = discover_site_servers(conn, base_dn)

        # Phase 2: Management points (gives us hostnames + site codes)
        infra.management_points = discover_management_points(conn, base_dn)

        # Phase 3: Sites (cross-reference with MP site codes for CAS detection)
        mp_site_codes = {mp.site_code for mp in infra.management_points if mp.site_code}
        infra.sites = discover_sites(conn, base_dn, mp_site_codes)

        # Phase 4: PXE distribution points
        infra.distribution_points = discover_distribution_points(conn, base_dn)

        # Phase 5: SCCM-related accounts (fuzzy search)
        infra.sccm_accounts = discover_sccm_accounts(conn, base_dn)

    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    return infra
