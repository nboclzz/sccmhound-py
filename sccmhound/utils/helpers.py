"""Utility functions ported from src/HelperUtilities.cs."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser

logger = logging.getLogger(__name__)


def get_domain_sid_from_user_sid(sid: str) -> str:
    """Extract domain SID by stripping the RID (everything after the last dash).

    Port of C# getDomainSidFromUserSid — uses regex ``^(.*)(?=-)``
    """
    match = re.match(r"^(.*)(?=-)", sid)
    return match.group(0) if match else ""


def convert_ldap_to_domain(ldap_path: str) -> str:
    """Convert an LDAP distinguished name to a DNS domain name.

    Example: ``CN=foo,DC=corp,DC=local`` → ``corp.local``
    """
    if not ldap_path:
        return ""
    parts = ldap_path.split(",")
    dc_parts = [p.strip()[3:] for p in parts if p.strip().upper().startswith("DC=")]
    return ".".join(dc_parts)


def get_domain_from_resource(resource_name: str | None, netbios_name: str | None) -> str:
    """Extract domain FQDN from a resource name by stripping the NetBIOS prefix.

    Example: ``SERVER.corp.local``, ``SERVER`` → ``corp.local``
    """
    if not resource_name or not netbios_name:
        return ""
    resource_name = resource_name.strip()
    netbios_name = netbios_name.strip()
    upper_resource = resource_name.upper()
    upper_netbios = netbios_name.upper()
    if upper_netbios in upper_resource:
        idx = upper_resource.index(upper_netbios)
        domain = resource_name[idx + len(netbios_name) :].strip("\\.").strip(".")
        return domain
    return ""


def lookup_netbios_return_fqdn(netbios: str, domains: list[BHDomain]) -> str:
    """Resolve a NetBIOS domain name to FQDN using the collected domains list."""
    for domain in domains:
        domain_netbios = domain.properties.get("netbios", "")
        if domain_netbios and domain_netbios.upper() == netbios.upper():
            return domain.properties.get("name", netbios)
    return netbios


def create_lookup_table_users(users: list[BHUser]) -> dict[str, BHUser]:
    """Build a lookup table keyed by ``sccmUniqueUserName`` (lowercased)."""
    table: dict[str, BHUser] = {}
    for user in users:
        key = user.properties.get("sccmUniqueUserName", "")
        if not key:
            continue
        key = key.lower()
        if key in table:
            logger.debug("Duplicate user key: %s", key)
            continue
        table[key] = user
    return table


def create_lookup_table_groups(groups: list[BHGroup]) -> dict[str, BHGroup]:
    """Build a lookup table keyed by ``name`` (lowercased)."""
    table: dict[str, BHGroup] = {}
    for group in groups:
        key = group.properties.get("name", "")
        if not key:
            continue
        key = key.lower()
        if key in table:
            logger.debug("Duplicate group key: %s", key)
            continue
        table[key] = group
    return table


def create_lookup_table_computers(computers: list[BHComputer]) -> dict[str, BHComputer]:
    """Build a lookup table keyed by ``sccmName``."""
    table: dict[str, BHComputer] = {}
    for computer in computers:
        key = computer.properties.get("sccmName", "")
        if not key:
            continue
        if key in table:
            logger.debug("Duplicate computer key: %s", key)
            continue
        table[key] = computer
    return table
