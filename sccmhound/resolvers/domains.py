"""Domain resolver. Ported from src/DomainsResolver.cs."""

from __future__ import annotations

import logging

from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser

logger = logging.getLogger(__name__)


def resolve_domains(
    users: list[BHUser], computers: list[BHComputer], groups: list[BHGroup]
) -> list[BHDomain]:
    """Extract unique domain objects from collected users, computers, and groups."""
    domains: list[BHDomain] = []
    seen_sids: set[str] = set()

    # From users
    for user in users:
        try:
            domain_sid = user.properties.get("domainsid", "")
            if not domain_sid or domain_sid in seen_sids:
                continue

            unique_name = user.properties.get("sccmUniqueUserName", "")
            dn = user.properties.get("distinguishedname", "")

            domain = BHDomain(object_identifier=domain_sid)
            if unique_name and "\\" in unique_name:
                domain.properties["netbios"] = unique_name.split("\\")[0]
            domain.properties["name"] = user.properties.get("domain", "")
            domain.properties["domain"] = user.properties.get("domain", "")
            domain.properties["domainsid"] = domain_sid
            domain.properties["highvalue"] = True

            if dn and "DC=" in dn:
                dc_start = dn.index("DC=")
                domain.properties["distinguishedname"] = f"DC={dn[dc_start + 3:]}".upper()

            domains.append(domain)
            seen_sids.add(domain_sid)
        except (KeyError, ValueError):
            pass

    logger.debug("Resolved domains from users")

    # From computers
    for computer in computers:
        try:
            domain_sid = computer.properties.get("domainsid", "")
            if not domain_sid or domain_sid in seen_sids:
                continue

            dn = computer.properties.get("distinguishedname", "")

            domain = BHDomain(object_identifier=domain_sid)
            domain.properties["netbios"] = computer.properties.get("sccmResourceDomainORWorkgroup", "")
            domain.properties["name"] = computer.properties.get("domain", "")
            domain.properties["domain"] = computer.properties.get("domain", "")
            domain.properties["domainsid"] = domain_sid
            domain.properties["highvalue"] = True

            if dn and "DC=" in dn:
                dc_start = dn.index("DC=")
                domain.properties["distinguishedname"] = f"DC={dn[dc_start + 3:]}".upper()

            domains.append(domain)
            seen_sids.add(domain_sid)
        except (KeyError, ValueError):
            pass

    logger.debug("Resolved domains from computers")

    # From groups
    for group in groups:
        try:
            domain_sid = group.properties.get("domainsid", "")
            if not domain_sid or domain_sid in seen_sids:
                continue

            domain_name = group.properties.get("domain", "")

            domain = BHDomain(object_identifier=domain_sid)
            domain.properties["name"] = domain_name
            domain.properties["domain"] = domain_name
            domain.properties["domainsid"] = domain_sid
            domain.properties["highvalue"] = True

            if domain_name:
                dn_parts = ",".join(f"DC={part.upper()}" for part in domain_name.split("."))
                domain.properties["distinguishedname"] = dn_parts

            domains.append(domain)
            seen_sids.add(domain_sid)
        except (KeyError, ValueError):
            pass

    logger.debug("Resolved domains from groups")
    logger.info("Resolved %d unique domains", len(domains))
    return domains
