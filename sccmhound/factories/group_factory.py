"""Group factory. Ported from src/factories/GroupFactory.cs."""

from __future__ import annotations

import logging

from sccmhound.ldap.sid_resolver import SIDResolver
from sccmhound.models.bloodhound import BHDomain, BHGroup

logger = logging.getLogger(__name__)


def create_group(
    group_name: str,
    domain_name: str,
    domains: list[BHDomain],
    sid_resolver: SIDResolver | None = None,
) -> BHGroup | None:
    """Create a BHGroup, attempting LDAP SID resolution if the domain is known."""
    if not group_name:
        return None

    logger.info("Attempting to resolve %s via identified domains", group_name)
    object_identifier = group_name

    for domain in domains:
        if domain_name.upper() == str(domain.properties.get("name", "")).upper():
            if sid_resolver:
                try:
                    resolved_sid = sid_resolver.get_group_sid(group_name)
                    if resolved_sid:
                        object_identifier = resolved_sid
                except Exception:
                    logger.warning("AD query for %s failed", group_name)
                    object_identifier = group_name
            break

    group = BHGroup(object_identifier=object_identifier)
    group.properties["name"] = group_name
    group.properties["domain"] = domain_name
    return group
