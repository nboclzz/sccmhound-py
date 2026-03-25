"""User factory. Ported from src/factories/UserFactory.cs."""

from __future__ import annotations

import logging

from sccmhound.ldap.sid_resolver import SIDResolver
from sccmhound.models.bloodhound import BHDomain, BHUser

logger = logging.getLogger(__name__)


def create_user(
    user_name: str,
    domain_name: str,
    domains: list[BHDomain],
    sid_resolver: SIDResolver | None = None,
) -> BHUser | None:
    """Create a BHUser, attempting LDAP SID resolution if the domain is known."""
    if not user_name:
        return None

    logger.info("Attempting to resolve %s via identified domains", user_name)
    object_identifier = user_name

    for domain in domains:
        if domain_name.upper() == str(domain.properties.get("name", "")).upper():
            if sid_resolver and user_name.split("@")[0].upper() != "ADMINISTRATOR":
                try:
                    resolved_sid = sid_resolver.get_user_sid(user_name)
                    if resolved_sid:
                        object_identifier = resolved_sid
                except Exception:
                    logger.warning("AD query for %s failed", user_name)
                    object_identifier = user_name
            break

    user = BHUser(object_identifier=object_identifier)
    user.properties["name"] = user_name
    user.properties["domain"] = domain_name
    return user
