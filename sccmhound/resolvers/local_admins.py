"""Local admin resolver. Ported from src/LocalAdminsResolver.cs."""

from __future__ import annotations

import logging

from sccmhound.factories.group_factory import create_group
from sccmhound.factories.user_factory import create_user
from sccmhound.ldap.sid_resolver import SIDResolver
from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser
from sccmhound.models.sccm import LocalAdmin
from sccmhound.utils.helpers import (
    create_lookup_table_computers,
    create_lookup_table_groups,
    create_lookup_table_users,
    lookup_netbios_return_fqdn,
)

logger = logging.getLogger(__name__)


def resolve_local_admins(
    computers: list[BHComputer],
    groups: list[BHGroup],
    users: list[BHUser],
    local_admins: list[LocalAdmin],
    domains: list[BHDomain],
    sid_resolver: SIDResolver | None = None,
) -> None:
    """Correlate local admin CMPivot data into computer LocalAdmins / LocalGroups.

    Mutates computer.local_admins and computer local_groups in place.
    Creates new BHUser/BHGroup objects for unresolved principals.
    """
    computer_lookup = create_lookup_table_computers(computers)
    user_lookup = create_lookup_table_users(users)
    group_lookup = create_lookup_table_groups(groups)

    # Per-computer admin tracking: comp_name → (computer, admin_users, admin_groups)
    comp_admins: dict[str, tuple[BHComputer, list[BHUser], list[BHGroup]]] = {}

    for la in local_admins:
        try:
            if la.device_name not in computer_lookup:
                continue

            computer = computer_lookup[la.device_name]
            comp_name = str(computer.properties.get("name", ""))

            if comp_name not in comp_admins:
                comp_admins[comp_name] = (computer, [], [])

            _, admin_users, admin_groups = comp_admins[comp_name]

            # Parse DOMAIN\name
            tokens = la.name.split("\\")
            if len(tokens) == 2:
                name, domain_part = tokens[1], tokens[0]
            else:
                name, domain_part = la.name, ""

            domain_fqdn = lookup_netbios_return_fqdn(domain_part, domains)

            if la.type == "User":
                user_key = la.name.lower()
                if user_key in user_lookup:
                    admin_users.append(user_lookup[user_key])
                else:
                    user = create_user(f"{name}@{domain_fqdn}".upper(), domain_fqdn, domains, sid_resolver)
                    if user:
                        users.append(user)
                        user_lookup[user_key] = user
                        admin_users.append(user)

            elif la.type == "Group":
                group_key = f"{name}@{domain_fqdn}".lower()
                if group_key in group_lookup:
                    admin_groups.append(group_lookup[group_key])
                else:
                    group = create_group(f"{name}@{domain_fqdn}".upper(), domain_fqdn, domains, sid_resolver)
                    if group:
                        groups.append(group)
                        group_lookup[group_key] = group
                        admin_groups.append(group)
        except Exception:
            logger.warning("Unable to resolve local admin for %s", la.name, exc_info=True)

    # Populate LocalAdmins and LocalGroups on computer objects
    for comp_name, (computer, admin_users, admin_groups) in comp_admins.items():
        results = []
        for user in admin_users:
            results.append({"ObjectIdentifier": user.object_identifier, "ObjectType": "User"})
        for group in admin_groups:
            results.append({"ObjectIdentifier": group.object_identifier, "ObjectType": "Group"})

        computer.local_admins = {
            "Collected": True,
            "FailureReason": None,
            "Results": results,
        }

    # Build LocalGroups array for BloodHound v5+ format
    for computer in computers:
        admin_results = computer.local_admins.get("Results", [])
        if admin_results:
            comp_name = computer.properties.get("name", "")
            local_group = {
                "Name": f"ADMINISTRATORS@{comp_name}",
                "ObjectIdentifier": f"{comp_name}-S-1-5-32-544",
                "Collected": True,
                "FailureReason": None,
                "Results": [
                    {"ObjectIdentifier": r["ObjectIdentifier"], "ObjectType": r["ObjectType"]}
                    for r in admin_results
                ],
            }
            # Store as the LocalGroups array expected by BH CE
            computer.local_admins = {"Collected": True, "FailureReason": None, "Results": admin_results}
            # Attach LocalGroups for v6 compat
            if not hasattr(computer, "_local_groups"):
                computer._local_groups = []
            computer._local_groups = [local_group]

    logger.info("Resolved local admins for %d computers", len(comp_admins))
