"""Computer session resolver. Ported from src/ComputerSessionsResolver.cs."""

from __future__ import annotations

import logging

from sccmhound.factories.user_factory import create_user
from sccmhound.ldap.sid_resolver import SIDResolver
from sccmhound.models.bloodhound import BHComputer, BHDomain, BHUser
from sccmhound.models.sccm import UserMachineRelationship
from sccmhound.utils.helpers import (
    create_lookup_table_computers,
    create_lookup_table_users,
    lookup_netbios_return_fqdn,
)

logger = logging.getLogger(__name__)


def resolve_sessions(
    computers: list[BHComputer],
    users: list[BHUser],
    relationships: list[UserMachineRelationship],
    domains: list[BHDomain],
    sid_resolver: SIDResolver | None = None,
) -> None:
    """Correlate user-machine relationships into computer session data.

    Mutates computer.sessions in place. Creates new BHUser objects for unresolved users
    and appends them to the users list.
    """
    computer_lookup = create_lookup_table_computers(computers)
    user_lookup = create_lookup_table_users(users)

    # Track sessions per computer (by computer name)
    computer_sessions: dict[str, tuple[BHComputer, list[BHUser]]] = {}

    for rel in relationships:
        try:
            if rel.resource_name not in computer_lookup:
                continue

            computer = computer_lookup[rel.resource_name]
            comp_name = computer.properties.get("name", "")

            if comp_name not in computer_sessions:
                computer_sessions[comp_name] = (computer, [])

            _, session_users = computer_sessions[comp_name]

            user_key = rel.unique_user_name.lower()
            if user_key in user_lookup:
                session_users.append(user_lookup[user_key])
            else:
                # Create a new user for unresolved session
                tokens = user_key.split("\\")
                if len(tokens) == 2:
                    name, domain = tokens[1], tokens[0]
                else:
                    name, domain = user_key, ""

                domain = lookup_netbios_return_fqdn(domain, domains)
                user = create_user(f"{name}@{domain}".upper(), domain, domains, sid_resolver)
                if user:
                    users.append(user)
                    user_lookup[user_key] = user
                    session_users.append(user)
        except Exception:
            logger.debug("Error resolving session", exc_info=True)

    # Populate session data on computer objects
    for comp_name, (computer, session_users) in computer_sessions.items():
        sessions = []
        for user in session_users:
            sessions.append({
                "ComputerSID": computer.object_identifier,
                "UserSID": user.object_identifier,
            })
        computer.sessions = {
            "Collected": True,
            "FailureReason": None,
            "Results": sessions,
        }

    logger.info("Resolved sessions for %d computers", len(computer_sessions))
