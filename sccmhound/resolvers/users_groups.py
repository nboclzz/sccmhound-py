"""User-group membership resolver. Ported from src/UsersGroupsResolver.cs."""

from __future__ import annotations

import logging

from sccmhound.models.bloodhound import BHGroup, BHUser
from sccmhound.utils.helpers import create_lookup_table_groups

logger = logging.getLogger(__name__)


def resolve_users_groups(users: list[BHUser], groups: list[BHGroup]) -> None:
    """Populate group membership by matching users' sccmUserGroupName to groups.

    Mutates group.members in place; removes sccmUserGroupName from user properties.
    """
    group_lookup = create_lookup_table_groups(groups)

    for user in users:
        user_group_names = user.properties.get("sccmUserGroupName")
        if not user_group_names:
            continue

        user_domain = user.properties.get("domain", "")

        for group_name_raw in user_group_names:
            if "\\" not in group_name_raw:
                continue
            short_name = group_name_raw.split("\\")[1].upper()
            key = f"{short_name}@{user_domain}".lower()

            if key in group_lookup:
                group = group_lookup[key]
                group.members.append({
                    "ObjectIdentifier": user.object_identifier,
                    "ObjectType": "User",
                })

        # Remove internal property before JSON output
        user.properties.pop("sccmUserGroupName", None)

    logger.info("Resolved user-group memberships")
