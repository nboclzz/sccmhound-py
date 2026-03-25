"""LDAP SID resolution. Replaces C# HelperUtilities.GetUserSid / GetGroupSid."""

from __future__ import annotations

import logging

from sccmhound.auth.credentials import Credentials
from sccmhound.ldap.connection_manager import LdapConnectionManager

logger = logging.getLogger(__name__)


class SIDResolver:
    """Resolve user/group SIDs via LDAP search (sAMAccountName → objectSid)."""

    def __init__(self, connection_manager: LdapConnectionManager, credentials: Credentials):
        self.connection_manager = connection_manager
        self.credentials = credentials

    def _domain_to_base_dn(self, domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split("."))

    def get_user_sid(self, user_principal_name: str) -> str | None:
        """Resolve ``username@domain`` → SID string via LDAP."""
        parts = user_principal_name.split("@", 1)
        if len(parts) != 2:
            return None

        username, domain = parts
        logger.info("Attempting to resolve %s via LDAP://%s", username, domain)

        conn = self.connection_manager.get_connection(domain, self.credentials)
        if not conn:
            return None

        base_dn = self._domain_to_base_dn(domain)
        conn.search(base_dn, f"(&(objectClass=user)(sAMAccountName={username}))", attributes=["objectSid"])
        if conn.entries:
            sid = str(conn.entries[0].objectSid)
            logger.debug("Resolved %s → %s", user_principal_name, sid)
            return sid
        return None

    def get_group_sid(self, group_principal_name: str) -> str | None:
        """Resolve ``groupname@domain`` → SID string via LDAP."""
        parts = group_principal_name.split("@", 1)
        if len(parts) != 2:
            return None

        group_name, domain = parts
        logger.info("Attempting to resolve %s via LDAP://%s", group_name, domain)

        conn = self.connection_manager.get_connection(domain, self.credentials)
        if not conn:
            return None

        base_dn = self._domain_to_base_dn(domain)
        conn.search(base_dn, f"(&(objectClass=group)(sAMAccountName={group_name}))", attributes=["objectSid"])
        if conn.entries:
            sid = str(conn.entries[0].objectSid)
            logger.debug("Resolved %s → %s", group_principal_name, sid)
            return sid
        return None
