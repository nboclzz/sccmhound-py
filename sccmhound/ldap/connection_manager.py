"""Singleton LDAP connection pool. Ported from src/LDAPConnectionManager.cs."""

from __future__ import annotations

import logging
import threading

from ldap3 import ALL, NTLM, SASL, Connection, Server

from sccmhound.auth.credentials import AuthMethod, Credentials

logger = logging.getLogger(__name__)


class LdapConnectionManager:
    """Thread-safe singleton that pools one ldap3 Connection per domain."""

    _instance: LdapConnectionManager | None = None
    _lock = threading.Lock()

    def __new__(cls) -> LdapConnectionManager:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._connections: dict[str, Connection] = {}
                    inst._failed_domains: set[str] = set()
                    cls._instance = inst
        return cls._instance

    def get_connection(self, domain: str, credentials: Credentials) -> Connection | None:
        if not domain:
            return None

        key = domain.lower()
        with self._lock:
            if key in self._failed_domains:
                return None

            if key in self._connections:
                conn = self._connections[key]
                if conn.bound:
                    return conn

            try:
                server = Server(domain, get_info=ALL)
                if credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE):
                    credentials.setup_ccache()
                    conn = Connection(server, authentication=SASL, sasl_mechanism="GSSAPI")
                else:
                    user = f"{credentials.domain}\\{credentials.username}"
                    password = credentials.password or credentials.ntlm_hash
                    conn = Connection(server, user=user, password=password, authentication=NTLM)

                conn.bind()
                self._connections[key] = conn
                logger.info("Created LDAP connection to %s", domain)
                return conn
            except Exception:
                logger.warning("Failed to connect to LDAP for domain %s", domain, exc_info=True)
                self._failed_domains.add(key)
                return None

    def cleanup(self) -> None:
        with self._lock:
            for conn in self._connections.values():
                try:
                    conn.unbind()
                except Exception:
                    pass
            self._connections.clear()
            logger.info("LDAP connections cleaned up")

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.cleanup()
            cls._instance = None
