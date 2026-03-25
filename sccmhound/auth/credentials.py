from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class AuthMethod(Enum):
    PASSWORD = auto()
    NTLM_HASH = auto()
    KERBEROS = auto()
    CCACHE = auto()


@dataclass
class Credentials:
    """Centralized credential store shared by all connectors (WMI, LDAP, HTTP)."""

    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""  # "LMHASH:NTHASH" or ":NTHASH"
    kerberos: bool = False
    ccache: str = ""  # Path to ccache file
    dc_ip: Optional[str] = None

    @property
    def auth_method(self) -> AuthMethod:
        if self.ccache:
            return AuthMethod.CCACHE
        if self.kerberos:
            return AuthMethod.KERBEROS
        if self.ntlm_hash:
            return AuthMethod.NTLM_HASH
        return AuthMethod.PASSWORD

    @property
    def lm_hash(self) -> str:
        if ":" in self.ntlm_hash:
            return self.ntlm_hash.split(":")[0]
        return ""

    @property
    def nt_hash(self) -> str:
        if ":" in self.ntlm_hash:
            return self.ntlm_hash.split(":")[-1]
        return self.ntlm_hash

    def setup_ccache(self) -> None:
        """Set KRB5CCNAME env var for impacket/ldap3 Kerberos ticket reuse."""
        if self.ccache:
            os.environ["KRB5CCNAME"] = self.ccache
