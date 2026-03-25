"""SMB-based probes for SCCM infrastructure enumeration.

Discovers:
- SMB signing status on site servers/DB servers (TAKEOVER-1/2 feasibility)
- Site database server hostname via remote registry (RECON-6)
- Client push installation status via remote registry
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from impacket.smbconnection import SMBConnection

from sccmhound.auth.credentials import AuthMethod, Credentials

logger = logging.getLogger(__name__)


@dataclass
class SMBProbeResult:
    target: str
    signing_required: bool = True
    db_server: str = ""
    client_push_enabled: bool = False
    reachable: bool = False
    error: str = ""


def check_smb_signing(target: str, credentials: Credentials) -> bool | None:
    """Check if SMB signing is required on target. Returns None if unreachable."""
    try:
        do_kerberos = credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE)
        if credentials.auth_method == AuthMethod.CCACHE:
            credentials.setup_ccache()

        conn = SMBConnection(target, target, sess_port=445)
        if credentials.auth_method == AuthMethod.NTLM_HASH:
            conn.login(
                credentials.username, "",
                credentials.domain,
                credentials.lm_hash, credentials.nt_hash,
            )
        elif do_kerberos:
            conn.kerberosLogin(
                credentials.username, credentials.password,
                credentials.domain,
                credentials.lm_hash, credentials.nt_hash,
                kdcHost=credentials.dc_ip,
            )
        else:
            conn.login(credentials.username, credentials.password, credentials.domain)

        signing = conn.isSigningRequired()
        conn.close()
        logger.info("SMB signing on %s: %s", target, "required" if signing else "NOT required")
        return signing
    except Exception as e:
        logger.debug("SMB signing check failed for %s: %s", target, e)
        return None


def discover_db_server_via_registry(target: str, credentials: Credentials) -> str:
    """Read remote registry to find SCCM site database server (RECON-6).

    Reads HKLM\\SOFTWARE\\Microsoft\\SMS\\COMPONENTS\\SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers
    which contains the database server hostname.
    """
    try:
        from impacket.dcerpc.v5 import rrp, transport

        do_kerberos = credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE)

        string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_smb_connection(_get_smb_connection(target, credentials))

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open HKLM
        resp = rrp.hOpenLocalMachine(dce)
        root_key = resp["phKey"]

        # Try to read the SMS component manager key for DB server
        try:
            resp = rrp.hBaseRegOpenKey(
                dce, root_key,
                "SOFTWARE\\Microsoft\\SMS\\COMPONENTS\\SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers"
            )
            sub_key = resp["phkResult"]

            # Enumerate values — DB server is typically listed as a value name
            i = 0
            db_server = ""
            while True:
                try:
                    resp = rrp.hBaseRegEnumValue(dce, sub_key, i)
                    value_name = resp["lpValueNameOut"].rstrip("\x00")
                    if value_name:
                        db_server = value_name
                        break
                    i += 1
                except Exception:
                    break

            if db_server:
                logger.info("Discovered DB server via registry on %s: %s", target, db_server)
                return db_server
        except Exception:
            logger.debug("SMS registry key not found on %s", target)

        dce.disconnect()
    except Exception as e:
        logger.debug("Registry probe failed for %s: %s", target, e)

    return ""


def _get_smb_connection(target: str, credentials: Credentials) -> SMBConnection:
    """Create authenticated SMB connection for RPC transport."""
    conn = SMBConnection(target, target, sess_port=445)
    do_kerberos = credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE)

    if credentials.auth_method == AuthMethod.NTLM_HASH:
        conn.login(credentials.username, "", credentials.domain, credentials.lm_hash, credentials.nt_hash)
    elif do_kerberos:
        conn.kerberosLogin(
            credentials.username, credentials.password, credentials.domain,
            credentials.lm_hash, credentials.nt_hash, kdcHost=credentials.dc_ip,
        )
    else:
        conn.login(credentials.username, credentials.password, credentials.domain)

    return conn


def probe_site_server(target: str, credentials: Credentials) -> SMBProbeResult:
    """Run all SMB probes against a site server."""
    result = SMBProbeResult(target=target)

    signing = check_smb_signing(target, credentials)
    if signing is None:
        result.error = "Unreachable via SMB"
        return result

    result.reachable = True
    result.signing_required = signing
    result.db_server = discover_db_server_via_registry(target, credentials)

    return result
