"""WMI connector using impacket DCOM. Replaces C# SCCMConnector (System.Management.ManagementScope)."""

from __future__ import annotations

import logging
from typing import Any

from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from sccmhound.auth.credentials import AuthMethod, Credentials

logger = logging.getLogger(__name__)


class WMIConnector:
    """Connect to SCCM WMI namespace via impacket DCOM."""

    def __init__(self, server: str, site_code: str, credentials: Credentials):
        self.server = server
        self.site_code = site_code
        self.credentials = credentials
        self.namespace = f"root/SMS/site_{site_code}"
        self._dcom: DCOMConnection | None = None
        self._wmi_services = None

    def connect(self) -> None:
        do_kerberos = self.credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE)
        if self.credentials.auth_method == AuthMethod.CCACHE:
            self.credentials.setup_ccache()

        logger.info("Connecting to WMI namespace %s on %s", self.namespace, self.server)

        self._dcom = DCOMConnection(
            self.server,
            self.credentials.username,
            self.credentials.password,
            self.credentials.domain,
            self.credentials.lm_hash,
            self.credentials.nt_hash,
            oxidResolver=True,
            doKerberos=do_kerberos,
            kdcHost=self.credentials.dc_ip,
        )

        i_interface = self._dcom.CoCreateInstanceEx(
            impacket_wmi.CLSID_WbemLevel1Login, impacket_wmi.IID_IWbemLevel1Login
        )
        i_wbem_login = impacket_wmi.IWbemLevel1Login(i_interface)
        self._wmi_services = i_wbem_login.NTLMLogin(f"//./{self.namespace}", NULL, NULL)
        i_wbem_login.RemRelease()
        logger.info("WMI connection established")

    def exec_query(self, query: str) -> list[dict[str, Any]]:
        """Execute a WQL query and return results as a list of dicts."""
        if self._wmi_services is None:
            raise RuntimeError("Not connected. Call connect() first.")

        logger.debug("WQL: %s", query)
        i_enum = self._wmi_services.ExecQuery(query)
        results: list[dict[str, Any]] = []

        while True:
            try:
                obj = i_enum.Next(0xFFFFFFFF, 1)[0]
                record = obj.getProperties()
                row: dict[str, Any] = {}
                for name, prop in record.items():
                    row[name] = prop["value"]
                results.append(row)
            except Exception as e:
                if "S_FALSE" in str(e) or "WBEM_S_FALSE" in str(e):
                    break
                raise

        logger.debug("Query returned %d results", len(results))
        return results

    @property
    def is_connected(self) -> bool:
        return self._wmi_services is not None

    def disconnect(self) -> None:
        if self._dcom:
            self._dcom.disconnect()
            self._dcom = None
            self._wmi_services = None

    @classmethod
    def create_instance(cls, server: str, site_code: str, credentials: Credentials) -> WMIConnector:
        connector = cls(server, site_code, credentials)
        connector.connect()
        return connector
