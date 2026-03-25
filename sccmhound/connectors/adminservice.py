"""AdminService HTTPS connector. Replaces C# AdminServiceConnector (HttpClient + Negotiate auth)."""

from __future__ import annotations

import logging

import requests
import urllib3
from requests_ntlm import HttpNtlmAuth

from sccmhound.auth.credentials import AuthMethod, Credentials

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class AdminServiceConnector:
    """Connect to SCCM AdminService API at ``https://{server}/AdminService/v1.0/``."""

    def __init__(self, server: str, credentials: Credentials):
        self.base_url = f"https://{server}/AdminService/v1.0/"
        self.credentials = credentials
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False  # Matches C# ServerCertificateCustomValidationCallback = true

        if self.credentials.auth_method == AuthMethod.PASSWORD:
            session.auth = HttpNtlmAuth(
                f"{self.credentials.domain}\\{self.credentials.username}",
                self.credentials.password,
            )
        elif self.credentials.auth_method == AuthMethod.NTLM_HASH:
            session.auth = HttpNtlmAuth(
                f"{self.credentials.domain}\\{self.credentials.username}",
                f"0:{self.credentials.nt_hash}",
            )
        elif self.credentials.auth_method in (AuthMethod.KERBEROS, AuthMethod.CCACHE):
            try:
                from requests_kerberos import HTTPKerberosAuth, REQUIRED

                session.auth = HTTPKerberosAuth(mutual_authentication=REQUIRED)
            except ImportError:
                raise RuntimeError("requests-kerberos required for Kerberos auth to AdminService")
        # If no explicit creds, session uses no auth (current user context — only works on Windows)

        return session

    def get(self, path: str) -> requests.Response:
        url = self.base_url + path
        logger.debug("GET %s", url)
        return self.session.get(url)

    def post(self, path: str, json_data: dict) -> requests.Response:
        url = self.base_url + path
        logger.debug("POST %s", url)
        return self.session.post(url, json=json_data)

    @classmethod
    def create_instance(cls, server: str, credentials: Credentials) -> AdminServiceConnector | None:
        """Factory: test connection to SMS_Collection, return connector or None."""
        test_url = f"https://{server}/AdminService/wmi/SMS_Collection"
        session = requests.Session()
        session.verify = False

        if credentials.auth_method == AuthMethod.PASSWORD:
            session.auth = HttpNtlmAuth(
                f"{credentials.domain}\\{credentials.username}",
                credentials.password,
            )
        elif credentials.auth_method == AuthMethod.NTLM_HASH:
            session.auth = HttpNtlmAuth(
                f"{credentials.domain}\\{credentials.username}",
                f"0:{credentials.nt_hash}",
            )

        try:
            resp = session.get(test_url)
            if resp.ok:
                logger.info("AdminService connection successful")
                return cls(server, credentials)
            elif resp.status_code == 403:
                raise PermissionError("403 Forbidden from AdminService API")
            else:
                logger.warning("AdminService test returned %d", resp.status_code)
                return None
        except requests.ConnectionError as e:
            logger.warning("AdminService connection failed: %s", e)
            return None
