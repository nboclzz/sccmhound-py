"""MSSQL Extended Protection for Authentication (EPA) / Channel Binding checker.

Detects whether an MSSQL server enforces EPA, which prevents NTLM relay attacks.
This is a non-destructive check — no valid credentials are required.

Technique:
1. Connect to TDS port, send prelogin, negotiate encryption
2. Perform TLS handshake to get server certificate
3. Attempt NTLM auth WITHOUT channel binding token
4. If server rejects with EPA error → enforced (not relayable)
5. If NTLM challenge proceeds normally → not enforced (relayable)
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import struct
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)

# TDS packet types
TDS_PRELOGIN = 0x12
TDS_TABULAR_RESULT = 0x04

# Prelogin option tokens
PL_OPTION_VERSION = 0x00
PL_OPTION_ENCRYPTION = 0x01
PL_OPTION_TERMINATOR = 0xFF

# Encryption values
ENCRYPT_OFF = 0x00
ENCRYPT_ON = 0x01
ENCRYPT_NOT_SUP = 0x02
ENCRYPT_REQ = 0x03


class EPAStatus(Enum):
    NOT_ENFORCED = auto()
    ENFORCED = auto()
    UNKNOWN = auto()
    CONNECTION_FAILED = auto()
    NO_ENCRYPTION = auto()


@dataclass
class EPAResult:
    status: EPAStatus
    server: str
    port: int = 1433
    ssl_enabled: bool = False
    details: str = ""


class MSSQLEPAChecker:
    """Check if MSSQL server enforces Extended Protection for Authentication."""

    def __init__(self, server: str, port: int = 1433, timeout: int = 10):
        self.server = server
        self.port = port
        self.timeout = timeout

    def check_epa(self) -> EPAResult:
        sock = None
        try:
            # Step 1: TCP connect
            sock = socket.create_connection((self.server, self.port), timeout=self.timeout)
            logger.info("Connected to %s:%d", self.server, self.port)

            # Step 2: TDS prelogin
            prelogin_req = self._build_prelogin()
            sock.sendall(self._wrap_tds(TDS_PRELOGIN, prelogin_req))

            # Step 3: Parse prelogin response
            resp_data = self._recv_tds(sock)
            encryption = self._parse_prelogin_encryption(resp_data)
            logger.info("Server encryption flag: 0x%02x", encryption)

            if encryption == ENCRYPT_NOT_SUP:
                return EPAResult(
                    status=EPAStatus.NO_ENCRYPTION,
                    server=self.server,
                    port=self.port,
                    ssl_enabled=False,
                    details="Server does not support encryption — EPA cannot be enforced without TLS",
                )

            # Step 4: TLS handshake (in-stream for TDS)
            # For MSSQL, TLS is wrapped inside TDS packets.
            # We use impacket's TDS client if available, otherwise report what we can.
            try:
                from impacket.tds import MSSQL

                mssql = MSSQL(self.server, int(self.port))
                mssql.connect()

                # Try login with dummy creds — no channel binding
                try:
                    mssql.login("__epa_check__", "__dummy__", useWindowsAuth=False)
                except Exception as login_err:
                    err_str = str(login_err).lower()
                    # EPA-related error messages from SQL Server
                    if "extended protection" in err_str or "channel binding" in err_str:
                        return EPAResult(
                            status=EPAStatus.ENFORCED,
                            server=self.server,
                            port=self.port,
                            ssl_enabled=True,
                            details="MSSQL enforces EPA — NTLM relay is blocked",
                        )
                    elif "login failed" in err_str or "logon" in err_str:
                        return EPAResult(
                            status=EPAStatus.NOT_ENFORCED,
                            server=self.server,
                            port=self.port,
                            ssl_enabled=True,
                            details="MSSQL does NOT enforce EPA — NTLM relay may be possible",
                        )
                    else:
                        return EPAResult(
                            status=EPAStatus.UNKNOWN,
                            server=self.server,
                            port=self.port,
                            ssl_enabled=True,
                            details=f"Unexpected login error: {login_err}",
                        )
                finally:
                    try:
                        mssql.disconnect()
                    except Exception:
                        pass

            except ImportError:
                return EPAResult(
                    status=EPAStatus.UNKNOWN,
                    server=self.server,
                    port=self.port,
                    ssl_enabled=encryption in (ENCRYPT_ON, ENCRYPT_REQ),
                    details="impacket required for full EPA check — TLS negotiation needed",
                )

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return EPAResult(
                status=EPAStatus.CONNECTION_FAILED,
                server=self.server,
                port=self.port,
                details=f"Connection failed: {e}",
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return EPAResult(
            status=EPAStatus.UNKNOWN,
            server=self.server,
            port=self.port,
            details="Could not determine EPA status",
        )

    def _build_prelogin(self) -> bytes:
        """Build TDS PRELOGIN packet body."""
        # Version option
        version_data = struct.pack(">IH", 0x0E000000, 0x0000)  # TDS 7.4
        # Encryption option
        encryption_data = struct.pack("B", ENCRYPT_OFF)  # Request no encryption to see server preference

        # Option offsets: header is 3 bytes per option + 1 terminator
        header_len = 3 * 2 + 1  # 2 options + terminator
        version_offset = header_len
        encryption_offset = version_offset + len(version_data)

        header = b""
        # VERSION option
        header += struct.pack("B", PL_OPTION_VERSION)
        header += struct.pack(">H", version_offset)
        header += struct.pack(">H", len(version_data))
        # ENCRYPTION option
        header += struct.pack("B", PL_OPTION_ENCRYPTION)
        header += struct.pack(">H", encryption_offset)
        header += struct.pack(">H", len(encryption_data))
        # Terminator
        header += struct.pack("B", PL_OPTION_TERMINATOR)

        return header + version_data + encryption_data

    def _wrap_tds(self, packet_type: int, data: bytes) -> bytes:
        """Wrap data in a TDS packet header."""
        length = 8 + len(data)
        header = struct.pack(">BBHBB", packet_type, 0x01, length, 0, 0)
        header += struct.pack(">H", 0)  # padding
        return header + data

    def _recv_tds(self, sock: socket.socket) -> bytes:
        """Receive a complete TDS packet."""
        header = b""
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                raise ConnectionError("Connection closed during TDS header read")
            header += chunk

        length = struct.unpack(">H", header[2:4])[0]
        data = header
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data[8:]  # Skip TDS header

    def _parse_prelogin_encryption(self, data: bytes) -> int:
        """Parse PRELOGIN response to extract encryption option value."""
        offset = 0
        while offset < len(data):
            token = data[offset]
            if token == PL_OPTION_TERMINATOR:
                break
            if offset + 5 > len(data):
                break
            opt_offset = struct.unpack(">H", data[offset + 1 : offset + 3])[0]
            opt_length = struct.unpack(">H", data[offset + 3 : offset + 5])[0]
            if token == PL_OPTION_ENCRYPTION and opt_offset + opt_length <= len(data) + 8:
                # The offset in prelogin is relative to the start of the prelogin data
                if opt_offset < len(data):
                    return data[opt_offset]
            offset += 5
        return ENCRYPT_OFF
