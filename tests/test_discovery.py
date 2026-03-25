"""Tests for LDAP auto-discovery module."""

import struct

from sccmhound.discovery.ldap_discovery import (
    SCCMDistributionPoint,
    SCCMInfrastructure,
    SCCMManagementPoint,
    SCCMSite,
    SCCMSiteServer,
    _parse_sid,
    _parse_acl_for_full_control,
)


def _build_sid_bytes(sid_str: str) -> bytes:
    """Build binary SID from string like S-1-5-21-..."""
    parts = sid_str.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]

    result = struct.pack("BB", revision, len(sub_authorities))
    result += authority.to_bytes(6, byteorder="big")
    for sa in sub_authorities:
        result += struct.pack("<I", sa)
    return result


def test_parse_sid():
    sid_bytes = _build_sid_bytes("S-1-5-21-1234-5678-9012")
    assert _parse_sid(sid_bytes) == "S-1-5-21-1234-5678-9012"


def test_parse_sid_with_rid():
    sid_bytes = _build_sid_bytes("S-1-5-21-111-222-333-1001")
    assert _parse_sid(sid_bytes) == "S-1-5-21-111-222-333-1001"


def test_parse_sid_empty():
    assert _parse_sid(b"") == ""
    assert _parse_sid(None) == ""


def _build_security_descriptor(sids: list[str]) -> bytes:
    """Build a minimal security descriptor with DACL containing ACCESS_ALLOWED_ACE entries."""
    # Build ACEs
    aces = b""
    for sid_str in sids:
        sid_bytes = _build_sid_bytes(sid_str)
        ace_size = 8 + len(sid_bytes)  # type(1) + flags(1) + size(2) + mask(4) + SID
        ace = struct.pack("<BBH", 0x00, 0x00, ace_size)  # ACCESS_ALLOWED_ACE_TYPE
        ace += struct.pack("<I", 0xF01FF)  # FullControl mask
        ace += sid_bytes
        aces += ace

    # Build DACL: revision(1) + sbz(1) + size(2) + ace_count(2) + sbz2(2) + ACEs
    dacl_size = 8 + len(aces)
    dacl = struct.pack("<BBHHH", 0x02, 0x00, dacl_size, len(sids), 0x0000)
    dacl += aces

    # Build security descriptor header
    # revision(1) + sbz(1) + control(2) + owner_off(4) + group_off(4) + sacl_off(4) + dacl_off(4)
    dacl_offset = 20  # Right after the header
    header = struct.pack("<BBHIIII", 0x01, 0x00, 0x8004, 0, 0, 0, dacl_offset)

    return header + dacl


def test_parse_acl_for_full_control():
    sids = ["S-1-5-21-1234-5678-9012-1001", "S-1-5-21-1234-5678-9012-1002"]
    sd = _build_security_descriptor(sids)
    result = _parse_acl_for_full_control(sd)
    assert len(result) == 2
    assert "S-1-5-21-1234-5678-9012-1001" in result
    assert "S-1-5-21-1234-5678-9012-1002" in result


def test_parse_acl_skips_well_known():
    sids = ["S-1-5-18", "S-1-5-21-1234-5678-9012-1001"]  # SYSTEM + real SID
    sd = _build_security_descriptor(sids)
    result = _parse_acl_for_full_control(sd)
    assert len(result) == 1
    assert "S-1-5-21-1234-5678-9012-1001" in result


def test_parse_acl_empty():
    assert _parse_acl_for_full_control(b"") == []


def test_infrastructure_primary_server():
    infra = SCCMInfrastructure()
    infra.site_servers = [SCCMSiteServer(hostname="sccm01.corp.local", sid="S-1-5-21-xxx")]
    infra.management_points = [SCCMManagementPoint(hostname="sccm01.corp.local", site_code="PS1")]
    assert infra.primary_server == "sccm01.corp.local"
    assert infra.primary_site_code == "PS1"


def test_infrastructure_primary_from_mp_only():
    infra = SCCMInfrastructure()
    infra.management_points = [SCCMManagementPoint(hostname="mp01.corp.local", site_code="AB1", is_default=True)]
    assert infra.primary_server == "mp01.corp.local"
    assert infra.primary_site_code == "AB1"
    assert infra.primary_mp == "mp01.corp.local"


def test_infrastructure_cas_detection():
    infra = SCCMInfrastructure()
    infra.sites = [
        SCCMSite(site_code="CAS", is_cas=True),
        SCCMSite(site_code="PS1", is_cas=False),
    ]
    assert infra.primary_site_code == "PS1"


def test_infrastructure_empty():
    infra = SCCMInfrastructure()
    assert infra.primary_server is None
    assert infra.primary_site_code is None
    assert infra.primary_mp is None
    assert "No SCCM infrastructure found" in infra.summary()


def test_infrastructure_summary():
    infra = SCCMInfrastructure()
    infra.site_servers = [SCCMSiteServer(hostname="sccm01.corp.local")]
    infra.management_points = [SCCMManagementPoint(hostname="sccm01.corp.local", site_code="PS1", is_default=True)]
    infra.sites = [SCCMSite(site_code="PS1")]
    infra.distribution_points = [SCCMDistributionPoint(hostname="dp01.corp.local", is_pxe=True)]
    infra.sccm_accounts = [{"name": "sccm-svc"}]

    summary = infra.summary()
    assert "sccm01.corp.local" in summary
    assert "PS1" in summary
    assert "(default)" in summary
    assert "(PXE)" in summary
    assert "1" in summary  # accounts count
