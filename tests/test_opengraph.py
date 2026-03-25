"""Tests for OpenGraph output format and attack path edge generation."""

import json
import os
import tempfile

from sccmhound.discovery.ldap_discovery import (
    SCCMDistributionPoint,
    SCCMInfrastructure,
    SCCMManagementPoint,
    SCCMSite,
    SCCMSiteServer,
)
from sccmhound.models.bloodhound import BHComputer
from sccmhound.output.opengraph_writer import build_opengraph, write_opengraph


def _make_infra():
    infra = SCCMInfrastructure()
    infra.site_servers = [SCCMSiteServer(hostname="sccm01.corp.local", sid="S-1-5-21-111-222-333-2001")]
    infra.management_points = [SCCMManagementPoint(hostname="sccm01.corp.local", site_code="PS1", is_default=True)]
    infra.sites = [SCCMSite(site_code="PS1", name="PS1")]
    infra.distribution_points = [SCCMDistributionPoint(hostname="dp01.corp.local", is_pxe=True)]
    return infra


def _make_computers():
    c1 = BHComputer(object_identifier="S-1-5-21-111-222-333-3001")
    c1.properties = {"name": "WS01.CORP.LOCAL", "sccmName": "WS01"}
    c2 = BHComputer(object_identifier="S-1-5-21-111-222-333-3002")
    c2.properties = {"name": "WS02.CORP.LOCAL", "sccmName": "WS02"}
    # Add site server as a collected computer too
    ss = BHComputer(object_identifier="S-1-5-21-111-222-333-2001")
    ss.properties = {"name": "SCCM01.CORP.LOCAL", "sccmName": "SCCM01"}
    return [c1, c2, ss]


def test_opengraph_top_level_structure():
    data = build_opengraph(_make_infra(), _make_computers())
    assert "metadata" in data
    assert "graph" in data
    assert data["metadata"]["source_kind"] == "SCCMBase"
    assert "nodes" in data["graph"]
    assert "edges" in data["graph"]
    # Must NOT have "meta" or "data" (legacy format — BH CE rejects mixed)
    assert "meta" not in data
    assert "data" not in data


def test_opengraph_site_node():
    data = build_opengraph(_make_infra(), _make_computers())
    site_nodes = [n for n in data["graph"]["nodes"] if "SCCMSite" in n["kinds"]]
    assert len(site_nodes) == 1
    assert site_nodes[0]["id"] == "sccm-site-PS1"
    assert site_nodes[0]["kinds"] == ["SCCMSite", "SCCMBase"]
    assert site_nodes[0]["properties"]["sitecode"] == "PS1"


def test_opengraph_site_server_edge():
    data = build_opengraph(_make_infra(), _make_computers())
    ss_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMSiteServerFor"]
    assert len(ss_edges) == 1
    # Should link via SID since site server is in the computers list
    assert ss_edges[0]["start"]["value"] == "S-1-5-21-111-222-333-2001"
    assert ss_edges[0]["end"]["value"] == "sccm-site-PS1"


def test_opengraph_mp_edge():
    data = build_opengraph(_make_infra(), _make_computers())
    mp_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMManagementPointFor"]
    assert len(mp_edges) == 1
    assert mp_edges[0]["end"]["value"] == "sccm-site-PS1"


def test_opengraph_dp_edge_with_pxe():
    data = build_opengraph(_make_infra(), _make_computers())
    dp_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMDistributionPointFor"]
    assert len(dp_edges) == 1
    assert dp_edges[0]["properties"]["pxe_enabled"] is True


def test_opengraph_manages_edges():
    """EXEC-1/EXEC-2: SCCMSite should have SCCMManages edge to each managed computer."""
    data = build_opengraph(_make_infra(), _make_computers())
    manages_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMManages"]
    # 3 computers (WS01, WS02, SCCM01)
    assert len(manages_edges) == 3
    # All start from the site
    for edge in manages_edges:
        assert edge["start"]["value"] == "sccm-site-PS1"


def test_opengraph_relay_target_takeover1():
    """TAKEOVER-1: EPA not enforced on DB → SCCMRelayTarget edge."""
    data = build_opengraph(
        _make_infra(), _make_computers(),
        db_server="db01.corp.local",
        epa_enforced=False,
    )
    relay_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMRelayTarget"]
    assert len(relay_edges) == 1
    assert relay_edges[0]["properties"]["epa_enforced"] is False
    assert "TAKEOVER-1" in relay_edges[0]["properties"]["relay_reasons"][0]


def test_opengraph_relay_target_takeover2():
    """TAKEOVER-2: SMB signing not required on DB → SCCMRelayTarget edge."""
    data = build_opengraph(
        _make_infra(), _make_computers(),
        db_server="db01.corp.local",
        db_signing_required=False,
    )
    relay_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMRelayTarget"]
    assert len(relay_edges) == 1
    assert relay_edges[0]["properties"]["smb_signing_required"] is False
    assert "TAKEOVER-2" in relay_edges[0]["properties"]["relay_reasons"][0]


def test_opengraph_no_relay_when_secured():
    """No SCCMRelayTarget edge when EPA enforced + signing required."""
    data = build_opengraph(
        _make_infra(), _make_computers(),
        db_server="db01.corp.local",
        epa_enforced=True,
        db_signing_required=True,
    )
    relay_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMRelayTarget"]
    assert len(relay_edges) == 0


def test_opengraph_db_server_edge():
    data = build_opengraph(
        _make_infra(), _make_computers(),
        db_server="db01.corp.local",
    )
    db_edges = [e for e in data["graph"]["edges"] if e["kind"] == "SCCMDBServerFor"]
    assert len(db_edges) == 1
    assert db_edges[0]["end"]["value"] == "sccm-site-PS1"


def test_opengraph_node_format_no_objectid():
    """BH CE forbids objectid in properties — verify it's not present."""
    data = build_opengraph(_make_infra(), _make_computers())
    for node in data["graph"]["nodes"]:
        assert "objectid" not in node.get("properties", {}), f"objectid found in node {node['id']}"


def test_opengraph_edge_kind_alphanumeric():
    """BH CE requires edge kinds to match ^[A-Za-z0-9_]+$."""
    import re
    data = build_opengraph(
        _make_infra(), _make_computers(),
        db_server="db01", epa_enforced=False,
    )
    for edge in data["graph"]["edges"]:
        assert re.match(r"^[A-Za-z0-9_]+$", edge["kind"]), f"Invalid edge kind: {edge['kind']}"


def test_write_opengraph_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = write_opengraph(_make_infra(), _make_computers(), tmpdir)
        assert os.path.exists(filepath)
        assert filepath.endswith(".json")

        with open(filepath) as f:
            data = json.load(f)

        assert data["metadata"]["source_kind"] == "SCCMBase"
        assert len(data["graph"]["nodes"]) > 0
        assert len(data["graph"]["edges"]) > 0
