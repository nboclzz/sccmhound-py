"""BloodHound CE OpenGraph JSON writer.

Produces the OpenGraph ingest format with custom SCCM node types and edges
that represent SCCM attack paths discoverable by SCCMHound.

Format spec: https://github.com/SpecterOps/BloodHound (streamdecoder.go + jsonschema/)
Reference impl: https://github.com/SpecterOps/SCOMHound (opengraphy.py)

Nodes created:
  - SCCMSite (one per discovered site code)

Edges created (linking to existing AD Computer nodes by SID):
  - SCCMSiteServerFor: Computer → SCCMSite (site server role)
  - SCCMManagementPointFor: Computer → SCCMSite (MP role)
  - SCCMDistributionPointFor: Computer → SCCMSite (DP role, with PXE flag)
  - SCCMManages: SCCMSite → Computer (all managed clients from WMI)
  - SCCMDBServerFor: Computer → SCCMSite (database server, if discovered)
  - SCCMRelayTarget: marks DB server as relay target when EPA not enforced + signing disabled

Attack paths detectable in BloodHound after import:
  - EXEC-1/EXEC-2: SCCMSite -[SCCMManages]-> Computer (code exec on managed clients)
  - CRED-1: DP with pxe_enabled=true property (PXE credential theft)
  - TAKEOVER-1: SCCMRelayTarget edge on DB server (NTLM relay to MSSQL)
  - TAKEOVER-2: DB server with signing_required=false (NTLM relay to SMB)
  - ELEVATE-2: SCCMSite with client_push_enabled=true (client push relay)
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from sccmhound.discovery.ldap_discovery import SCCMInfrastructure
from sccmhound.models.bloodhound import BHComputer

SOURCE_KIND = "SCCMBase"


def _node(node_id: str, kinds: list[str], properties: dict[str, Any]) -> dict:
    """Build an OpenGraph node. id is uppercased by BH CE on ingest."""
    return {
        "id": node_id,
        "kinds": kinds,
        "properties": {k: v for k, v in properties.items() if v is not None},
    }


def _edge(kind: str, start_id: str, end_id: str, properties: dict[str, Any] | None = None) -> dict:
    """Build an OpenGraph edge."""
    edge: dict[str, Any] = {
        "kind": kind,
        "start": {"value": start_id, "match_by": "id"},
        "end": {"value": end_id, "match_by": "id"},
    }
    if properties:
        edge["properties"] = properties
    return edge


def build_opengraph(
    infra: SCCMInfrastructure,
    computers: list[BHComputer],
    db_server: str = "",
    db_signing_required: bool | None = None,
    site_server_signing_required: bool | None = None,
    epa_enforced: bool | None = None,
    client_push_enabled: bool | None = None,
) -> dict[str, Any]:
    """Build the complete OpenGraph JSON structure.

    Args:
        infra: Discovered SCCM infrastructure from LDAP
        computers: Collected computers from WMI (already have SIDs)
        db_server: Database server hostname (from registry probe)
        db_signing_required: SMB signing on DB server
        site_server_signing_required: SMB signing on site server
        epa_enforced: MSSQL EPA status on DB server
        client_push_enabled: Whether client push installation is enabled
    """
    nodes: list[dict] = []
    edges: list[dict] = []

    # --- Build computer SID lookup from collected data ---
    # Maps hostname (lowercase, short name) to SID for edge linking
    computer_sid_by_name: dict[str, str] = {}
    for comp in computers:
        sccm_name = comp.properties.get("sccmName", "")
        if sccm_name:
            computer_sid_by_name[sccm_name.lower()] = comp.object_identifier
        # Also index by FQDN
        fqdn = comp.properties.get("name", "")
        if fqdn:
            computer_sid_by_name[fqdn.lower()] = comp.object_identifier

    # --- SCCMSite nodes ---
    for site in infra.sites:
        if not site.site_code:
            continue
        site_id = f"sccm-site-{site.site_code}"
        props: dict[str, Any] = {
            "name": f"SCCM Site {site.site_code}",
            "displayname": f"SCCM Site {site.site_code}",
            "sitecode": site.site_code,
            "is_cas": site.is_cas,
        }
        if client_push_enabled is not None:
            props["client_push_enabled"] = client_push_enabled
        nodes.append(_node(site_id, ["SCCMSite", SOURCE_KIND], props))

    # If no sites from LDAP but we have a site code from MPs, create the node
    site_codes_created = {s.site_code for s in infra.sites if s.site_code}
    for mp in infra.management_points:
        if mp.site_code and mp.site_code not in site_codes_created:
            site_id = f"sccm-site-{mp.site_code}"
            nodes.append(_node(site_id, ["SCCMSite", SOURCE_KIND], {
                "name": f"SCCM Site {mp.site_code}",
                "displayname": f"SCCM Site {mp.site_code}",
                "sitecode": mp.site_code,
            }))
            site_codes_created.add(mp.site_code)

    # --- Site Server edges ---
    primary_site_code = infra.primary_site_code or ""
    for ss in infra.site_servers:
        hostname = ss.hostname.lower()
        # Try to match to an existing computer SID
        comp_sid = computer_sid_by_name.get(hostname) or computer_sid_by_name.get(hostname.split(".")[0])
        start_id = comp_sid or ss.sid or f"sccm-server-{hostname}"

        # If we don't have the SID, create a node for it
        if not comp_sid:
            nodes.append(_node(start_id, ["Computer", SOURCE_KIND], {
                "name": ss.hostname.upper(),
                "displayname": ss.hostname,
            }))

        if primary_site_code:
            edge_props: dict[str, Any] = {}
            if site_server_signing_required is not None:
                edge_props["smb_signing_required"] = site_server_signing_required
            edges.append(_edge("SCCMSiteServerFor", start_id, f"sccm-site-{primary_site_code}", edge_props or None))

    # --- Management Point edges ---
    for mp in infra.management_points:
        if not mp.site_code:
            continue
        hostname = mp.hostname.lower()
        comp_sid = computer_sid_by_name.get(hostname) or computer_sid_by_name.get(hostname.split(".")[0])
        start_id = comp_sid or f"sccm-mp-{hostname}"

        if not comp_sid:
            nodes.append(_node(start_id, ["Computer", SOURCE_KIND], {
                "name": mp.hostname.upper(),
                "displayname": mp.hostname,
            }))

        edges.append(_edge(
            "SCCMManagementPointFor", start_id, f"sccm-site-{mp.site_code}",
            {"is_default": mp.is_default} if mp.is_default else None,
        ))

    # --- Distribution Point edges ---
    for dp in infra.distribution_points:
        hostname = dp.hostname.lower()
        comp_sid = computer_sid_by_name.get(hostname) or computer_sid_by_name.get(hostname.split(".")[0])
        start_id = comp_sid or f"sccm-dp-{hostname}"

        if not comp_sid:
            nodes.append(_node(start_id, ["Computer", SOURCE_KIND], {
                "name": dp.hostname.upper(),
                "displayname": dp.hostname,
            }))

        if primary_site_code:
            edges.append(_edge(
                "SCCMDistributionPointFor", start_id, f"sccm-site-{primary_site_code}",
                {"pxe_enabled": True} if dp.is_pxe else None,
            ))

    # --- SCCMManages edges (site → each managed computer) ---
    # This is the key attack path edge: EXEC-1/EXEC-2
    if primary_site_code:
        site_id = f"sccm-site-{primary_site_code}"
        for comp in computers:
            if comp.object_identifier:
                edges.append(_edge("SCCMManages", site_id, comp.object_identifier))

    # --- Database server edges ---
    if db_server and primary_site_code:
        db_hostname = db_server.lower()
        comp_sid = computer_sid_by_name.get(db_hostname) or computer_sid_by_name.get(db_hostname.split(".")[0])
        db_id = comp_sid or f"sccm-db-{db_hostname}"

        if not comp_sid:
            nodes.append(_node(db_id, ["Computer", SOURCE_KIND], {
                "name": db_server.upper(),
                "displayname": db_server,
            }))

        db_edge_props: dict[str, Any] = {}
        if db_signing_required is not None:
            db_edge_props["smb_signing_required"] = db_signing_required
        if epa_enforced is not None:
            db_edge_props["epa_enforced"] = epa_enforced
        edges.append(_edge("SCCMDBServerFor", db_id, f"sccm-site-{primary_site_code}", db_edge_props or None))

        # TAKEOVER-1/2: If EPA not enforced OR signing not required, mark as relay target
        relay_reasons = []
        if epa_enforced is False:
            relay_reasons.append("TAKEOVER-1: EPA not enforced on MSSQL")
        if db_signing_required is False:
            relay_reasons.append("TAKEOVER-2: SMB signing not required")

        if relay_reasons:
            edges.append(_edge("SCCMRelayTarget", f"sccm-site-{primary_site_code}", db_id, {
                "relay_reasons": relay_reasons,
                "epa_enforced": epa_enforced if epa_enforced is not None else True,
                "smb_signing_required": db_signing_required if db_signing_required is not None else True,
            }))

    return {
        "metadata": {"source_kind": SOURCE_KIND},
        "graph": {"nodes": nodes, "edges": edges},
    }


def write_opengraph(
    infra: SCCMInfrastructure,
    computers: list[BHComputer],
    output_dir: str = ".",
    db_server: str = "",
    db_signing_required: bool | None = None,
    site_server_signing_required: bool | None = None,
    epa_enforced: bool | None = None,
    client_push_enabled: bool | None = None,
) -> str:
    """Build and write OpenGraph JSON to file."""
    data = build_opengraph(
        infra, computers, db_server, db_signing_required,
        site_server_signing_required, epa_enforced, client_push_enabled,
    )

    ts = int(time.time() * 1000)
    filename = f"sccm-opengraph-{ts}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    return filepath
