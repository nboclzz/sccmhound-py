"""CLI entry point and main orchestration."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timedelta

from sccmhound.auth.credentials import Credentials
from sccmhound.config import Config

BANNER = r"""
   ▄████████  ▄████████  ▄████████   ▄▄▄▄███▄▄▄▄      ▄█    █▄     ▄██████▄  ███    █▄  ███▄▄▄▄   ████████▄
  ███    ███ ███    ███ ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███   ███    ███ ███    ███ ███▀▀▀██▄ ███   ▀███
  ███    █▀  ███    █▀  ███    █▀  ███   ███   ███   ███    ███   ███    ███ ███    ███ ███   ███ ███    ███
  ███        ███        ███        ███   ███   ███  ▄███▄▄▄▄███▄▄ ███    ███ ███    ███ ███   ███ ███    ███
▀███████████ ███        ███        ███   ███   ███ ▀▀███▀▀▀▀███▀  ███    ███ ███    ███ ███   ███ ███    ███
         ███ ███    █▄  ███    █▄  ███   ███   ███   ███    ███   ███    ███ ███    ███ ███   ███ ███    ███
   ▄█    ███ ███    ███ ███    ███ ███   ███   ███   ███    ███   ███    ███ ███    ███ ███   ███ ███   ▄███
 ▄████████▀  ████████▀  ████████▀   ▀█   ███   █▀    ███    █▀     ▀██████▀  ████████▀   ▀█   █▀  ████████▀
                                                                                              [Python Edition]
"""

logger = logging.getLogger("sccmhound")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sccmhound",
        description="SCCMHound-py: BloodHound collector for Microsoft Configuration Manager",
    )

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--domain", required=True, help="Target domain (e.g. CORP.LOCAL)")
    target.add_argument("--dc-ip", help="Domain Controller IP (if omitted, domain name is used for DNS)")
    target.add_argument("--server", help="SCCM server override (skip auto-discovery)")
    target.add_argument("--sitecode", help="SCCM site code override (skip auto-discovery)")

    collection = parser.add_argument_group("Collection")
    collection.add_argument(
        "-c", "--collectionmethods", default="Default",
        choices=["Default", "LocalAdmins", "CurrentSessions", "All"],
        help="Collection method (default: Default)",
    )
    collection.add_argument("--loop", action="store_true", help="Enable loop collection")
    collection.add_argument("--loopduration", default="00:30:00", help="Loop duration HH:MM:SS (default: 00:30:00)")
    collection.add_argument("--loopsleep", type=int, default=60, help="Sleep between loops in seconds (default: 60)")
    collection.add_argument("--hc", action="store_true", help="Health check: test auth and exit")

    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", help="Username")
    auth.add_argument("-p", "--password", help="Password")
    auth.add_argument("-H", "--hash", dest="ntlm_hash", help="NTLM hash (LMHASH:NTHASH or :NTHASH)")
    auth.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    auth.add_argument("--ccache", help="Path to ccache file")

    checks = parser.add_argument_group("Security Checks")
    checks.add_argument("--check-epa", action="store_true", help="Check MSSQL EPA/channel binding on site DB")
    checks.add_argument("--sql-server", help="MSSQL server for EPA check (auto-discovered if omitted)")
    checks.add_argument("--sql-port", type=int, default=1433, help="MSSQL port (default: 1433)")

    parser.add_argument("-o", "--output-dir", default=".", help="Output directory for JSON files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug output (implies verbose)")

    return parser


def _parse_duration(duration_str: str) -> timedelta:
    parts = duration_str.split(":")
    if len(parts) == 3:
        return timedelta(hours=int(parts[0]), minutes=int(parts[1]), seconds=int(parts[2]))
    return timedelta(minutes=30)


def _setup_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def invoke(config: Config) -> None:
    """Main orchestration with auto-discovery."""
    from sccmhound.collectors.adminservice_collector import AdminServiceCollector
    from sccmhound.collectors.wmi_collector import WMICollector
    from sccmhound.connectors.adminservice import AdminServiceConnector
    from sccmhound.connectors.wmi import WMIConnector
    from sccmhound.discovery.ldap_discovery import SCCMInfrastructure, discover_sccm
    from sccmhound.discovery.smb_probes import check_smb_signing, probe_site_server
    from sccmhound.ldap.connection_manager import LdapConnectionManager
    from sccmhound.ldap.sid_resolver import SIDResolver
    from sccmhound.output import json_writer
    from sccmhound.output.opengraph_writer import write_opengraph
    from sccmhound.resolvers.domains import resolve_domains
    from sccmhound.resolvers.local_admins import resolve_local_admins
    from sccmhound.resolvers.sessions import resolve_sessions
    from sccmhound.resolvers.users_groups import resolve_users_groups

    cm = config.collection_methods.lower()
    server = config.server
    site_code = config.site_code
    mp_server = server  # Management point for AdminService (may differ from site server)

    # Track infrastructure + probe results for OpenGraph output
    infra = SCCMInfrastructure()
    db_server = ""
    db_signing_required: bool | None = None
    site_server_signing_required: bool | None = None
    epa_enforced: bool | None = None

    # --- Discovery phase ---
    if not server or not site_code:
        print(f"Discovering SCCM infrastructure in {config.credentials.domain}...")
        try:
            infra = discover_sccm(config.credentials, dc_ip=config.credentials.dc_ip)
        except Exception as e:
            print(f"Discovery failed: {e}")
            if config.verbose:
                logger.exception("Discovery error")
            return

        if not infra.primary_server and not infra.primary_site_code:
            print("No SCCM infrastructure found in this domain.")
            return

        print(f"\nDiscovered SCCM infrastructure:")
        print(infra.summary())
        print()

        # Use discovered values if not explicitly overridden
        if not server:
            server = infra.primary_server
        if not site_code:
            site_code = infra.primary_site_code
        if infra.primary_mp:
            mp_server = infra.primary_mp

        if not server or not site_code:
            print("Could not determine SCCM server or site code from discovery.")
            print("Use --server and --sitecode to specify manually.")
            return

        print(f"Using site server: {server}")
        print(f"Using site code: {site_code}")
        if mp_server != server:
            print(f"Using management point: {mp_server}")
        print()

    # --- SMB probes on discovered infrastructure ---
    if server and infra.site_servers:
        print(f"Probing site server {server} via SMB...")
        try:
            probe_result = probe_site_server(server, config.credentials)
            if probe_result.reachable:
                site_server_signing_required = probe_result.signing_required
                print(f"  SMB signing: {'required' if probe_result.signing_required else 'NOT required'}")
                if probe_result.db_server:
                    db_server = probe_result.db_server
                    print(f"  Site database server: {db_server}")

                    # Check SMB signing on DB server too
                    print(f"  Checking SMB signing on DB server {db_server}...")
                    db_signing_required = check_smb_signing(db_server, config.credentials)
                    if db_signing_required is not None:
                        print(f"  DB SMB signing: {'required' if db_signing_required else 'NOT required'}")
                        if not db_signing_required:
                            print(f"  [!] TAKEOVER-2: SMB signing NOT required on DB server — NTLM relay possible")
            else:
                print(f"  SMB unreachable: {probe_result.error}")
        except Exception as e:
            logger.debug("SMB probe error: %s", e)

    # --- EPA check (run early so results go into OpenGraph) ---
    if config.check_epa or db_server:
        try:
            from sccmhound.checks.mssql_epa import EPAStatus, MSSQLEPAChecker
            sql_target = config.sql_server or db_server or server
            if sql_target:
                print(f"Checking MSSQL EPA on {sql_target}:{config.sql_port}...")
                checker = MSSQLEPAChecker(sql_target, config.sql_port)
                epa_result = checker.check_epa()
                epa_enforced = epa_result.status == EPAStatus.ENFORCED
                print(f"  EPA Status: {epa_result.status.name} — {epa_result.details}")
                if epa_result.status == EPAStatus.NOT_ENFORCED:
                    print(f"  [!] TAKEOVER-1: EPA NOT enforced — NTLM relay to MSSQL possible")
        except Exception as e:
            logger.debug("EPA check error: %s", e)

    # --- Connection phase ---
    print(f"Connecting to {server} (sitecode: {site_code})")
    try:
        print("Establishing WMI connection...")
        wmi_connector = WMIConnector.create_instance(server, site_code, config.credentials)
    except Exception as e:
        print(f"Failed to establish WMI connection: {e}")
        if config.verbose:
            logger.exception("WMI connection error")
        return

    admin_connector = None
    admin_collector = None
    if cm in ("localadmins", "currentsessions", "all"):
        try:
            admin_target = mp_server or server
            admin_connector = AdminServiceConnector.create_instance(admin_target, config.credentials)
            if admin_connector:
                admin_collector = AdminServiceCollector(admin_connector)
                if not admin_collector.get_collections():
                    raise RuntimeError("Could not access SMS00001 collection")
            else:
                print("AdminService connection failed")
                return
        except PermissionError:
            print("403 from AdminService API. Are you an SCCM Full Administrator?\nNote: DA != SCCM Full Administrator!")
            return
        except Exception as e:
            print(f"AdminService connection error: {e}")
            if config.verbose:
                logger.exception("AdminService error")
            return

    # --- Health check ---
    if config.health_check:
        if wmi_connector.is_connected:
            print(f"Connection to {server} (sitecode: {site_code}) established!")
            print("Health check passed!")
        else:
            print("Health check failed.")
        return

    if not wmi_connector.is_connected:
        print("WMI connector is not connected.")
        return

    print(f"Connection to {server} (sitecode: {site_code}) established!")
    wmi_collector = WMICollector(wmi_connector)

    # --- LDAP setup ---
    ldap_mgr = LdapConnectionManager()
    sid_resolver = SIDResolver(ldap_mgr, config.credentials)

    # --- Collection phase ---
    try:
        print(f"Collecting computer objects from {site_code}...")
        computers = wmi_collector.query_computers()
        print(f"Collected {len(computers)} computers")

        print(f"Collecting user objects from {site_code}...")
        users = wmi_collector.query_users()
        print(f"Collected {len(users)} users")

        print(f"Collecting group objects from {site_code}...")
        groups = wmi_collector.query_groups()
        print(f"Collected {len(groups)} groups")

        print(f"Collecting user-machine relationships from {site_code}...")
        relationships = wmi_collector.query_user_machine_relationships()
        print(f"Collected {len(relationships)} relationships")

        if not any([computers, users, groups, relationships]):
            print("No objects returned. Check that your account has sufficient SCCM access.")
            return
    except Exception as e:
        print(f"Data collection error: {e}")
        if config.verbose:
            logger.exception("Collection error")
        return

    # --- Resolution phase ---
    try:
        print("Resolving domains...")
        domains = resolve_domains(users, computers, groups)

        print("Resolving user-group memberships...")
        resolve_users_groups(users, groups)

        print("Resolving sessions...")
        resolve_sessions(computers, users, relationships, domains, sid_resolver)
    except Exception as e:
        print(f"Resolution error: {e}")
        if config.verbose:
            logger.exception("Resolution error")
        return

    # --- CMPivot collection ---
    if cm in ("localadmins", "all") and admin_collector:
        try:
            print("Collecting local administrators via CMPivot...")
            local_admins = admin_collector.get_administrators()
            resolve_local_admins(computers, groups, users, local_admins, domains, sid_resolver)
        except PermissionError as e:
            print(f"Permission error: {e}")
            return
        except Exception as e:
            print(f"Local admin collection error: {e}")
            if config.verbose:
                logger.exception("Local admin error")
            return

    if cm in ("currentsessions", "all") and admin_collector:
        try:
            print("Collecting current sessions via CMPivot...")
            cmpivot_relationships = admin_collector.get_users()
            resolve_sessions(computers, users, cmpivot_relationships, domains, sid_resolver)
        except PermissionError as e:
            print(f"Permission error: {e}")
            return
        except Exception as e:
            print(f"CMPivot session collection error: {e}")
            if config.verbose:
                logger.exception("CMPivot session error")
            return

    # --- Output phase ---
    try:
        print("Writing JSON output...")
        f1 = json_writer.write_computers(computers, config.output_dir)
        f2 = json_writer.write_groups(groups, config.output_dir)
        f3 = json_writer.write_users(users, config.output_dir)
        f4 = json_writer.write_domains(domains, config.output_dir)
        print(f"Wrote: {f1}, {f2}, {f3}, {f4}")
    except Exception as e:
        print(f"JSON write error: {e}")
        if config.verbose:
            logger.exception("JSON write error")
        return

    # --- Loop collection ---
    if config.loop:
        duration = _parse_duration(config.loop_duration)
        end_time = datetime.now() + duration
        loop_count = 1

        print("Starting collection loops...")
        while datetime.now() < end_time:
            print(f"Sleeping for {config.loop_sleep} seconds...")
            time.sleep(config.loop_sleep)

            print(f"Loop iteration {loop_count}...")
            try:
                relationships = wmi_collector.query_user_machine_relationships()
                resolve_sessions(computers, users, relationships, domains, sid_resolver)

                if cm in ("currentsessions", "all") and admin_collector:
                    cmpivot_rels = admin_collector.get_users()
                    resolve_sessions(computers, users, cmpivot_rels, domains, sid_resolver)

                json_writer.write_sessions(computers, config.output_dir)
            except Exception as e:
                print(f"Loop error: {e}")
                if config.verbose:
                    logger.exception("Loop error")
                break

            loop_count += 1

    # --- OpenGraph output (SCCM attack paths for BloodHound CE) ---
    if infra.site_servers or infra.management_points or infra.sites:
        try:
            print("Writing OpenGraph JSON (SCCM attack paths)...")
            og_file = write_opengraph(
                infra, computers, config.output_dir,
                db_server=db_server,
                db_signing_required=db_signing_required,
                site_server_signing_required=site_server_signing_required,
                epa_enforced=epa_enforced,
            )
            print(f"Wrote: {og_file}")
            print("Import this file into BloodHound CE to visualize SCCM attack paths.")
        except Exception as e:
            print(f"OpenGraph write error: {e}")
            if config.verbose:
                logger.exception("OpenGraph error")

    # --- Cleanup ---
    try:
        LdapConnectionManager().cleanup()
    except Exception:
        pass

    wmi_connector.disconnect()
    print("Hound out!")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose, args.debug)
    print(BANNER)

    # Validate credentials — need at least one auth method
    has_password = args.username and args.password
    has_hash = args.ntlm_hash
    has_kerberos = args.kerberos or args.ccache

    if not has_password and not has_hash and not has_kerberos:
        print("Error: provide credentials via -u/-p, -H (hash), -k (kerberos), or --ccache")
        sys.exit(1)

    credentials = Credentials(
        username=args.username or "",
        password=args.password or "",
        domain=args.domain,
        ntlm_hash=args.ntlm_hash or "",
        kerberos=args.kerberos,
        ccache=args.ccache or "",
        dc_ip=args.dc_ip,
    )

    config = Config(
        server=args.server or "",
        site_code=args.sitecode or "",
        collection_methods=args.collectionmethods,
        loop=args.loop,
        loop_duration=args.loopduration,
        loop_sleep=args.loopsleep,
        health_check=args.hc,
        credentials=credentials,
        verbose=args.verbose or args.debug,
        debug=args.debug,
        output_dir=args.output_dir,
        check_epa=args.check_epa,
        sql_server=args.sql_server,
        sql_port=args.sql_port,
    )

    invoke(config)
