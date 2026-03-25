"""WMI data collector. Ported from src/SCCMCollector.cs — runs WQL queries against SCCM."""

from __future__ import annotations

import logging
import re
from typing import Any

from sccmhound.connectors.wmi import WMIConnector
from sccmhound.models.bloodhound import BHComputer, BHGroup, BHUser
from sccmhound.models.sccm import UserMachineRelationship
from sccmhound.utils.helpers import (
    convert_ldap_to_domain,
    get_domain_from_resource,
    get_domain_sid_from_user_sid,
)

logger = logging.getLogger(__name__)

# Azure SID pattern: GUID\GUID
AZURE_SID_RE = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
    r"\\[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)


def _get(row: dict[str, Any], key: str, default: str = "") -> str:
    """Safely get a string property from a WMI result row."""
    val = row.get(key)
    if val is None:
        return default
    return str(val)


def _get_obj(row: dict[str, Any], key: str) -> Any:
    """Get a raw property value (may be list, bool, None)."""
    return row.get(key)


class WMICollector:
    """Port of C# SCCMCollector. Queries SMS_R_System, SMS_R_User, SMS_R_UserGroup, SMS_CombinedDeviceResources."""

    def __init__(self, connector: WMIConnector):
        self.connector = connector

    def query_computers(self) -> list[BHComputer]:
        """SELECT * FROM SMS_R_System"""
        results = self.connector.exec_query("SELECT * FROM SMS_R_System")
        computers: list[BHComputer] = []

        for row in results:
            try:
                sid = _get(row, "SID")
                if not sid:
                    continue

                comp = BHComputer(object_identifier=sid)

                # Domain resolution fallback chain: FullDomainName → DN → ResourceNames
                domain = _get(row, "FullDomainName")
                if not domain:
                    dn = _get(row, "DistinguishedName")
                    if dn:
                        domain = convert_ldap_to_domain(dn)
                    else:
                        resource_names = _get_obj(row, "ResourceNames")
                        netbios_name = _get(row, "NetbiosName")
                        if resource_names and netbios_name:
                            resource_name = resource_names[0] if isinstance(resource_names, list) else str(resource_names)
                            domain = get_domain_from_resource(resource_name, netbios_name)

                if domain:
                    comp.properties["domain"] = domain.upper()

                name = _get(row, "Name")
                if name:
                    comp.properties["name"] = f"{name}.{domain}".upper()
                    comp.properties["sccmName"] = name

                dn = _get(row, "DistinguishedName")
                if dn:
                    comp.properties["distinguishedname"] = dn

                comp.properties["domainsid"] = get_domain_sid_from_user_sid(sid)

                netbios = _get(row, "NetbiosName")
                if netbios:
                    comp.properties["samaccountname"] = netbios + "$"

                primary_gid = _get(row, "PrimaryGroupID")
                if primary_gid:
                    comp.primary_group_sid = f"{get_domain_sid_from_user_sid(sid)}-{primary_gid}"

                os_name = _get(row, "OperatingSystemNameandVersion")
                if os_name:
                    comp.properties["operatingsystem"] = os_name

                # SCCM-specific properties
                comp.properties["sccmActive"] = bool(_get_obj(row, "Active"))
                ad_site = _get(row, "ADSiteName")
                if ad_site:
                    comp.properties["sccmADSiteName"] = ad_site
                comp.properties["sccmClient"] = bool(_get_obj(row, "Client"))
                comp.properties["sccmDecomissioned"] = bool(_get_obj(row, "Decomissioned"))

                ip_addresses = _get_obj(row, "IPAddresses")
                if ip_addresses:
                    comp.properties["sccmIPAddresses"] = list(ip_addresses) if not isinstance(ip_addresses, list) else ip_addresses

                last_logon_domain = _get(row, "LastLogonUserDomain")
                if last_logon_domain:
                    comp.properties["sccmLastLogonUserDomain"] = last_logon_domain

                last_logon_user = _get(row, "LastLogonUserName")
                if last_logon_user:
                    comp.properties["sccmLastLogonUserName"] = last_logon_user

                last_logon_ts = _get(row, "LastLogonTimestamp")
                if last_logon_ts:
                    comp.properties["sccmLastLogonTimestamp"] = last_logon_ts

                resource_domain = _get(row, "ResourceDomainORWorkgroup")
                if resource_domain:
                    comp.properties["sccmResourceDomainORWorkgroup"] = resource_domain

                for arr_prop in ("SystemContainerName", "SystemGroupName", "SystemRoles", "ResourceNames"):
                    val = _get_obj(row, arr_prop)
                    if val is not None:
                        comp.properties[f"sccm{arr_prop}"] = list(val) if not isinstance(val, list) else val

                uac = _get(row, "UserAccountControl")
                if uac:
                    comp.properties["sccmUserAccountControl"] = uac

                resource_id = _get(row, "ResourceID")
                if resource_id:
                    comp.properties["sccmResourceID"] = resource_id

                computers.append(comp)
            except Exception:
                logger.debug("Error processing computer record", exc_info=True)

        logger.info("Collected %d computers", len(computers))
        return computers

    def query_users(self) -> list[BHUser]:
        """SELECT * FROM SMS_R_User"""
        results = self.connector.exec_query("SELECT * FROM SMS_R_User")
        users: list[BHUser] = []

        for row in results:
            try:
                sid = _get(row, "SID")
                if not sid:
                    continue

                # Skip Azure SID objects
                if AZURE_SID_RE.match(sid):
                    logger.debug("Skipping Azure object: %s", sid)
                    continue

                unique_user_name = _get(row, "UniqueUserName")
                # Skip computer accounts
                if unique_user_name.endswith("$"):
                    continue

                user = BHUser(object_identifier=sid)

                if unique_user_name:
                    user.properties["sccmUniqueUserName"] = unique_user_name

                upn = _get(row, "UserPrincipalName")
                domain = _get(row, "FullDomainName")
                if not domain:
                    # Extract domain from UPN
                    match = re.search(r"(?<=@)(.?)*", upn)
                    domain = match.group(0) if match else ""
                else:
                    user.properties["domain"] = domain.upper()

                if upn and "onmicrosoft.com" in upn.lower():
                    user.properties["sccmMicrosoftAccountName"] = upn.upper()

                # Build name from UniqueUserName: strip netbios prefix
                name_match = re.search(r"(?<=\\)(.?)*", unique_user_name)
                name_part = name_match.group(0) if name_match else unique_user_name
                user.properties["name"] = f"{name_part}@{domain}".upper()

                dn = _get(row, "DistinguishedName")
                if dn:
                    user.properties["distinguishedname"] = dn.upper()

                user.properties["domainsid"] = get_domain_sid_from_user_sid(sid)

                display_name = _get(row, "FullUserName")
                if display_name:
                    user.properties["displayname"] = display_name

                email = _get(row, "Mail")
                if email:
                    user.properties["email"] = email

                primary_gid = _get(row, "PrimaryGroupID")
                if primary_gid:
                    user.primary_group_sid = f"{get_domain_sid_from_user_sid(sid)}-{primary_gid}"

                # SCCM-specific properties
                creation_date = _get(row, "CreationDate")
                if creation_date:
                    user.properties["sccmCreationDate"] = creation_date

                for arr_prop in ("AgentName", "AgentSite", "AgentTime", "UserContainerName", "UserGroupName"):
                    val = _get_obj(row, arr_prop)
                    if val is not None:
                        user.properties[f"sccm{arr_prop}"] = list(val) if not isinstance(val, list) else val

                uac = _get(row, "UserAccountControl")
                if uac:
                    user.properties["sccmUserAccountControl"] = uac

                resource_id = _get(row, "ResourceID")
                if resource_id:
                    user.properties["sccmResourceID"] = resource_id

                users.append(user)
            except Exception:
                logger.debug("Error processing user record", exc_info=True)

        logger.info("Collected %d users", len(users))
        return users

    def query_groups(self) -> list[BHGroup]:
        """SELECT * FROM SMS_R_UserGroup"""
        results = self.connector.exec_query("SELECT * FROM SMS_R_UserGroup")
        groups: list[BHGroup] = []

        for row in results:
            try:
                sid = _get(row, "SID")
                if not sid:
                    continue

                group = BHGroup(object_identifier=sid)
                domain = _get(row, "ADDomainName").upper()
                if domain:
                    group.properties["domain"] = domain

                group.properties["domainsid"] = get_domain_sid_from_user_sid(sid)

                name = _get(row, "UniqueUsergroupName")
                if name and "\\" in name:
                    group.properties["name"] = f"{name.split(chr(92))[1].upper()}@{domain.upper()}"

                groups.append(group)
            except Exception:
                logger.debug("Error processing group record", exc_info=True)

        logger.info("Collected %d groups", len(groups))
        return groups

    def query_user_machine_relationships(self) -> list[UserMachineRelationship]:
        """SELECT * FROM SMS_CombinedDeviceResources WHERE CurrentLogonUser IS NOT NULL"""
        results = self.connector.exec_query(
            "SELECT * FROM SMS_CombinedDeviceResources WHERE CurrentLogonUser IS NOT NULL"
        )
        relationships: list[UserMachineRelationship] = []

        for row in results:
            try:
                resource_name = _get(row, "Name")
                current_user = _get(row, "CurrentLogonUser")
                if resource_name and current_user:
                    relationships.append(UserMachineRelationship(resource_name, current_user))
            except Exception:
                logger.debug("Error processing relationship record", exc_info=True)

        logger.info("Collected %d user-machine relationships", len(relationships))
        return relationships
