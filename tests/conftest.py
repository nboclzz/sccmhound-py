"""Shared test fixtures."""

import pytest

from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser
from sccmhound.models.sccm import LocalAdmin, UserMachineRelationship


@pytest.fixture
def sample_users():
    u1 = BHUser(object_identifier="S-1-5-21-1234-5678-9012-1001")
    u1.properties = {
        "name": "JSMITH@CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
        "distinguishedname": "CN=JSMITH,OU=USERS,DC=CORP,DC=LOCAL",
        "sccmUniqueUserName": "CORP\\jsmith",
        "sccmUserGroupName": ["CORP\\Domain Users", "CORP\\IT Admins"],
    }
    u1.primary_group_sid = "S-1-5-21-1234-5678-9012-513"

    u2 = BHUser(object_identifier="S-1-5-21-1234-5678-9012-1002")
    u2.properties = {
        "name": "JDOE@CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
        "distinguishedname": "CN=JDOE,OU=USERS,DC=CORP,DC=LOCAL",
        "sccmUniqueUserName": "CORP\\jdoe",
        "sccmUserGroupName": ["CORP\\Domain Users"],
    }
    return [u1, u2]


@pytest.fixture
def sample_computers():
    c1 = BHComputer(object_identifier="S-1-5-21-1234-5678-9012-2001")
    c1.properties = {
        "name": "WS01.CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
        "distinguishedname": "CN=WS01,OU=COMPUTERS,DC=CORP,DC=LOCAL",
        "sccmName": "WS01",
        "sccmResourceDomainORWorkgroup": "CORP",
    }

    c2 = BHComputer(object_identifier="S-1-5-21-1234-5678-9012-2002")
    c2.properties = {
        "name": "WS02.CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
        "distinguishedname": "CN=WS02,OU=COMPUTERS,DC=CORP,DC=LOCAL",
        "sccmName": "WS02",
        "sccmResourceDomainORWorkgroup": "CORP",
    }
    return [c1, c2]


@pytest.fixture
def sample_groups():
    g1 = BHGroup(object_identifier="S-1-5-21-1234-5678-9012-513")
    g1.properties = {
        "name": "DOMAIN USERS@CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
    }

    g2 = BHGroup(object_identifier="S-1-5-21-1234-5678-9012-3001")
    g2.properties = {
        "name": "IT ADMINS@CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
    }
    return [g1, g2]


@pytest.fixture
def sample_domains():
    d = BHDomain(object_identifier="S-1-5-21-1234-5678-9012")
    d.properties = {
        "name": "CORP.LOCAL",
        "domain": "CORP.LOCAL",
        "domainsid": "S-1-5-21-1234-5678-9012",
        "netbios": "CORP",
        "highvalue": True,
        "distinguishedname": "DC=CORP,DC=LOCAL",
    }
    return [d]


@pytest.fixture
def sample_relationships():
    return [
        UserMachineRelationship("WS01", "CORP\\jsmith"),
        UserMachineRelationship("WS02", "CORP\\jdoe"),
        UserMachineRelationship("WS01", "CORP\\jdoe"),
    ]


@pytest.fixture
def sample_local_admins():
    return [
        LocalAdmin(type="User", name="CORP\\jsmith", device_name="WS01"),
        LocalAdmin(type="Group", name="CORP\\IT Admins", device_name="WS01"),
        LocalAdmin(type="User", name="CORP\\jdoe", device_name="WS02"),
    ]
