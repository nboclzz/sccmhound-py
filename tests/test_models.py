"""Tests for BloodHound model serialization."""

from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser


def test_user_to_dict():
    user = BHUser(object_identifier="S-1-5-21-111-222-333-1001")
    user.properties = {"name": "TEST@DOMAIN.COM", "domain": "DOMAIN.COM"}
    d = user.to_dict()
    assert d["ObjectIdentifier"] == "S-1-5-21-111-222-333-1001"
    assert d["Properties"]["name"] == "TEST@DOMAIN.COM"
    assert d["IsDeleted"] is False
    assert "AllowedToDelegate" in d
    assert "SPNTargets" in d


def test_computer_to_dict():
    comp = BHComputer(object_identifier="S-1-5-21-111-222-333-2001")
    comp.properties = {"name": "HOST.DOMAIN.COM"}
    d = comp.to_dict()
    assert d["ObjectIdentifier"] == "S-1-5-21-111-222-333-2001"
    assert d["Sessions"]["Collected"] is False
    assert d["LocalAdmins"]["Collected"] is False
    assert d["Status"] is None


def test_group_to_dict():
    group = BHGroup(object_identifier="S-1-5-21-111-222-333-512")
    group.properties = {"name": "DOMAIN ADMINS@DOMAIN.COM"}
    group.members = [{"ObjectIdentifier": "S-1-5-21-111-222-333-1001", "ObjectType": "User"}]
    d = group.to_dict()
    assert len(d["Members"]) == 1
    assert d["Members"][0]["ObjectType"] == "User"


def test_domain_to_dict():
    dom = BHDomain(object_identifier="S-1-5-21-111-222-333")
    dom.properties = {"name": "DOMAIN.COM", "highvalue": True}
    d = dom.to_dict()
    assert d["Properties"]["highvalue"] is True
    assert "GPOChanges" in d
    assert "Trusts" in d
