"""Tests for resolver modules."""

from sccmhound.resolvers.domains import resolve_domains
from sccmhound.resolvers.local_admins import resolve_local_admins
from sccmhound.resolvers.sessions import resolve_sessions
from sccmhound.resolvers.users_groups import resolve_users_groups


def test_resolve_domains(sample_users, sample_computers, sample_groups):
    domains = resolve_domains(sample_users, sample_computers, sample_groups)
    assert len(domains) == 1
    assert domains[0].object_identifier == "S-1-5-21-1234-5678-9012"
    assert domains[0].properties["name"] == "CORP.LOCAL"
    assert domains[0].properties["highvalue"] is True


def test_resolve_users_groups(sample_users, sample_groups):
    resolve_users_groups(sample_users, sample_groups)
    # Domain Users group should have both users as members
    domain_users = sample_groups[0]
    assert len(domain_users.members) == 2

    # IT Admins group should have only jsmith
    it_admins = sample_groups[1]
    assert len(it_admins.members) == 1
    assert it_admins.members[0]["ObjectIdentifier"] == "S-1-5-21-1234-5678-9012-1001"

    # sccmUserGroupName should be removed from user properties
    assert "sccmUserGroupName" not in sample_users[0].properties


def test_resolve_sessions(sample_computers, sample_users, sample_relationships, sample_domains):
    resolve_sessions(sample_computers, sample_users, sample_relationships, sample_domains)

    # WS01 should have sessions with jsmith and jdoe
    ws01 = sample_computers[0]
    assert ws01.sessions["Collected"] is True
    assert len(ws01.sessions["Results"]) == 2

    # WS02 should have session with jdoe
    ws02 = sample_computers[1]
    assert ws02.sessions["Collected"] is True
    assert len(ws02.sessions["Results"]) == 1


def test_resolve_local_admins(sample_computers, sample_groups, sample_users, sample_local_admins, sample_domains):
    resolve_local_admins(sample_computers, sample_groups, sample_users, sample_local_admins, sample_domains)

    # WS01 should have jsmith (User) and IT Admins (Group) as local admins
    ws01 = sample_computers[0]
    assert ws01.local_admins["Collected"] is True
    results = ws01.local_admins["Results"]
    assert len(results) == 2

    # WS02 should have jdoe as local admin
    ws02 = sample_computers[1]
    assert ws02.local_admins["Collected"] is True
    assert len(ws02.local_admins["Results"]) == 1
