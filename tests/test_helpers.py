"""Tests for utils/helpers.py — ported from tests/HelperUtilitiesTests.cs."""

from sccmhound.utils.helpers import (
    convert_ldap_to_domain,
    create_lookup_table_computers,
    create_lookup_table_groups,
    create_lookup_table_users,
    get_domain_from_resource,
    get_domain_sid_from_user_sid,
    lookup_netbios_return_fqdn,
)


def test_get_domain_sid_from_user_sid():
    assert get_domain_sid_from_user_sid("S-1-5-21-1234-5678-9012-1001") == "S-1-5-21-1234-5678-9012"


def test_get_domain_sid_empty():
    assert get_domain_sid_from_user_sid("") == ""


def test_convert_ldap_to_domain():
    assert convert_ldap_to_domain("CN=foo,OU=bar,DC=corp,DC=local") == "corp.local"


def test_convert_ldap_to_domain_empty():
    assert convert_ldap_to_domain("") == ""


def test_convert_ldap_single_dc():
    assert convert_ldap_to_domain("DC=example") == "example"


def test_get_domain_from_resource():
    assert get_domain_from_resource("WS01.corp.local", "WS01") == "corp.local"


def test_get_domain_from_resource_no_match():
    assert get_domain_from_resource("SERVER01.other.com", "WORKSTATION") == ""


def test_get_domain_from_resource_empty():
    assert get_domain_from_resource("", "WS01") == ""
    assert get_domain_from_resource("WS01.corp.local", "") == ""
    assert get_domain_from_resource(None, None) == ""


def test_lookup_netbios_return_fqdn(sample_domains):
    assert lookup_netbios_return_fqdn("CORP", sample_domains) == "CORP.LOCAL"


def test_lookup_netbios_not_found(sample_domains):
    assert lookup_netbios_return_fqdn("UNKNOWN", sample_domains) == "UNKNOWN"


def test_create_lookup_table_users(sample_users):
    table = create_lookup_table_users(sample_users)
    assert "corp\\jsmith" in table
    assert "corp\\jdoe" in table
    assert table["corp\\jsmith"].object_identifier == "S-1-5-21-1234-5678-9012-1001"


def test_create_lookup_table_groups(sample_groups):
    table = create_lookup_table_groups(sample_groups)
    assert "domain users@corp.local" in table
    assert "it admins@corp.local" in table


def test_create_lookup_table_computers(sample_computers):
    table = create_lookup_table_computers(sample_computers)
    assert "WS01" in table
    assert "WS02" in table
