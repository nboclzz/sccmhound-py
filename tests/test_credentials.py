"""Tests for auth/credentials.py."""

from sccmhound.auth.credentials import AuthMethod, Credentials


def test_password_auth():
    cred = Credentials(username="admin", password="pass", domain="CORP")
    assert cred.auth_method == AuthMethod.PASSWORD


def test_hash_auth():
    cred = Credentials(username="admin", domain="CORP", ntlm_hash="aad3b435b51404ee:e0fb1fb85756ce429227d5b380fcef18")
    assert cred.auth_method == AuthMethod.NTLM_HASH
    assert cred.lm_hash == "aad3b435b51404ee"
    assert cred.nt_hash == "e0fb1fb85756ce429227d5b380fcef18"


def test_hash_auth_nt_only():
    cred = Credentials(username="admin", domain="CORP", ntlm_hash=":e0fb1fb85756ce429227d5b380fcef18")
    assert cred.auth_method == AuthMethod.NTLM_HASH
    assert cred.lm_hash == ""
    assert cred.nt_hash == "e0fb1fb85756ce429227d5b380fcef18"


def test_kerberos_auth():
    cred = Credentials(username="admin", domain="CORP", kerberos=True)
    assert cred.auth_method == AuthMethod.KERBEROS


def test_ccache_auth():
    cred = Credentials(ccache="/tmp/krb5cc_1000")
    assert cred.auth_method == AuthMethod.CCACHE
