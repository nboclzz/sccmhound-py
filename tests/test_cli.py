"""Tests for CLI argument parsing."""

from sccmhound.cli import build_parser


def test_required_args():
    parser = build_parser()
    args = parser.parse_args(["--server", "sccm01", "--sitecode", "PS1"])
    assert args.server == "sccm01"
    assert args.sitecode == "PS1"
    assert args.collectionmethods == "Default"
    assert args.loop is False
    assert args.hc is False


def test_all_args():
    parser = build_parser()
    args = parser.parse_args([
        "--server", "sccm01", "--sitecode", "PS1",
        "-c", "All", "--loop", "--loopduration", "01:00:00", "--loopsleep", "120",
        "-u", "admin", "-p", "password", "-d", "CORP",
        "-v", "--check-epa", "--sql-server", "db01", "--sql-port", "1433",
        "-o", "/tmp/output",
    ])
    assert args.collectionmethods == "All"
    assert args.loop is True
    assert args.loopduration == "01:00:00"
    assert args.loopsleep == 120
    assert args.username == "admin"
    assert args.check_epa is True
    assert args.sql_server == "db01"
    assert args.output_dir == "/tmp/output"


def test_hash_auth_flag():
    parser = build_parser()
    args = parser.parse_args([
        "--server", "s", "--sitecode", "c",
        "-H", ":e0fb1fb85756ce429227d5b380fcef18",
    ])
    assert args.ntlm_hash == ":e0fb1fb85756ce429227d5b380fcef18"


def test_kerberos_flag():
    parser = build_parser()
    args = parser.parse_args(["--server", "s", "--sitecode", "c", "-k", "--dc-ip", "10.0.0.1"])
    assert args.kerberos is True
    assert args.dc_ip == "10.0.0.1"
