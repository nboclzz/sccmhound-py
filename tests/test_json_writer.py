"""Tests for JSON writer output format."""

import json
import os
import tempfile

from sccmhound.models.bloodhound import BHComputer, BHDomain, BHGroup, BHUser
from sccmhound.output.json_writer import write_computers, write_domains, write_groups, write_users


def test_write_computers_format(sample_computers):
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = write_computers(sample_computers, tmpdir)
        assert os.path.exists(filepath)

        with open(filepath) as f:
            data = json.load(f)

        assert "data" in data
        assert "meta" in data
        assert data["meta"]["type"] == "computers"
        assert data["meta"]["count"] == 2
        assert data["meta"]["version"] == 5
        assert len(data["data"]) == 2
        assert "ObjectIdentifier" in data["data"][0]


def test_write_users_format(sample_users):
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = write_users(sample_users, tmpdir)

        with open(filepath) as f:
            data = json.load(f)

        assert data["meta"]["type"] == "users"
        assert data["meta"]["count"] == 2


def test_write_groups_format(sample_groups):
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = write_groups(sample_groups, tmpdir)

        with open(filepath) as f:
            data = json.load(f)

        assert data["meta"]["type"] == "groups"


def test_write_domains_format(sample_domains):
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = write_domains(sample_domains, tmpdir)

        with open(filepath) as f:
            data = json.load(f)

        assert data["meta"]["type"] == "domains"
        assert data["data"][0]["Properties"]["highvalue"] is True
