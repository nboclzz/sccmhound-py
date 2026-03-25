"""BloodHound v5 JSON file writer. Ported from src/JSONWriter.cs."""

from __future__ import annotations

import json
import os
import time
from typing import Any


def _write_file(objects: list, data_type: str, output_dir: str = ".", filename: str | None = None) -> str:
    if filename is None:
        ts = int(time.time() * 1000)
        filename = f"{data_type}-{ts}.json"

    filepath = os.path.join(output_dir, filename)

    envelope: dict[str, Any] = {
        "data": [obj.to_dict() for obj in objects],
        "meta": {
            "methods": 0,
            "type": data_type,
            "count": len(objects),
            "version": 5,
        },
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2, default=str)

    return filepath


def write_computers(computers: list, output_dir: str = ".") -> str:
    return _write_file(computers, "computers", output_dir)


def write_users(users: list, output_dir: str = ".") -> str:
    return _write_file(users, "users", output_dir)


def write_groups(groups: list, output_dir: str = ".") -> str:
    return _write_file(groups, "groups", output_dir)


def write_domains(domains: list, output_dir: str = ".") -> str:
    return _write_file(domains, "domains", output_dir)


def write_sessions(computers: list, output_dir: str = ".") -> str:
    """Write session loop output (computers with updated session data)."""
    ts = int(time.time() * 1000)
    return _write_file(computers, "computers", output_dir, filename=f"sessions-{ts}.json")
