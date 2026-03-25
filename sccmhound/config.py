"""Runtime configuration dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sccmhound.auth.credentials import Credentials


@dataclass
class Config:
    server: str = ""
    site_code: str = ""
    collection_methods: str = "Default"
    loop: bool = False
    loop_duration: str = "00:30:00"
    loop_sleep: int = 60
    health_check: bool = False
    credentials: Credentials = field(default_factory=Credentials)
    verbose: bool = False
    debug: bool = False
    output_dir: str = "."
    check_epa: bool = False
    sql_server: Optional[str] = None
    sql_port: int = 1433
