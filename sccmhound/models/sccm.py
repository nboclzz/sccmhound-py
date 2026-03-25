"""Internal SCCM data models (not serialized to BloodHound JSON directly)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserMachineRelationship:
    """Maps a computer resource to a logged-on user. Populated from SMS_CombinedDeviceResources."""

    resource_name: str = ""
    unique_user_name: str = ""  # DOMAIN\username format


@dataclass
class LocalAdmin:
    """A local administrator entry from CMPivot Administrators query."""

    type: str = ""  # "User" or "Group"
    name: str = ""  # DOMAIN\name
    device_name: str = ""
