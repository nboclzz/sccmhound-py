"""BloodHound v5 output model dataclasses.

Replaces the SharpHoundCommonLib.OutputTypes dependency (Computer, User, Group, Domain, Session, etc.)
with standalone Python dataclasses that serialize to the exact BloodHound JSON schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _empty_api_result() -> dict[str, Any]:
    return {"Collected": False, "FailureReason": None, "Results": []}


@dataclass
class BHComputer:
    object_identifier: str = ""
    primary_group_sid: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    sessions: dict[str, Any] = field(default_factory=_empty_api_result)
    privileged_sessions: dict[str, Any] = field(default_factory=_empty_api_result)
    registry_sessions: dict[str, Any] = field(default_factory=_empty_api_result)
    local_admins: dict[str, Any] = field(default_factory=_empty_api_result)
    remote_desktop_users: dict[str, Any] = field(default_factory=_empty_api_result)
    dcom_users: dict[str, Any] = field(default_factory=_empty_api_result)
    ps_remote_users: dict[str, Any] = field(default_factory=_empty_api_result)
    allowed_to_delegate: list[dict[str, str]] = field(default_factory=list)
    allowed_to_act: list[dict[str, str]] = field(default_factory=list)
    aces: list[dict[str, Any]] = field(default_factory=list)
    has_sid_history: list[dict[str, str]] = field(default_factory=list)
    is_deleted: bool = False
    status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ObjectIdentifier": self.object_identifier,
            "PrimaryGroupSID": self.primary_group_sid,
            "Properties": self.properties,
            "Sessions": self.sessions,
            "PrivilegedSessions": self.privileged_sessions,
            "RegistrySessions": self.registry_sessions,
            "LocalAdmins": self.local_admins,
            "RemoteDesktopUsers": self.remote_desktop_users,
            "DcomUsers": self.dcom_users,
            "PSRemoteUsers": self.ps_remote_users,
            "AllowedToDelegate": self.allowed_to_delegate,
            "AllowedToAct": self.allowed_to_act,
            "Aces": self.aces,
            "HasSIDHistory": self.has_sid_history,
            "IsDeleted": self.is_deleted,
            "Status": self.status,
        }


@dataclass
class BHUser:
    object_identifier: str = ""
    primary_group_sid: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    allowed_to_delegate: list[dict[str, str]] = field(default_factory=list)
    spn_targets: list[dict[str, str]] = field(default_factory=list)
    aces: list[dict[str, Any]] = field(default_factory=list)
    has_sid_history: list[dict[str, str]] = field(default_factory=list)
    is_deleted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ObjectIdentifier": self.object_identifier,
            "PrimaryGroupSID": self.primary_group_sid,
            "Properties": self.properties,
            "AllowedToDelegate": self.allowed_to_delegate,
            "SPNTargets": self.spn_targets,
            "Aces": self.aces,
            "HasSIDHistory": self.has_sid_history,
            "IsDeleted": self.is_deleted,
        }


@dataclass
class BHGroup:
    object_identifier: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    members: list[dict[str, str]] = field(default_factory=list)
    aces: list[dict[str, Any]] = field(default_factory=list)
    is_deleted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ObjectIdentifier": self.object_identifier,
            "Properties": self.properties,
            "Members": self.members,
            "Aces": self.aces,
            "IsDeleted": self.is_deleted,
        }


@dataclass
class BHDomain:
    object_identifier: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    trusts: list[dict[str, Any]] = field(default_factory=list)
    child_objects: list[dict[str, str]] = field(default_factory=list)
    links: list[dict[str, Any]] = field(default_factory=list)
    gpo_changes: dict[str, list] = field(default_factory=lambda: {
        "AffectedComputers": [],
        "DcomUsers": [],
        "LocalAdmins": [],
        "PSRemoteUsers": [],
        "RemoteDesktopUsers": [],
    })
    aces: list[dict[str, Any]] = field(default_factory=list)
    is_deleted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ObjectIdentifier": self.object_identifier,
            "Properties": self.properties,
            "Trusts": self.trusts,
            "ChildObjects": self.child_objects,
            "Links": self.links,
            "GPOChanges": self.gpo_changes,
            "Aces": self.aces,
            "IsDeleted": self.is_deleted,
        }
