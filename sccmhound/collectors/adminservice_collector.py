"""AdminService / CMPivot collector. Ported from src/AdminServiceCollector.cs."""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET

from sccmhound.connectors.adminservice import AdminServiceConnector
from sccmhound.models.sccm import LocalAdmin, UserMachineRelationship

logger = logging.getLogger(__name__)


class AdminServiceCollector:
    """Execute CMPivot queries via the SCCM AdminService REST API."""

    def __init__(self, connector: AdminServiceConnector):
        self.connector = connector

    def get_collections(self) -> bool:
        """Test access to SMS00001 collection."""
        resp = self.connector.get("Collections('SMS00001')")
        if resp.ok:
            return True
        if resp.status_code == 403:
            raise PermissionError(resp.reason)
        return False

    def submit_cmpivot_query(self, query: str) -> int:
        """Submit a CMPivot query to All Systems (SMS00001). Returns OperationId or negative error code."""
        logger.info("Executing CMPivot query '%s' on All Systems collection", query)
        resp = self.connector.post(
            "Collections('SMS00001')/AdminService.RunCMPivot",
            {"InputQuery": query},
        )
        if resp.ok:
            return int(resp.json()["OperationId"])
        if resp.status_code == 403:
            return -403
        return -1

    def retrieve_cmpivot_result(
        self, operation_id: int, sleep_seconds: int = 30, check_threshold: int = 3
    ) -> list[dict]:
        """Poll CMPivotStatus until results stabilize (count matches check_threshold consecutive times)."""
        logger.info("Retrieving CMPivot results for operation %d", operation_id)
        uri = f"SMS_CMPivotStatus?$filter=ClientOperationId eq {operation_id}"
        loop_count = 0
        results = None

        while loop_count < check_threshold:
            resp = self.connector.get(uri)
            if resp.ok:
                temp_results = resp.json().get("value", [])
                if results is not None:
                    logger.info("Retrieved %d results", len(results))
                    if len(results) == len(temp_results):
                        loop_count += 1
                else:
                    loop_count += 1
                results = temp_results
                time.sleep(sleep_seconds)

        return results or []

    def get_administrators(self) -> list[LocalAdmin]:
        """CMPivot 'Administrators' query — returns local admin entries per device."""
        job = self.submit_cmpivot_query("Administrators")
        if job == -403:
            raise PermissionError("Insufficient permissions to create CMPivot jobs")
        if job < 0:
            raise RuntimeError("Unknown error submitting CMPivot query")

        results = self.retrieve_cmpivot_result(job, 30, 3)
        local_admins: list[LocalAdmin] = []

        for result in results:
            device_name = result.get("DeviceName", "")
            xml_output = result.get("ScriptOutput", "")
            try:
                root = ET.fromstring(xml_output)
                for elem in root.iter("e"):
                    obj_class = elem.get("ObjectClass", "")
                    name = elem.get("Name", "")
                    local_admins.append(LocalAdmin(type=obj_class, name=name, device_name=device_name))
            except ET.ParseError:
                logger.debug("Could not parse XML for device %s", device_name)

        logger.info("Collected %d local admin entries", len(local_admins))
        return local_admins

    def get_users(self) -> list[UserMachineRelationship]:
        """CMPivot 'User' query — returns current sessions per device."""
        job = self.submit_cmpivot_query("User")
        if job == -403:
            raise PermissionError("Insufficient permissions to create CMPivot jobs")
        if job < 0:
            raise RuntimeError("Unknown error submitting CMPivot query")

        results = self.retrieve_cmpivot_result(job, 30, 3)
        relationships: list[UserMachineRelationship] = []

        for result in results:
            device_name = result.get("DeviceName", "")
            xml_output = result.get("ScriptOutput", "")
            try:
                root = ET.fromstring(xml_output)
                for elem in root.iter("e"):
                    username = elem.get("UserName", "")
                    if username:
                        relationships.append(UserMachineRelationship(device_name, username))
            except ET.ParseError:
                logger.debug("Could not parse XML for device %s", device_name)

        logger.info("Collected %d CMPivot user sessions", len(relationships))
        return relationships
