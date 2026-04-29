"""Target validation service"""

import ipaddress
import re
from typing import Any


class TargetValidator:
    IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
    DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    URL_RE = re.compile(r'^https?://')

    @classmethod
    def validate(cls, target: str) -> dict[str, Any]:
        """Validate and classify a scan target."""
        target = target.strip()

        if cls.IP_RE.match(target):
            try:
                net = ipaddress.ip_network(target, strict=False)
                return {
                    "valid": True,
                    "normalized": target,
                    "type": "ip",
                    "is_external": not net.is_private,
                }
            except ValueError:
                return {"valid": False, "error": f"Invalid IP: {target}"}

        if cls.URL_RE.match(target):
            host = target.split("//")[1].split("/")[0].split(":")[0]
            if not host:
                return {"valid": False, "error": f"Invalid target: {target}"}
            return {
                "valid": True,
                "normalized": target,
                "type": "url",
                "is_external": True,
            }

        if cls.DOMAIN_RE.match(target):
            return {
                "valid": True,
                "normalized": target.lower(),
                "type": "domain",
                "is_external": True,
            }

        return {"valid": False, "error": f"Invalid target: {target}"}
