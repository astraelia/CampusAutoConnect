"""Explicit local Windows checks; safe summary only, never campus authentication."""

import argparse
import json
import platform
import sys
import uuid

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials
from campus_autoconnect.core.network import WindowsNetworkProvider
from campus_autoconnect.security.credentials import WindowsCredentialStore
from campus_autoconnect.services.connectivity import ConnectivityService


def main() -> int:
    parser = argparse.ArgumentParser(description="本机 Windows 检查，不发送校园网认证")
    parser.add_argument(
        "--credential-smoke", action="store_true", help="写入、更新、删除随机引用的虚构凭据"
    )
    parser.add_argument(
        "--connectivity-smoke", action="store_true", help="执行不含凭据的默认互联网探测"
    )
    args = parser.parse_args()
    report = {
        "kind": "windows_host_smoke_no_campus_login",
        "python": platform.python_version(),
        "windows": platform.version(),
    }
    failed = False
    try:
        network = WindowsNetworkProvider().snapshot()
        report["network"] = {
            "connected": network.connected,
            "adapter_count": len(network.adapters),
            "ssid_detected": network.ssid is not None,
            "warnings": network.warnings,
            "has_ipv4": any(a.ipv4 for a in network.adapters),
            "has_ipv6": any(a.ipv6 for a in network.adapters),
            "has_gateway": any(a.gateways for a in network.adapters),
            "has_dns": any(a.dns for a in network.adapters),
        }
    except CampusError as exc:
        report["network"] = {"error_code": exc.code.value}
        failed = True
    if args.connectivity_smoke:
        connection = ConnectivityService().check()
        report["connectivity"] = {
            "online": connection.online,
            "code": connection.code.value,
            "portal_discovered": connection.portal_url is not None,
            "observations": [
                {"expected": item.expected, "reachable": item.reachable, "code": item.code.value}
                for item in connection.observations
            ],
        }
    if args.credential_smoke:
        store = WindowsCredentialStore()
        reference = "m1-smoke-" + uuid.uuid4().hex
        result = {
            "backend": "WindowsCredentialStore",
            "created": False,
            "updated": False,
            "deleted": False,
        }
        try:
            store.set(reference, Credentials("synthetic-smoke-user", "synthetic-smoke-password"))
            result["created"] = store.get(reference) == Credentials(
                "synthetic-smoke-user", "synthetic-smoke-password"
            )
            store.set(
                reference, Credentials("synthetic-smoke-update", "synthetic-smoke-password-2")
            )
            result["updated"] = store.get(reference) == Credentials(
                "synthetic-smoke-update", "synthetic-smoke-password-2"
            )
        except CampusError as exc:
            result["error_code"] = exc.code.value
            failed = True
        finally:
            try:
                store.delete(reference)
                result["deleted"] = not store.exists(reference)
            except CampusError as exc:
                result["cleanup_error"] = exc.code.value
                failed = True
        report["credentials"] = result
        if not all(result.get(key) for key in ("created", "updated", "deleted")):
            failed = True
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
