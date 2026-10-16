from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from huawei_tower.modem.api import ReadOnlyModemClient
from huawei_tower.modem.security import redact_secrets
from huawei_tower.modem.xmlutil import element_to_dict, parse_xml

DEFAULT_ENDPOINTS = [
    "/api/device/basic_information",
    "/api/net/current-plmn",
    "/api/monitoring/traffic-statistics",
    "/api/dialup/connection",
    "/api/dialup/mobile-dataswitch",
    "/api/pin/status",
    "/api/user/state-login",
    "/api/global/module-switch",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only H158-381 endpoint probe.")
    parser.add_argument("--base-url", default="https://192.168.70.1")
    parser.add_argument("--endpoint", action="append", dest="endpoints")
    parser.add_argument("--ca-bundle", help="Path to trusted CA bundle; TLS verification stays enabled.")
    args = parser.parse_args()

    client = ReadOnlyModemClient(args.base_url, verify_tls=args.ca_bundle or True)
    snapshot = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "read-only",
        "results": {},
    }
    try:
        for path in args.endpoints or DEFAULT_ENDPOINTS:
            response = client.get(path)
            body = response.text
            try:
                payload = element_to_dict(parse_xml(body))
            except Exception:
                payload = {"raw": redact_secrets(body)}
            snapshot["results"][path] = {
                "http_status": response.status_code,
                "payload": payload,
            }
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
