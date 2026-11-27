from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode


def request_json(
    url: str, payload: dict[str, Any] | None = None, timeout_seconds: int = 10
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"detail": body}
        return error.code, parsed


def wait_for_error_metric(prometheus_url: str, orders_url: str, timeout_seconds: int = 90) -> None:
    query = 'service:error_ratio:rate5m{service="inventory"}'
    url = f"{prometheus_url.rstrip('/')}/api/v1/query?{urlencode({'query': query})}"
    deadline = time.monotonic() + timeout_seconds
    last_error = "no error-ratio sample is available yet"
    next_failure_at = time.monotonic()
    while time.monotonic() < deadline:
        if time.monotonic() >= next_failure_at:
            status, body = request_json(
                f"{orders_url}/orders",
                {"item_id": "demo-item", "quantity": 1},
            )
            if status != 502:
                raise SystemExit(f"Expected another injected HTTP 502; received {status}: {body}")
            next_failure_at = time.monotonic() + 5

        try:
            status, body = request_json(url)
        except urllib.error.URLError as error:
            last_error = str(error)
        else:
            data = body.get("data")
            results = data.get("result", []) if isinstance(data, dict) else []
            try:
                has_error_sample = bool(results) and float(results[0]["value"][1]) > 0
            except (IndexError, KeyError, TypeError, ValueError):
                has_error_sample = False
            if status == 200 and has_error_sample:
                print("Prometheus has recorded the injected inventory errors.")
                return
            last_error = str(body.get("error", "no error-ratio sample is available yet"))
        time.sleep(3)
    raise SystemExit(f"Timed out waiting for Prometheus error metrics: {last_error}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trigger a service failure and run incident analysis."
    )
    parser.add_argument("--orders-url", default="http://localhost:8001")
    parser.add_argument("--inventory-url", default="http://localhost:8003")
    parser.add_argument("--incident-url", default="http://localhost:8000")
    parser.add_argument("--prometheus-url", default="http://localhost:9090")
    args = parser.parse_args()

    status, body = request_json(
        f"{args.inventory_url}/chaos",
        {"mode": "error", "ttl_seconds": 120},
    )
    if status != 200:
        raise SystemExit(f"Could not enable inventory chaos ({status}): {body}")
    print("Enabled a bounded inventory error injection.")

    status, body = request_json(
        f"{args.orders_url}/orders",
        {"item_id": "demo-item", "quantity": 1},
    )
    if status != 502:
        raise SystemExit(f"Expected orders to return HTTP 502; received {status}: {body}")
    print("Triggered the failure: orders returned HTTP 502 after inventory failed.")
    started_at = datetime.now(UTC).isoformat()
    try:
        wait_for_error_metric(args.prometheus_url, args.orders_url)
    finally:
        status, body = request_json(f"{args.inventory_url}/chaos", {"mode": "off"})
        if status != 200:
            raise SystemExit(f"Could not disable inventory chaos ({status}): {body}")

    fingerprint = f"demo-{int(time.time())}"
    alert = {
        "status": "firing",
        "receiver": "incident-commander",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "DemoInventoryFailure",
                    "service": "inventory",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Inventory errors triggered by the demo",
                    "description": "A bounded chaos error caused orders to fail.",
                },
                "startsAt": started_at,
                "fingerprint": fingerprint,
            }
        ],
        "commonLabels": {"service": "inventory"},
    }
    status, analysis = request_json(f"{args.incident_url}/alerts", alert, timeout_seconds=45)
    if status != 200:
        raise SystemExit(f"Incident analysis failed ({status}): {analysis}")
    print(json.dumps(analysis, indent=2))

    alert["status"] = "resolved"
    alert["alerts"][0]["status"] = "resolved"
    alert["alerts"][0]["endsAt"] = datetime.now(UTC).isoformat()
    status, resolved = request_json(f"{args.incident_url}/alerts", alert)
    if status != 200:
        raise SystemExit(f"Postmortem generation failed ({status}): {resolved}")
    print(json.dumps(resolved, indent=2))
    print("Review the generated markdown and audit log under ./artifacts.")


if __name__ == "__main__":
    main()
