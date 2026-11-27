from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import quote

import requests


def _show_report(incident_id: str, base_url: str) -> None:
    if not incident_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for character in incident_id
    ):
        raise SystemExit("incident_id may contain only letters, numbers, underscores, and hyphens.")
    response = requests.get(
        f"{base_url.rstrip('/')}/incidents/{quote(incident_id, safe='')}/report",
        timeout=30,
    )
    response.raise_for_status()
    print(response.text, end="")


def _request_runbook(args: argparse.Namespace) -> None:
    if args.action == "scale" and args.replicas is None:
        raise SystemExit("--replicas is required for scale")
    if args.action != "scale" and args.replicas is not None:
        raise SystemExit("--replicas can only be used with scale")
    confirmation = input(
        f"Type APPROVE to {args.action} {args.service}"
        + (f" to {args.replicas} replicas" if args.replicas else "")
        + ": "
    )
    if confirmation != "APPROVE":
        print("No action requested; approval was not confirmed.", file=sys.stderr)
        raise SystemExit(2)
    token = os.getenv("APPROVAL_TOKEN", "")
    if not token:
        raise SystemExit("Set APPROVAL_TOKEN before submitting a runbook action.")
    response = requests.post(
        f"{args.url.rstrip('/')}/approvals/{args.action}",
        headers={"X-Approval-Token": token},
        json={
            "approved": True,
            "approver": args.approver,
            "service": args.service,
            "replicas": args.replicas,
        },
        timeout=30,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show incident reports or request a human-approved runbook action."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="Print a completed incident investigation report")
    show.add_argument("incident_id")
    show.add_argument("--url", default="http://localhost:8000")

    for action in ("restart", "scale", "rollback"):
        runbook = commands.add_parser(action, help=f"Request a human-approved {action}")
        runbook.add_argument("service", choices=["orders", "payments", "inventory"])
        runbook.add_argument("--approver", required=True, help="Name recorded in the audit log")
        runbook.add_argument("--replicas", type=int, help="Required for scale (2-10)")
        runbook.add_argument(
            "--url", default="http://localhost:8000", help="Incident Commander base URL"
        )

    args = parser.parse_args()
    if args.command == "show":
        _show_report(args.incident_id, args.url)
    else:
        _request_runbook(args)


if __name__ == "__main__":
    main()
