"""ArsGoatia CLI — command-line interface for assessment management."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arsgoatia", description="ArsGoatia CLI")
    sub = parser.add_subparsers(dest="command")

    create_p = sub.add_parser("create", help="Create a new assessment")
    create_p.add_argument("--name", required=True)
    create_p.add_argument("--scope", required=True, help="Target scope (e.g., juice-shop:3000)")

    status_p = sub.add_parser("status", help="Get assessment status")
    status_p.add_argument("assessment_id")

    sub.add_parser("list", help="List assessments")

    stop_p = sub.add_parser("stop", help="Emergency stop")
    stop_p.add_argument("assessment_id")
    stop_p.add_argument("--reason", required=True)

    approve_p = sub.add_parser("approve", help="Approve a pending action")
    approve_p.add_argument("action_id")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    print(f"[stub] {args.command} — not yet connected to API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
