"""NetGuard: Mini Network Access Policy Checker.

Run:
    python main.py
    python main.py data/requests.csv
"""

import csv
import sys
from pathlib import Path

from policy import AccessRequest, evaluate_request


DEFAULT_CSV_PATH = Path("data") / "requests.csv"


def load_requests(csv_path: Path) -> list[AccessRequest]:
    """Read device access requests from a CSV file."""

    requests: list[AccessRequest] = []

    with csv_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        for row_number, row in enumerate(reader, start=2):
            try:
                requests.append(
                    AccessRequest(
                        device_name=row["device_name"],
                        device_type=row["device_type"],
                        vlan=int(row["vlan"]),
                        source_ip=row["source_ip"],
                        destination=row["destination"],
                        port=int(row["port"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"Invalid CSV row {row_number}: {row}") from error

    return requests


def print_report(requests: list[AccessRequest]) -> None:
    """Print a clean allow/deny report for all requests."""

    print("NetGuard Access Policy Report")
    print("=" * 90)
    print(
        f"{'Device':<18} {'Type':<10} {'VLAN':<6} {'Source IP':<15} "
        f"{'Destination':<15} {'Port':<6} {'Result':<7} Reason"
    )
    print("-" * 90)

    for request in requests:
        decision = evaluate_request(request)
        print(
            f"{request.device_name:<18} {request.device_type:<10} {request.vlan:<6} "
            f"{request.source_ip:<15} {request.destination:<15} {request.port:<6} "
            f"{decision.status:<7} {decision.reason}"
        )


def main() -> int:
    """Program entry point."""

    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV_PATH

    if not csv_path.exists():
        print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
        return 1

    try:
        requests = load_requests(csv_path)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print_report(requests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
