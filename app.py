"""Local Flask dashboard for NetGuard access policy results."""

from pathlib import Path

from flask import Flask, jsonify, render_template, request

from main import DEFAULT_CSV_PATH, load_requests
from policy import AccessRequest, evaluate_request


app = Flask(__name__)


def request_to_row(access_request: AccessRequest) -> dict:
    """Convert one policy check into a dictionary for HTML and JSON output."""

    decision = evaluate_request(access_request)
    return {
        "device_name": access_request.device_name,
        "device_type": access_request.device_type,
        "source_ip": access_request.source_ip,
        "vlan": access_request.vlan,
        "destination": access_request.destination,
        "port": access_request.port,
        "decision": decision.status,
        "allowed": decision.allowed,
        "reason": decision.reason,
    }


def get_processed_requests(csv_path: Path = DEFAULT_CSV_PATH) -> list[dict]:
    """Read CSV rows and attach the policy decision for each request."""

    return [request_to_row(access_request) for access_request in load_requests(csv_path)]


def find_most_suspicious(rows: list[dict]) -> dict | None:
    """Pick a simple highest-risk request from denied traffic."""

    sensitive_destinations = {"admin_panel", "file_server", "logging_server"}
    denied_rows = [row for row in rows if not row["allowed"]]

    if not denied_rows:
        return None

    for row in denied_rows:
        if row["destination"] in sensitive_destinations:
            return row

    return denied_rows[0]


def apply_filters(rows: list[dict], decision_filter: str, vlan_filter: str) -> list[dict]:
    """Apply dashboard query-string filters to the processed request rows."""

    filtered_rows = rows

    if decision_filter == "allowed":
        filtered_rows = [row for row in filtered_rows if row["allowed"]]
    elif decision_filter == "denied":
        filtered_rows = [row for row in filtered_rows if not row["allowed"]]

    if vlan_filter:
        filtered_rows = [row for row in filtered_rows if str(row["vlan"]) == vlan_filter]

    return filtered_rows


@app.route("/")
def dashboard():
    """Render the local security dashboard."""

    rows = get_processed_requests()
    decision_filter = request.args.get("decision", "all")
    vlan_filter = request.args.get("vlan", "")
    filtered_rows = apply_filters(rows, decision_filter, vlan_filter)
    allowed_count = sum(1 for row in rows if row["allowed"])
    denied_count = len(rows) - allowed_count
    vlans = sorted({row["vlan"] for row in rows})

    summary = {
        "total": len(rows),
        "allowed": allowed_count,
        "denied": denied_count,
        "suspicious": find_most_suspicious(rows),
    }

    return render_template(
        "index.html",
        rows=filtered_rows,
        summary=summary,
        vlans=vlans,
        selected_decision=decision_filter,
        selected_vlan=vlan_filter,
    )


@app.route("/api/requests")
def api_requests():
    """Return processed access requests as JSON for scripts or integrations."""

    rows = get_processed_requests()
    decision_filter = request.args.get("decision", "all")
    vlan_filter = request.args.get("vlan", "")
    return jsonify(apply_filters(rows, decision_filter, vlan_filter))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
