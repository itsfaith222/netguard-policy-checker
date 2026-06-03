from policy import AccessRequest, evaluate_request
from app import app, get_processed_requests


def make_request(device_type: str, vlan: int, destination: str, port: int) -> AccessRequest:
    return AccessRequest(
        device_name="test-device",
        device_type=device_type,
        vlan=vlan,
        source_ip="10.0.0.10",
        destination=destination,
        port=port,
    )


def test_employee_vlan_10_can_access_internal_app_on_443():
    decision = evaluate_request(make_request("employee", 10, "internal_app", 443))

    assert decision.allowed is True
    assert decision.status == "ALLOW"


def test_guest_vlan_30_can_access_internet_on_80_and_443():
    http_decision = evaluate_request(make_request("guest", 30, "internet", 80))
    https_decision = evaluate_request(make_request("guest", 30, "internet", 443))

    assert http_decision.allowed is True
    assert https_decision.allowed is True


def test_guest_cannot_access_sensitive_internal_services():
    for destination in ("file_server", "admin_panel", "logging_server"):
        decision = evaluate_request(make_request("guest", 30, destination, 443))

        assert decision.allowed is False
        assert "segmented" in decision.reason


def test_security_vlan_20_can_access_logging_and_internal_app():
    logging_decision = evaluate_request(make_request("security", 20, "logging_server", 514))
    app_decision = evaluate_request(make_request("security", 20, "internal_app", 443))

    assert logging_decision.allowed is True
    assert app_decision.allowed is True


def test_admin_vlan_40_can_access_admin_panel_on_22():
    decision = evaluate_request(make_request("admin", 40, "admin_panel", 22))

    assert decision.allowed is True


def test_unknown_vlan_is_denied_by_default():
    decision = evaluate_request(make_request("contractor", 99, "internet", 443))

    assert decision.allowed is False
    assert "default deny" in decision.reason


def test_role_on_wrong_vlan_is_denied():
    decision = evaluate_request(make_request("guest", 10, "internet", 443))

    assert decision.allowed is False
    assert "do not belong" in decision.reason


def test_unlisted_access_is_denied_by_default():
    decision = evaluate_request(make_request("employee", 10, "admin_panel", 22))

    assert decision.allowed is False
    assert "default deny" in decision.reason


def test_dashboard_processes_csv_requests_with_decisions():
    rows = get_processed_requests()

    assert len(rows) == 12
    assert rows[0]["decision"] == "ALLOW"
    assert rows[1]["decision"] == "DENY"
    assert "reason" in rows[0]


def test_api_requests_returns_processed_json():
    client = app.test_client()

    response = client.get("/api/requests")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 12
    assert {"ALLOW", "DENY"} == {row["decision"] for row in data}


def test_api_requests_can_filter_denied_vlan():
    client = app.test_client()

    response = client.get("/api/requests?decision=denied&vlan=30")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1
    assert data[0]["device_name"] == "guest-laptop-03"
