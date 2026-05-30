"""Access policy logic for NetGuard.

This module keeps the security decisions separate from the command-line code.
That makes the policy easier to test and easier to change later.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessRequest:
    """A single device access request from the CSV file."""

    device_name: str
    device_type: str
    vlan: int
    source_ip: str
    destination: str
    port: int


@dataclass(frozen=True)
class PolicyDecision:
    """The result of checking one access request."""

    allowed: bool
    reason: str

    @property
    def status(self) -> str:
        """Return a report-friendly status label."""
        return "ALLOW" if self.allowed else "DENY"


# Network segmentation map:
# Each VLAN represents a different trust zone in the network.
VLAN_DEVICE_TYPES = {
    10: "employee",
    20: "security",
    30: "guest",
    40: "admin",
}


# Least privilege allow rules:
# Only the exact traffic required for each role is listed here.
ALLOW_RULES = {
    ("employee", 10, "internal_app", 443): "Employees may use the internal app over HTTPS.",
    ("guest", 30, "internet", 80): "Guests may browse the internet over HTTP.",
    ("guest", 30, "internet", 443): "Guests may browse the internet over HTTPS.",
    ("security", 20, "logging_server", 514): "Security devices may send logs to the logging server.",
    ("security", 20, "internal_app", 443): "Security devices may use the internal app over HTTPS.",
    ("admin", 40, "admin_panel", 22): "Admins may access the admin panel over SSH.",
}


# Extra deny rule to make an important segmentation rule obvious.
GUEST_BLOCKED_DESTINATIONS = {"file_server", "admin_panel", "logging_server"}


def evaluate_request(request: AccessRequest) -> PolicyDecision:
    """Return ALLOW or DENY for one access request.

    The policy follows a default-deny model:
    traffic is denied unless an explicit allow rule permits it.
    """

    device_type = request.device_type.strip().lower()
    destination = request.destination.strip().lower()
    rule = (device_type, request.vlan, destination, request.port)

    expected_type = VLAN_DEVICE_TYPES.get(request.vlan)
    if expected_type is None:
        return PolicyDecision(False, f"Unknown VLAN {request.vlan}; default deny.")

    if expected_type != device_type:
        return PolicyDecision(
            False,
            f"{request.device_type} devices do not belong on VLAN {request.vlan}; expected {expected_type}.",
        )

    if device_type == "guest" and destination in GUEST_BLOCKED_DESTINATIONS:
        return PolicyDecision(
            False,
            f"Guest VLAN is segmented away from {destination}; guests may only access internet ports 80 and 443.",
        )

    if rule in ALLOW_RULES:
        return PolicyDecision(True, ALLOW_RULES[rule])

    return PolicyDecision(
        False,
        "No explicit allow rule matched; default deny enforces least privilege.",
    )
