"""
HawkEye-AI — Role-Based Access Control

Simple role-gating for the analyst dashboard. Supports 'admin' and
'viewer' roles without requiring a full authentication system.
"""

ROLES = {"admin", "viewer"}


def can_dismiss_alert(role: str) -> bool:
    """
    Check whether the given role can dismiss/act on alerts.

    Args:
        role: The user's role string ('admin' or 'viewer').

    Returns:
        True if the role is 'admin', False otherwise.
    """
    return role.lower().strip() == "admin"


def get_role_permissions(role: str) -> dict:
    """
    Get a dictionary of permissions for UI rendering decisions.

    Args:
        role: The user's role string.

    Returns:
        Dict with boolean permission flags:
            - can_dismiss: whether the user can dismiss alerts
            - can_verify_integrity: whether integrity check is available
            - can_export: whether the user can export alert data
    """
    role = role.lower().strip()
    return {
        "can_dismiss": role == "admin",
        "can_verify_integrity": True,  # Both roles can verify
        "can_export": role == "admin",
    }
