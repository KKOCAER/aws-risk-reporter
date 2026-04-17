"""Placeholder action service for analyst-triggered workflows."""


def request_action(finding_id: str, action_type: str, requested_by: str = "analyst"):
    return {
        "finding_id": finding_id,
        "action_type": action_type,
        "requested_by": requested_by,
        "status": "queued",
    }
