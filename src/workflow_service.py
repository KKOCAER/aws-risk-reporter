"""Placeholder workflow service for remediation orchestration."""


def transition_workflow(current_status: str, target_status: str) -> dict:
    return {"from": current_status, "to": target_status}
