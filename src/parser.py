import json


def load_alerts(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = []
    for item in data:
        alerts.append(
            {
                "id": item.get("id", "unknown-id"),
                "aws_account_id": item.get("aws_account_id", ""),
                "service": item.get("service", "unknown"),
                "resource_type": item.get("resource_type", "unknown"),
                "resource": item.get("resource", "unknown"),
                "region": item.get("region", "unknown"),
                "severity": item.get("severity", "low"),
                "alert_type": item.get("alert_type", "Unknown"),
                "description": item.get("description", ""),
                "timestamp": item.get("timestamp", ""),
                "environment": item.get("environment", "unknown"),
                "owner": item.get("owner", "unassigned"),
                "exposure": item.get("exposure", "private"),
                "privilege_level": item.get("privilege_level", "low"),
                "data_sensitivity": item.get("data_sensitivity", "unknown"),
                "exploitability": item.get("exploitability", "low"),
                "workflow_status": item.get("workflow_status", "NEW"),
                "compliance_status": item.get("compliance_status", "UNKNOWN"),
                "source_product": item.get("source_product", "custom-analyzer"),
                "tags": item.get("tags", {}),
            }
        )

    return alerts
