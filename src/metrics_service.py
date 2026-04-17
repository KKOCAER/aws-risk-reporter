"""Placeholder metrics service for operational dashboards."""


def summarize_metrics(findings: list[dict]) -> dict:
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
    }
