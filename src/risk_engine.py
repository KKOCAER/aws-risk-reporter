from typing import Any, Dict

from score_engine import calculate_score_breakdown, risk_band


def _determine_response_mode(score: int) -> str:
    if score >= 85:
        return "auto-remediation-candidate"
    if score >= 70:
        return "manual-approval-required"
    if score >= 45:
        return "investigate-and-monitor"
    return "report-only"


def _derive_why_it_matters(alert: Dict[str, Any], breakdown: Dict[str, Any]) -> str:
    components = breakdown["components"]

    top_drivers = sorted(
        components.items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    )[:3]

    reasons = [item[1]["reason"] for item in top_drivers if item[1]["score"] > 0]
    reasons_text = "; ".join(reasons) if reasons else "baseline risk factors"

    alert_type = alert.get("alert_type", "Unknown finding")
    resource = alert.get("resource", "unknown resource")
    region = alert.get("region", "unknown region")
    owner = alert.get("owner", "unassigned owner")
    environment = alert.get("environment", "unknown environment")

    return (
        f"{alert_type} affects '{resource}' in {region} ({environment}). "
        f"Owner: {owner}. Primary risk drivers: {reasons_text}."
    )


def _derive_recommended_action(alert: Dict[str, Any], score: int) -> str:
    alert_type = str(alert.get("alert_type", "")).strip().lower()

    action_map = {
        "public bucket": (
            "Enable S3 Block Public Access, review bucket policy and ACLs, "
            "validate whether public exposure is intentional, and restrict access."
        ),
        "open security group": (
            "Restrict inbound rules to trusted IP ranges, remove 0.0.0.0/0 or ::/0 "
            "for admin ports, and confirm business justification for exposed services."
        ),
        "excessive permissions": (
            "Replace wildcard permissions with least-privilege policies, "
            "scope actions/resources tightly, and review trust relationships."
        ),
        "cloudtrail disabled": (
            "Re-enable CloudTrail, validate multi-region logging, protect log delivery, "
            "and confirm log integrity controls."
        ),
        "unencrypted volume": (
            "Create encrypted snapshots, migrate workloads to encrypted EBS volumes, "
            "and enforce encryption by default."
        ),
    }

    for key, action in action_map.items():
        if key in alert_type:
            if score >= 85:
                return action + " Treat as immediate remediation candidate."
            if score >= 70:
                return action + " Execute under change approval."
            return action

    if score >= 85:
        return "Contain exposure quickly, validate blast radius, and assign immediate remediation."
    if score >= 70:
        return "Review with owner team, validate exploit path, and remediate in the next urgent change window."
    if score >= 45:
        return "Investigate context, collect evidence, and schedule remediation based on business impact."
    return "Track in backlog and reassess if environment or exposure changes."


def _derive_auto_remediation(alert: Dict[str, Any], score: int) -> bool:
    alert_type = str(alert.get("alert_type", "")).strip().lower()

    if score < 85:
        return False

    safe_auto_patterns = [
        "public bucket",
        "open security group",
        "cloudtrail disabled",
    ]
    return any(pattern in alert_type for pattern in safe_auto_patterns)


def evaluate_risk(alert: Dict[str, Any]) -> Dict[str, Any]:
    breakdown = calculate_score_breakdown(alert)
    score = breakdown["score"]
    priority = risk_band(score)

    return {
        "score": score,
        "priority": priority,
        "response_mode": _determine_response_mode(score),
        "auto_remediation_available": _derive_auto_remediation(alert, score),
        "why_it_matters": _derive_why_it_matters(alert, breakdown),
        "recommended_action": _derive_recommended_action(alert, score),
        "breakdown": breakdown["components"],
    }


def assign_priority(alert: Dict[str, Any]) -> str:
    return evaluate_risk(alert)["priority"]


def generate_summary(alert: Dict[str, Any], priority: str | None = None) -> str:
    return evaluate_risk(alert)["why_it_matters"]


def get_remediation(alert: Dict[str, Any]) -> str:
    return evaluate_risk(alert)["recommended_action"]
