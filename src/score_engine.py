import re
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

SEVERITY_BASE = {
    "critical": 35,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}

SERVICE_WEIGHT = {
    "iam": 12,
    "s3": 10,
    "ec2": 9,
    "cloudtrail": 8,
    "ebs": 6,
}

DATA_SENSITIVITY_WEIGHT = {
    "critical": 18,
    "high": 14,
    "medium": 8,
    "low": 3,
    "unknown": 4,
}

ENVIRONMENT_WEIGHT = {
    "prod": 10,
    "production": 10,
    "staging": 5,
    "dev": 2,
    "test": 1,
    "unknown": 3,
}


def normalize_text(*parts: Any) -> str:
    return " ".join(str(p or "").strip().lower() for p in parts if p is not None)


def infer_severity_base(alert: Dict[str, Any]) -> Tuple[int, str]:
    severity = str(alert.get("severity", "")).strip().lower()
    if severity not in SEVERITY_BASE:
        severity = "low"
    return SEVERITY_BASE[severity], f"severity={severity}"


def infer_service_weight(alert: Dict[str, Any]) -> Tuple[int, str]:
    service = str(alert.get("service", "")).strip().lower()
    return SERVICE_WEIGHT.get(service, 5), f"service={service or 'unknown'}"


def infer_exposure(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    explicit = str(alert.get("exposure", "")).strip().lower()
    explicit_map = {
        "public": 20,
        "internet-facing": 18,
        "cross-account": 12,
        "internal": 6,
        "private": 0,
    }

    if explicit in explicit_map:
        return explicit_map[explicit], f"explicit exposure={explicit}"

    if re.search(r"0\.0\.0\.0/0|::/0|public read|public access|public bucket|internet", text):
        return 20, "internet/public exposure"

    if re.search(r"cross-account|external account", text):
        return 12, "cross-account exposure"

    return 2, "no clear external exposure"


def infer_exploitability(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    explicit = str(alert.get("exploitability", "")).strip().lower()
    explicit_map = {
        "high": 18,
        "medium": 10,
        "low": 4,
    }

    if explicit in explicit_map:
        return explicit_map[explicit], f"explicit exploitability={explicit}"

    if re.search(r"0\.0\.0\.0/0.*port (22|3389)|port (22|3389).*0\.0\.0\.0/0", text):
        return 18, "remote admin port exposed"

    if re.search(r"wildcard|(\*:\*)|actions and resources", text):
        return 16, "wildcard or broad permissions"

    if re.search(r"public bucket|public read|public access", text):
        return 14, "direct external access path"

    if re.search(r"disabled|not enabled", text):
        return 8, "control disabled"

    if re.search(r"unencrypted", text):
        return 5, "misconfiguration without direct exploit path"

    return 6, "default exploitability"


def infer_data_sensitivity(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    explicit = str(alert.get("data_sensitivity", "")).strip().lower()
    if explicit:
        score = DATA_SENSITIVITY_WEIGHT.get(explicit, DATA_SENSITIVITY_WEIGHT["unknown"])
        return score, f"explicit data_sensitivity={explicit}"

    if re.search(r"customer|payment|pii|personal|identity|finance|secret", text):
        return 12, "sensitive data indicators found"

    if str(alert.get("service", "")).strip().lower() == "s3":
        return 6, "storage service with unknown data sensitivity"

    return DATA_SENSITIVITY_WEIGHT["unknown"], "unknown data sensitivity"


def infer_privilege_impact(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    explicit = str(alert.get("privilege_level", "")).strip().lower()
    explicit_map = {
        "admin": 18,
        "high": 14,
        "medium": 8,
        "low": 3,
    }

    if explicit in explicit_map:
        return explicit_map[explicit], f"explicit privilege_level={explicit}"

    if re.search(r"admin|administrator", text):
        return 18, "admin-level impact"

    if re.search(r"wildcard|assume role|iam role|iam user|excessive permissions", text):
        return 14, "identity/permission risk"

    if str(alert.get("service", "")).strip().lower() == "iam":
        return 12, "IAM finding"

    return 4, "limited privilege impact"


def infer_control_gap(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    if re.search(r"cloudtrail disabled|logging is disabled|audit disabled", text):
        return 12, "detection/audit gap"

    if re.search(r"unencrypted|encryption disabled", text):
        return 6, "protection control gap"

    return 0, "no major control gap"


def infer_environment(alert: Dict[str, Any], text: str) -> Tuple[int, str]:
    explicit = str(alert.get("environment", "")).strip().lower()
    if explicit:
        return ENVIRONMENT_WEIGHT.get(explicit, ENVIRONMENT_WEIGHT["unknown"]), f"explicit environment={explicit}"

    if re.search(r"\bprod\b|\bproduction\b", text):
        return 10, "production indicator found"

    if re.search(r"\bdev\b|\btest\b|\bstaging\b", text):
        return 2, "non-production indicator found"

    return ENVIRONMENT_WEIGHT["unknown"], "environment unknown"


def recency_bonus(alert: Dict[str, Any]) -> Tuple[int, str]:
    timestamp = str(alert.get("timestamp", "")).strip()
    if not timestamp:
        return 0, "no timestamp bonus"

    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600

        if age_hours <= 24:
            return 3, "fresh finding <=24h"
        if age_hours <= 72:
            return 1, "recent finding <=72h"
    except ValueError:
        pass

    return 0, "no timestamp bonus"


def calculate_score_breakdown(alert: Dict[str, Any]) -> Dict[str, Any]:
    text = normalize_text(
        alert.get("alert_type"),
        alert.get("description"),
        alert.get("service"),
        alert.get("resource"),
        alert.get("region"),
        alert.get("owner"),
        alert.get("environment"),
    )

    components = {
        "severity_base": infer_severity_base(alert),
        "service_weight": infer_service_weight(alert),
        "exposure": infer_exposure(alert, text),
        "exploitability": infer_exploitability(alert, text),
        "data_sensitivity": infer_data_sensitivity(alert, text),
        "privilege_impact": infer_privilege_impact(alert, text),
        "control_gap": infer_control_gap(alert, text),
        "environment": infer_environment(alert, text),
        "recency_bonus": recency_bonus(alert),
    }

    raw_total = sum(score for score, _ in components.values())
    final_score = max(0, min(100, raw_total))

    return {
        "score": int(round(final_score)),
        "components": {
            name: {"score": score, "reason": reason}
            for name, (score, reason) in components.items()
        },
    }


def calculate_score(alert: Dict[str, Any]) -> int:
    return calculate_score_breakdown(alert)["score"]


def risk_band(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"
