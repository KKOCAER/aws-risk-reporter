from typing import Any, Dict, List


def _severity_to_internal(severity_obj: Dict[str, Any]) -> str:
    label = str(severity_obj.get("Label", "")).strip().lower()
    if label in {"critical", "high", "medium", "low", "info"}:
        return label

    normalized = severity_obj.get("Normalized")
    if isinstance(normalized, int):
        if normalized >= 90:
            return "critical"
        if normalized >= 70:
            return "high"
        if normalized >= 40:
            return "medium"
        return "low"

    return "low"


def _first_resource(finding: Dict[str, Any]) -> Dict[str, Any]:
    resources = finding.get("Resources", [])
    return resources[0] if resources else {}


def _infer_service(resource_type: str, product_name: str, title: str, description: str) -> str:
    resource_type_l = (resource_type or "").lower()
    text = f"{title} {description}".lower()

    if "s3" in resource_type_l or "bucket" in text:
        return "s3"
    if "securitygroup" in resource_type_l or "ec2" in resource_type_l or "0.0.0.0/0" in text:
        return "ec2"
    if "iam" in resource_type_l or "role" in resource_type_l or "user" in resource_type_l:
        return "iam"
    if "cloudtrail" in resource_type_l or "trail" in text:
        return "cloudtrail"
    if "ebs" in resource_type_l or "volume" in text:
        return "ebs"

    product_l = (product_name or "").lower()
    if "security hub" in product_l:
        return "securityhub"
    return "unknown"


def _infer_exposure(title: str, description: str) -> str:
    text = f"{title} {description}".lower()

    if any(x in text for x in ["public", "internet", "0.0.0.0/0", "::/0"]):
        return "public"
    if "cross-account" in text:
        return "cross-account"
    return "private"


def _infer_privilege_level(title: str, description: str, resource_type: str) -> str:
    text = f"{title} {description} {resource_type}".lower()

    if any(x in text for x in ["administrator", "admin", "wildcard"]):
        return "admin"
    if any(x in text for x in ["iam", "assume role", "permissions"]):
        return "high"
    if any(x in text for x in ["security group", "ssh", "port 22", "port 3389"]):
        return "medium"
    return "low"


def _infer_exploitability(title: str, description: str) -> str:
    text = f"{title} {description}".lower()

    if any(x in text for x in ["0.0.0.0/0", "::/0", "public", "wildcard"]):
        return "high"
    if any(x in text for x in ["disabled", "unencrypted"]):
        return "medium"
    return "low"


def _infer_data_sensitivity(tags: Dict[str, str], title: str, description: str) -> str:
    explicit = str(tags.get("DataSensitivity", "")).strip().lower()
    if explicit in {"critical", "high", "medium", "low"}:
        return explicit

    text = f"{title} {description}".lower()
    if any(x in text for x in ["customer", "payment", "pii", "personal"]):
        return "high"

    return "unknown"


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    resource = _first_resource(finding)
    resource_tags = resource.get("Tags", {}) or {}

    title = finding.get("Title", "Unknown finding")
    description = finding.get("Description", "")
    resource_type = resource.get("Type", "unknown")
    product_name = finding.get("ProductName", "Security Hub")

    return {
        "id": finding.get("Id", "unknown-id"),
        "schema_version": finding.get("SchemaVersion", ""),
        "product_arn": finding.get("ProductArn", ""),
        "generator_id": finding.get("GeneratorId", ""),
        "aws_account_id": finding.get("AwsAccountId", ""),
        "service": _infer_service(resource_type, product_name, title, description),
        "resource_type": resource_type,
        "resource": resource.get("Id", "unknown"),
        "region": finding.get("Region") or resource.get("Region", "unknown"),
        "severity": _severity_to_internal(finding.get("Severity", {})),
        "alert_type": title,
        "description": description,
        "timestamp": finding.get("UpdatedAt") or finding.get("CreatedAt", ""),
        "environment": str(resource_tags.get("Environment", "unknown")).lower(),
        "owner": resource_tags.get("Owner", "unassigned"),
        "exposure": _infer_exposure(title, description),
        "privilege_level": _infer_privilege_level(title, description, resource_type),
        "data_sensitivity": _infer_data_sensitivity(resource_tags, title, description),
        "exploitability": _infer_exploitability(title, description),
        "workflow_status": finding.get("Workflow", {}).get("Status", "NEW"),
        "record_state": finding.get("RecordState", "ACTIVE"),
        "compliance_status": finding.get("Compliance", {}).get("Status", "UNKNOWN"),
        "security_control_id": finding.get("Compliance", {}).get("SecurityControlId", ""),
        "source_product": product_name,
        "types": finding.get("Types", []),
        "tags": resource_tags,
    }


def normalize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_finding(f) for f in findings]


def extract_findings_from_imported_v2_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detail = event.get("detail", {})
    findings = detail.get("findings", [])
    return normalize_findings(findings)
