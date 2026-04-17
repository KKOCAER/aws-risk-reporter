import json
from typing import List, Dict, Any

from finding_mapper import normalize_findings


def load_sample_findings(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return normalize_findings(raw)
