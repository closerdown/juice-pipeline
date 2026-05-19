import json, os, math

WS = os.environ["WORKSPACE"]
TRIVY_FILES = [
    WS + "/output/trivy-result.json",
    WS + "/output/trivy-frontend-result.json",
    WS + "/output/trivy-nodemodules-result.json",
    WS + "/output/trivy-sbom-result.json",
]
OWASP_JSON = WS + "/output/dependency-check-report.json"
NPM_FILES = [WS + "/output/npm-audit-root.json", WS + "/output/npm-audit-frontend.json"]
OUTPUT_FILE = WS + "/output/merged_vulns.json"

SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

def norm_sev(s):
    return SEV_MAP.get((s or "").lower(), "UNKNOWN")

def parse_score(val):
    try:
        f = float(val)
        return f if f > 0 else None
    except (ValueError, TypeError):
        return None

def round_up_1_decimal(x):
    return math.ceil(x * 10.0) / 10.0

def cvss_v3_score(vector):
    if not vector or "CVSS:3." not in vector:
        return None
    metrics = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        metrics[k] = v
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics.get("AV"))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC"))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI"))
    scope = metrics.get("S")
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("C"))
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("I"))
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("A"))
    if None in [av, ac, ui, c, i, a] or scope not in ["U", "C"]:
        return None
    if scope == "U":
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR"))
    else:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(metrics.get("PR"))
    if pr is None:
        return None
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if isc_base <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        impact = 6.42 * isc_base
        base = impact + exploitability
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        base = 1.08 * (impact + exploitability)
    return round_up_1_decimal(min(base, 10.0))

def extract_best_cvss_from_obj(obj):
    scores = []
    if not isinstance(obj, dict):
        return None
    for key in ["score", "baseScore", "cvss_score", "cvssScore", "severity_score"]:
        score = parse_score(obj.get(key))
        if score is not None:
            scores.append(score)
    for key in ["vector", "vectorString", "cvssVector", "CVSSVector", "score"]:
        val = obj.get(key)
        if isinstance(val, str) and "CVSS:3." in val:
            score = cvss_v3_score(val)
            if score is not None:
                scores.append(score)
    return max(scores) if scores else None

def better(prev, current):
    if prev is None:
        return current
    if current["cvss"] is not None and (prev["cvss"] is None or current["cvss"] > prev["cvss"]):
        return current
    return prev

def parse_trivy(paths):
    vulns = {}
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
