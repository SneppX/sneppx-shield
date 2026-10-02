"""Compliance control matrix for AI frameworks/models.

Maps organizational/technical controls to EU AI Act, ISO 42001 and
NIST AI RMF themes. Controls are evaluated lazily against the facts
collected by an audit (present/absent evidence).
"""

# id, frameworks, title, evidence key or None (treat as informational)
_CONTROLS = [
    {
        "id": "C-01",
        "frameworks": ["eu-ai-act", "iso-42001"],
        "title": "Digital asset provenance (SBOM)",
        "evidence": "has_sbom",
    },
    {
        "id": "C-02",
        "frameworks": ["eu-ai-act"],
        "title": "Integrity verification (signed artifacts)",
        "evidence": "signature_verified",
    },
    {
        "id": "C-03",
        "frameworks": ["eu-ai-act", "iso-42001", "nist-ai-rmf"],
        "title": "Risk assessment performed",
        "evidence": "risk_assessed",
    },
    {
        "id": "C-04",
        "frameworks": ["iso-42001", "nist-ai-rmf"],
        "title": "Human oversight / review process defined",
        "evidence": "human_oversight",
    },
    {
        "id": "C-05",
        "frameworks": ["eu-ai-act", "nist-ai-rmf"],
        "title": "Learning / provenance transparent (model card)",
        "evidence": "model_card",
    },
    {
        "id": "C-06",
        "frameworks": ["eu-ai-act", "iso-42001"],
        "title": "Incident monitoring & logging enabled",
        "evidence": "monitoring",
    },
    {
        "id": "C-07",
        "frameworks": ["iso-42001"],
        "title": "Access control on model registry",
        "evidence": "access_control",
    },
    {
        "id": "C-08",
        "frameworks": ["nist-ai-rmf"],
        "title": "Adversarial robustness tested",
        "evidence": "robustness_tested",
    },
    {
        "id": "C-09",
        "frameworks": ["eu-ai-act", "nist-ai-rmf"],
        "title": "Data governance and provenance documented",
        "evidence": "data_provenance",
    },
]


def score(facts):
    """Evaluate controls against facts. Returns (passed, total, findings)."""
    findings = []
    passed = 0
    for control in _CONTROLS:
        ev = control["evidence"]
        passed_here = bool(facts.get(ev, False)) if ev else False
        findings.append(
            {
                "id": control["id"],
                "title": control["title"],
                "frameworks": control["frameworks"],
                "passed": passed_here,
                "evidence": ev,
            }
        )
        passed += 1 if passed_here else 0
    total = len(_CONTROLS)
    return passed, total, findings


def rating(passed, total):
    ratio = passed / total if total else 0.0
    if ratio >= 0.8:
        return "pass"
    if ratio >= 0.5:
        return "review"
    return "fail"


def matrix():
    """Return control registry for documentation/reporting purposes."""
    return list(_CONTROLS)