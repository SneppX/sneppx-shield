"""Audit orchestration: collect SBOM + signature + compliance facts."""

import pathlib

from sneppx_shield import compliance, sbom, signature


def collect(model_path, evidence=None):
    """Run a full audit against a model artifact and return facts."""
    model_path = pathlib.Path(model_path)
    evidence = dict(evidence or {})

    bom = sbom.collect_sbom(model_path)
    ok_sig, sig_detail = verify_artifact(model_path)

    facts = {
        "model": str(model_path),
        "is_dir": model_path.is_dir(),
        "file_count": bom["file_count"],
        "total_bytes": bom["total_bytes"],
        "has_sbom": True,
        "signature_verified": ok_sig,
        "signature_detail": sig_detail,
        # default evidence set to False unless caller supplies it
        "risk_assessed": evidence.get("risk_assessed", False),
        "human_oversight": evidence.get("human_oversight", False),
        "model_card": evidence.get("model_card", False),
        "monitoring": evidence.get("monitoring", False),
        "access_control": evidence.get("access_control", False),
        "robustness_tested": evidence.get("robustness_tested", False),
        "bom": bom,
    }
    passed, total, findings = compliance.score(facts)
    facts["compliance_passed"] = passed
    facts["compliance_total"] = total
    facts["compliance_findings"] = findings
    facts["compliance_rating"] = compliance.rating(passed, total)
    return facts


def verify_artifact(model_path):
    """Verify a detached signature if present for the artifact."""
    try:
        if model_path.is_dir():
            return False, {"error": "directory artifacts need per-file signing"}
        return signature.verify_signature(model_path)
    except OSError as exc:
        return False, {"error": str(exc)}