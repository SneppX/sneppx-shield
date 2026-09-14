from sneppx_shield import audit, compliance, report


def _facts_all_pass(model):
    evidence = {
        "risk_assessed": True,
        "human_oversight": True,
        "model_card": True,
        "monitoring": True,
        "access_control": True,
        "robustness_tested": True,
    }
    return audit.collect(model, evidence=evidence)


def test_compliance_score_all_pass(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"data")
    from sneppx_shield.signature import sign_file

    sign_file(f)
    facts = _facts_all_pass(f)
    assert facts["compliance_passed"] == facts["compliance_total"]
    assert facts["compliance_rating"] == "pass"


def test_compliance_score_defaults_to_fail(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"data")
    facts = audit.collect(f)
    assert facts["compliance_rating"] == "fail"
    assert facts["compliance_passed"] == 1  # only signature/evidence-independent maybe


def test_rating_thresholds():
    assert compliance.rating(8, 8) == "pass"
    assert compliance.rating(5, 8) == "review"
    assert compliance.rating(2, 8) == "fail"


def test_report_markdown_smoke(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"data")
    facts = audit.collect(f)
    text = report.render(facts, fmt="markdown")
    assert "SneppX Shield Audit Report" in text
    assert "Compliance score" in text
    assert "## SBOM" in text


def test_report_json_smoke(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"data")
    facts = audit.collect(f)
    text = report.render(facts, fmt="json")
    import json

    assert json.loads(text)["model"] == str(f)


def test_directory_artifact_signature_skipped(tmp_path):
    f = tmp_path / "model.txt"
    f.write_text("x", encoding="utf-8")
    facts = audit.collect(tmp_path)
    assert facts["signature_verified"] is False
    assert "directory artifacts" in facts["signature_detail"]["error"]