import json

from sneppx_shield import cli


def _make_artifact(tmp_path):
    (tmp_path / "model.txt").write_text("hello-model", encoding="utf-8")
    (tmp_path / "weights.bin").write_bytes(b"\x00\xff" * 64)
    return tmp_path / "model.txt"


def test_sbom_cli_json(tmp_path, capsys):
    art = _make_artifact(tmp_path)
    rc = cli.main(["sbom", str(art), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["format"] == "sneppx-shield-sbom"
    assert payload["file_count"] == 1
    assert len(payload["files"][0]["sha256"]) == 64


def test_sbom_cli_markdown(tmp_path, capsys):
    art = _make_artifact(tmp_path)
    rc = cli.main(["sbom", str(art), "--format", "markdown"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "# SneppX Shield SBOM" in out
    assert "model.txt" in out


def test_sbom_cli_recursive_dir(tmp_path, capsys):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.bin").write_bytes(b"a" * 8)
    (tmp_path / "sub" / "b.bin").write_bytes(b"b" * 8)
    rc = cli.main(["sbom", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["file_count"] == 2
    paths = {f["path"] for f in payload["files"]}
    assert paths == {"a.bin", "sub/b.bin"}


def test_sbom_cli_no_hash(tmp_path, capsys):
    art = _make_artifact(tmp_path)
    cli.main(["sbom", str(art), "--no-hash"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["files"][0]["sha256"] is None


def test_sbom_cli_out_file(tmp_path):
    art = _make_artifact(tmp_path)
    out = tmp_path / "out.json"
    rc = cli.main(["sbom", str(art), "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["file_count"] == 1


def test_sbom_cli_missing(tmp_path, capsys):
    rc = cli.main(["sbom", str(tmp_path / "nope")])
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_audit_ci_pass(tmp_path, capsys):
    art = _make_artifact(tmp_path)
    evidence = ("model_card=true,risk_assessed=true,human_oversight=true,"
                "monitoring=true,access_control=true,robustness_tested=true")
    rc = cli.main(["audit", str(art), "--ci", "--evidence", evidence])
    out = capsys.readouterr().out
    assert rc == 0
    assert "rating=pass" in out
    assert "::group::sneppx-shield audit" in out


def test_audit_ci_fail_flags_error(tmp_path, capsys):
    art = _make_artifact(tmp_path)
    rc = cli.main(["audit", str(art), "--ci"])
    out, err = capsys.readouterr()
    assert rc == 1
    assert "rating=" in out
    assert "::error title=sneppx-shield" in err or "::error title=sneppx-shield" in out