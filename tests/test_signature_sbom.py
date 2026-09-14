import hashlib
import json

import pytest

from sneppx_shield import sbom
from sneppx_shield.signature import sign_file, verify_signature


def test_collect_sbom_directory(tmp_path):
    (tmp_path / "model.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "weights.bin").write_bytes(b"\x00\x01" * 100)
    bom = sbom.collect_sbom(tmp_path)

    assert bom["file_count"] == 2
    assert bom["total_bytes"] == 5 + 200
    by_path = {f["path"]: f for f in bom["files"]}
    assert "model.txt" in by_path
    assert by_path["model.txt"]["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_collect_sbom_single_file(tmp_path):
    f = tmp_path / "one.bin"
    f.write_bytes(b"\x01" * 16)
    bom = sbom.collect_sbom(f)
    assert bom["file_count"] == 1
    assert bom["files"][0]["path"] == "one.bin"


def test_collect_sbom_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        sbom.collect_sbom(tmp_path / "nope")


def test_sbom_json(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    bom = sbom.collect_sbom(f)
    out = tmp_path / "sbom.json"
    sbom.to_sbom_json(bom, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["format"] == "sneppx-shield-sbom"
    assert loaded["file_count"] == 1


def test_sign_and_verify_roundtrip(tmp_path):
    f = tmp_path / "artifact.bin"
    f.write_bytes(b"payload" * 10)
    sig_path, _ = sign_file(f)
    ok, detail = verify_signature(f, sig_path=sig_path)
    assert ok is True
    assert detail["signer"] is None


def test_verify_rejects_tampered(tmp_path):
    f = tmp_path / "artifact.bin"
    f.write_bytes(b"payload" * 10)
    sig_path, _ = sign_file(f)
    f.write_bytes(b"payload" * 10 + b"tampered")
    ok, detail = verify_signature(f, sig_path=sig_path)
    assert ok is False
    assert detail["error"] == "message hash mismatch"


def test_verify_missing_signature(tmp_path):
    f = tmp_path / "artifact.bin"
    f.write_bytes(b"x")
    ok, detail = verify_signature(f, sig_path=tmp_path / "missing.sig")
    assert ok is False
    assert "no signature" in detail["error"]