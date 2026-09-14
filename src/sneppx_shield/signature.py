"""Detached signature creation/verification for model artifacts.

Skeleton implementation using SHA-256 + an ed25519-style signature file.

Signature file format (JSON):
    {
      "algorithm": "sneppx-sha256",
      "message_sha256": "<hex>",
      "signature": "<hex>",
      "signer": "<optional signer id>"
    }

The production path integrates `sneppx-alg`'s Ed25519 implementation
(SNEPPX_ed25519_sign/verify). This module provides the portable layout and
verification plumbing around it.
"""

import hashlib
import json
import pathlib


def _default_sign_keypair():
    """Placeholder keypair (deterministic) - replace with real key management."""
    return "placeholder-secret", "placeholder-public"


def sign_file(path, keypair=None, signer=None):
    """Create *path + '.sig'* detached signature (widget-style, demo-only)."""
    keypair = keypair or _default_sign_keypair()
    shared = keypair[1]  # demo uses the public/shared material keyed by the secret side
    digest = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    sig = hashlib.sha256((digest + shared).encode("utf-8")).hexdigest()
    payload = {
        "algorithm": "sneppx-sha256",
        "message_sha256": digest,
        "signature": sig,
        "signer": signer,
    }
    sig_path = pathlib.Path(str(path) + ".sig")
    sig_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return sig_path, payload


def verify_signature(path, sig_path=None, public_key=None):
    """Verify a detached signature. Returns (ok: bool, detail: dict)."""
    path = pathlib.Path(path)
    sig_path = pathlib.Path(sig_path) if sig_path else pathlib.Path(str(path) + ".sig")
    if not sig_path.exists():
        return False, {"error": "no signature file", "sig_path": str(sig_path)}
    try:
        payload = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, {"error": "unparsable signature", "detail": str(exc)}

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if payload.get("message_sha256") != digest:
        return False, {"error": "message hash mismatch", "expected": payload.get("message_sha256"), "actual": digest}

    public_key = public_key or _default_sign_keypair()[1]
    expected = hashlib.sha256((digest + public_key).encode("utf-8")).hexdigest()
    if payload.get("signature") != expected:
        return False, {"error": "signature mismatch"}
    return True, {"algorithm": payload.get("algorithm"), "signer": payload.get("signer")}