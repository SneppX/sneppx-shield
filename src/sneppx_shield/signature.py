"""Detached Ed25519 signature creation/verification for model artifacts.

Uses the bundled pure-Python :mod:`sneppx_shield.ed25519` (RFC 8032), the
same scheme as ``sneppx-alg``'s ``SNEPPX_ed25519_*`` API, so shield-signed
artifacts are verifiable with the same public keys across the ecosystem.

Signature file format (JSON, portable layout):
    {
      "algorithm": "ed25519",
      "message_sha256": "<hex>",
      "public_key": "<hex>",
      "signature": "<hex>",
      "signer": "<optional signer id>"
    }

Usage:
    pk, sk = signature.new_keypair(save_to="keys/")
    signature.sign_file("model.bin", secret_key=sk, signer="team-a")
    ok, detail = signature.verify_signature("model.bin")
"""

import hashlib
import json
import pathlib

from sneppx_shield import ed25519

KEYPAIR_FILENAME = "sneppx_shield_keypair.json"
PUBLIC_KEY_FILENAME = "sneppx_shield_public_key.pem"


def new_keypair(save_to=None):
    """Generate an Ed25519 keypair; optionally persist it.

    Returns ``(pk_hex, sk_hex)``. ``save_to`` may be a directory; the secret
    keypair is written to ``KEYPAIR_FILENAME`` inside it only when requested,
    so callers control their own key management.
    """
    pk, sk = ed25519.keypair()
    if save_to is not None:
        dest = pathlib.Path(save_to)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / KEYPAIR_FILENAME).write_text(
            json.dumps({"seed": sk[:32].hex(), "public_key": pk.hex()}, indent=2),
            encoding="utf-8",
        )
        (dest / PUBLIC_KEY_FILENAME).write_text(pk.hex(), encoding="utf-8")
    return pk.hex(), sk.hex()


def _coerce_secret_key(value):
    """Accept a 64-byte secret key as bytes or hex text."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise TypeError("secret key must be bytes or hex string")


def _coerce_public_key(value):
    """Accept a 32-byte public key as bytes or hex text."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise TypeError("public key must be bytes or hex string")


def sign_file(path, secret_key=None, signer=None):
    """Create ``*path + '.sig'`` with a real Ed25519 signature.

    ``secret_key`` is required (RFC 8032 64-byte form: ``seed || public_key``);
    get one from :func:`new_keypair`. Without it the artifact is NOT signed -
    an error is raised so a secret key can never be silently omitted.
    """
    if secret_key is None:
        raise ValueError("signing requires a secret key (use signature.new_keypair())")
    sk = _coerce_secret_key(secret_key)
    data = pathlib.Path(path).read_bytes()
    sig = ed25519.sign(sk, data)
    pk = sk[32:]
    payload = {
        "algorithm": "ed25519",
        "message_sha256": hashlib.sha256(data).hexdigest(),
        "public_key": pk.hex(),
        "signature": sig.hex(),
        "signer": signer,
    }
    sig_path = pathlib.Path(str(path) + ".sig")
    sig_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return sig_path, payload


def verify_signature(path, sig_path=None, public_key=None):
    """Verify a detached Ed25519 signature.

    Returns ``(ok: bool, detail: dict)``. ``public_key`` (bytes or hex)
    overrides the key embedded in the signature file, which is useful for
    verifying against an expected signer key.
    """
    path = pathlib.Path(path)
    sig_path = pathlib.Path(sig_path) if sig_path else pathlib.Path(str(path) + ".sig")
    if not sig_path.exists():
        return False, {"error": "no signature file", "sig_path": str(sig_path)}
    try:
        payload = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, {"error": "unparsable signature", "detail": str(exc)}

    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if payload.get("message_sha256") != digest:
        return False, {
            "error": "message hash mismatch",
            "expected": payload.get("message_sha256"),
            "actual": digest,
        }

    pk = _coerce_public_key(public_key) if public_key is not None else None
    if pk is None:
        try:
            pk = _coerce_public_key(payload.get("public_key"))
        except (KeyError, ValueError, TypeError):
            return False, {"error": "no public key in signature file"}
    try:
        sig = bytes.fromhex(payload.get("signature", ""))
    except (ValueError, TypeError):
        return False, {"error": "unparsable signature field"}

    try:
        ok = bool(ed25519.verify(pk, data, sig))
    except (ValueError, TypeError):
        return False, {"error": "signature verification crashed"}

    if not ok:
        return False, {"error": "signature mismatch"}
    return True, {
        "algorithm": payload.get("algorithm"),
        "signer": payload.get("signer"),
    }


def verify_batch(paths, sig_paths=None, public_key=None):
    """Verify Ed25519 signatures for a batch of artifacts.

    Returns list of ``(ok: bool, detail: dict)`` tuples, one per artifact.
    ``sig_paths`` and ``public_key`` can be scalars (applied to all) or lists
    matching the length of ``paths``.
    """
    if sig_paths is None:
        sig_paths = [None] * len(paths)
    if isinstance(sig_paths, pathlib.Path):
        sig_paths = [sig_paths] * len(paths)
    if isinstance(public_key, pathlib.Path):
        public_key = [public_key] * len(paths)

    results = []
    for i, path in enumerate(paths):
        sp = sig_paths[i] if i < len(sig_paths) else None
        pk = (
            public_key[i]
            if (isinstance(public_key, list) and i < len(public_key))
            else public_key
        )
        results.append(verify_artifact(path, sp, pk))
    return results


def verify_artifact(path, sig_path=None, public_key=None):
    """Verify both message hash and Ed25519 signature of an artifact.

    Returns ``(ok: bool, detail: dict)``. Combines hash check and signature
    verification into a single call for convenience.
    """
    path = pathlib.Path(path)
    sig_path = pathlib.Path(sig_path) if sig_path else pathlib.Path(str(path) + ".sig")
    if not sig_path.exists():
        return False, {"error": "no signature file", "sig_path": str(sig_path)}
    try:
        payload = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, {"error": "unparsable signature", "detail": str(exc)}

    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if payload.get("message_sha256") != digest:
        return False, {
            "error": "message hash mismatch",
            "expected": payload.get("message_sha256"),
            "actual": digest,
        }

    pk = _coerce_public_key(public_key) if public_key is not None else None
    if pk is None:
        try:
            pk = _coerce_public_key(payload.get("public_key"))
        except (KeyError, ValueError, TypeError):
            return False, {"error": "no public key in signature file"}
    try:
        sig = bytes.fromhex(payload.get("signature", ""))
    except (ValueError, TypeError):
        return False, {"error": "unparsable signature field"}

    try:
        ok = bool(ed25519.verify(pk, data, sig))
    except (ValueError, TypeError):
        return False, {"error": "signature verification crashed"}

    if not ok:
        return False, {"error": "signature mismatch"}
    return True, {
        "algorithm": payload.get("algorithm"),
        "signer": payload.get("signer"),
    }
