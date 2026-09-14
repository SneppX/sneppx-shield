"""Verify the pure-Python Ed25519 against RFC 8032 test vectors."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sneppx_shield import ed25519  # noqa: E402


def _seed_sk(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pk = ed25519.publickey_from_seed(seed)
    return pk, seed + pk


VECTORS = [
    # (seed_hex, pk_hex, msg_hex, sig_hex)
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def test_rfc8032_vectors():
    for i, (seed, pk_hex, msg_hex, sig_hex) in enumerate(VECTORS, 1):
        got_pk, sk = _seed_sk(seed)
        assert got_pk == bytes.fromhex(pk_hex), f"vector {i}: pk mismatch"
        msg = bytes.fromhex(msg_hex)
        sig = ed25519.sign(sk, msg)
        assert sig == bytes.fromhex(sig_hex), f"vector {i}: sig mismatch"
        assert ed25519.verify(got_pk, msg, sig) is True
        assert ed25519.verify(got_pk, msg + b"x", sig) is False


def test_roundtrip_and_tamper():
    pk, sk = ed25519.keypair()
    for message in (b"", b"hello", b"\x00" * 300):
        sig = ed25519.sign(sk, message)
        assert ed25519.verify(pk, message, sig) is True
        assert ed25519.verify(pk, message + b"X", sig) is False
        assert ed25519.verify(b"0" * 32, message, sig) is False
    short = ed25519.publickey_from_seed(bytes.fromhex(VECTORS[0][0]))
    assert short == bytes.fromhex(VECTORS[0][1])