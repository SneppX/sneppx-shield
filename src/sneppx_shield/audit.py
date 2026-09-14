def collect(model_path):
    """Collect SBOM/security facts from a model artifact (skeleton)."""
    return {
        "model": str(model_path),
        "size_bytes": 0,
        "hash_sha256": None,
        "signature_verified": False,
        "framework": "unknown",
    }
