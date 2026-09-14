"""SBOM collection for a model artifact directory."""

import hashlib
import json
import os
import pathlib

_CHUNK = 1024 * 1024

# memory guard: only hash files up to this size (bytes) by default
_LOGGED_HASH_MAX = 512 * 1024 * 1024


def _sha256(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def collect_sbom(root):
    """Walk *root* and produce an SBOM summary of every file beneath it."""
    root = pathlib.Path(root)
    if not root.exists():
        raise FileNotFoundError(root)
    files = []
    if root.is_file():
        paths = [root]
    else:
        paths = sorted(p for p in root.rglob("*") if p.is_file())
    for path in paths:
        rel = os.path.relpath(path, root) if root.is_dir() else path.name
        size = path.stat().st_size
        files.append(
            {
                "path": rel.replace(os.sep, "/"),
                "size_bytes": size,
                "sha256": _sha256(path) if size <= _LOGGED_HASH_MAX else None,
            }
        )
    return {
        "root": str(root),
        "file_count": len(files),
        "total_bytes": sum(f["size_bytes"] for f in files),
        "files": files,
    }


def to_sbom_json(sbom, path):
    payload = {
        "format": "sneppx-shield-sbom",
        "version": "0.1.0",
        **sbom,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return payload