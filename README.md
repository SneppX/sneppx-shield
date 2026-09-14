# SNEPPX Shield - AI Security & Compliance Suite

Security and compliance tooling around the `sneppx-alg` core: SBOM
generation, detached-signature verification, and compliance scoring against
EU AI Act / ISO 42001 / NIST AI RMF control themes.

> Status: alpha (MIT open core). Commercial/enterprise tiers sold separately.

## Features
- **SBOM extraction** - walk a model artifact (file or directory), compute
  per-file SHA-256 + sizes, emit a portable SBOM JSON.
- **Signature verification** - detached `.sig` signing/verification;
  production path integrates `sneppx-alg` Ed25519 (see `signature.py`).
- **Compliance scoring** - 8 controls across three frameworks, with
  pass/review/fail rating.
- **Reports** - Markdown or JSON.
- **CLI** - `sneppx-shield audit|sign`.

## Usage

```bash
# audit a model (stdout Markdown)
sneppx-shield audit ./model_dir

# audit with evidence and exit-code gating for CI
sneppx-shield audit ./model_dir \
  --evidence model_card=true,risk_assessed=true,monitoring=true \
  --format json --out report.json --strict

# sign a single-file artifact (produces artifact.bin.sig)
sneppx-shield sign ./artifact.bin --signer "SneppX org"
```

Exit codes: `0` ok, `1` non-compliant under `--strict`, `2` usage/input error.

## Layout
- `src/sneppx_shield/sbom.py` - SBOM collection
- `src/sneppx_shield/signature.py` - detached signature sign/verify
- `src/sneppx_shield/compliance.py` - control matrix + scoring
- `src/sneppx_shield/audit.py` - audit orchestration
- `src/sneppx_shield/report.py` - Markdown/JSON renderers
- `src/sneppx_shield/cli.py` - entry point
- `tests/` - pytest suite (stdlib only, no install deps)

## Roadmap
- [x] SBOM extraction
- [x] signed-artifact verification (portable layout; Ed25519 integration next)
- [x] compliance score (EU AI Act / ISO 42001 / NIST AI RMF)
- [ ] real Ed25519/Dilithium integration from `sneppx-alg`
- [ ] adversarial watermark hooks
- [ ] PDF report export

## License
MIT - part of the SneppX open-core ecosystem. Commercial/enterprise tiers sold separately.