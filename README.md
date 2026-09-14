# SNEPPX Shield - AI Security & Compliance Suite

Security and compliance tooling around the `sneppx-alg` core, including
SBOM generation, signed-model verification (Ed25519/Dilithium), watermarking
hooks, and audit report generation.

> Status: skeleton (WIP)

## Layout
- `src/sneppx_shield/cli.py` - `sneppx-shield audit <model>` entry point
- `src/sneppx_shield/audit.py` - collects SBOM/security facts from a model
- `src/sneppx_shield/report.py` - renders Markdown/PDF compliance reports
- `tests/` - smoke tests

## Roadmap
- [ ] SBOM extraction
- [ ] signed-update verification integration
- [ ] adversarial watermark hooks
- [ ] report generation (EU AI Act / ISO 42001)

## License
MIT - part of the SneppX open-core ecosystem. Commercial/enterprise tiers sold separately.
