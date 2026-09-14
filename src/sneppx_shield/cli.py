import argparse
import json
import pathlib
import sys

from sneppx_shield import signature


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sneppx-shield", description="AI security & compliance suite")
    parser.add_argument("--version", action="version", version="sneppx-shield 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit a model artifact")
    audit.add_argument("model", help="path to the model artifact (file or directory)")
    audit.add_argument("--format", choices=["markdown", "json"], default="markdown")
    audit.add_argument("--out", help="write report to this file instead of stdout")
    audit.add_argument("--evidence", help="comma-separated key=value evidence, e.g. model_card=true,risk_assessed=true")
    audit.add_argument("--strict", action="store_true", help="exit non-zero when rating != pass")

    sign = sub.add_parser("sign", help="sign a model artifact (detached signature)")
    sign.add_argument("model", help="path to the model file")
    sign.add_argument("--signer", default=None)

    args = parser.parse_args(argv)

    if args.command == "audit":
        return _run_audit(args)
    if args.command == "sign":
        sig_path, _ = signature.sign_file(args.model, signer=args.signer)
        print(f"signed -> {sig_path}")
        return 0
    return 2


def _run_audit(args):
    from sneppx_shield import audit, report

    evidence = _parse_evidence(args.evidence)
    try:
        facts = audit.collect(args.model, evidence=evidence)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = report.render(facts, fmt=args.format)
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        print(f"report written -> {args.out}")
    else:
        print(text)

    if args.strict and facts["compliance_rating"] != "pass":
        return 1
    return 0


def _parse_evidence(raw):
    if not raw:
        return {}
    out = {}
    for item in raw.split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        out[key.strip()] = value.strip().lower() in {"1", "true", "yes"}
    return out


if __name__ == "__main__":
    sys.exit(main())