import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sneppx-shield", description="AI security & compliance suite")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit a model artifact")
    audit.add_argument("model", help="path to the model artifact")
    args = parser.parse_args(argv)
    if args.command == "audit":
        from sneppx_shield.audit import collect
        facts = collect(args.model)
        from sneppx_shield.report import render
        print(render(facts))


if __name__ == "__main__":
    main()
