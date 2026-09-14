import json


def render(facts):
    """Render a compliance report as Markdown (skeleton)."""
    return "# SneppX Shield Report\n\n" + json.dumps(facts, indent=2)
